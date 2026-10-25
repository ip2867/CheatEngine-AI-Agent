--[[
  ce_ai_bridge.lua  --  CE-side bridge for the CE+AI project (P0)
  Loaded via CE autorun (C:\Program Files\Cheat Engine\autorun\ is writable).

  Design constraints this file must satisfy:
    * All CE API calls happen on the main thread. Only pipe I/O runs on the worker
      thread, via createThread + synchronize. synchronize is never nested.
    * Wire format is length-prefixed JSON: 4-byte little-endian length, then UTF-8 bytes.
    * Every command has a timeout; a hung command must not wedge the pipe forever.

  P0 scope: ping / proc_info / read. Scanning and writes come in P1/P2.
]]

local BRIDGE_VERSION = '0.4.0'
local PIPE_NAME      = 'CE_AI_Bridge_v1_0'

-- Bridge-owned state. Kept in CE's process, so it survives an orchestrator restart.
local bridgeState = {
  scans = {},          -- scanId -> { memscan, foundlist, count }
  nextScanId = 0,
  startedAt = os.time(),
  auditFn = nil,       -- set by the Python side through 'audit_init'
}

-- Targets the bridge is willing to attach to. Anything else is refused before
-- OpenProcess is called. Populated by the Python side; empty means "deny all".
local allowedImages = {}

local function logf(fmt, ...)
  print('[CE-AI] ' .. string.format(fmt, ...))
end

local function audit(event, detail)
  if bridgeState.auditFn then
    pcall(bridgeState.auditFn, event, detail)
  end
end

----------------------------------------------------------------------
-- JSON (minimal, no external deps)
----------------------------------------------------------------------

local Json = {}

local function jsonEscape(s)
  s = s:gsub('[%z\1-\31\\"]', function(c)
    if c == '"' then return '\\"' end
    if c == '\\' then return '\\\\' end
    if c == '\n' then return '\\n' end
    if c == '\r' then return '\\r' end
    if c == '\t' then return '\\t' end
    return string.format('\\u%04x', c:byte())
  end)
  return s
end

local function isArray(t)
  if type(t) ~= 'table' then return false end
  local n = 0
  for k in pairs(t) do
    if type(k) ~= 'number' then return false end
    n = n + 1
  end
  return n == #t and n > 0
end

function Json.encode(v)
  local tv = type(v)
  if v == nil then return 'null'
  elseif tv == 'boolean' then return v and 'true' or 'false'
  elseif tv == 'number' then
    if v ~= v or v == math.huge or v == -math.huge then return 'null' end
    if math.floor(v) == v and math.abs(v) < 9007199254740992 then
      return string.format('%d', v)
    end
    return string.format('%.17g', v)
  elseif tv == 'string' then
    return '"' .. jsonEscape(v) .. '"'
  elseif tv == 'table' then
    local out = {}
    if isArray(v) then
      for i = 1, #v do out[i] = Json.encode(v[i]) end
      return '[' .. table.concat(out, ',') .. ']'
    else
      for k, val in pairs(v) do
        if type(k) == 'string' then
          out[#out + 1] = '"' .. jsonEscape(k) .. '":' .. Json.encode(val)
        end
      end
      return '{' .. table.concat(out, ',') .. '}'
    end
  end
  return 'null'
end

local function jsonDecode(str)
  local pos = 1

  local function skip()
    while pos <= #str do
      local c = str:sub(pos, pos)
      if c == ' ' or c == '\t' or c == '\n' or c == '\r' then pos = pos + 1 else break end
    end
  end

  local parseValue

  local function parseString()
    pos = pos + 1
    local buf = {}
    while pos <= #str do
      local c = str:sub(pos, pos)
      if c == '"' then pos = pos + 1; return table.concat(buf)
      elseif c == '\\' then
        local n = str:sub(pos + 1, pos + 1)
        if n == 'n' then buf[#buf + 1] = '\n'
        elseif n == 'r' then buf[#buf + 1] = '\r'
        elseif n == 't' then buf[#buf + 1] = '\t'
        elseif n == 'b' then buf[#buf + 1] = '\b'
        elseif n == 'f' then buf[#buf + 1] = '\f'
        elseif n == 'u' then
          local hex = str:sub(pos + 2, pos + 5)
          local cp = tonumber(hex, 16) or 63
          if cp >= 0xD800 and cp <= 0xDBFF then
            local hex2 = str:sub(pos + 8, pos + 11)
            local lo = tonumber(hex2, 16)
            if lo and lo >= 0xDC00 and lo <= 0xDFFF then
              cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
              pos = pos + 6
            end
          end
          buf[#buf + 1] = utf8.char(cp)
          pos = pos + 4
        else buf[#buf + 1] = n end
        pos = pos + 2
      else
        buf[#buf + 1] = c
        pos = pos + 1
      end
    end
    error('unterminated string')
  end

  parseValue = function()
    skip()
    local c = str:sub(pos, pos)
    if c == '{' then
      pos = pos + 1
      local obj = {}
      skip()
      if str:sub(pos, pos) == '}' then pos = pos + 1; return obj end
      while true do
        skip()
        local k = parseString()
        skip()
        pos = pos + 1 -- ':'
        obj[k] = parseValue()
        skip()
        local d = str:sub(pos, pos)
        pos = pos + 1
        if d == '}' then return obj end
      end
    elseif c == '[' then
      pos = pos + 1
      local arr = {}
      skip()
      if str:sub(pos, pos) == ']' then pos = pos + 1; return arr end
      while true do
        arr[#arr + 1] = parseValue()
        skip()
        local d = str:sub(pos, pos)
        pos = pos + 1
        if d == ']' then return arr end
      end
    elseif c == '"' then
      return parseString()
    elseif str:sub(pos, pos + 3) == 'true' then pos = pos + 4; return true
    elseif str:sub(pos, pos + 4) == 'false' then pos = pos + 5; return false
    elseif str:sub(pos, pos + 3) == 'null' then pos = pos + 4; return nil
    else
      local num = str:match('^-?%d+%.?%d*[eE]?[-+]?%d*', pos)
      if not num or num == '' then error('unexpected character at ' .. pos) end
      pos = pos + #num
      return tonumber(num)
    end
  end

  local ok, result = pcall(function() return parseValue() end)
  if not ok then return nil, tostring(result) end
  return result
end

Json.decode = jsonDecode

----------------------------------------------------------------------
-- Frame I/O
----------------------------------------------------------------------

local function writeFrame(pipe, tbl)
  local payload = Json.encode(tbl)
  local len = #payload
  local header = {
    len % 256,
    math.floor(len / 256) % 256,
    math.floor(len / 65536) % 256,
    math.floor(len / 16777216) % 256,
  }
  pipe.writeBytes(header, 4)
  pipe.writeString(payload)
end

local function readFrame(pipe)
  local hdr = pipe.readBytes(4)
  if hdr == nil or #hdr < 4 then return nil, 'short header' end
  local len = hdr[1] + hdr[2] * 256 + hdr[3] * 65536 + hdr[4] * 16777216
  if len <= 0 or len > 8 * 1024 * 1024 then return nil, 'bad length ' .. tostring(len) end
  local payload = pipe.readString(len)
  if payload == nil then return nil, 'short body' end
  local ok, decoded = pcall(Json.decode, payload)
  if not ok then return nil, 'json error: ' .. tostring(decoded) end
  return decoded
end

----------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------

local function hex(n)
  if n == nil then return nil end
  return string.format('0x%X', n)
end

-- Addresses arrive as "0x1A2B", "1A2B" (from CE's own scan results), or numbers.
-- Parsing bare hex as decimal silently yields a wrong address, so try hex second.
local function parseAddr(v)
  if type(v) == 'number' then return v end
  if type(v) ~= 'string' then return nil end
  local trimmed = v:gsub('^%s+', ''):gsub('%s+$', '')
  local n = tonumber(trimmed)
  if n ~= nil then return n end
  local hexOnly = trimmed:gsub('^0[xX]', '')
  if hexOnly:match('^%x+$') then
    return tonumber(hexOnly, 16)
  end
  -- "module+offset" / "module-offset".  This is how every reverse-engineering
  -- note writes an address and how v1's own documentation writes them, so
  -- rejecting it just taught callers to hand-resolve bases and get them wrong.
  local modName, sign, offText = trimmed:match('^([%w_%.%-]+)%s*([%+%-])%s*(.+)$')
  if modName ~= nil and offText ~= nil then
    local off = tonumber(offText)
    if off == nil then
      local h = offText:gsub('^0[xX]', '')
      if h:match('^%x+$') then off = tonumber(h, 16) end
    end
    if off == nil then return nil end
    local base, found = nil, false
    local okPcall, mod = pcall(function() return getAddress(modName) end)
    if okPcall and type(mod) == 'number' and mod ~= 0 then
      base, found = mod, true
    end
    if not found then
      local okEnum, mods = pcall(enumModules)
      if okEnum and type(mods) == 'table' then
        local wanted = modName:lower()
        for i = 1, #mods do
          local m = mods[i]
          if tostring(m.Name):lower() == wanted then base, found = m.Address, true break end
        end
      end
    end
    if not found then return nil end
    if sign == '-' then return base - off end
    return base + off
  end
  return nil
end

local function ok(data)
  return { ok = true, data = data }
end

-- `extra` lets a failure carry actionable fields (hint, current value, the
-- refusals list) instead of forcing the caller to parse the message text.
local function fail(code, message, extra)
  local err = { code = code, message = message }
  if type(extra) == 'table' then
    for k, v in pairs(extra) do if err[k] == nil then err[k] = v end end
  end
  return { ok = false, error = err }
end

-- CE's read* functions silently return 0/garbage for unmapped addresses instead
-- of raising, which makes a hallucinated address indistinguishable from a real
-- zero value. Validate before reading: the address must be committed and readable.
local MEM_COMMIT = 0x1000
local PAGE_GUARD = 0x100
local PAGE_NOACCESS = 0x01

local function checkReadable(addr)
  local info = getMemoryRegionInfo(addr)
  if info == nil then
    return false, 'address is not mapped'
  end
  if info.State ~= MEM_COMMIT then
    return false, string.format('region not committed (State=0x%X)', info.State)
  end
  local prot = info.Protect or 0
  if (prot & PAGE_NOACCESS) ~= 0 then
    return false, string.format('page has no access (Protect=0x%X)', prot)
  end
  if (prot & PAGE_GUARD) ~= 0 then
    return false, string.format('page is a guard page (Protect=0x%X)', prot)
  end
  return true
end

-- Reads `size` bytes and returns them either as a byte table or a raw string.
-- CE's own readBytes returns a string; the v1 handlers mostly wanted the table
-- form for value reconstruction, and a raw string for hashing/comparison.
-- Grab Cheat Engine's own readBytes before shadowing the name.  `local function
-- readBytes` makes `readBytes` visible inside its own body, so any call to it
-- there is a recursive call to this wrapper, not to the engine -- it overflowed
-- the stack, pcall swallowed the error, and every byte read in the bridge
-- reported "no data" for months of this session's debugging.
local ceReadBytes = readBytes

-- Reads `size` bytes and returns them either as a byte table or a raw string.
-- celua.txt:61 -- readBytes(address, bytecount, ReturnAsTable).
local function readBytes(addr, size, asTable)
  if size == nil or size <= 0 then return nil end
  local readable = checkReadable(addr)
  if not readable then return nil end
  local okRead, raw = pcall(function() return ceReadBytes(addr, size, asTable == true) end)
  if not okRead or raw == nil then return nil end
  if asTable == true and type(raw) == 'string' then
    local out = {}
    for i = 1, #raw do out[i] = raw:byte(i) end
    return out
  end
  return raw
end

-- Runs fn on the main thread and returns its result to the worker thread.
local function onMain(fn)
  local result
  synchronize(function() result = fn() end)
  return result
end

----------------------------------------------------------------------
-- Whitelist
----------------------------------------------------------------------

-- Resolve a PID to its image path so the whitelist can be enforced on the
-- actual executable, not on a caller-supplied name.
local function imagePathOf(pid)
  local modules = enumModules(pid)
  if modules == nil or modules[1] == nil then return nil end
  return modules[1].PathToFile or modules[1].Name
end

local function isAllowed(pid)
  if #allowedImages == 0 then return false, 'whitelist is empty' end
  local path = imagePathOf(pid)
  if path == nil then return false, 'cannot resolve image path for pid ' .. tostring(pid) end
  local lower = path:lower()
  for i = 1, #allowedImages do
    local needle = allowedImages[i]:lower()
    if lower == needle or lower:sub(-#needle) == needle then
      return true, path
    end
  end
  return false, path
end


----------------------------------------------------------------------
-- Command handlers (each runs on the MAIN thread)
----------------------------------------------------------------------

----------------------------------------------------------------------
-- v2 modules
-- Included here rather than dofile()d: these files share the bridge's local
-- helpers (hex, parseAddr, ok, fail, readBytes, TRIGGERS) and must not each
-- carry a private copy of them, or the address parsing would drift between the
-- scan path and the breakpoint path.
----------------------------------------------------------------------

local function __loadModule(name)
  local here = debug.getinfo(1, 'S').source:gsub('^@', '')
  local dir = here:match('^(.*[\\/])') or ''
  local candidates = {
    dir .. name,
    dir .. name .. '.lua',
  }
  for _, path in ipairs(candidates) do
    local f = io.open(path, 'r')
    if f ~= nil then
      local src = f:read('*a')
      f:close()
      local chunk, perr = load(src, '@' .. path)
      if chunk == nil then
        error('cannot compile ' .. path .. ': ' .. tostring(perr))
      end
      return chunk()
    end
  end
  return nil, 'module not found next to the bridge: ' .. name
end

local insn, insnErr = __loadModule('v2_insn.lua')
local policy, policyErr = __loadModule('v2_policy.lua')
local bpMod, bpErr = __loadModule('v2_bp.lua')
local causal, causalErr = __loadModule('v2_causal.lua')
local handlers = {}

-- The instruction module needs the bridge's own address parser; hand it over
-- once instead of duplicating the parser inside every module.
if insn ~= nil then
  pcall(function() insn.configure({ hex = hex, parseAddr = parseAddr,
                                   checkReadable = checkReadable,
                                   readBytes = readBytes }) end)
end

handlers.set_whitelist = function(args)
  local list = args.images or {}
  allowedImages = {}
  for i = 1, #list do
    allowedImages[#allowedImages + 1] = tostring(list[i])
  end
  logf('whitelist set: %d entries', #allowedImages)
  return ok({ count = #allowedImages })
end

handlers.get_whitelist = function()
  return ok({ images = allowedImages })
end

handlers.ping = function()
  return ok({
    pong = true,
    version = BRIDGE_VERSION,
    ceVersion = getCEVersion and tostring(getCEVersion()) or 'unknown',
    uptime = os.time() - bridgeState.startedAt,
  })
end

handlers.proc_info = function()
  local pid = getOpenedProcessID()
  if pid == nil or pid == 0 then
    return fail('NOT_ATTACHED', 'no process attached')
  end

  local bits = 32
  if targetIs64Bit and targetIs64Bit() then bits = 64 end

  local modules = enumModules() or {}
  local mainModule = modules[1]

  return ok({
    pid = pid,
    name = mainModule and mainModule.Name or '',
    bits = bits,
    moduleCount = #modules,
    mainModule = mainModule and mainModule.Name or nil,
    mainBase = mainModule and hex(mainModule.Address) or nil,
  })
end

-- Every address handed to the model should carry its owning module, so a later
-- ASLR relocation can be expressed as module+offset instead of an absolute value.
handlers.module_of = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end

  local modules = enumModules() or {}
  for i = 1, #modules do
    local m = modules[i]
    local base = m.Address
    local size = m.Size or 0
    if size > 0 and addr >= base and addr < base + size then
      return ok({
        module = m.Name,
        base = hex(base),
        offset = hex(addr - base),
        offsetDec = addr - base,
      })
    end
  end
  return ok({ module = false, base = false, offset = false })
end

handlers.read = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr must be a number or hex string') end

  local readable, reason = checkReadable(addr)
  if not readable then
    return fail('ADDRESS_NOT_MAPPED', reason)
  end

  local vtype = args.type or 'dword'
  local out = {}

  local okRead, value = pcall(function()
    if vtype == 'dword' then return readInteger(addr)
    elseif vtype == 'qword' then return readQword(addr)
    elseif vtype == 'word' then return readSmallInteger(addr)
    elseif vtype == 'byte' then
      -- pcall returns (true, nil) when the body returns nil, so `okRead and value
      -- == nil` is a read failure, not a zero.  Return a sentinel that the
      -- caller below turns into READ_FAILED instead of silently answering {}.
      local one = readBytes(addr, 1, true)
      if one == nil or one[1] == nil then error('byte read returned no data at ' .. hex(addr)) end
      return one[1]
    elseif vtype == 'float' then return readFloat(addr)
    elseif vtype == 'double' then return readDouble(addr)
    elseif vtype == 'pointer' then return readPointer(addr)
    elseif vtype == 'utf16' then return readString(addr, 256, true)
    elseif vtype == 'bytes' or vtype == 'aob' then
      -- Raw dump.  Capped because the reply travels as one JSON frame and a
      -- whole-section dump would be megabytes of hex for no extra information.
      local count = tonumber(args.count or args.length) or 16
      if count < 1 then count = 1 end
      if count > 4096 then count = 4096 end
      local tabs = readBytes(addr, count, true)
      if tabs == nil then return nil end
      local parts = {}
      for i = 1, #tabs do parts[i] = string.format('%02X', tabs[i]) end
      return table.concat(parts, ' ')
    else return readString(addr, 256, false) end
  end)

  if not okRead then
    return fail('READ_FAILED', tostring(value))
  end

  out.value = value
  if type(value) == 'number' and vtype ~= 'float' and vtype ~= 'double' then
    out.hex = hex(value)
  end

  return ok(out)
end

handlers.attach = function(args)
  local pid = tonumber(args.pid)
  local name = args.name

  if pid == nil and name == nil then
    return fail('VALIDATION_FAILED', 'pid or name required')
  end

  -- Resolve the PID first so the whitelist is checked against the real image
  -- path, before CE is allowed to open a handle to the target.
  local targetPid = pid
  if targetPid == nil then
    -- CE only accepts a name here; resolve it by trying the open and re-checking.
    openProcess(name)
    targetPid = getOpenedProcessID()
    if targetPid == nil or targetPid == 0 then
      return fail('ATTACH_FAILED', 'could not find process ' .. tostring(name))
    end
    local allowed, path = isAllowed(targetPid)
    if not allowed then
      pcall(function() closeProcess() end)
      audit('attach_denied', { pid = targetPid, path = path })
      return fail('PERMISSION_DENIED', 'not whitelisted: ' .. tostring(path))
    end
    return ok({ pid = targetPid })
  end

  local allowed, path = isAllowed(targetPid)
  if not allowed then
    audit('attach_denied', { pid = targetPid, path = path })
    return fail('PERMISSION_DENIED', 'not whitelisted: ' .. tostring(path))
  end

  openProcess(targetPid)
  local opened = getOpenedProcessID()
  if opened == nil or opened == 0 then
    return fail('ATTACH_FAILED', 'could not attach to pid ' .. targetPid)
  end

  audit('attach', { pid = opened, path = path })
  return ok({ pid = opened, path = path })
end

----------------------------------------------------------------------
-- Scan (P1 starts here, minimal version to prove the path)
----------------------------------------------------------------------

local VAR_TYPES = {
  byte = vtByte, word = vtWord, dword = vtDword, qword = vtQword,
  float = vtSingle, double = vtDouble, string = vtString,
}

local VAR_SIZES = {
  byte = 1, word = 2, dword = 4, qword = 8, float = 4, double = 8,
}

local function typeSize(vtypeName)
  return VAR_SIZES[vtypeName] or 4
end

local function newScanId()
  bridgeState.nextScanId = bridgeState.nextScanId + 1
  return 's' .. bridgeState.nextScanId
end

handlers.scan_first = function(args)
  local vtypeName = args.type or 'dword'
  local vartype = VAR_TYPES[vtypeName]
  if vartype == nil then
    return fail('VALIDATION_FAILED', 'unsupported type: ' .. tostring(vtypeName))
  end

  -- S1/S2 gates.  v1 spent an entire run narrowing an anchor nobody had ever
  -- verified: the first scan found 34k addresses because the anchor was wrong,
  -- and every later scan inherited that error.  The gates are opt-in via
  -- CE_AI_POLICY=0 so unit probes can still drive the raw scanner, but the
  -- default path cannot skip them.
  if policy ~= nil and os.getenv('CE_AI_POLICY') ~= '0' then
    local gate, gateErr = policy.gateScan('scan_first', args, getOpenedProcessID())
    if gate == nil then
      return { ok = false, error = gateErr }
    end
  end

  -- First scans accept a range, not just an exact value.  Hunting a heap field
  -- whose current value is unknown used to mean an unknown scan (whose results
  -- live on disk and take minutes to narrow) or a blind exact guess.  A range
  -- first scan is the practical middle: it keeps a candidate set that fits in
  -- memory, so every later narrowing step stays fast and readable.
  local OPS_FIRST = {
    exact = soExactValue,
    bigger = soBiggerThan,
    smaller = soSmallerThan,
    between = soValueBetween,
  }
  local opName = args.op or args.mode
  local op = opName and OPS_FIRST[opName] or nil
  local wantsRange = op ~= nil and op ~= soExactValue

  -- 'unknown' starts a scan that records every address, so a later `decreased`
  -- can narrow by behaviour when the current value is not known. This is the CE
  -- "unknown initial value" scan.
  local isUnknown = (not wantsRange) and (args.value == nil or tostring(args.value) == 'unknown')

  local value = args.value
  if not isUnknown and value == nil then
    return fail('VALIDATION_FAILED', 'value required for first scan')
  end
  -- Only `between` takes two bounds.  `bigger`/`smaller` take a single
  -- threshold in `value`, so demanding value2 there rejected valid calls.
  if op == soValueBetween and args.value2 == nil then
    return fail('VALIDATION_FAILED', opName .. ' scan needs value2 (the upper bound)')
  end

  -- Values must be strings for CE's scan API.  isHexadecimalInput tells CE how
  -- to READ input1, so a hex value must stay hex when that flag is set.  The
  -- previous code converted "0x64" to "100" and then still flagged it as hex,
  -- making CE scan 0x100 instead of 0x64.  Worse, tonumber("0x64", 16) is nil
  -- in Lua 5.3 (an explicit base forbids the 0x prefix), so the `or 0` turned
  -- every 0x-prefixed scan into a silent scan for zero.
  local valueStr = isUnknown and '0' or tostring(value)
  local isHex = false
  if type(value) == 'string' then
    local stripped = value:match('^%s*0[xX](%x+)%s*$')
    if stripped then
      valueStr = stripped
      isHex = true
    elseif args.hex == true and value:match('^%s*[%x]+%s*$') then
      -- Bare hex is only assumed when the caller asks for it.  Guessing would
      -- turn "100" into 0x100 for anyone who meant the decimal hundred.
      valueStr = value:match('^%s*([%x]+)%s*$')
      isHex = true
    end
  end

  local ms = createMemScan()
  if ms == nil then return fail('INTERNAL', 'createMemScan failed') end

  local protection = args.protect or '+W-C'
  local aligned = args.aligned == true
  local alignType = aligned and fsmAligned or fsmNotAligned
  local alignParam = aligned and '4' or nil

  -- Hard cap at the real Windows user-mode ceiling. 0x7FFFFFFFFFFFFFFF (used by
  -- several published bridges) reaches into kernel space and can BSOD a scan.
  local startAddr = tonumber(args.start) or 0
  local stopAddr = tonumber(args.stop) or 0x00007FFFFFFFFFFF

  -- An unknown scan with no explicit range walks the entire user address space
  -- and keeps the results on disk.  That is minutes of work, and because every
  -- bridge command is synchronize()d onto Cheat Engine's main thread it also
  -- freezes the CE window for the whole time -- Windows responds by killing the
  -- process (Event Log: "Application Hang", cheatengine-x86_64-SSE4-AVX2.exe).
  -- Refusing is the honest answer: "unknown" without a bound is almost always a
  -- caller that meant a range scan and forgot one.
  if isUnknown and args.start == nil and args.stop == nil then
    return fail('RANGE_REQUIRED',
      'unknown scan needs start/stop; scanning the whole address space blocks '
      .. 'the Cheat Engine UI and gets CE killed. Narrow to the regions you care '
      .. 'about first (memory_regions lists them), or use a range first scan '
      .. '(op=between/bigger/smaller) when the value has a plausible bound')
  end

  local scanOption = isUnknown and soUnknownValue or (op or soExactValue)

  -- A range first scan also needs its upper bound written in the same notation
  -- as the lower bound, otherwise hex ranges silently compare a hex low bound
  -- against a decimal high bound.
  local value2Str = nil
  if wantsRange then
    value2Str = tostring(args.value2)
    if type(args.value2) == 'string' then
      local s2 = args.value2:match('^%s*0[xX](%x+)%s*$')
      if s2 then
        value2Str = s2
        isHex = true
      elseif isHex and args.value2:match('^%s*[%x]+%s*$') then
        value2Str = args.value2:match('^%s*([%x]+)%s*$')
      end
    end
  end


  ms.firstScan(scanOption, vartype, rtRounded, valueStr, value2Str,
               startAddr, stopAddr, protection, alignType, alignParam,
               isHex, false, false, false)
  -- waitTillDone returns false on timeout (celua.txt:2649).  Ignoring it meant
  -- an unfinished scan was read back as FoundCount 0 and reported as "no
  -- matches", which reads like a wrong anchor instead of a stalled scan.
  if ms.waitTillDone(60000) == false then
    return fail('SCAN_TIMEOUT', 'first scan did not finish within 60s; '
             .. 'narrow the range (start/stop) or relax the protection filter')
  end

  -- Differential nextScans (changed / unchanged / decreased / increased) do not
  -- compare against "whatever the memscan had last": CE compares against a
  -- NAMED saved result list, and per celua.txt:2643 ("savedResultName ... First
  -- scan is called FIRST") Cheat Engine already stores the first scan under
  -- 'FIRST' by itself.
  --
  -- Do NOT call saveCurrentResults('FIRST') here to "make sure".  Saving a
  -- result set that CE is still holding wedges the debugger thread: the handler
  -- returns, the reply is written, and then CE's window stops pumping messages
  -- until Windows kills the process ("Application Hang").  Measured: handler
  -- total 9 ms, firstScan 27 ms, waitTillDone 33 ms, then a permanent freeze --
  -- reproducible with a 4 KB scan, attached or not.
  local baselineName = 'FIRST'

  -- FoundCount is the truth for how many addresses the scan matched, and it is
  -- available without materialising a FoundList.  Do NOT build one here: an
  -- attached FoundList pulls the whole result set into a list and leaves CE's
  -- memscan with no previous-result baseline, which made every later
  -- changed/unchanged/decreased nextScan return nonsense (unchanged kept all
  -- 96918 rows, changed wiped them all).  The list is created lazily, only
  -- when something actually needs to page or read addresses (see ensureList).
  local foundCount = 0
  do
    local okfc, fc = pcall(function() return ms.FoundCount end)
    if okfc and tonumber(fc) then foundCount = tonumber(fc) end
  end

  local scanId = newScanId()
  bridgeState.scans[scanId] = {
    memscan = ms, foundlist = nil, count = foundCount,
    unknown = isUnknown, onDisk = false, baseline = baselineName,
    vtype = vtypeName, size = typeSize(vtypeName),
  }

  local out = {
    scanId = scanId, total = foundCount, type = vtypeName, value = valueStr,
    op = isUnknown and 'unknown' or (opName or 'exact'),
  }
  -- A first scan always leaves a usable result set.  An unknown scan over the
  -- whole address space spills to disk, but its count is real and a
  -- changed/unchanged nextScan still works on it, so nothing is "unavailable".
  out.resultsAvailable = true
  if foundCount == 0 then
    out.note = 'no address matched this first scan. The anchor is wrong or too '
            .. 'narrow -- pick a different value or range before narrowing further'
  end
  return ok(out)
end

handlers.scan_results = function(args)
  local scanId = args.scanId
  local rec = bridgeState.scans[scanId]
  if rec == nil then return fail('NOT_FOUND', 'unknown scanId: ' .. tostring(scanId)) end

  local limit = tonumber(args.limit) or 50
  if limit < 1 then limit = 1 elseif limit > 200 then limit = 200 end
  local offset = tonumber(args.offset) or 0

  -- Addresses can only be read from a FoundList.  Build it here, on demand,
  -- rather than in scan_first: attaching a list early destroys the memscan's
  -- previous-result baseline that changed/unchanged nextScans compare against.
  local listCount = 0
  if rec.count > 0 then
    pcall(function()
      if rec.foundlist == nil then
        rec.foundlist = createFoundList(rec.memscan)
        rec.foundlist.initialize()
      end
      listCount = rec.foundlist.getCount()
    end)
  end
  if listCount == 0 then
    return ok({
      scanId = scanId, total = rec.count, offset = offset, returned = 0, items = {},
      resultsAvailable = false,
      note = 'this scan holds ' .. tostring(rec.count) .. ' results that cannot '
          .. 'be paged (whole-address-space scans keep them on disk); narrow with '
          .. 'scan_next (changed/unchanged/decreased/increased) or use a range first scan',
    })
  end

  local items = {}
  -- Report the scan's real total, not the size of the in-memory list: after a
  -- narrowing scan the list can lag the count, and a silently smaller total
  -- reads like the scan lost results.
  local total = rec.count
  local last = math.min(offset + limit, math.min(total, listCount))
  -- FoundList is 0-indexed: Address[0] .. Address[count-1]
  local liveReads, staleCount = 0, 0
  for i = offset, last - 1 do
    local a = rec.foundlist.Address[i]
    local scanValue = rec.foundlist.Value[i]
    -- FoundList caches the value from scan time.  Handing that back as "value"
    -- made every candidate set look frozen: a caller would compare a cached 4
    -- against fresh memory and conclude nothing had changed.  Read the address
    -- again and say which number is which.
    local nowValue, liveOk = nil, false
    local retried, staleReason = false, nil
    if a ~= nil and rec.vtype ~= nil then
      local num = parseAddr(a)
      if num ~= nil then
        local sz = rec.size or 4
        -- readBytes is defined above this handler; readRaw is not.  A Lua local
        -- only exists after its `local function` line, so calling readRaw here
        -- resolved to a nil global and every page threw INTERNAL.  Same trap as
        -- the v2 module that called checkReadable as a global.
        local before = readBytes(num, sz, true)
        if before == nil then
          -- Heap pages genuinely change state between the scan and this read:
          -- a page can be reserved/freed and re-committed in that window, and
          -- MemScan happily reported it while it was still committed.  Reporting
          -- the scan-time snapshot as the live value would be a lie, but so is
          -- calling it unmapped without a second look.  Re-probe once before
          -- deciding, and keep the reason so the caller can act on it.
          retried = true
          local chk, why = checkReadable(num)
          staleReason = why or (chk and 'read returned no data')
          before = readBytes(num, sz, true)
        end
        if before ~= nil then
          local v = 0
          for k = sz, 1, -1 do v = v * 256 + before[k] end
          nowValue, liveOk = v, true
        end
      end
    end
    local item = { addr = a, value = scanValue, scanValue = scanValue }
    if liveOk then
      item.value = nowValue
      item.live = true
      liveReads = liveReads + 1
      if tostring(nowValue) ~= tostring(scanValue) then item.changedSinceScan = true end
    else
      item.live = false
      item.staleReason = staleReason or 'address could not be re-read'
      item.retried = retried
      staleCount = staleCount + 1
    end
    items[#items + 1] = item
  end

  local out = {
    scanId = scanId,
    total = total,
    offset = offset,
    returned = #items,
    items = items,
    valueSource = 'live read of each address; scanValue is the value recorded at '
               .. 'scan time',
    liveReads = liveReads,
  }
  if staleCount > 0 then
    out.staleReads = staleCount
    out.note = tostring(staleCount) .. ' of ' .. tostring(#items)
            .. ' candidate(s) could not be re-read even after a retry; those are '
            .. 'heap pages that changed state after the scan.  Their value field is '
            .. 'the scan-time snapshot and item.staleReason says why.  Drop them '
            .. 'with cset_exclude, or re-run the narrowing scan -- do not treat a '
            .. 'stale candidate as a live one'
  end
  return ok(out)
end

handlers.scan_stats = function(args)
  local rec = bridgeState.scans[args.scanId]
  if rec == nil then return fail('NOT_FOUND', 'unknown scanId') end
  local p = rec.memscan.getProgress()
  return ok({
    scanId = args.scanId,
    total = rec.count,
    progressTotal = p and p.TotalAddressesToScan or nil,
    progressDone = p and p.CurrentlyScanned or nil,
    found = p and p.ResultsFound or nil,
  })
end

handlers.scan_next = function(args)
  local scanId = args.scanId
  local rec = bridgeState.scans[scanId]
  if rec == nil then return fail('NOT_FOUND', 'unknown scanId: ' .. tostring(scanId)) end

  local opName = args.op or 'exact'
  local OPS = {
    exact = soExactValue,
    bigger = soBiggerThan,
    smaller = soSmallerThan,
    between = soValueBetween,
    increased = soIncreasedValue,
    decreased = soDecreasedValue,
    changed = soChanged,
    unchanged = soUnchanged,
  }
  local op = OPS[opName]
  if op == nil then return fail('VALIDATION_FAILED', 'unsupported op: ' .. tostring(opName)) end

  -- S1/S2 gates.  Narrowing is where a wrong anchor gets laundered into a
  -- confident-looking candidate set, so this path is gated exactly like
  -- scan_first.  Same CE_AI_POLICY=0 escape hatch for unit probes.
  if policy ~= nil and os.getenv('CE_AI_POLICY') ~= '0' then
    local gate, gateErr = policy.gateScan('scan_next', args, getOpenedProcessID())
    if gate == nil then
      return { ok = false, error = gateErr }
    end
  end

  local valueStr = args.value ~= nil and tostring(args.value) or nil
  local value2 = args.value2 ~= nil and tostring(args.value2) or nil
  local isHex = false

  -- Same contract as scan_first: an 0x-prefixed value is hex and must stay hex
  -- so CE reads it correctly.  This used to be hardcoded to false, which made
  -- `between 0x60 0x70` and every other hex nextScan parse as decimal.
  if type(args.value) == 'string' then
    local s = args.value:match('^%s*0[xX](%x+)%s*$')
    if s then
      valueStr = s
      isHex = true
    elseif args.hex == true and args.value:match('^%s*[%x]+%s*$') then
      valueStr = args.value:match('^%s*([%x]+)%s*$')
      isHex = true
    end
  end
  if type(args.value2) == 'string' then
    local s2 = args.value2:match('^%s*0[xX](%x+)%s*$')
    if s2 then
      value2 = s2
      isHex = true
    end
  end

  -- A narrowing scan must never increase the result count. Snapshot it so a
  -- polluted rescan is caught instead of silently handed to the model.
  local before = rec.count

  -- savedresultname is the 10th argument and is what makes a differential scan
  -- possible at all (celua.txt:2618, 2640-2643).  Leaving it nil meant CE had
  -- nothing to compare against: unchanged echoed the whole set back and
  -- changed returned 0 even for an address just written by hand.
  local baseline = rec.baseline or 'FIRST'
  rec.memscan.nextScan(op, rtRounded, valueStr, value2, isHex, false, false, false,
                       false, baseline)
  if rec.memscan.waitTillDone(60000) == false then
    return fail('SCAN_TIMEOUT', 'narrowing scan did not finish within 60s')
  end

  -- No saveCurrentResults here either: it is the same call that wedges CE in
  -- scan_first, and crossing the baseline forward is not worth a dead process.
  -- The cost is that a second consecutive differential scan compares against the
  -- original first scan; the noise that introduces is visible in the counters,
  -- which is what the caller is supposed to reason about anyway.

  -- FoundCount is what the scan actually matched.  Do not touch the FoundList
  -- here: refreshing it invalidates the memscan's own previous-result baseline,
  -- which is exactly what the NEXT differential scan needs.  The list is
  -- refreshed lazily by scan_results.
  local after = before
  do
    local okfc, fc = pcall(function() return rec.memscan.FoundCount end)
    if okfc and tonumber(fc) then after = tonumber(fc) end
  end
  rec.count = after

  if rec.foundlist ~= nil then
    -- Keep an already-attached list in step with the count so a page read
    -- right after this call shows the new set rather than the old one.
    pcall(function()
      rec.foundlist.deinitialize()
      rec.foundlist.initialize()
      local lc = rec.foundlist.getCount()
      if lc == 0 then rec.foundlist = nil end
    end)
  end

  if after > before then
    return fail('SCAN_GREW', string.format(
      'result count grew from %d to %d; scan state is suspect', before, after))
  end

  local out = { scanId = scanId, total = after, before = before, op = opName }
  if after == 0 then
    -- A narrowing scan that eliminates everything is a result, not an error.
    -- Say so explicitly: "0 candidates" is the strongest possible refutation of
    -- the hypothesis behind this scan, and it must not read like a tool failure.
    out.resultsAvailable = false
    out.note = 'narrowing eliminated every candidate. If the target genuinely '
            .. 'changed, the value you anchored on was wrong -- start a new first '
            .. 'scan instead of retrying this one.'
  else
    out.resultsAvailable = true
  end
  return ok(out)
end

handlers.release_scan = function(args)
  local scanId = args.scanId
  local rec = bridgeState.scans[scanId]
  if rec == nil then return fail('NOT_FOUND', 'unknown scanId') end
  -- foundlist is nil unless something paged or read addresses.
  if rec.foundlist ~= nil then
    pcall(function() rec.foundlist.deinitialize() end)
    pcall(function() rec.foundlist.destroy() end)
  end
  pcall(function() rec.memscan.destroy() end)
  bridgeState.scans[scanId] = nil
  return ok({ released = scanId })
end

----------------------------------------------------------------------
-- Analysis group
----------------------------------------------------------------------

handlers.enum_modules = function(args)
  local modules = enumModules() or {}
  local limit = math.min(tonumber(args.limit) or 100, 200)
  local offset = tonumber(args.offset) or 0

  local items = {}
  local last = math.min(offset + limit, #modules)
  for i = offset + 1, last do
    local m = modules[i]
    items[#items + 1] = {
      name = m.Name,
      base = hex(m.Address),
      size = m.Size,
      is64 = m.Is64Bit,
    }
  end

  return ok({ total = #modules, offset = offset, returned = #items, items = items })
end

handlers.module_sections = function(args)
  local name = args.name
  if name == nil then return fail('VALIDATION_FAILED', 'module name required') end

  local okCall, sections = pcall(enumSectionsOfModule, name)
  if not okCall or sections == nil then
    return fail('NOT_FOUND', 'no sections for module ' .. tostring(name))
  end

  local items = {}
  for i = 1, math.min(#sections, 32) do
    local s = sections[i]
    items[#items + 1] = {
      name = s.Name,
      base = hex(s.Address),
      size = s.Size,
    }
  end
  return ok({ module = name, returned = #items, items = items })
end

handlers.regions = function(args)
  local regions = enumMemoryRegions() or {}
  local limit = math.min(tonumber(args.limit) or 100, 200)
  local offset = tonumber(args.offset) or 0
  local wantWritable = args.writable == true

  local filtered = {}
  for i = 1, #regions do
    local r = regions[i]
    if r.State == 0x1000 then  -- MEM_COMMIT
      local prot = r.Protect or 0
      -- PAGE_READWRITE 0x04, WRITECOPY 0x08, EXECUTE_READWRITE 0x40, EXECUTE_WRITECOPY 0x80
      local writable = (prot & 0x04) ~= 0 or (prot & 0x08) ~= 0
                    or (prot & 0x40) ~= 0 or (prot & 0x80) ~= 0
      if (not wantWritable) or writable then
        filtered[#filtered + 1] = {
          base = hex(r.BaseAddress),
          size = r.RegionSize,
          protect = string.format('0x%X', r.Protect or 0),
          writable = writable,
        }
      end
    end
  end

  local items = {}
  local last = math.min(offset + limit, #filtered)
  for i = offset + 1, last do
    items[#items + 1] = filtered[i]
  end

  return ok({ total = #filtered, offset = offset, returned = #items, items = items })
end

handlers.read_chain = function(args)
  local addr = parseAddr(args.base)
  if addr == nil then return fail('VALIDATION_FAILED', 'base required') end
  local offsets = args.offsets or {}

  local hops = {}
  local cur = addr
  for i = 1, #offsets do
    local readable, why = checkReadable(cur)
    if not readable then
      return fail('ADDRESS_NOT_MAPPED', string.format('hop %d at %s: %s', i - 1, hex(cur), why))
    end
    local ptr = readPointer(cur)
    hops[#hops + 1] = { addr = hex(cur), pointer = hex(ptr) }
    cur = ptr + tonumber(offsets[i])
  end

  local readable, why = checkReadable(cur)
  if not readable then
    return fail('ADDRESS_NOT_MAPPED', 'final address ' .. hex(cur) .. ': ' .. why)
  end

  local finalValue = readInteger(cur)
  hops[#hops + 1] = { addr = hex(cur), value = finalValue }

  return ok({ hops = hops, final = hex(cur), finalValue = finalValue })
end

handlers.disasm = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  local count = math.min(tonumber(args.count) or 10, 64)

  local readable, why = checkReadable(addr)
  if not readable then return fail('ADDRESS_NOT_MAPPED', why) end

  local items = {}
  local cur = addr
  local d = createDisassembler()
  for i = 1, count do
    local okCall, text = pcall(disassemble, cur)
    if not okCall or text == nil then break end
    local size = getInstructionSize(cur) or 1
    items[#items + 1] = { addr = hex(cur), size = size, text = text }
    cur = cur + size
  end
  if d then pcall(function() d.destroy() end) end

  return ok({ start = hex(addr), returned = #items, items = items })
end

handlers.func_range = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  local okCall, startAddr, stopAddr = pcall(getFunctionRange, addr)
  if not okCall or startAddr == nil then
    return fail('NOT_FOUND', 'no function range for ' .. hex(addr))
  end
  return ok({ start = hex(startAddr), stop = hex(stopAddr), size = (stopAddr or startAddr) - startAddr })
end

handlers.aob_scan = function(args)
  local pattern = args.pattern
  if pattern == nil or pattern == '' then
    return fail('VALIDATION_FAILED', 'pattern required')
  end
  local limit = math.min(tonumber(args.limit) or 50, 200)

  -- AOBScan returns a single StringList of every match, or nil. Treating it as
  -- (first, all) silently reads the wrong value and reports zero hits.
  local okCall, list = pcall(AOBScan, pattern)
  if not okCall then
    return fail('SCAN_FAILED', tostring(list))
  end
  if list == nil then
    -- Zero hits is not "unique".  v1 returned unique=true here, so a caller that
    -- only ever checked `unique` treated an empty scan as a confirmed single
    -- match -- the same class of bug as counting a HIT whenever hits > 0.
    return ok({ count = 0, unique = false, returned = 0, items = {},
                note = 'no match for this AOB pattern; that is an absent pattern, '
                    .. 'not a unique one -- check the pattern bytes before concluding '
                    .. 'the code is gone' })
  end

  local count = list.Count or 0
  local items = {}
  for i = 0, math.min(count, limit) - 1 do
    local addrStr = list[i]
    if addrStr ~= nil then
      items[#items + 1] = { addr = tostring(addrStr) }
    end
  end
  pcall(function() list.destroy() end)

  local out = { count = count, unique = (count == 1), returned = #items, items = items }
  if count > 1 then
    out.note = 'pattern is ambiguous: ' .. tostring(count) .. ' matches. Do not treat '
            .. 'any single one as the site until you can distinguish them (the usual '
            .. 'tie-breakers are caller module, surrounding bytes, and which one is '
            .. 'executed when the behaviour happens)'
  end
  return ok(out)
end

----------------------------------------------------------------------
-- Pointer chain discovery (reverse scan)
--
-- CE 7.7 exposes no Lua pointer-scan API, so chains are found by scanning for
-- values that point at a known target, one level at a time, and stopping when a
-- candidate lands inside a loaded module. This is heuristic: it finds chains that
-- exist in committed memory right now, not the GUI scanner's static analysis.
----------------------------------------------------------------------

-- Find addresses in writable memory whose stored pointer, plus some small
-- offset in [0, maxOff], lands exactly on `target`. A real pointer chain stores
-- a pointer to the *struct base* and reaches the field by adding an offset, so
-- scanning for the exact target value alone would miss almost every real chain.
local function scanPointersNear(target, maxOff, maxResults)
  local ms = createMemScan()
  if ms == nil then return nil, 0 end

  local lo = target > maxOff and (target - maxOff) or 0
  ms.firstScan(soValueBetween, vtQword, rtRounded, tostring(lo), tostring(target),
               0, 0x00007FFFFFFFFFFF, '+W-C', fsmAligned, tostring(ptrSize),
               false, false, false, false)
  ms.waitTillDone(30000)

  local fl = createFoundList(ms)
  fl.initialize()
  local n = fl.getCount()

  local out = {}
  for i = 0, math.min(n, maxResults) - 1 do
    local ptrAddr = tonumber(fl.getAddress(i), 16)
    local stored = tonumber(fl.getValue(i))
    if ptrAddr ~= nil and stored ~= nil then
      out[#out + 1] = { addr = ptrAddr, offset = target - stored }
    end
  end

  pcall(function() fl.deinitialize() end)
  pcall(function() fl.destroy() end)
  pcall(function() ms.destroy() end)
  return out, n
end

local function moduleRangeOf(addr, modules)
  for i = 1, #modules do
    local m = modules[i]
    if m.Size and m.Size > 0 and addr >= m.Address and addr < m.Address + m.Size then
      return m, addr - m.Address
    end
  end
  return nil
end

handlers.chain_build = function(args)
  local target = parseAddr(args.target)
  if target == nil then return fail('VALIDATION_FAILED', 'target required') end

  local maxDepth = math.min(tonumber(args.maxDepth) or 3, 5)
  local maxResults = math.min(tonumber(args.maxResults) or 20, 20)
  local perLevelCap = tonumber(args.perLevelCap) or 2000
  local maxOff = math.min(tonumber(args.maxOffset) or 0x1000, 0x10000)

  local modules = enumModules() or {}
  local chains = {}
  local truncatedLevels = {}
  -- The reverse scan used to hardcode alignment 8, which silently skips every
  -- pointer slot in a 32-bit target (4-byte slots are only 8-aligned half the
  -- time).  Alignment must follow the pointer width of the process being read.
  local ptrSize = 8
  do
    local okPs, ps = pcall(function() return getPointerSize() end)
    if okPs and tonumber(ps) and tonumber(ps) > 0 then ptrSize = tonumber(ps) end
  end

  -- Each candidate carries the chain of offsets that leads from it down to the
  -- target. Starting at the target itself, we walk *upward* one pointer level per
  -- round: find addresses whose stored value equals the current candidate.
  local candidates = { { addr = target, offsets = {} } }

  for depth = 1, maxDepth do
    local nextLevel = {}

    for c = 1, #candidates do
      local cand = candidates[c]
      local ptrs, total = scanPointersNear(cand.addr, maxOff, perLevelCap)
      if ptrs == nil then break end

      for p = 1, #ptrs do
        local hit = ptrs[p]
        local ptrAddr = hit.addr
        local m, offset = moduleRangeOf(ptrAddr, modules)

        if m ~= nil then
          -- Reached static memory: [module+offset], then each dereference
          -- offset from this level down to the target's field.
          local offsets = {}
          if hit.offset ~= 0 then offsets[#offsets + 1] = hit.offset end
          for k = 1, #cand.offsets do offsets[#offsets + 1] = cand.offsets[k] end
          chains[#chains + 1] = {
            base = m.Name .. '+' .. hex(offset),
            baseAddr = hex(ptrAddr),
            offsets = offsets,
            depth = depth,
            -- Deliberately not called "confidence": it is not a probability of
            -- anything, it is a heuristic ordering score.  The old name made it
            -- look like evidence and callers quoted it as if it were.
            heuristicScore = math.max(10, 100 - depth * 20 - math.floor(total / 100)),
            heuristicNote = 'ordering heuristic only: shorter chains through holders '
                         .. 'with fewer references rank higher; not a probability',
          }
          if #chains >= maxResults then break end
        else
          local offsets = {}
          if hit.offset ~= 0 then offsets[#offsets + 1] = hit.offset end
          for k = 1, #cand.offsets do offsets[#offsets + 1] = cand.offsets[k] end
          nextLevel[#nextLevel + 1] = { addr = ptrAddr, offsets = offsets }
        end
      end
      if #chains >= maxResults then break end
    end

    if #chains >= maxResults or #nextLevel == 0 then break end
    if #nextLevel > perLevelCap then
      -- Truncation used to be silent, so a caller could not tell "only 2000
      -- candidates exist" from "we threw the rest away".  A pointer chain search
      -- that quietly loses candidates is worse than one that admits a bound.
      truncatedLevels[#truncatedLevels + 1] = {
        level = depth, kept = perLevelCap, dropped = #nextLevel - perLevelCap,
        totalBeforeTruncation = #nextLevel,
      }
      local trimmed = {}
      for i = 1, perLevelCap do trimmed[i] = nextLevel[i] end
      nextLevel = trimmed
    end
    candidates = nextLevel
  end

  return ok({
    target = hex(target),
    chainsFound = #chains,
    chains = chains,
    pointerSize = ptrSize,
    truncatedLevels = truncatedLevels,
    note = 'Heuristic reverse scan. Chains reflect current memory, not a static analysis.'
        .. (#truncatedLevels > 0 and ' Some levels were capped at perLevelCap; see '
            .. 'truncatedLevels for how many candidates were dropped.' or ''),
  })
end

handlers.struct_dissect = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  local maxFields = math.min(tonumber(args.maxFields) or 32, 64)

  local readable, why = checkReadable(addr)
  if not readable then return fail('ADDRESS_NOT_MAPPED', why) end

  local fields = {}
  for i = 0, maxFields - 1 do
    local off = i * 4
    local fieldAddr = addr + off
    local canRead = checkReadable(fieldAddr)
    if not canRead then break end

    local asInt = readInteger(fieldAddr)
    local asFloat = readFloat(fieldAddr)
    local guess = 'int'
    if asFloat ~= nil and asFloat == asFloat and math.abs(asFloat) > 0.0001 and math.abs(asFloat) < 1e9
       and asFloat ~= math.floor(asFloat) then
      guess = 'float'
    end

    fields[#fields + 1] = {
      offset = string.format('0x%X', off),
      int = asInt,
      float = asFloat,
      guess = guess,
      likelyPointer = (asInt ~= nil and moduleRangeOf(asInt, enumModules() or {}) ~= nil),
    }
  end

  return ok({ addr = hex(addr), returned = #fields, fields = fields })
end

----------------------------------------------------------------------
-- Write group (opt-in: the Python layer only registers these when writes are
-- enabled, and every write must carry an `expect` value as an optimistic lock)
----------------------------------------------------------------------

local writeLog = {}   -- append-only undo stack: {addr, oldBytes, newBytes, ts}

local WRITE_TYPES = {
  byte = { size = 1, write = function(a, v) writeBytes(a, math.floor(v) % 256) end },
  word = { size = 2, write = function(a, v)
             local n = math.floor(v) % 65536
             writeBytes(a, n % 256, math.floor(n / 256) % 256)
           end },
  dword = { size = 4, write = function(a, v)
              local n = math.floor(v) % 4294967296
              writeBytes(a, n % 256, math.floor(n / 256) % 256,
                         math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
            end },
  qword = { size = 8, write = function(a, v)
              local n = v
              local bytes = {}
              for i = 1, 8 do
                bytes[i] = n % 256
                n = math.floor(n / 256)
              end
              writeBytes(a, bytes)
            end },
  -- float/double were missing entirely, so a float health bar could be read but
  -- never written.  CE's Lua is 5.3 and has string.pack, so the encoding is
  -- exact rather than hand-rolled.
  float = { size = 4, write = function(a, v)
              local s = string.pack('<f', v)
              local b = {}
              for i = 1, 4 do b[i] = s:byte(i) end
              writeBytes(a, b)
            end,
            read = function(bytes)
              local s = string.char(table.unpack(bytes, 1, 4))
              return string.unpack('<f', s)
            end },
  double = { size = 8, write = function(a, v)
               local s = string.pack('<d', v)
               local b = {}
               for i = 1, 8 do b[i] = s:byte(i) end
               writeBytes(a, b)
             end,
             read = function(bytes)
               local s = string.char(table.unpack(bytes, 1, 8))
               return string.unpack('<d', s)
             end },
}

local function bytesToHex(bytes)
  if bytes == nil then return nil end
  local parts = {}
  for i = 1, #bytes do parts[i] = string.format('%02X', bytes[i]) end
  return table.concat(parts, ' ')
end

local function readRaw(addr, size)
  local b = readBytes(addr, size, true)
  if b == nil then return nil end
  return b
end

local function bytesEqual(a, b)
  if a == nil or b == nil or #a ~= #b then return false end
  for i = 1, #a do
    if a[i] ~= b[i] then return false end
  end
  return true
end

handlers.write = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end

  local vtypeName = args.type or 'dword'
  local wt = WRITE_TYPES[vtypeName]
  if wt == nil then
    return fail('VALIDATION_FAILED', 'unsupported write type: ' .. tostring(vtypeName)
                .. ' (use byte/word/dword/qword, or write_bytes for arbitrary data)')
  end

  local value = tonumber(args.value)
  if value == nil then return fail('VALIDATION_FAILED', 'value must be a number') end

  -- G1 first, on purpose.  The old order checked the mapping before the lock, so
  -- a caller that passed a bad address and no lock was told ADDRESS_NOT_MAPPED --
  -- and then "fixed" it by hunting for a better address while still leaving the
  -- lock out.  Argument errors must surface before state errors.
  local expect = args.expect
  if expect == nil and os.getenv('CE_AI_UNSAFE_WRITES') ~= '1' then
    return fail('EXPECT_REQUIRED',
      'write needs expect=<current value> as an optimistic lock; read the address '
      .. 'first and pass the value you saw. (Set CE_AI_UNSAFE_WRITES=1 to bypass.)',
      { addr = hex(addr) })
  end

  local readable, why = checkReadable(addr)
  if not readable then return fail('ADDRESS_NOT_MAPPED', why) end

  -- It used to be optional, which meant the default path had no concurrency
  -- protection at all -- and a wrong write into a live heap is unrecoverable,
  -- because whatever was there is simply gone.  CE_AI_UNSAFE_WRITES=1 is the
  -- deliberate escape hatch for scripts that already read the address.
  local before = readRaw(addr, wt.size)
  if expect ~= nil then
    local expectNum = tonumber(expect)
    if expectNum == nil then
      return fail('VALIDATION_FAILED', 'expect must be numeric')
    end
    local actual = 0
    for i = wt.size, 1, -1 do actual = actual * 256 + before[i] end
    if actual ~= expectNum then
      return fail('STALE', string.format(
        'expected %d at %s but found %d; re-read before writing', expectNum, hex(addr), actual))
    end
  end

  -- The read-only refusal that used to live here is gone on purpose.  On CE 7.7
  -- there is no working way to change a page's protection from Lua
  -- (virtualprotect and virtualProtectEx are both nil, and setMemoryProtection
  -- does not affect a process the GUI has not open()ed), yet CE's own
  -- writeBytes -- the function every write in this file goes through -- already
  -- handles the protection change internally.  Blocking on getMemoryProtection
  -- therefore did not protect anything: it only made the bridge unable to patch
  -- code that CE itself can patch.  The optimistic expectHex lock above still
  -- guards against writing a stale address.
  local okWrite, err = pcall(wt.write, addr, value)
  if not okWrite then
    return fail('WRITE_FAILED', tostring(err))
  end

  -- G2: read back. CE's writeBytes has no documented return value, so the
  -- read-back is the only evidence the write landed.
  local after = readRaw(addr, wt.size)
  local expected = {}
  if wt.read ~= nil then
    -- float/double: compare the decoded value, not the bytes, so a value that
    -- round-trips through the same encoding verifies and a NaN does not.
    local got = wt.read(after)
    local verifiedF = got ~= nil and (got == value or math.abs(got - value) <= math.abs(value) * 1e-6)
    if verifiedF then
      writeLog[#writeLog + 1] = {
        addr = addr, size = wt.size, old = before, new = after, ts = os.time(),
      }
    end
    return ok({
      addr = hex(addr), type = vtypeName,
      before = wt.read(before), after = got,
      verified = verifiedF, undoEntries = #writeLog,
    })
  end
  local n = value
  for i = 1, wt.size do
    expected[i] = n % 256
    n = math.floor(n / 256)
  end

  local verified = bytesEqual(after, expected)

  if verified then
    writeLog[#writeLog + 1] = {
      addr = addr, size = wt.size, old = before, new = after, ts = os.time(),
    }
  end

  local function asNumber(bytes)
    if bytes == nil then return nil end
    local v = 0
    for i = wt.size, 1, -1 do v = v * 256 + bytes[i] end
    return v
  end

  return ok({
    addr = hex(addr),
    type = vtypeName,
    before = asNumber(before),
    after = asNumber(after),
    verified = verified,
    undoEntries = #writeLog,
  })
end

handlers.write_bytes = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end

  local hexstr = args.hex
  if type(hexstr) ~= 'string' then
    return fail('VALIDATION_FAILED', 'hex string required, e.g. "90 90 90"')
  end

  local bytes = {}
  for token in hexstr:gmatch('%x%x') do
    bytes[#bytes + 1] = tonumber(token, 16)
  end
  if #bytes == 0 then return fail('VALIDATION_FAILED', 'no bytes parsed from hex string') end
  if #bytes > 4096 then return fail('VALIDATION_FAILED', 'refusing to write more than 4096 bytes') end

  local readable, why = checkReadable(addr)
  if not readable then return fail('ADDRESS_NOT_MAPPED', why) end

  -- No read-only refusal here either: see the note in handlers.write.  CE's own
  -- writeBytes performs the protection change, and on CE 7.7 the bridge has no
  -- other way to make a code page writable.  expectHex below is the real guard.
  local before = readRaw(addr, #bytes)

  -- Same optimistic lock as handlers.write.  This path wrote arbitrary bytes with
  -- no lock at all, which is the single most destructive command in the bridge:
  -- a stale address rewrites whatever now lives there.
  local expectHex = args.expectHex
  if expectHex == nil and os.getenv('CE_AI_UNSAFE_WRITES') ~= '1' then
    return fail('EXPECT_REQUIRED',
      'write_bytes needs expectHex=<current bytes, e.g. "48 8b 05"> as an '
      .. 'optimistic lock; read the address first. (Set CE_AI_UNSAFE_WRITES=1 to bypass.)',
      { addr = hex(addr), currentHex = bytesToHex(before) })
  end
  if expectHex ~= nil then
    local expectBytes = {}
    for token in tostring(expectHex):gmatch('%x%x') do
      expectBytes[#expectBytes + 1] = tonumber(token, 16)
    end
    if #expectBytes ~= #bytes then
      return fail('VALIDATION_FAILED', string.format(
        'expectHex has %d bytes but you are writing %d; they must match',
        #expectBytes, #bytes))
    end
    if not bytesEqual(before, expectBytes) then
      return fail('STALE', string.format(
        'expected %s at %s but found %s; re-read before writing',
        bytesToHex(expectBytes), hex(addr), bytesToHex(before)))
    end
  end

  local okWrite, err = pcall(writeBytes, addr, bytes)
  if not okWrite then return fail('WRITE_FAILED', tostring(err)) end

  local after = readRaw(addr, #bytes)
  local verified = bytesEqual(after, bytes)

  if verified then
    writeLog[#writeLog + 1] = { addr = addr, size = #bytes, old = before, new = after, ts = os.time() }
  end

  return ok({ addr = hex(addr), size = #bytes, verified = verified, undoEntries = #writeLog })
end

handlers.undo = function(args)
  local count = tonumber(args.count) or 1
  local restored = {}
  local skipped = 0

  for i = 1, count do
    local entry = writeLog[#writeLog]
    if entry == nil then break end

    -- Only roll back if memory still holds what we wrote; otherwise something
    -- else changed it and restoring our stale snapshot would be destructive.
    local current = readRaw(entry.addr, entry.size)
    if bytesEqual(current, entry.new) then
      pcall(writeBytes, entry.addr, entry.old)
      local check = readRaw(entry.addr, entry.size)
      restored[#restored + 1] = {
        addr = hex(entry.addr),
        restored = bytesEqual(check, entry.old),
      }
      writeLog[#writeLog] = nil
    else
      -- Keep the entry.  v1 popped it here, which threw away the only copy of
      -- the original bytes -- exactly when they are most valuable, because
      -- something else has since overwritten the address.
      restored[#restored + 1] = {
        addr = hex(entry.addr),
        restored = false,
        conflict = 'memory changed since the write; not rolled back, original value kept below',
        original = bytesToHex(entry.old),
        expected = bytesToHex(entry.new),
        current = bytesToHex(current),
        note = 'if you know the current value belongs to someone else, undo this '
            .. 'entry by hand with write_bytes(expectHex="<current>", ...)',
      }
      skipped = skipped + 1
    end
  end

  return ok({ restored = restored, remaining = #writeLog, skipped = skipped })
end

handlers.write_readonly = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  local hexstr = args.hex
  if type(hexstr) ~= 'string' then
    return fail('VALIDATION_FAILED', 'hex string required, e.g. "90 90"')
  end

  local bytes = {}
  for token in hexstr:gmatch('%x%x') do bytes[#bytes + 1] = tonumber(token, 16) end
  if #bytes == 0 then return fail('VALIDATION_FAILED', 'no bytes parsed') end
  if #bytes > 4096 then return fail('VALIDATION_FAILED', 'refusing to write more than 4096 bytes') end

  local expectHex = args.expectHex
  if expectHex == nil and os.getenv('CE_AI_UNSAFE_WRITES') ~= '1' then
    return fail('EXPECT_REQUIRED',
      'write_readonly needs expectHex=<current bytes>; patching code is the most '
      .. 'destructive thing this bridge can do')
  end

  local before = readRaw(addr, #bytes)
  if before == nil then
    return fail('ADDRESS_NOT_MAPPED', 'cannot read the target bytes')
  end
  if expectHex ~= nil then
    local expectBytes = {}
    for token in tostring(expectHex):gmatch('%x%x') do
      expectBytes[#expectBytes + 1] = tonumber(token, 16)
    end
    if not bytesEqual(before, expectBytes) then
      return fail('STALE', string.format('expected %s at %s but found %s',
        bytesToHex(expectBytes), hex(addr), bytesToHex(before)))
    end
  end

  local prot = getMemoryProtection(addr)
  if prot ~= nil and prot.w == true then
    return fail('VALIDATION_FAILED',
      'page is already writable; use write_bytes instead -- this command exists '
      .. 'only to handle the protection change explicitly',
      { protection = prot })
  end

  -- This CE build (7.7) exposes neither `virtualprotect` nor `virtualProtectEx`;
  -- the global the old code called is nil, so this command failed every time.
  -- What it does expose is getMemoryProtection(addr) and
  -- setMemoryProtection(addr, protection), which is the pair used below.
  --
  -- The old protection is read first so it can be restored verbatim afterwards.
  -- getMemoryProtection returns {w=<bool>, r=<bool>, x=<bool>} on CE 7.7 -- it
  -- carries no `protect` string, so the old restore value is reconstructed from
  -- the three flags.  A page that is not readable cannot be verified after the
  -- write, which is the only evidence this command has, so refuse it outright.
  local protBefore = getMemoryProtection(addr)
  if protBefore == nil or protBefore.r ~= true then
    return fail('PROTECTION_FAILED',
      'could not read the protection of ' .. hex(addr)
      .. '; refusing to patch code blind')
  end
  local oldProtect
  if protBefore.x == true and protBefore.w == true then oldProtect = 'rwx'
  elseif protBefore.x == true then oldProtect = 'r-x'
  elseif protBefore.w == true then oldProtect = 'rw-'
  else oldProtect = 'r--' end
  -- setMemoryProtection silently accepts a name it does not understand and
  -- leaves the page as it was, so every candidate spelling is tried and each
  -- result is READ BACK.  Numeric Windows constants come first because they are
  -- unambiguous: 0x40 PAGE_EXECUTE_READWRITE, 0x04 PAGE_READWRITE.
  -- A successful call also needs the process to be open()ed in this CE session;
  -- the handler above that attaches a pid already did that.
  local tried = {}
  local function attemptSet(mode)
    pcall(function() setMemoryProtection(addr, mode) end)
    local now = getMemoryProtection(addr)
    table.insert(tried, tostring(mode) .. '->' .. (now and tostring(now.w) or 'nil'))
    return now ~= nil and now.w == true
  end
  local changed = attemptSet(0x40) or attemptSet('rwx') or attemptSet(0x04) or attemptSet('rw')
  if not changed then
    return fail('PROTECTION_FAILED',
      'page at ' .. hex(addr) .. ' is still not writable; getMemoryProtection now says w='
      .. tostring((getMemoryProtection(addr) or {}).w)
      .. ' (tried ' .. table.concat(tried, ', ') .. ')')
  end

  local okWrite, writeErr = pcall(writeBytes, addr, bytes)
  -- Always put the protection back, even if the write threw: leaving a code page
  -- writable changes the target's behaviour for the rest of the session.
  local restoreOk, restoreErr = pcall(function()
    if changed then setMemoryProtection(addr, oldProtect) end
  end)

  if not okWrite then
    return fail('WRITE_FAILED', tostring(writeErr))
  end

  local after = readRaw(addr, #bytes)
  local verified = bytesEqual(after, bytes)
  if verified then
    writeLog[#writeLog + 1] = {
      addr = addr, size = #bytes, old = before, new = after, ts = os.time(),
    }
  end

  local out = {
    addr = hex(addr), size = #bytes, verified = verified,
    protectionRestored = restoreOk, undoEntries = #writeLog,
  }
  if not restoreOk then
    out.note = 'write landed but the page protection could not be restored: '
            .. tostring(restoreErr) .. '; restart the target to be safe'
  end
  return ok(out)
end

handlers.write_log = function()  local items = {}
  for i = 1, #writeLog do
    local e = writeLog[i]
    items[#items + 1] = { addr = hex(e.addr), size = e.size, ts = e.ts }
  end
  return ok({ count = #writeLog, items = items })
end

----------------------------------------------------------------------
-- Breakpoints
----------------------------------------------------------------------

local bpRegistry = {}   -- bpId -> { address, size, trigger, hits = {} }
local bpCounter = 0
local activeBpId = nil

-- CE calls this global on every breakpoint hit. It must continue immediately so
-- the target is not left frozen, and it must never touch the pipe (that call
-- happens on a debug thread and would deadlock against the main thread).
function debugger_onBreakpoint()
  local id = activeBpId
  if id ~= nil and bpRegistry[id] ~= nil then
    local rec = bpRegistry[id]
    if #rec.hits < 64 then
      local ctx = debug_getCurrentContextTable and debug_getCurrentContextTable(false) or {}
      rec.hits[#rec.hits + 1] = {
        ip = hex(ctx.RIP or ctx.EIP or 0),
        rax = hex(ctx.RAX or ctx.EAX or 0),
        rbx = hex(ctx.RBX or ctx.EBX or 0),
        rcx = hex(ctx.RCX or ctx.ECX or 0),
        rdx = hex(ctx.RDX or ctx.EDX or 0),
        rsp = hex(ctx.RSP or ctx.ESP or 0),
      }
    end
    rec.hitCount = (rec.hitCount or 0) + 1
  end
  -- Always continue: a stopped target that the model forgets to resume is worse
  -- than a missed hit.
  pcall(debug_continueFromBreakpoint, co_run)
  return 0
end

local TRIGGERS = { execute = bptExecute, write = bptWrite, access = bptAccess }

-- The v2 modules were loaded above but could not be configured there, because
-- TRIGGERS only exists now.  Wiring them here means a missing helper fails at
-- load time rather than in the middle of a probe.
--
-- These calls are NOT wrapped in pcall.  They were, and it cost real time: v2_bp
-- had no M.configure at all, so the pcall swallowed "attempt to call a nil
-- field" and the module ran with hex/readBytes/insn all nil -- bps_arm died with
-- "attempt to call a nil value (global 'hex')" far from the actual mistake.
local modConfigErrors = {}
local function configureModule(mod, name, deps)
  if mod == nil then
    modConfigErrors[#modConfigErrors + 1] = name .. ': module not loaded'
    return false
  end
  if type(mod.configure) ~= 'function' then
    modConfigErrors[#modConfigErrors + 1] = name .. ': module has no configure()'
    return false
  end
  local okCfg, cfgErr = mod.configure(deps)
  if not okCfg then
    modConfigErrors[#modConfigErrors + 1] = name .. ': ' .. tostring(cfgErr)
    return false
  end
  return true
end
if bpMod ~= nil or causal ~= nil then
  configureModule(bpMod, 'v2_bp', { insn = insn, hex = hex, parseAddr = parseAddr,
                                    readBytes = readBytes, TRIGGERS = TRIGGERS })
  configureModule(causal, 'v2_causal', { insn = insn, hex = hex, parseAddr = parseAddr,
                                         readBytes = readBytes, TRIGGERS = TRIGGERS,
                                         ensureDebugger = bpMod and bpMod.ensureDebugger,
                                         -- probeCausal arms its own watch; without
                                         -- these two it called bare globals that do
                                         -- not exist in a load()-ed chunk, and the
                                         -- failure happened while the pcall arguments
                                         -- were being evaluated, so pcall could not
                                         -- even catch it.
                                         mkCallback = bpMod and bpMod.makeCallback })
end
handlers.set_breakpoint = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end

  local triggerName = args.trigger or 'write'
  local trigger = TRIGGERS[triggerName]
  if trigger == nil then
    return fail('VALIDATION_FAILED', 'trigger must be execute/write/access')
  end

  local size = tonumber(args.size) or 8

  -- Attaching the debugger is an explicit prerequisite; without it,
  -- debug_setBreakpoint silently does nothing useful.
  if debug_isDebugging == nil or not debug_isDebugging() then
    local okStart, err = pcall(debugProcess, 1)
    if not okStart then
      return fail('DEBUGGER_UNAVAILABLE', 'debugProcess failed: ' .. tostring(err))
    end
    if not debug_isDebugging() then
      return fail('DEBUGGER_UNAVAILABLE', 'debugger did not start (target may forbid debugging)')
    end
  end

  -- debug_canBreak() reports whether the target is *currently stopped and
  -- resumable*, not whether a breakpoint can be set. Gating on it here rejects
  -- every breakpoint on a running target, so it is deliberately not used.

  local okSet, bp, bpId = pcall(debug_setBreakpoint, addr, size, trigger)
  if not okSet or bp == nil then
    return fail('BREAKPOINT_FAILED', tostring(bp))
  end

  bpCounter = bpCounter + 1
  local id = 'bp' .. bpCounter
  bpRegistry[id] = { address = addr, size = size, trigger = triggerName, hits = {}, hitCount = 0 }
  activeBpId = id

  return ok({ bpId = id, addr = hex(addr), trigger = triggerName, size = size,
              debuggerActive = true })
end

handlers.bp_hits = function(args)
  local id = args.bpId
  local rec = bpRegistry[id]
  if rec == nil then return fail('NOT_FOUND', 'unknown bpId: ' .. tostring(id)) end

  local limit = math.min(tonumber(args.limit) or 50, 200)
  local items = {}
  for i = 1, math.min(#rec.hits, limit) do
    items[#items + 1] = rec.hits[i]
  end

  return ok({
    bpId = id,
    totalHits = rec.hitCount or 0,
    captured = #rec.hits,
    returned = #items,
    items = items,
  })
end

handlers.clear_breakpoint = function(args)
  local id = args.bpId
  local rec = bpRegistry[id]
  if rec == nil then return fail('NOT_FOUND', 'unknown bpId: ' .. tostring(id)) end

  pcall(debug_removeBreakpoint, rec.address)
  bpRegistry[id] = nil
  if activeBpId == id then
    local any = nil
    for k in pairs(bpRegistry) do
      any = k
      break
    end
    activeBpId = any
  end

  return ok({ cleared = id })
end

handlers.debug_state = function()
  local started = debug_isDebugging ~= nil and debug_isDebugging() or false
  local canBreak = debug_canBreak ~= nil and debug_canBreak() or false
  local ids = {}
  for k, v in pairs(bpRegistry) do
    ids[#ids + 1] = { bpId = k, addr = hex(v.address), hits = v.hitCount or 0 }
  end
  return ok({ debugging = started, canBreak = canBreak, breakpoints = ids })
end
handlers.simulate_bp_hit = function()
  local id = activeBpId
  if id == nil then return fail('NOT_FOUND', 'no active breakpoint') end
  local before = bpRegistry[id] and bpRegistry[id].hitCount or 0
  pcall(debugger_onBreakpoint)
  local after = bpRegistry[id] and bpRegistry[id].hitCount or 0
  return ok({ bpId = id, hitsBefore = before, hitsAfter = after,
              note = 'bookkeeping only; no hardware trap occurred' })
end

----------------------------------------------------------------------
-- v2 command handlers
--
-- These wrap the modules above.  Nothing here does real work: it validates,
-- calls the module, and structures the refusal. Keeping the wrapper thin is
-- deliberate -- the moment a handler starts making decisions, the two copies of
-- those decisions (handler and module) drift apart.
----------------------------------------------------------------------

local function modMissing(mod, err, name)
  if mod == nil then
    return fail('MODULE_MISSING', name .. ' failed to load: ' .. tostring(err)
      .. ' (deploy_bridge.sh copies every ce/bridge/*.lua next to the bridge)')
  end
  return nil
end

-- Give the modules the bridge helpers they need.  Done here (once) rather than
-- per call, so a missing dependency fails at load time instead of mid-scan.
if insn ~= nil then
  pcall(function() insn.configure({ hex = hex, parseAddr = parseAddr,
                                   checkReadable = checkReadable,
                                   readBytes = readBytes }) end)
end
-- NOTE: bpMod/causal are configured at the bottom of this block, after TRIGGERS
-- exists (it is declared further down, next to the v1 breakpoint handlers).

-- The MCP layer spells arguments snake_case (hypothesis_id) while the bridge
-- spells them camelCase (hypothesisId).  Translating here, once, means the two
-- ends cannot disagree -- and disagree they did: scan_first silently ignored
-- hypothesis_id and rejected every gated call with HYPOTHESIS_REQUIRED.
local function normaliseArgs(args)
  if args == nil then return {} end
  local out = {}
  for k, v in pairs(args) do
    out[k] = v
    local camel = k:gsub('_(%l)', function(c) return c:upper() end)
    if camel ~= k and out[camel] == nil then out[camel] = v end
  end
  return out
end

-- celua.txt:209 -- getRTTIClassName(address).  Cheat Engine has had this all
-- along; the bridge never wrapped it, so every object-identification attempt in
-- this project was guessing field offsets in the dark.  It walks the vtable back
-- to the RTTI structures the compiler emitted, which is the only way to tell a
-- Player from a Texture without reading the target's source.
handlers.rtti_class = function(args)
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  local target = addr
  -- Callers pass either the object itself or the vtable pointer they found in
  -- it.  Reading the vtable is the useful default: an object's first qword is
  -- its vtable when it is polymorphic.
  if args.object == true then
    local vt = readBytes(addr, 8, true)
    if vt == nil then return fail('ADDRESS_NOT_MAPPED', 'cannot read object at ' .. hex(addr)) end
    target = 0
    for i = 8, 1, -1 do target = target * 256 + vt[i] end
  end
  local okName, name = pcall(function() return getRTTIClassName(target) end)
  if not okName then
    return fail('RTTI_UNAVAILABLE', tostring(name))
  end
  local resolved = {}
  -- MSVC decorates real class names ("AVPlayer@@"); show the clean form too.
  if name ~= nil then
    local clean = tostring(name):gsub('^%.?%?A[VU]', ''):gsub('@@?$', '')
    resolved.raw = tostring(name)
    resolved.class = clean
  end
  return ok({
    queried = hex(target),
    object = args.object == true and hex(addr) or nil,
    className = resolved.class,
    rawName = resolved.raw,
    note = resolved.class ~= nil and nil or
      'no RTTI name here. Cheat Engine only decodes MS2017-shaped and Pascal '
      .. 'vtables, so a minGW/clang object or a non-polymorphic struct legitimately '
      .. 'has none; that is not proof the address is not an object',
  })
end

-- Disassembly and the static reference index live in v2_insn.lua; these are the
-- thin command shims over it.
handlers.disasm_decode = function(args)
  local missing = modMissing(insn, insnErr, 'v2_insn.lua')
  if missing then return missing end
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  local recs, err = insn.decode(addr, args.count, args.stopAtJump)
  if recs == nil then return fail('DISASSEMBLE_FAILED', tostring(err)) end
  return ok({ addr = hex(addr), count = #recs, instructions = recs })
end

handlers.xref_find = function(args)
  local missing = modMissing(insn, insnErr, 'v2_insn.lua')
  if missing then return missing end
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  local res, err = insn.references(addr, args.module, args.refresh)
  if res == nil then return fail('NO_REFERENCES', tostring(err)) end
  return ok(res)
end

handlers.ptr_trace_static = function(args)
  local missing = modMissing(insn, insnErr, 'v2_insn.lua')
  if missing then return missing end
  local addr = parseAddr(args.addr)
  if addr == nil then return fail('VALIDATION_FAILED', 'addr required') end
  return ok(insn.traceStatic(addr, args.maxDepth))
end

-- Set when the debug-path probe could not reach a verdict; surfaced in the reply.
local bpPathWarning = nil

handlers.bps_arm = function(args)
  local missing = modMissing(bpMod, bpErr, 'v2_bp.lua')
  if missing then return missing end

  -- S3 without the ceremony: a caller that cannot say what it expects to see
  -- is not running an experiment, it is watching memory and hoping.
  local entries = args.entries or {}
  if #entries == 0 then
    return fail('VALIDATION_FAILED', 'entries is required: [{addr, size, trigger, label}]')
  end

  if args.autoDebug ~= false then
    local okDbg, dbgReason = bpMod.ensureDebugger()
    if not okDbg then
      return fail('DEBUGGER_FAILED', tostring(dbgReason))
    end
  end

  -- Arming only records the watch in Cheat Engine's list.  That list fills up
  -- even when CE never attached a real debugger (an unelevated CE is the common
  -- case), and such a watch never fires -- the return of arm() then looks like a
  -- success, every hit count stays 0, and the caller concludes the target does
  -- not write that address.  Only debug_breakThread + debug_isBroken answers
  -- "can this debugger stop this process at all", so refuse to hand out watches
  -- that cannot fire.  An inconclusive probe (nil) is allowed through with a
  -- warning instead of blocking work on platforms that cannot break a thread.
  if args.verifyPaths ~= false then
    local probeTid = args.probeThread or nil
    if probeTid == nil and type(args.entries) == 'table' and args.entries[1] ~= nil then
      probeTid = args.entries[1].threadId
    end
    local pathOk, pathWhy = bpMod.debugPathWorks(probeTid)
    if pathOk == false then
      return fail('DEBUGGER_NOT_CONNECTED',
        'refusing to arm breakpoints: ' .. tostring(pathWhy),
        { hint = 'start Cheat Engine as administrator, then arm again; '
               .. 'pass verifyPaths=false only if you have another way to '
               .. 'prove the debugger works' })
    end
    if pathOk == nil then bpPathWarning = tostring(pathWhy) end
  end

  local armed, refused = {}, {}
  -- hardwareOnly installs the debug register with no Lua callback so Cheat
  -- Engine itself owns the hit count.  That is insurance against this bridge's
  -- own callback plumbing being the thing that is broken: if CE's list shows the
  -- breakpoint fired and bps_hits still says 0, the fault is provably ours.
  local hardwareOnly = args.hardwareOnly == true
  for i = 1, #entries do
    local e = entries[i]
    local addr = parseAddr(e.addr)
    if addr == nil then
      refused[#refused + 1] = { addr = tostring(e.addr), code = 'VALIDATION_FAILED',
                                message = 'unparseable address' }
    else
      local rec, err, reused = bpMod.arm(addr, e.size, e.trigger, e.label, hardwareOnly)
      if rec == nil then
        refused[#refused + 1] = { addr = hex(addr), code = err.code, message = err.message,
                                  drSlotsUsed = err.drSlotsUsed,
                                  drSlotsNeeded = err.drSlotsNeeded }
      else
        armed[#armed + 1] = { bpId = rec.bpId, addr = hex(rec.addr), size = rec.size,
                              trigger = rec.trigger, label = rec.label,
                              reused = reused and true or false,
                              hardwareOnly = rec.hardwareOnly or nil }
      end
    end
  end

  local snap = bpMod.snapshot()
  local out = {
    armed = armed, refused = refused,
    drSlotsUsed = snap.drSlotsUsed, drSlotsFree = snap.drSlotsFree,
    drSlotsTotal = snap.drSlotsTotal,
  }
  if bpPathWarning ~= nil then
    out.debugPathWarning = bpPathWarning
    bpPathWarning = nil
  end
  if #refused > 0 and #armed == 0 then
    return { ok = false, error = { code = 'ALL_BREAKPOINTS_REFUSED',
      message = 'none of the requested breakpoints could be armed',
      refusals = refused } }
  end
  out.note = 'arm the watch BEFORE performing the action, then read bps_hits; a hit '
          .. 'count alone is not evidence, run probe_causal for that'
  return ok(out)
end

handlers.bps_clear = function(args)
  local missing = modMissing(bpMod, bpErr, 'v2_bp.lua')
  if missing then return missing end
  -- Accept all three spellings on purpose.  `all` collides with Lua's nothing in
  -- particular, but the MCP tool calls this argument `all_bps`, normaliseArgs
  -- turns that into `allBps`, and a caller has no way to discover that the
  -- bridge only reads `all`.  Silently refusing to clear every breakpoint while
  -- reporting VALIDATION_FAILED looks like a parameter typo, not a wiring bug --
  -- exactly the class of failure this project keeps chasing.
  local target = args.bpId or args.addr or args.all or args.allBps or args.all_breakpoints
  if target == nil then
    return fail('VALIDATION_FAILED',
      'pass bpId, addr, or all_bps=true (aliases: all, allBps)')
  end
  if target == true then target = 'all' end
  local res, err = bpMod.clear(target)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.bps_hits = function(args)
  local missing = modMissing(bpMod, bpErr, 'v2_bp.lua')
  if missing then return missing end
  if args.bpId == nil and args.addr == nil then
    return fail('VALIDATION_FAILED', 'bpId or addr required')
  end
  local res, err = bpMod.hits(args.bpId or args.addr, args.limit)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.bp_snapshot = function(args)
  local missing = modMissing(bpMod, bpErr, 'v2_bp.lua')
  if missing then return missing end
  return ok(bpMod.snapshot())
end

handlers.read_registers = function(args)
  local missing = modMissing(bpMod, bpErr, 'v2_bp.lua')
  if missing then return missing end
  local res, err = bpMod.registers()
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.enum_threads = function(args)
  local missing = modMissing(bpMod, bpErr, 'v2_bp.lua')
  if missing then return missing end
  return ok(bpMod.threads())
end

handlers.hypothesis_open = function(args)
  local missing = modMissing(policy, policyErr, 'v2_policy.lua')
  if missing then return missing end
  local rec, err = policy.hypothesisOpen(args.statement, args.anchorFamily,
                                         args.anchorValue, args.expectField,
                                         args.expectDelta, args.calibratedBy)
  if rec == nil then return fail(err.code, err.message) end
  return ok({ hypothesisId = rec.hypId, status = rec.status,
              statement = rec.statement, anchorFamily = rec.anchorFamily,
              nextStep = 'anchor_calibrate(...) to get a calibrationTicket, then '
                      .. 'scan_first(..., hypothesisId="' .. rec.hypId .. '")' })
end

handlers.hypothesis_refute = function(args)
  local missing = modMissing(policy, policyErr, 'v2_policy.lua')
  if missing then return missing end
  local res, err = policy.hypothesisRefute(args.hypothesisId, args.reason)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.hypothesis_confirm = function(args)
  local missing = modMissing(policy, policyErr, 'v2_policy.lua')
  if missing then return missing end
  local res, err = policy.hypothesisConfirm(args.hypothesisId, args.evidence)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.hypothesis_list = function(args)
  local missing = modMissing(policy, policyErr, 'v2_policy.lua')
  if missing then return missing end
  return ok(policy.hypothesisList(args.status))
end

handlers.anchor_calibrate = function(args)
  local missing = modMissing(policy, policyErr, 'v2_policy.lua')
  if missing then return missing end
  local pid = getOpenedProcessID()
  local res, err = policy.calibrate(pid, args.calibrateField, args.action,
                                    args.expectedDelta, args.observedBefore,
                                    args.observedAfter)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.cset_from_scan = function(args)
  local missing = modMissing(causal, causalErr, 'v2_causal.lua')
  if missing then return missing end

  -- Scanning inside this call would bypass the S1/S2 gates that scan_first
  -- enforces, so the set is built from an existing scan id only.
  local items = nil
  if args.scanId ~= nil then
    local rec = bridgeState.scans[tostring(args.scanId)]
    if rec == nil then
      return fail('NOT_FOUND', 'no scan ' .. tostring(args.scanId),
                  { nextStep = 'scan_first/scan_next return a scanId' })
    end
    if rec.foundlist == nil then
      return fail('RESULTS_ON_DISK',
        'scan ' .. tostring(args.scanId) .. ' holds ' .. tostring(rec.count)
        .. ' results that are not pageable; narrow it with scan_next (changed/'
        .. 'unchanged/decreased) or page it with scan_results first')
    end
    items = {}
    for i = 1, rec.foundlist.getCount() do
      items[#items + 1] = rec.foundlist.Address[i]
    end
  else
    items = args.addrs or args.items
  end

  local res, err = causal.csetFrom(args.kind or 'explicit', args.name, items, args.note)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.cset_page = function(args)
  local missing = modMissing(causal, causalErr, 'v2_causal.lua')
  if missing then return missing end
  local res, err = causal.csetPage(args.csetId, args.offset, args.limit)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.cset_exclude = function(args)
  local missing = modMissing(causal, causalErr, 'v2_causal.lua')
  if missing then return missing end
  local res, err = causal.csetExclude(args.csetId, args.tag or args.addr, args.reason)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.cset_stats = function(args)
  local missing = modMissing(causal, causalErr, 'v2_causal.lua')
  if missing then return missing end
  local res, err = causal.csetStats(args.csetId)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.cset_list = function(args)
  local missing = modMissing(causal, causalErr, 'v2_causal.lua')
  if missing then return missing end
  return ok(causal.csetList())
end

handlers.probe_causal = function(args)
  local missing = modMissing(causal, causalErr, 'v2_causal.lua')
  if missing then return missing end
  local res, err = causal.probeCausal(args)
  if res == nil then return fail(err.code, err.message) end
  return ok(res)
end

handlers.policy_stats = function(args)
  local missing = modMissing(policy, policyErr, 'v2_policy.lua')
  if missing then return missing end
  return ok(policy.stats())
end

-- Module wiring health.  A module that failed to configure is not merely idle:
-- it will raise "attempt to call a nil value" from somewhere deep inside a probe
-- much later.  Surfacing it here costs one call and turns that into a named
-- problem at the moment it happens.
handlers.bridge_info = function(args)
  local modules = {
    { name = 'v2_insn', loaded = insn ~= nil, err = insnErr },
    { name = 'v2_policy', loaded = policy ~= nil, err = policyErr },
    { name = 'v2_bp', loaded = bpMod ~= nil, err = bpErr },
    { name = 'v2_causal', loaded = causal ~= nil, err = causalErr },
  }
  return ok({
    bridgeVersion = BRIDGE_VERSION,
    ceVersion = getCEVersion and getCEVersion(),
    handlerCount = (function()
      local n = 0
      for _ in pairs(handlers) do n = n + 1 end
      return n
    end)(),
    modules = modules,
    configureErrors = modConfigErrors,
    -- The write gate lives in the MCP layer (ce_mcp_server.py WRITES_ENABLED),
    -- not here: the bridge has no notion of CE_AI_ENABLE_WRITES and reading it
    -- here just returned false forever.  Report the thing this process can
    -- actually observe -- whether it is allowed to write at all -- and name the
    -- env vars that the *other* layer reads so the caller is not misled.
    writeGate = 'mcp',
    unsafeWritesBypass = os.getenv('CE_AI_UNSAFE_WRITES') == '1',
    policyGate = os.getenv('CE_AI_POLICY') ~= '0',
  })
end

----------------------------------------------------------------------

-- Dispatch (called on the WORKER thread; marshals to main)
----------------------------------------------------------------------

local function dispatch(frame)
  local id = frame.id
  local name = frame.cmd

  if type(name) ~= 'string' then
    return { id = id, ok = false, error = { code = 'VALIDATION_FAILED', message = 'cmd required' } }
  end

  local handler = handlers[name]
  if handler == nil then
    return { id = id, ok = false, error = { code = 'UNKNOWN_COMMAND', message = 'no such command: ' .. name } }
  end

  local args = normaliseArgs(frame.args)

  local mainResult = onMain(function()
    local okCall, res = pcall(handler, args)
    if not okCall then return fail('INTERNAL', tostring(res)) end
    return res
  end)

  if mainResult == nil then
    mainResult = fail('INTERNAL', 'main thread returned nothing')
  end

  mainResult.id = id
  return mainResult
end

----------------------------------------------------------------------
-- Server loop
----------------------------------------------------------------------

local function serveConnection(pipe)
  pipe.Timeout = 300

  while true do
    local frame, err = readFrame(pipe)
    if frame == nil then
      if err then print('[CE-AI] read ended: ' .. err) end
      break
    end

    local response = dispatch(frame)
    writeFrame(pipe, response)
  end
end

local function startServer()
  -- maxInstanceCount > 1: a client that exits without closing cleanly must not
  -- lock every later connection out with ERROR_PIPE_BUSY (231).
  local server = createPipe(PIPE_NAME, 65536, 65536, 8)
  if server == nil or not server.valid then
    print('[CE-AI] failed to create pipe ' .. PIPE_NAME)
    return nil
  end
  print('[CE-AI] listening on ' .. PIPE_NAME .. ' (v' .. BRIDGE_VERSION .. ')')

  local t = createThread(function(thread)
    thread.Name = 'CE-AI bridge accept'
    thread.freeOnTerminate(false)
    while not thread.Terminated do
      local conn = server.acceptConnection(true)
      if conn then
        print('[CE-AI] client connected')
        -- Serve each client on its own thread: a client that dies mid-command
        -- must not stop the accept loop from taking the next connection.
        local worker = createThread(function(w)
          w.Name = 'CE-AI client session'
          w.freeOnTerminate(true)
          pcall(serveConnection, conn)
          pcall(function() conn.destroy() end)
          print('[CE-AI] client disconnected')
        end)
        if worker == nil then
          pcall(serveConnection, conn)
          pcall(function() conn.destroy() end)
        end
      end
    end
  end)
  return t
end

local server = startServer()
if server == nil then
  print('[CE-AI] bridge not started')
end
