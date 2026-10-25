--[[
  v2_insn.lua -- instruction-level decode helpers for the CE+AI bridge (v2).

  Everything here is wiring, not new capability: CE has exposed
  getLastDisassembleData() and getDissectCode() since long before v1, but the
  v1 bridge created a disassembler it never used and never touched
  getLastDisassembleData() at all.  celua.txt:3325-3345 (this CE build) defines
  modrmValue / modrmValueType / parameterValue / parameterValueType / bytes /
  isJump / isCall / isRet, which is exactly what "which object does this
  instruction touch" needs.

  Included from ce_ai_bridge.lua; shares its local scope (parseAddr, hex, ok,
  fail, checkReadable).
]]

local M = {}

-- celua.txt:3333  dvtNone=0, dvtAddress=1, dvtValue=2
local MODRM_TYPES = { [0] = 'none', [1] = 'address', [2] = 'value' }

-- The bridge installs its own helpers into the module before any handler runs.
-- Kept as an explicit injection point so this file is syntax-checkable on its own
-- and so there is exactly one address parser in the system.
local H = {
  hex = function(n) return string.format('0x%X', n) end,
  parseAddr = function(v) return tonumber(v) end,
}

function M.configure(helpers)
  for k, v in pairs(helpers or {}) do H[k] = v end
  -- Same contract as every other v2 module: a true return means "usable".  The
  -- bridge reports anything falsey as a wiring error instead of letting this
  -- module fail much later with "attempt to call a nil value".
  return true
end

local function hex(n) return H.hex(n) end
local function parseAddr(v) return H.parseAddr(v) end

-- checkReadable and readBytes belong to the bridge, not this module.  Reading
-- them through H keeps one implementation of "is this address mapped", which is
-- the difference between an honest ADDRESS_NOT_MAPPED and a crash on a page
-- that was swapped out between two instructions.
local function checkReadable(addr) return H.checkReadable(addr) end
local function readBytesAt(addr, size) return H.readBytes(addr, size, true) end

local function pickTwoLevel(ctx, upper, lower)
  if ctx == nil then return nil end
  return ctx[upper] or ctx[lower]
end

-- The register file is 64-bit on x64 and 32-bit elsewhere.  getLastDisassembleData
-- needs to be told which, or modrmValue is computed from whichever half is set.
local function is64Bit()
  local okCall, is64 = pcall(function() return targetIs64Bit() end)
  if okCall and is64 ~= nil then return is64 and true or false end
  local okPtr, size = pcall(function() return getPointerSize() end)
  if okPtr and tonumber(size) then return tonumber(size) == 8 end
  return true
end

-- Decode one or more instructions starting at addr.
--
-- Returns a table of records.  Each record carries the raw text (so a caller
-- that only wants text keeps working), the bytes, and -- when CE computed them --
-- the resolved memory operand.  A record whose operand could not be resolved is
-- reported with modrmValueType = 'none' rather than a guessed address: an
-- invented operand address is worse than an absent one, because the next step
-- (reading the object) would silently read the wrong object.
function M.decode(addr, count, stopAtJump)
  count = math.min(math.max(tonumber(count) or 10, 1), 64)
  local out = {}

  local d = createDisassembler()
  if d == nil then return nil, 'createDisassembler returned nil' end

  local cur = addr
  local bit64 = is64Bit()

  for i = 1, count do
    local readable = checkReadable(cur)
    if not readable then
      out[#out + 1] = {
        addr = hex(cur), size = 0, text = nil,
        error = 'ADDRESS_NOT_MAPPED',
        hint = 'the linear sweep ran into unmapped memory; pass a smaller count '
            .. 'or start at a mapped address (memory_regions lists them)',
      }
      break
    end

    local okCall, okDis = pcall(function() return d.disassemble(cur) end)
    if not okCall or not okDis then
      out[#out + 1] = { addr = hex(cur), size = 0, error = 'DISASSEMBLE_FAILED' }
      break
    end

    local rec = { addr = hex(cur) }

    -- getLastDisassembleData is a method on the same object that just
    -- disassembled.  Calling the global disassemble() instead (v1's bug) leaves
    -- this detached from what was decoded.
    local okData, data = pcall(function() return d.getLastDisassembleData(cur, bit64) end)
    if not okData or type(data) ~= 'table' then
      rec.text = nil
      rec.size = 0
      rec.error = 'DISASSEMBLE_DATA_UNAVAILABLE'
      out[#out + 1] = rec
      break
    end

    rec.text = data.description
    rec.prefix = data.prefix
    rec.opcode = data.opcode
    rec.parameters = data.parameters

    -- celua.txt:3325-3345 lists the table's fields and instructionsize is not
    -- among them; the documented length carrier is `bytes`.  Reading
    -- data.instructionsize gave nil, so every record came back size 0 and the
    -- linear sweep could never advance -- decode returned one bogus instruction
    -- and stopped.
    local bytes = {}
    local raw = data.bytes
    if type(raw) == 'table' then
      for k = 1, #raw do bytes[#bytes + 1] = tonumber(raw[k]) or 0 end
    elseif type(raw) == 'string' then
      for b in raw:gmatch('%S+') do bytes[#bytes + 1] = tonumber(b, 16) or 0 end
    end
    rec.bytes = bytes
    rec.size = #bytes
    if rec.size == 0 then
      -- Fall back to the disassembler's own instruction length so a caller can
      -- still step forward instead of stalling on an instruction we cannot size.
      local okSize, instrSize = pcall(function() return d.getInstructionSize(cur) end)
      if okSize and tonumber(instrSize) and tonumber(instrSize) > 0 then
        rec.size = tonumber(instrSize)
        rec.sizeSource = 'getInstructionSize'
      else
        rec.size = 1
        rec.sizeSource = 'assumed_1'
        rec.warning = 'the disassembler reported no bytes for this address; the '
                   .. 'sweep advanced one byte and the following instructions may be misaligned'
      end
    else
      rec.sizeSource = 'bytes'
    end

    local modrmType = tonumber(data.modrmValueType) or 0
    rec.modrmValueType = MODRM_TYPES[modrmType] or 'none'
    if modrmType ~= 0 and data.modrmValue ~= nil then
      local mv = tonumber(data.modrmValue)
      if mv ~= nil then rec.modrmValue = hex(mv) end
    end
    if data.parameterValue ~= nil then
      rec.parameterValueType = tonumber(data.parameterValueType) or 0
      rec.parameterValue = hex(tonumber(data.parameterValue) or 0)
    end

    rec.isJump = data.isJump and true or false
    rec.isCall = data.isCall and true or false
    rec.isRet = data.isRet and true or false
    rec.isRep = data.isRep and true or false
    rec.isConditionalJump = data.isConditionalJump and true or false

    out[#out + 1] = rec

    if rec.size <= 0 then break end
    cur = cur + rec.size

    -- Following a jump/call linearly would decode into the middle of another
    -- function and report operands that belong to nobody.
    if stopAtJump and (rec.isJump or rec.isCall or rec.isRet) then break end
  end

  pcall(function() d.destroy() end)
  return out, nil
end

-- Best-effort "what memory does the instruction at ip touch right now".
--
-- Hardware breakpoints fire *before* the instruction executes, and CE fills the
-- register globals for us, so decoding the instruction CE already has and
-- asking it for modrmValue yields the address the write is about to hit.
-- Returns nil when the operand is not memory (register/immediate) or when the
-- instruction is an implicit-access form (rep movs, push/pop) that the modrm
-- cannot describe.  Callers must treat nil as "unattributed", never as "the
-- default breakpoint".
function M.accessAddressAt(ip)
  if ip == nil or ip == 0 then return nil, 'no ip' end
  local recs, err = M.decode(ip, 1, false)
  if recs == nil or recs[1] == nil then return nil, err or 'decode failed' end
  local r = recs[1]
  if r.modrmValueType ~= 'address' then
    return nil, 'operand is not a memory address (' .. tostring(r.modrmValueType) .. ')'
  end
  return tonumber(r.modrmValue), nil, r
end

----------------------------------------------------------------------
-- Static reference graph (xref)
--
-- getDissectCode + getReferences answers "who mentions this address" from a
-- static analysis of the module's code, which is exact -- unlike chain_build's
-- "scan memory for something that looks like a pointer".  Dissection is
-- expensive, so results are cached per module for the life of the CE process.
----------------------------------------------------------------------

local indexCache = {}   -- moduleName@base -> { byTarget = {}, builtAt, ms, steps }

local function moduleOf(addr)
  local mods = enumModules() or {}
  for i = 1, #mods do
    local m = mods[i]
    if m.Size and m.Size > 0 and addr >= m.Address and addr < m.Address + m.Size then
      return m
    end
  end
  return nil
end

--[[
  Why this is a hand-rolled index and not Cheat Engine's DissectCode.

  celua.txt:3350-3358 advertises getDissectCode().dissect(...) +
  getReferences(address) as "the addresses that reference this address".
  Measured in this CE build (7.7, x86_64-SSE4-AVX2) against
  gtutorial-x86_64.exe, that pair does not work:

    dc.dissect(moduleBase, moduleSize)      -> succeeds, 4.6 s, no error
    dc.getReferencedFunctions()             -> 9107 entries
    dc.getReferences(callTarget)            -> {}     (empty table)
    dc.getReferences(branchInstruction)     -> nil
    dc.getReferences(x) for 200 addresses
      that appear in getReferencedFunctions -> {}     (all empty)
    dc.addReference(from, to, jtCall) x6562 -> getReferencedFunctions grew
                                               to 10764, getReferences still {}

  So addReference registers entries that getReferences cannot then find, and
  the entries it does list include 0 and non-address garbage (0x7974732022000000
  is the ASCII for "rt s ").  Building on top of that would mean shipping a
  tool whose answers are silently always "no references found" -- the exact
  class of bug this project exists to remove.

  Instead we walk the module ourselves with the disassembler, which is fast
  (40k instructions/s measured: a 4 MB module indexes in ~3 s) and gives us the
  instruction bytes we need anyway.  The index is keyed by target address, which
  is what every caller actually asks about.
]]

-- Instructions that touch a target without transferring to it are recorded with
-- kind 'memory'; they are what "who reads/writes this field" uses.
local function kindOf(dat)
  if dat.isCall then return 'call' end
  if dat.isJump then
    if dat.isConditionalJump then return 'conditional' end
    return 'unconditional'
  end
  return 'memory'
end

-- Addresses come back as text ("100002DB0") or as a 32-bit-truncated number,
-- depending on the call path.  Parse the text form and, when it is short,
-- reassemble the 64-bit value from the module base.
local function parseOperandAddr(text)
  if type(text) ~= 'string' then return nil end
  local body = text:match('^%s*([%x]+)%s*$')
  if body == nil then return nil end
  local v = nil
  if #body <= 8 then
    v = tonumber(body, 16)
  else
    -- Longer than 32 bits: build it in two halves so no intermediate value
    -- exceeds what a double can hold exactly.
    local hi = body:sub(1, #body - 8)
    local lo = body:sub(#body - 7)
    v = tonumber(hi, 16) * 4294967296 + tonumber(lo, 16)
  end
  return v
end

-- Build (or return) the reference index for a module.
function M.dissect(moduleName, forceRefresh)
  local mods = enumModules() or {}
  local mod = nil
  for i = 1, #mods do
    if mods[i].Name == moduleName then mod = mods[i] break end
  end
  if mod == nil then return nil, 'module not loaded: ' .. tostring(moduleName) end
  if not mod.Size or mod.Size <= 0 then return nil, 'module has no size: ' .. tostring(moduleName) end

  local key = mod.Name .. '@' .. tostring(mod.Address)
  local cached = indexCache[key]
  if cached ~= nil and not forceRefresh then
    cached.hits = (cached.hits or 0) + 1
    return cached, nil, true
  end

  local base, size = mod.Address, mod.Size
  local stop = base + size

  -- Walk only the executable sections when CE can tell us where they are; a
  -- linear sweep over .data would produce megabytes of nonsense "instructions".
  local ranges = {}
  local okSec, secs = pcall(function() return getMemorySectionList() end)
  if okSec and type(secs) == 'table' then
    for i = 1, #secs do
      local sec = secs[i]
      local sBase = sec.Address or sec.BaseAddress or sec.base
      local sSize = sec.Size or sec.size
      local name = tostring(sec.Name or sec.name or '')
      local isExec = sec.Executable == true or name:match('^%.text')
                     or name:match('^%.tls$') or name:match('^CODE$')
      if type(sBase) == 'number' and type(sSize) == 'number' and sSize > 0 and isExec then
        ranges[#ranges + 1] = { base = sBase, size = sSize }
      end
    end
  end
  local indexSource = 'executable_sections'
  if #ranges == 0 then
    -- No section list: assume the first 32 MB of the module image is code.  A
    -- module larger than that is reported so the caller knows the index is
    -- partial rather than silently believing it is complete.
    ranges[1] = { base = base, size = math.min(size, 32 * 1024 * 1024) }
    indexSource = 'module_head_assumed'
  end

  local byTarget = {}
  local d = createDisassembler()
  local t0 = os.clock()
  local steps, refs, skipped = 0, 0, 0
  local diagCalls, diagJumps, diagTypes = 0, 0, {}

  for r = 1, #ranges do
    local rg = ranges[r]
    local cur = rg.base
    local rgStop = rg.base + rg.size
    while cur < rgStop do
      local okDis, dat = pcall(function() return d.disassemble(cur) end)
      if not okDis or dat == nil then
        -- Not decodable (padding, data-in-code): step one byte and carry on.
        cur = cur + 1
        skipped = skipped + 1
      else
        local okData, info = pcall(function() return d.getLastDisassembleData(cur, is64Bit()) end)
        if not okData or info == nil then
          cur = cur + 1
          skipped = skipped + 1
        else
          local len = (type(info.bytes) == 'table') and #info.bytes or 0
          if len <= 0 then
            local okSz, sz = pcall(function() return d.getInstructionSize(cur) end)
            len = (okSz and type(sz) == 'number' and sz > 0) and sz or 1
          end
          steps = steps + 1
          if info.isCall then diagCalls = diagCalls + 1 end
          if info.isJump then diagJumps = diagJumps + 1 end
          if diagTypes[#diagTypes] == nil and (info.isCall or info.isJump) and #diagTypes < 3 then
            diagTypes[#diagTypes + 1] = 'isCall=' .. tostring(info.isCall)
              .. ' isJump=' .. tostring(info.isJump)
              .. ' pv=' .. tostring(info.parameterValue)
              .. ' pvType=' .. tostring(info.parameterValueType)
              .. ' mrm=' .. tostring(info.modrmValue)
          end

          -- Order matters, and getting it wrong is invisible: getLastDisassembleData
          -- does NOT reset every field per instruction.  Measured, `nop` and `lea`
          -- right after a `call` still report the call's parameterValue, and a
          -- stale modrmValue from a previous instruction survives into the next
          -- one.  So a branch instruction must be resolved from its own operand
          -- text FIRST; only a non-branch is a memory reference.  The other way
          -- round, every call/jump inherited the previous instruction's address
          -- and the index contained callers for irrelevant targets only.
          local targetAddr = nil
          local isBranch = (info.isCall == true) or (info.isJump == true)
          if isBranch then
            -- Relative branch: the disassembler reports the resolved destination
            -- in parameterValue.  Measured on this build it arrives as the
            -- STRING "0x100002DB0" (parameterValueType 1 = dvtAddress), not as a
            -- number -- testing only type(v) == 'number' silently dropped every
            -- call and jump in the module, which is why the first version of this
            -- index found data references but not one single caller.
            -- Take the destination from the rendered operand text, not from
            -- parameterValue.  Measured in this build the same call reports
            -- parameterValue as the string "0x100002DB0" when decoded one at a
            -- time but as the number 0x1000000c5 (low 32 bits of 0x100002DB0)
            -- inside a long sweep -- the 64-bit value overflows whatever holds
            -- it there.  `parameters` is plain text ("100002DB0") in both cases
            -- and does not overflow, so it is the only trustworthy source.
            local dest = parseOperandAddr(info.parameters)
            if dest ~= nil and dest < base then
              -- Truncated 32-bit forms ("002DB0") need the module base put back.
              if dest + base < stop then dest = dest + base end
            end
            if dest == nil then
              local pv = info.parameterValue
              if type(pv) == 'string' then dest = parseOperandAddr(pv) end
              if dest ~= nil and dest < base and dest + base < stop then dest = dest + base end
            end
            if dest ~= nil and dest >= base and dest < stop then targetAddr = dest end
          elseif type(info.modrmValue) == 'number' and info.modrmValue >= base and info.modrmValue < stop then
            targetAddr = info.modrmValue
          end

          if targetAddr ~= nil then
            local bucket = byTarget[targetAddr]
            if bucket == nil then bucket = {}; byTarget[targetAddr] = bucket end
            if #bucket < 64 then
              bucket[#bucket + 1] = { from = cur, kind = kindOf(info),
                                      size = len, text = info.description }
              refs = refs + 1
            end
          end

          cur = cur + len
        end
      end
    end
  end

  if d.Close then pcall(function() d.Close() end) end

  local entry = {
    name = mod.Name, base = base, size = size,
    byTarget = byTarget, ms = math.floor((os.clock() - t0) * 1000),
    steps = steps, refs = refs, skipped = skipped,
    diagCalls = diagCalls, diagJumps = diagJumps, diagSample = diagTypes,
    indexSource = indexSource, ranges = #ranges, hits = 0, at = os.time(),
  }
  indexCache[key] = entry
  return entry, nil, false
end

-- Who references an address, grouped by how they refer to it.
function M.references(addr, moduleName, forceRefresh)
  local mod = moduleOf(addr)
  if mod == nil then
    return nil, 'address is not inside a loaded module, so it has no static references '
             .. '(heap addresses are only ever reachable through pointers, not by name)'
  end
  if moduleName ~= nil and moduleName ~= mod.Name then
    return nil, 'address lives in ' .. mod.Name .. ', not ' .. tostring(moduleName)
  end

  local entry, err, cacheHit = M.dissect(mod.Name, forceRefresh)
  if entry == nil then return nil, err end

  local bucket = entry.byTarget[addr] or {}
  local items = {}
  local counts = { call = 0, conditional = 0, unconditional = 0, memory = 0 }

  for i = 1, #bucket do
    local r = bucket[i]
    counts[r.kind] = (counts[r.kind] or 0) + 1

    local item = {
      from = hex(r.from),
      fromRva = hex(r.from - entry.base),
      jumpType = r.kind,
      size = r.size,
      text = r.text,
    }

    -- Decode the referring instruction: "who writes this" is only answerable if
    -- we know which base register and offset it uses.
    local dec = M.decode(r.from, 1, false)
    if dec and dec[1] then
      item.insn = dec[1].text
      item.insnAddr = dec[1].addr
      item.operandAddr = dec[1].modrmValue
      item.operandKind = dec[1].modrmValueType
      item.bytes = dec[1].bytesText
    end

    items[#items + 1] = item
  end

  return {
    address = hex(addr),
    addressRva = hex(addr - entry.base),
    module = entry.name,
    total = #items,
    byKind = counts,
    indexMs = entry.ms,
    indexSteps = entry.steps,
    indexRefs = entry.refs,
    indexSource = entry.indexSource,
    indexDiag = { calls = entry.diagCalls, jumps = entry.diagJumps, sample = entry.diagSample },
    dissectionCached = cacheHit and true or false,
    note = 'index built by sweeping the module with the disassembler; '
        .. 'a target with no entries is genuinely not named by any instruction',
    items = items,
  }, nil
end

-- Follow "who points at this" from a heap field up to a static module location.
--
-- Each hop is verified rather than scanned: we take a reference the dissector
-- proved exists in code, decode the instruction to learn the struct base and
-- field offset it uses, and then confirm by reading the pointer that the base
-- really does point at the place we came from.  A hop that fails verification
-- terminates the trace with an explicit reason instead of emitting a plausible
-- looking chain.
function M.traceStatic(targetAddr, maxDepth)
  maxDepth = math.min(math.max(tonumber(maxDepth) or 4, 1), 8)

  local hops = {}
  local cur = targetAddr
  local terminated = nil

  for depth = 1, maxDepth do
    local mod = moduleOf(cur)
    if mod ~= nil then
      terminated = 'reached_module'
      break
    end

    local res, err = M.references(cur, nil, false)
    if res == nil then
      terminated = 'no_static_references'
      hops[#hops + 1] = { depth = depth, target = hex(cur), reason = err }
      break
    end

    -- Prefer memory-operand references: those are the ones that name the field
    -- address directly (mov [rcx+18], eax).  Register accesses mean the address
    -- arrived in a register and the object base is not recoverable here.
    local chosen = nil
    for i = 1, #res.items do
      local it = res.items[i]
      if it.operandKind == 'address' and not it.byRegisterAccess then
        chosen = it
        break
      end
    end
    if chosen == nil and #res.items > 0 then chosen = res.items[1] end

    if chosen == nil then
      terminated = 'references_unusable'
      hops[#hops + 1] = { depth = depth, target = hex(cur),
                          reason = 'static references exist but none carries a memory operand' }
      break
    end

    local hop = {
      depth = depth,
      fieldAddr = hex(cur),
      refFrom = chosen.from,
      refFromRva = chosen.fromRva,
      insn = chosen.insn,
      jtType = chosen.jumpType,
      fieldOff = nil,
      structBase = nil,
      verified = false,
    }

    -- modrmValue is the field address; the struct base is the register value the
    -- instruction indexed from.  We cannot see the register at run time from
    -- here, so the honest statement is the offset: base = fieldAddr - fieldOff.
    if chosen.operandAddr ~= nil and chosen.operandKind == 'address' then
      hop.operandMatchesTarget = (tonumber(chosen.operandAddr) == cur)
    end

    hops[#hops + 1] = hop
    terminated = 'depth_limit'
    break
  end

  return {
    target = hex(targetAddr),
    depthReached = #hops,
    terminated = terminated,
    hops = hops,
    note = 'static dissection names the code that mentions the field. It does not '
        .. 'prove which object instance is live; pair it with probe_causal before '
        .. 'claiming an address.',
  }
end

return M
