--[[
  v2_bp.lua -- multiple simultaneous breakpoints with per-target hit accounting.

  v1 kept ONE global `activeBpId` and recorded every hardware trap against it
  (ce_ai_bridge.lua:1371-1394 in the v1 baseline).  Two consequences, both
  observed in the v1 logs:

    * only one address could be watched at a time, which forced the strategy
      "arm one candidate, fire, look, arm the next" -- bp_hunt.py:64-66 says so
      in its own comment;
    * clearing one breakpoint made `activeBpId` fall back to whatever entry
      happened to come first in `pairs()`, so later hits were silently
      attributed to an address nobody was watching.

  The fix is not a bigger registry, it is using the API correctly: CE's
  debug_setBreakpoint takes a `functiontocall` that fires *for that breakpoint*.
  debugeventhandler.pas:385-387 and LuaCaller.pas:1259-1277 confirm the closure
  is invoked per breakpoint and is NOT handed the breakpoint object, so the
  closure must capture its own address.  That capture is what makes attribution
  exact instead of a guess.

  Hard limit worth stating once: x86 has four debug registers (DR0-DR3), and
  debughelper.pas:2910-2929 raises rsAllDebugRegistersAreUsedUp past that.  A
  range breakpoint is split into one slot per range, and execute/watch share the
  same pool.  So this module reports `drSlotsUsed` and refuses cleanly instead of
  letting CE throw a Pascal exception at the caller.

  Included from ce_ai_bridge.lua; shares its local scope.
]]

local M = {}

local DR_SLOTS = 4          -- DR0..DR3; measured as the hard limit, see header
local MAX_CAPTURE = 64      -- per-breakpoint hit detail cap

local TRIGGERS = { execute = bptExecute, write = bptWrite, access = bptAccess }

-- Host helpers, injected by ce_ai_bridge.lua.  This chunk is loaded with `load`,
-- so the bridge's locals (hex, parseAddr, readBytes, the insn module, TRIGGERS)
-- are NOT in scope here unless they are handed over.  Calling them as globals
-- raised "attempt to call a nil value (global 'hex')" -- and because the bridge
-- wired this module through pcall, the failure was swallowed and bps_arm simply
-- did nothing while looking like it had been configured.
local host = {
  hex = nil, parseAddr = nil, readBytes = nil, insn = nil, TRIGGERS = TRIGGERS,
}

local function hex(v)
  if host.hex ~= nil then return host.hex(v) end
  -- Fallback keeps reports readable when the bridge did not inject hex().
  if type(v) == 'number' then return string.format('0x%X', v) end
  return tostring(v)
end

local function readBytes(addr, size, asTable)
  if host.readBytes == nil then return nil end
  return host.readBytes(addr, size, asTable)
end

-- Same trap as readBytes: this module is loaded with load(), so the bridge's
-- locals are not in scope and every name here must be forwarded explicitly.
-- parseAddr was used in resolve() from the start and silently resolved to a
-- global nil, which is why clearing a breakpoint by address never worked.
local function parseAddr(v)
  if host.parseAddr == nil then return nil end
  return host.parseAddr(v)
end

-- Configure the module.  Deliberately NOT pcall'd by the caller any more: a
-- missing helper must be visible, not silently skipped.
function M.configure(deps)
  -- Captured before the loop on purpose: `TRIGGERS` starts life as an upvalue,
  -- so the first statement that assigns to it turns the name into a *new local*
  -- for the whole body of this function.  Referring to it later in the same
  -- function (or in a nested closure that reads it) then sees that fresh local
  -- instead of the upvalue.  Reading it once here keeps the upvalue alive.
  local triggersModel = TRIGGERS
  local okType = type(deps) == 'table'
  -- tostring(), never concatenating the raw value: `type(deps) .. '<text>'`
  -- raised "attempt to concatenate a nil value" whenever deps was nil, which is
  -- exactly the case this message exists to describe.
  if not okType then
    return false, 'configure needs a table (got ' .. tostring(type(deps)) .. ')'
  end
  for k, v in pairs(deps) do
    if k == 'TRIGGERS' then
      triggersModel = v
      host.TRIGGERS = v
    elseif k == 'insn' then
      host.insn = v
    else
      host[k] = v
    end
  end
  -- Anything that is not explicitly injected keeps its built-in value, so the
  -- module stays usable with a partial dependency set.
  if host.hex == nil and deps.hex == nil then host.hex = nil end
  return true
end

-- Main table.  Key is the normalised address string, NOT a counter: two calls
-- that watch the same address must share one slot, and a cleared entry must
-- never be able to receive hits that belong to a different address.
local registry = {}          -- key -> record
local alias = {}             -- bpId -> key
local bpCounter = 0
local lastPid = nil        -- target the current registry belongs to

local function keyOf(addr, trigger)
  return string.format('%X:%s', addr, trigger)
end

-- Is `addr` actually watched by Cheat Engine right now?  This module's registry
-- only proves we called debug_setBreakpoint once; CE is free to have dropped the
-- watch since (target restarted, debugger detached, CE capped its list).  Ask CE
-- itself (celua.txt:883) and never trust the record.
-- Count Cheat Engine's own breakpoints, or nil when the list cannot be read.
-- Distinct from "zero": an unreadable list is not evidence that nothing is armed.
local function ceBreakpointCountOrNil()
  local okList, list = pcall(function() return debug_getBreakpointList() end)
  if not okList or type(list) ~= 'table' then return nil end
  local n = 0
  for _ in pairs(list) do n = n + 1 end
  return n
end

local function ceHasWatch(addr)
  local okList, list = pcall(function() return debug_getBreakpointList() end)
  if not okList or type(list) ~= 'table' then return nil end
  for _, a in pairs(list) do
    local n = tonumber(a)
    if n ~= nil and n == addr then return true end
  end
  return false
end

local function newBpId()
  bpCounter = bpCounter + 1
  return 'bp' .. bpCounter
end

local function slotsNeeded(addr, size)
  -- CE splits a watched range into one slot per aligned unit it covers.  Being
  -- pessimistic here (assume one slot per touched 8-byte unit) keeps bps_arm
  -- from handing CE something it will reject halfway through, which would leave
  -- a half-armed state.
  local first = math.floor(addr / 8)
  local last = math.floor((addr + math.max(size, 1) - 1) / 8)
  return math.max(1, last - first + 1)
end

local function drSlotsAvailable()
  local used = 0
  for _, rec in pairs(registry) do
    if rec.armed then used = used + (rec.slots or 1) end
  end
  return math.max(0, DR_SLOTS - used), used
end

local function registerCapture(rec, ctx, accessAddr, insn)
  rec.hitCount = rec.hitCount + 1
  rec.lastHitTs = os.time()
  if rec.firstHitTs == nil then rec.firstHitTs = rec.lastHitTs end
  if #rec.hits >= MAX_CAPTURE then return end

  local ip = ctx and (ctx.RIP or ctx.EIP)
  local item = {
    seq = rec.hitCount,
    ip = hex(ip),
    regs = {},
  }
  if ctx then
    for _, r in ipairs({ 'RAX','RBX','RCX','RDX','RSI','RDI','RBP','RSP','R8','R9',
                         'R10','R11','R12','R13','R14','R15','EFLAGS' }) do
      if ctx[r] ~= nil then item.regs[r] = hex(ctx[r]) end
    end
    -- 32-bit targets expose the E-prefixed names instead.
    for _, r in ipairs({ 'EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP' }) do
      local e = 'E' .. r:sub(2)
      if ctx[e] ~= nil and item.regs[r] == nil then item.regs[r] = hex(ctx[e]) end
    end
  end

  if accessAddr ~= nil then
    item.accessAddr = hex(accessAddr)
    -- Hardware write breakpoints fire BEFORE the instruction retires, so this
    -- read is the pre-write value.  Anything derived from the operand instead is
    -- labelled as such -- a fabricated "after" value is exactly how v1 convinced
    -- itself it had evidence.
    local before = readBytes(rec.addr, math.max(rec.size, 1), true)
    if before ~= nil then
      local v = 0
      for i = #before, 1, -1 do v = v * 256 + before[i] end
      item.valueBefore = v
      item.valueBeforeSource = 'read_before'
    end
  end
  if insn ~= nil then
    item.insn = insn.text
    item.insnBytes = insn.bytes
  end
  rec.hits[#rec.hits + 1] = item
end

-- The per-breakpoint callback.  Runs on the debugger thread: it must return
-- fast and must NEVER touch the pipe (that would deadlock against the main
-- thread).  All it does here is bookkeeping plus one small memory read.
local function makeCallback(rec)
  return function()
    local okCall, err = pcall(function()
      local ctx = nil
      local okCtx, c = pcall(function() return debug_getCurrentContextTable(false) end)
      if okCtx and type(c) == 'table' then ctx = c end

      local ip = ctx and (ctx.RIP or ctx.EIP) or 0
      local accessAddr, why, insn = nil, nil, nil
      if host.insn ~= nil then
        local okAddr, a, w, d = pcall(host.insn.accessAddressAt, ip)
        if okAddr then accessAddr, why, insn = a, w, d end
      end
      registerCapture(rec, ctx, accessAddr, insn)
      -- Remember why attribution failed; bps_hits reports it rather than
      -- quietly filing the hit under the nearest breakpoint (v1's bug).
      if accessAddr == nil then rec.unattributed = (rec.unattributed or 0) + 1 end
    end)
    if not okCall then
      rec.callbackErrors = (rec.callbackErrors or 0) + 1
      rec.lastCallbackError = tostring(err)
    end
    pcall(debug_continueFromBreakpoint, co_run)
    return 0
  end
end

-- Arm one breakpoint.  Returns a per-entry result so a partial failure is
-- visible: "armed 3 of 5, these two were rejected and why".
--
-- hardwareOnly=true installs the debug register WITHOUT a Lua callback and
-- without a registry record.  That is the whole point: Cheat Engine's own
-- breakpoint list then owns the hit, counts it, and can show it in the CE GUI,
-- so "did the watch fire at all" can be answered by a source independent of the
-- callback plumbing.  Nothing is counted here -- bps_hits stays silent for these
-- -- because a count that nobody can cross-check is how v1 fooled itself.
function M.arm(addr, size, triggerName, label, hardwareOnly)
  triggerName = triggerName or 'write'
  local trigger = TRIGGERS[triggerName]
  if trigger == nil then
    return nil, { code = 'VALIDATION_FAILED',
                  message = 'trigger must be execute/write/access, got ' .. tostring(triggerName) }
  end
  size = tonumber(size) or 4
  if size ~= 1 and size ~= 2 and size ~= 4 and size ~= 8 then
    return nil, { code = 'VALIDATION_FAILED', message = 'size must be 1, 2, 4 or 8' }
  end

  -- Debug registers are per-process.  If the bridge is now looking at a different
  -- target, every existing record describes the wrong process.
  do
    local okPid, pidNow = pcall(function() return getOpenedProcessID() end)
    if okPid and pidNow ~= nil then
      if lastPid ~= nil and pidNow ~= lastPid then M.resetForNewTarget(pidNow) end
      lastPid = pidNow
    end
  end

  local key = keyOf(addr, triggerName)
  local existing = registry[key]
  if existing ~= nil then
    -- Reuse only when CE still holds the watch.  A record can outlive the watch
    -- it describes: bps_clear drops CE's entry but used to leave this registry
    -- intact, and attach moves to a different process while the keys (addr:trigger)
    -- stay valid-looking.  Incrementing refCount on such a record returned a
    -- "successfully armed" breakpoint that could never fire -- hitCount stayed 0
    -- and every conclusion drawn from it was void.  Drop the stale record and
    -- install a fresh one instead.
    if ceHasWatch(addr) == true then
      existing.refCount = (existing.refCount or 1) + 1
      return existing, nil, true
    end
    registry[key] = nil
    alias[existing.bpId] = nil
  end

  local need = slotsNeeded(addr, size)
  local avail, used = drSlotsAvailable()
  if need > avail then
    return nil, { code = 'DR_SLOTS_EXHAUSTED',
      message = string.format(
        'x86 provides %d debug registers and %d are already in use; this watch '
        .. 'needs %d. Clear some breakpoints (bps_clear "all") and retry with '
        .. 'fewer addresses at once -- the cap is the CPU, not the bridge.',
        DR_SLOTS, used, need),
      drSlotsUsed = used, drSlotsNeeded = need }
  end

  if hardwareOnly == true then
    -- No callback.  CE counts the hit itself and shows it in its own breakpoint
    -- list, which is the point: an independent answer to "did the watch fire".
    -- It still gets a record, because leaving it outside the registry meant
    -- bps_clear('all') could never remove it and the debug registers stayed
    -- occupied until Cheat Engine exited -- after which arming failed with
    -- "DR slots exhausted", pointing at the wrong cause entirely.
    local okHw, hwBp, hwErr = pcall(debug_setBreakpoint, addr, size, trigger)
    if not okHw then
      return nil, { code = 'BREAKPOINT_FAILED', message = tostring(hwBp),
                    hint = 'the target may forbid debugging, or the address is not mapped' }
    end
    if hwBp == nil then
      return nil, { code = 'BREAKPOINT_FAILED', message = tostring(hwErr) }
    end
    local hwRec = {
      addr = addr, size = size, trigger = triggerName, label = label,
      handle = hwBp, hardwareOnly = true, slots = need, armed = true,
      hits = {}, hitCount = 0, refCount = 1, bpId = newBpId(),
      armedAt = os.time(),
    }
    registry[key] = hwRec
    alias[hwRec.bpId] = key
    hwRec.note = 'installed with no callback; hit counting belongs to Cheat Engine, '
              .. 'so bps_hits will not see it. Check CE own breakpoint list to '
              .. 'confirm it fired.'
    return hwRec, nil, false
  end

  -- The record must exist before CE can fire the callback, so build it first and
  -- let the closure reference it.  A closure that captures `rec` by upvalue is
  -- the whole point: attribution becomes exact instead of "whichever breakpoint
  -- happens to be active".
  local rec = {
    addr = addr, size = size, trigger = triggerName, label = label,
    hits = {}, hitCount = 0, refCount = 1, slots = need,
    armedAt = os.time(), bpId = newBpId(), armed = false,
  }

  local okSet, bp, bpErr = pcall(debug_setBreakpoint, addr, size, trigger, false,
                                 makeCallback(rec))
  if not okSet then
    return nil, { code = 'BREAKPOINT_FAILED', message = tostring(bp),
                  hint = 'the target may forbid debugging, or the address is not mapped '
                      .. '(check memory_regions first)' }
  end
  if bp == nil then
    return nil, { code = 'BREAKPOINT_FAILED', message = tostring(bpErr) }
  end

  rec.handle = bp
  rec.armed = true
  registry[key] = rec
  alias[rec.bpId] = key
  return rec, nil, false
end

-- Exposed for v2_causal.probeCausal: the probe needs the same capture logic and
-- the same per-breakpoint closure, and a second copy would drift.
M.makeCallback = makeCallback

local function resolve(bpIdOrAddr)
  if bpIdOrAddr == nil then return nil end
  local s = tostring(bpIdOrAddr)
  local key = alias[s]
  if key ~= nil then return registry[key], key end
  local addr = parseAddr(s)
  if addr ~= nil then
    for k, rec in pairs(registry) do
      if rec.addr == addr then return rec, k end
    end
  end
  return nil
end

-- Clear by bpId, address, or the literal "all".  Other entries keep their counts:
-- that is the property v1 lacked and the thing a caller can actually rely on.
function M.clear(idOrAddr)
  if tostring(idOrAddr) == 'all' then
    local cleared, failed = {}, {}
    for k, rec in pairs(registry) do
      local okId, nativeId = pcall(function() return rec.handle and rec.handle.getID() end)
      if okId and nativeId ~= nil then
        if not pcall(debug_removeBreakpointByID, nativeId) then
          failed[#failed + 1] = rec.bpId
        end
      end
      -- Address removal is the fallback for handles that cannot report an id.
      -- Both calls are made because either alone can miss, and a watch left
      -- behind holds a debug register for the rest of the session.
      pcall(debug_removeBreakpoint, rec.addr)
      cleared[#cleared + 1] = rec.bpId
      alias[rec.bpId] = nil
      registry[k] = nil
    end
    local ceLeft = ceBreakpointCountOrNil()
    return { cleared = cleared, remaining = 0, clearFailed = (#failed > 0) and failed or nil,
             ceBreakpointsLeft = ceLeft,
             note = 'ceBreakpointsLeft is Cheat Engine own count after the clear; a '
                 .. 'non-zero value means watches exist that this registry never '
                 .. 'knew about' }
  end

  local rec, key = resolve(idOrAddr)
  if rec == nil then
    return nil, { code = 'NOT_FOUND', message = 'no breakpoint for ' .. tostring(idOrAddr) }
  end

  if rec.refCount > 1 then
    rec.refCount = rec.refCount - 1
    return { cleared = {}, stillArmed = { rec.bpId }, note = 'refCount decremented; still armed' }
  end

  if rec.handle ~= nil then
    local okId, nativeId = pcall(function() return rec.handle.getID() end)
    if okId and nativeId ~= nil then
      pcall(debug_removeBreakpointByID, nativeId)
    end
    pcall(debug_removeBreakpoint, rec.addr)
  end

  alias[rec.bpId] = nil
  registry[key] = nil

  local still = {}
  for _, r in pairs(registry) do still[#still + 1] = r.bpId end
  return { cleared = { rec.bpId }, stillArmed = still }
end

-- Snapshot of everything armed, including which hits have NOT been attributed.
-- `unattributed` is reported, never redistributed: a hit whose operand could not
-- be resolved is evidence of nothing, and folding it into the nearest breakpoint
-- is precisely how v1 manufactured false positives.
function M.snapshot()
  local armed = {}
  for _, rec in pairs(registry) do
    armed[#armed + 1] = {
      bpId = rec.bpId, addr = hex(rec.addr), size = rec.size,
      trigger = rec.trigger, label = rec.label,
      hitCount = rec.hitCount, captured = #rec.hits,
      unattributed = rec.unattributed or 0,
      slots = rec.slots, refCount = rec.refCount, armedAt = rec.armedAt,
      callbackErrors = rec.callbackErrors or 0,
    }
  end
  local avail, used = drSlotsAvailable()

  -- Everything above is this module's own bookkeeping: it proves we called
  -- debug_setBreakpoint, not that Cheat Engine kept the watch.  Ask CE itself
  -- what it has (celua.txt:883 debug_getBreakpointList) and compare.  A record
  -- whose address is missing from CE's list is a breakpoint that was silently
  -- rejected, and every zero hit count against it means nothing.
  local ceList, ceErr = nil, nil
  local okList, list = pcall(function() return debug_getBreakpointList() end)
  if okList and type(list) == 'table' then
    ceList = {}
    for _, a in pairs(list) do
      local n = tonumber(a)
      if n ~= nil then ceList[n] = true end
    end
  else
    ceErr = tostring(list)
  end

  for _, entry in ipairs(armed) do
    if ceList ~= nil then
      local n = parseAddr(entry.addr)
      entry.ceHasBreakpoint = (n ~= nil and ceList[n] == true)
    else
      entry.ceHasBreakpoint = nil
    end
  end

  local dbgRunning = false
  do
    local okDbg, isDbg = pcall(function() return debug_isDebugging() end)
    dbgRunning = (okDbg and isDbg == true)
  end

  return { armed = armed, count = #armed, drSlotsUsed = used, drSlotsFree = avail,
           drSlotsTotal = DR_SLOTS, debuggerRunning = dbgRunning,
           ceBreakpointCount = (ceList ~= nil) and (function()
             local n = 0
             for _ in pairs(ceList) do n = n + 1 end
             return n
           end)() or nil,
           ceBreakpointListError = ceErr,
           ceHasBreakpointNote = 'ceHasBreakpoint is Cheat Engine\'s own answer '
             .. '(debug_getBreakpointList), not this module\'s record.  false means '
             .. 'the watch was never installed and its hit count is meaningless.' }
end

-- Raw hit counter.  Deliberately contains NO boolean "did it fire / is it
-- causal" field: a caller must go through probe_causal to interpret these
-- numbers.  v1's `if totalHits == 0 then ... else "HIT"` is unreproducible when
-- there is nothing to read as a yes/no.
function M.hits(idOrAddr, limit)
  local rec, err = resolve(idOrAddr)
  if rec == nil then
    return nil, err or { code = 'NOT_FOUND', message = 'no breakpoint for ' .. tostring(idOrAddr) }
  end

  limit = math.min(tonumber(limit) or 50, MAX_CAPTURE)
  local items = {}
  for i = 1, math.min(#rec.hits, limit) do items[#items + 1] = rec.hits[i] end

  return {
    bpId = rec.bpId,
    address = hex(rec.addr),
    size = rec.size,
    trigger = rec.trigger,
    label = rec.label,
    hitCount = rec.hitCount,
    captured = #rec.hits,
    unattributedHits = rec.unattributed or 0,
    returned = #items,
    items = items,
    firstHitTs = rec.firstHitTs,
    lastHitTs = rec.lastHitTs,
    callbackErrors = rec.callbackErrors or 0,
    lastCallbackError = rec.lastCallbackError,
    truthCaveat = 'hitCount is a raw counter. A busy address is not a causally '
               .. 'written one; run probe_causal (baseline vs experiment rounds) '
               .. 'before drawing any conclusion.',
  }
end

-- Reset counters without re-arming, so a probe round can reuse the same watch
-- and keep the same DR slot.
function M.resetHits(idOrAddr)
  local rec, err = resolve(idOrAddr)
  if rec == nil then
    return nil, err or { code = 'NOT_FOUND', message = 'no breakpoint' }
  end
  rec.hitCount = 0
  rec.hits = {}
  rec.unattributed = 0
  rec.firstHitTs = nil
  rec.lastHitTs = nil
  return { bpId = rec.bpId, reset = true }
end

-- Prove the debug path actually reaches the target.  debug_getBreakpointList()
-- only shows what Cheat Engine *recorded*; it fills up even when CE never managed
-- to attach a real debugger (which is what happens when CE runs unelevated), so
-- a successful arm there means nothing.  debug_breakThread + debug_isBroken is
-- the only pair that answers "can this debugger stop this process at all".
--
-- Returns true, or false plus a reason.  A nil second value means "could not
-- determine" -- callers should treat that as usable but say so, since refusing on
-- an inconclusive probe would block legitimate work on platforms where breaking
-- a thread is momentarily impossible.
function M.debugPathWorks(probeThreadId)
  local tid = tonumber(probeThreadId)
  if tid == nil then
    local okT, threads = pcall(function() return getThreadlist() end)
    if okT and type(threads) == 'table' and #threads > 0 then
      local first = threads[1]
      tid = tonumber(type(first) == 'table' and (first.id or first.Id) or first)
    end
  end
  if tid == nil then return nil, 'no thread id available to probe with' end

  local wasDebugging = false
  pcall(function() wasDebugging = debug_isDebugging() == true end)
  if not wasDebugging then
    local okStart = pcall(function() return debugProcess(1) end)
    if not okStart then return false, 'debugProcess(1) failed' end
  end

  local okBreak = pcall(function() return debug_breakThread(tid) end)
  if not okBreak then return false, 'debug_breakThread(' .. tid .. ') failed' end

  local deadline = os.clock() + 2.0
  local isBroken = false
  while os.clock() < deadline do
    local okB, b = pcall(function() return debug_isBroken() end)
    if okB and b == true then isBroken = true break end
    pcall(function() return sleep(50) end)
  end

  if isBroken then
    pcall(function() return debug_continueFromBreakpoint(co_run) end)
    return true
  end

  -- Leave the thread running if it somehow stopped without us seeing it.
  pcall(function() return debug_continueFromBreakpoint(co_run) end)
  return false, 'the debugger never reported the target stopped, so breakpoints '
             .. 'would be recorded but never fire -- this is what happens when '
             .. 'Cheat Engine is not running elevated, or another debugger holds '
             .. 'the process'
end

-- Called when the bridge attaches to a different process.  Debug registers belong to
-- a process, so every record from the previous target is meaningless there: its
-- address may be mapped to something else, and its hit count can never increase.
-- Leaving the registry populated made arm() reuse those records and hand back
-- watches that Cheat Engine no longer held.
function M.resetForNewTarget(pid)
  local dropped = 0
  for k in pairs(registry) do
    registry[k] = nil
    dropped = dropped + 1
  end
  for k in pairs(alias) do alias[k] = nil end
  lastPid = pid
  return { dropped = dropped, pid = pid }
end

-- Ensure the debugger is attached.  Attaching is a side effect on the target, so
-- it only happens when a caller explicitly asks for breakpoints.
function M.ensureDebugger()
  local okIs, isDbg = pcall(debug_isDebugging)
  if okIs and isDbg then return true end
  local okStart, err = pcall(debugProcess, 1)
  if not okStart then return false, 'debugProcess failed: ' .. tostring(err) end
  local okAfter, after = pcall(debug_isDebugging)
  if not (okAfter and after) then
    return false, 'debugger did not start (the target may forbid debugging, or a '
                .. 'kernel-mode debugger interface is required)'
  end
  return true
end

-- Threads and a fuller register view.  v1 exposed six registers out of a
-- debug context and no thread list at all.
--
-- getThreadlist() returns plain thread IDs, not records -- indexing them as
-- `t.Id` raised "attempt to index a number value (local 't')" and the whole
-- call died.  Accept either shape so a CE build that starts returning records
-- does not break this again.
function M.threads()
  local okList, list = pcall(getThreadlist)
  if not okList or type(list) ~= 'table' then
    return { items = {}, note = 'getThreadlist unavailable: ' .. tostring(list) }
  end
  local okCur, currentId = pcall(function() return getOpenedProcessID() end)
  if not okCur then currentId = nil end
  local items = {}
  for i = 1, #list do
    local t = list[i]
    local entry
    if type(t) == 'number' then
      entry = { id = t, isCurrent = (currentId ~= nil and t == currentId) }
    elseif type(t) == 'table' then
      entry = {
        id = t.Id or t.id,
        handle = tostring(t.Handle or t.handle),
        isCurrent = t.isCurrent and true or false,
        isDebugging = t.isDebugging and true or false,
      }
    else
      entry = { id = tostring(t), unparsed = true }
    end
    entry.idText = tostring(entry.id)
    items[#items + 1] = entry
  end
  return { count = #items, items = items,
           note = 'ids only: CE 7.7 getThreadlist() yields numbers, so there is no '
               .. 'per-thread name or state to report' }
end

local REG_ORDER = {
  'RAX','RBX','RCX','RDX','RSI','RDI','RBP','RSP',
  'R8','R9','R10','R11','R12','R13','R14','R15',
  'RIP','EFLAGS',
}

function M.registers()
  local okDbg, isDbg = pcall(debug_isDebugging)
  if not (okDbg and isDbg) then
    return nil, { code = 'DEBUGGER_NOT_ATTACHED',
                  message = 'registers only exist while a breakpoint is stopped or the '
                         .. 'target is being debugged; arm a breakpoint first' }
  end
  local okCtx, ctx = pcall(function() return debug_getCurrentContextTable(false) end)
  if not okCtx or type(ctx) ~= 'table' then
    return nil, { code = 'CONTEXT_UNAVAILABLE',
                  message = 'debug_getCurrentContextTable returned nothing; the target is '
                         .. 'not stopped at a breakpoint right now' }
  end

  local regs = {}
  for _, name in ipairs(REG_ORDER) do
    if ctx[name] ~= nil then regs[name] = hex(ctx[name]) end
  end
  -- 32-bit targets: expose the E-names the debug context uses.
  if ctx.EAX ~= nil then
    for _, name in ipairs({ 'EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','EIP','EFLAGS' }) do
      if ctx[name] ~= nil and regs[name] == nil then regs[name] = hex(ctx[name]) end
    end
  end
  return { registers = regs, count = (function() local n=0 for _ in pairs(regs) do n=n+1 end return n end)() }
end

return M
