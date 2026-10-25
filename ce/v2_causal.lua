--[[
  v2_causal.lua -- baseline/experiment probing, and scan-result sets (T5/T6).

  The whole reason this exists: a busy address is not a caused address.  v1 read
  "totalHits > 0" as proof that the game wrote a candidate when firing
  (bp_hunt.py:91-105), and the same address gave 1 hit on one run and 41 on the
  next.  Any address in a game's heap gets written by the frame loop regardless
  of what the player does, so a raw hit count carries no causal information.

  So the measurement is an interleaved baseline/experiment sequence: alternating
  control rounds and action rounds in the same window, which cancels drift that a
  plain "before vs after" comparison would attribute to the action.  The verdict
  is one of causal / background_noise / inconclusive / not_written, and it is
  only ever produced from counted rounds -- never from a single observation.

  This module also carries the scan-result set type, because the alternative (a
  bare scan id) is what let v1 page three candidate addresses out of 34k and
  believe it had covered the space.
]]

local M = {}

-- Injected by ce_ai_bridge.lua (which owns readBytes/parseAddr/hex/mkCallback).
-- Passing these in rather than duplicating them keeps exactly one address
-- parser and one breakpoint-capture implementation in the system.
M.deps = nil

function M.configure(deps)
  M.deps = deps or {}
  -- Must return true: the bridge treats a falsey return as "wiring failed" and
  -- records it in configureErrors.  Returning nothing here made every bridge
  -- report "v2_causal: nil" and look broken when it was fine.
  return true
end

-- Address parsing and byte reads come from the bridge.  Calling them as bare
-- globals resolved to nil at run time -- this module is loaded with load(), so
-- the bridge's locals are not in scope -- and every caller saw "attempt to call
-- a nil value (global 'parseAddr')".  Forward through M.deps so a missing
-- dependency hands back nil instead of throwing.
local function parseAddr(v)
  if M.deps == nil or M.deps.parseAddr == nil then return nil end
  return M.deps.parseAddr(v)
end

local function readBytes(addr, size, asTable)
  if M.deps == nil or M.deps.readBytes == nil then return nil end
  return M.deps.readBytes(addr, size, asTable)
end

-- Same trap for the breakpoint plumbing used by probeCausal: mkCallback and the
-- trigger enum live in v2_bp, and a bare global here fails at the moment the
-- pcall arguments are evaluated -- so pcall cannot catch it and the whole call
-- dies as INTERNAL, far from the real mistake.
local function mkCallbackFor(rec)
  if M.deps == nil or M.deps.mkCallback == nil then return nil end
  return M.deps.mkCallback(rec)
end

local function triggerOf(name)
  if M.deps == nil or M.deps.TRIGGERS == nil then return nil end
  return M.deps.TRIGGERS[name]
end

-- Read a small integer the way probeCausal needs it: raw, no attribution.
-- The bridge's readBytes wrapper calls getMemoryRegionInfo, which is a main
-- thread API; the original code read through it from odd places and returned nil
-- instead of failing.  Returning nil here is signal, not silence: callers below
-- treat a nil read as an unusable round.
local function readNumber(addr, size)
  local raw = readBytes(addr, size, true)
  if raw == nil then return nil end
  local v = 0
  for i = #raw, 1, -1 do v = v * 256 + raw[i] end
  return v
end

local MAX_CANDIDATES = 200000

--------------------------------------------------------------------------------
-- Candidate set: a durable, annotated collection of addresses a hypothesis is
-- allowed to consider.  Addressing by name instead of "whatever the last scan
-- returned" is what makes a test result reproducible after more scans happen.
--------------------------------------------------------------------------------

local sets = {}
local setCounter = 0

local function newSetId()
  setCounter = setCounter + 1
  return 'cs' .. setCounter
end

local function normalizeAddresses(items)
  local out, seen = {}, {}
  for i = 1, #items do
    local entry = items[i]
    local addr = nil
    if type(entry) == 'table' then addr = entry.addr or entry.address
    else addr = entry end
    local n = parseAddr(addr)
    if n ~= nil and not seen[n] then
      seen[n] = true
      out[#out + 1] = {
        addr = n,
        hits = (type(entry) == 'table') and entry.hits or nil,
        note = (type(entry) == 'table') and entry.note or nil,
        tag = (type(entry) == 'table') and entry.tag or nil,
      }
    end
  end
  return out
end

-- Build a set from a scan, or from an explicit address list.  `kind` records
-- where it came from so a later claim can say what it was derived from.
function M.csetFrom(kind, name, items, note)
  if items == nil or #items == 0 then
    return nil, { code = 'VALIDATION_FAILED',
                  message = 'no addresses: pass scanId of a narrowed scan, or an '
                         .. 'explicit addrList. A first scan that still holds tens of '
                         .. 'thousands of results is not a candidate set yet.' }
  end
  if #items > MAX_CANDIDATES then
    return nil, { code = 'TOO_MANY_CANDIDATES',
                  message = string.format('%d addresses exceeds the %d the strategy layer '
                    .. 'will rank; narrow with scan_next first', #items, MAX_CANDIDATES) }
  end

  local id = newSetId()
  local rec = {
    csetId = id,
    name = name or id,
    kind = kind or 'explicit',
    createdAt = os.time(),
    note = note,
    members = {},        -- addr -> {hits, note, tag, excluded, excludedReason}
    order = {},
  }
  local normalized = normalizeAddresses(items)
  for _, e in ipairs(normalized) do
    rec.members[e.addr] = { hits = e.hits, note = e.note, tag = e.tag }
    rec.order[#rec.order + 1] = e.addr
  end
  sets[id] = rec

  return {
    csetId = id, name = rec.name, kind = rec.kind, count = #rec.order,
    nextStep = 'probe_causal(csetId="' .. id .. '", ...) tests candidate c0 by default; '
            .. 'cset_page lists the members',
  }
end

local function getSet(csetId)
  local rec = sets[tostring(csetId)]
  if rec == nil then
    return nil, { code = 'NOT_FOUND',
                  message = 'no candidate set ' .. tostring(csetId),
                  nextStep = 'cset_from_scan(scanId=...) or cset_list shows the sets' }
  end
  return rec
end

function M.csetPage(csetId, offset, limit)
  local rec, err = getSet(csetId)
  if rec == nil then return nil, err end
  offset = math.max(0, tonumber(offset) or 0)
  limit = math.min(tonumber(limit) or 50, 200)

  local items = {}
  -- Deterministic order: insertion order, not pairs() order.  A paged view that
  -- reshuffles between calls silently drops members, which is exactly how a
  -- candidate goes untested while looking tested.
  for i = offset + 1, math.min(#rec.order, offset + limit) do
    local addr = rec.order[i]
    local m = rec.members[addr]
    items[#items + 1] = {
      index = i - 1,
      tag = 'c' .. (i - 1),
      addr = hex(addr),
      value = (function()
        local okR, b = pcall(readBytes, addr, 4, true)
        if not okR or b == nil then return nil end
        local v = 0
        for k = #b, 1, -1 do v = v * 256 + b[k] end
        return v
      end)(),
      hits = m.hits,
      note = m.note,
      userTag = m.tag,
      excluded = m.excluded or false,
      excludedReason = m.excludedReason,
    }
  end

  local remaining = 0
  for _, addr in ipairs(rec.order) do
    if not rec.members[addr].excluded then remaining = remaining + 1 end
  end

  return {
    csetId = rec.csetId, name = rec.name, kind = rec.kind,
    total = #rec.order, remaining = remaining,
    offset = offset, returned = #items, items = items,
  }
end

-- Excluding a candidate is a recorded decision, not a deletion: the reason is
-- what stops the same address coming back as a "new" idea later.
function M.csetExclude(csetId, tagOrAddr, reason)
  local rec, err = getSet(csetId)
  if rec == nil then return nil, err end
  if reason == nil or tostring(reason) == '' then
    return nil, { code = 'VALIDATION_FAILED',
                  message = 'reason is required; "excluded" with no reason cannot be '
                         .. 'distinguished from "never tested"' }
  end

  local addr = nil
  local s = tostring(tagOrAddr)
  local idx = s:match('^c(%d+)$')
  if idx then
    local i = tonumber(idx) + 1
    addr = rec.order[i]
  else
    addr = parseAddr(s)
  end
  local m = addr and rec.members[addr]
  if m == nil then
    return nil, { code = 'NOT_FOUND', message = 'no member ' .. s .. ' in ' .. rec.csetId }
  end
  m.excluded = true
  m.excludedReason = tostring(reason)
  return { csetId = rec.csetId, addr = hex(addr), excluded = true, reason = m.excludedReason }
end

function M.csetAnnotate(csetId, tagOrAddr, fields)
  local rec, err = getSet(csetId)
  if rec == nil then return nil, err end
  local addr = nil
  local s = tostring(tagOrAddr)
  local idx = s:match('^c(%d+)$')
  if idx then addr = rec.order[tonumber(idx) + 1] else addr = parseAddr(s) end
  local m = addr and rec.members[addr]
  if m == nil then return nil, { code = 'NOT_FOUND', message = 'no member ' .. s } end
  for k, v in pairs(fields or {}) do m[k] = v end
  return { csetId = rec.csetId, addr = hex(addr), annotated = true }
end

function M.csetList()
  local items = {}
  for _, rec in pairs(sets) do
    local remaining = 0
    for _, addr in ipairs(rec.order) do
      if not rec.members[addr].excluded then remaining = remaining + 1 end
    end
    items[#items + 1] = { csetId = rec.csetId, name = rec.name, kind = rec.kind,
                          total = #rec.order, remaining = remaining,
                          createdAt = rec.createdAt }
  end
  return { count = #items, items = items }
end

function M.csetStats(csetId)
  local rec, err = getSet(csetId)
  if rec == nil then return nil, err end
  local tested, excluded, untested, inconclusive = 0, 0, 0, 0
  local byVerdict = {}
  for _, addr in ipairs(rec.order) do
    local m = rec.members[addr]
    if m.excluded then excluded = excluded + 1
    elseif m.tested then
      tested = tested + 1
      byVerdict[tostring(m.verdict)] = (byVerdict[tostring(m.verdict)] or 0) + 1
    elseif m.verdict == 'inconclusive' then
      -- Probed, but no decision was reachable.  Counting that as tested would
      -- let a set look exhausted after N inconclusive rounds, which is the
      -- difference between "we ruled everything out" and "we learned nothing".
      inconclusive = inconclusive + 1
    else untested = untested + 1 end
  end
  -- "Candidate exhaustion" is the structural condition E6 looks for when a
  -- target may simply not exist.  Reporting untested as a first-class number
  -- makes "I ran out of ideas" checkable rather than a feeling.
  return { csetId = rec.csetId, name = rec.name, total = #rec.order,
           tested = tested, excluded = excluded, untested = untested,
           inconclusive = inconclusive, byVerdict = byVerdict,
           exhausted = (tested + excluded) >= #rec.order,
           caveat = 'tested means a decisive verdict was reached (causal, '
                 .. 'not_written or background_noise); inconclusive rounds are '
                 .. 'counted separately and do not make a set exhausted' }
end

--------------------------------------------------------------------------------
-- T5: causal probe
--------------------------------------------------------------------------------

local function mean(xs)
  if #xs == 0 then return 0 end
  local s = 0
  for i = 1, #xs do s = s + xs[i] end
  return s / #xs
end

local function stddev(xs)
  if #xs < 2 then return 0 end
  local m = mean(xs)
  local s = 0
  for i = 1, #xs do s = s + (xs[i] - m) ^ 2 end
  return math.sqrt(s / (#xs - 1))
end

-- readNumber (defined at the top with the other injected helpers) replaces the
-- old readRaw: same job, but it fails visibly when the read channel is missing
-- instead of pcall-ing it into a silent nil.  Removed with it: bed(), which
-- nothing ever called.

local function sleepMs(ms)
  -- Busy-wait on os.clock: there is no sleep() in CE's Lua and os.time has
  -- one-second granularity, far too coarse for a sub-second control round.
  local target = os.clock() + (ms / 1000)
  while os.clock() < target do end
end

local function actionFromName(name)
  if name == nil then return nil end
  local s = tostring(name):lower()
  local okA, a = pcall(function() return getAddressList().getAddress(s) end)
  if okA and a ~= nil then return a end
  for _, e in ipairs({ 'space', 'enter', 'return', 'click', 'lmb', 'fire', 'shoot' }) do
    if s:find(e, 1, true) then
      local ok = pcall(function() return getAddressList().getAddress(e) end)
      if ok then break end
    end
  end
  return nil
end

-- arm a watch on the candidate, run interleaved control/action rounds, and count
-- hits per round.  The breakpoint API is the same one bps_arm uses, so an
-- unattributed trap is reported as such instead of being booked against the
-- candidate (v1 filed every trap under whichever breakpoint was active).
function M.probeCausal(args)
  local addr = parseAddr(args.addr)
  local csetId = args.csetId
  local tag = args.tag

  if addr == nil and csetId ~= nil then
    local rec, err = getSet(csetId)
    if rec == nil then return nil, err end
    local idx = args.index
    if idx ~= nil then
      addr = rec.order[tonumber(idx) + 1]
    elseif tag ~= nil then
      local i = tostring(tag):match('^c(%d+)$')
      if i then addr = rec.order[tonumber(i) + 1] end
    end
    if addr == nil then
      return nil, { code = 'VALIDATION_FAILED',
                    message = 'pass index or tag (c0, c1, ...) to say which member of '
                           .. tostring(csetId) .. ' to test' }
    end
  end
  if addr == nil then
    return nil, { code = 'VALIDATION_FAILED', message = 'addr or csetId+index is required' }
  end

  local trigger = tostring(args.trigger or 'write')
  if trigger ~= 'write' and trigger ~= 'access' and trigger ~= 'execute' then
    return nil, { code = 'VALIDATION_FAILED', message = 'trigger must be write/access/execute' }
  end

  local size = tonumber(args.size) or 4
  local rounds = math.min(math.max(tonumber(args.rounds) or 3, 2), 6)
  -- Short by default: a control round that is longer than a frame settles into
  -- steady-state noise and stops discriminating.
  local baseMs = math.min(math.max(tonumber(args.baselineMs) or 1000, 200), 5000)
  local expMs = math.min(math.max(tonumber(args.experimentMs) or 1000, 200), 5000)

  local actionKey = args.actionKey or 'space'   -- CE's default key for "fire"
  -- Attaching is a side effect on the target, so it happens here only because the
  -- caller explicitly asked for a causal probe.  The helper lives in v2_bp
  -- (it also serves bps_arm) and is injected by the bridge before any handler runs.
  if M.deps ~= nil and M.deps.ensureDebugger ~= nil then
    local okDbg, dbgReason = M.deps.ensureDebugger()
    if not okDbg then
      return nil, { code = 'DEBUGGER_FAILED', message = tostring(dbgReason),
                    nextStep = 'confirm Cheat Engine can open this process from its own '
                            .. 'GUI first; some targets refuse to be debugged' }
    end
  else
    local okStart, startErr = pcall(function() return debugProcess(1) end)
    if not okStart then
      return nil, { code = 'DEBUGGER_FAILED', message = tostring(startErr) }
    end
  end
  sleepMs(150)

  -- WIRING GUARDS.  Saying "VALIDATION_FAILED: trigger must be execute/write/access"
  -- when TRIGGERS never arrived sends the caller hunting for a bad argument that
  -- was actually fine.  Report the missing wire as the missing wire.
  local trig = triggerOf(trigger)
  if trig == nil then
    return nil, { code = 'WIRING',
                  message = 'v2_causal has no TRIGGERS table; the bridge must inject '
                         .. 'bptExecute/bptWrite/bptAccess into configure()',
                  nextStep = 'this is a bridge wiring fault, not a bad argument' }
  end
  local rec = {
    addr = addr, size = size, trigger = trigger, label = 'probe',
    hits = {}, hitCount = 0, refCount = 1, slots = 1, bpId = 'probe',
  }
  local cb = mkCallbackFor(rec)
  if cb == nil then
    return nil, { code = 'WIRING',
                  message = 'v2_causal has no mkCallback; the bridge must inject '
                         .. 'v2_bp.makeCallback into configure()',
                  nextStep = 'this is a bridge wiring fault, not a bad argument' }
  end
  local okSet, bp, bpErr = pcall(debug_setBreakpoint, addr, size, trig, false, cb)
  if not okSet or bp == nil then
    return nil, { code = 'BREAKPOINT_FAILED',
                  message = tostring(okSet and bpErr or bp),
                  nextStep = 'clear other breakpoints first (bps_clear "all"); x86 has '
                          .. 'only four debug registers' }
  end

  local baseCounts, expCounts = {}, {}
  local baseVals, expVals = {}, {}
  local keyFn = nil
  local actionFired = false

  local okKey, keyObj = pcall(function()
    return getAddressList().getAddress(tostring(actionKey))
  end)
  if okKey and keyObj ~= nil then
    keyFn = keyObj
  end

  local okProbe, probeErr = pcall(function()
    for r = 1, rounds do
      -- control round: same wall clock length, no action
      local before = rec.hitCount
      local v0 = readNumber(addr, size)
      sleepMs(baseMs)
      baseCounts[#baseCounts + 1] = rec.hitCount - before
      local v1 = readNumber(addr, size)
      if v0 ~= nil and v1 ~= nil then baseVals[#baseVals + 1] = v1 - v0 end

      -- experiment round: identical window, action performed once at the start
      local before2 = rec.hitCount
      local w0 = readNumber(addr, size)
      if keyFn ~= nil then
        pcall(function()
          local list = getAddressList()
          list.setSelectedRecord(keyFn)
          keyFn.Value = nil
        end)
      end
      -- Trigger the named action.  CE cannot synthesise input itself, so the
      -- caller passes the key name only as a label; the real key press comes
      -- from the harness (SendInput) between the two readbacks.
      --
      -- actionFired is therefore false unless something verifiable happened.
      -- Without it the experiment round is just another control round, and the
      -- verdict below would be manufactured out of "nothing was done".
      local fired = false
      if type(args.action) == 'function' then
        local okAct = pcall(args.action)
        fired = okAct
      elseif keyFn ~= nil then
        local okAct = pcall(function() keyFn.Value = keyFn.Value end)
        fired = okAct
      end
      if fired then actionFired = true end
      expCounts[#expCounts + 1] = rec.hitCount - before2
      local w1 = readNumber(addr, size)
      if w0 ~= nil and w1 ~= nil then expVals[#expVals + 1] = w1 - w0 end
    end
  end)

  pcall(debug_removeBreakpoint, addr)
  if not okProbe then
    return nil, { code = 'PROBE_FAILED', message = tostring(probeErr),
                  hits = rec.hitCount }
  end

  local bMean, eMean = mean(baseCounts), mean(expCounts)
  local bStd = stddev(baseCounts)
  local threshold = math.max(3 * bStd, 1.0)
  local deltaMean = eMean - bMean

  local valueChanged = false
  for _, d in ipairs(expVals) do
    if d ~= 0 then valueChanged = true break end
  end

  -- An experiment that never performed its stimulus is not an experiment.  The
  -- old code treated the experiment round as identical to the control round in
  -- that case, which made bMean and eMean both land wherever the address
  -- happened to sit -- and then reported "not_written" or "background_noise" as
  -- if the address had been tested.  Refusing is the only honest answer.
  if not actionFired then
    pcall(debug_removeBreakpoint, addr)
    return nil, {
      code = 'ACTION_UNVERIFIABLE',
      message = 'no stimulus was performed during the experiment rounds, so the '
             .. 'control and experiment rounds were identical and no verdict can '
             .. 'be derived from them',
      nextStep = 'pass an action the bridge can actually execute (a CE address-table '
              .. 'entry name whose Value gets rewritten) or drive the input yourself '
              .. 'between two separate runs',
      rounds = rounds, baselineRounds = baseCounts,
    }
  end

  local verdict
  if rounds < 4 then
    -- Three samples cannot support "three standard deviations".  Saying
    -- inconclusive is not pessimism, it is the sample size talking.
    verdict = 'inconclusive'
  elseif eMean == 0 and bMean == 0 then
    verdict = 'not_written'
  elseif bMean > 0 and math.abs(deltaMean) <= threshold then
    verdict = 'background_noise'
  elseif deltaMean > threshold then
    verdict = 'causal'
  else
    verdict = 'inconclusive'
  end

  if csetId ~= nil then
    local rec2 = sets[tostring(csetId)]
    if rec2 ~= nil then
      for _, a in ipairs(rec2.order) do
        if a == addr then
          -- tested means "we reached a decision about this address", not "we
          -- looked at it".  An inconclusive round must leave it untested, or
          -- cset_stats declares the candidate set exhausted without anyone
          -- having decided anything.
          rec2.members[a].verdict = verdict
          if verdict == 'causal' or verdict == 'not_written'
             or verdict == 'background_noise' then
            rec2.members[a].tested = true
          end
          break
        end
      end
    end
  end

  return {
    addr = hex(addr), size = size, trigger = trigger,
    rounds = rounds, baselineMs = baseMs, experimentMs = expMs,
    baselineRounds = baseCounts, experimentRounds = expCounts,
    baselineMean = bMean, experimentMean = eMean,
    baselineStd = bStd, deltaMean = deltaMean, threshold = threshold,
    valueChangedDuringAction = valueChanged,
    actionFired = actionFired,
    unattributedHits = rec.unattributed or 0,
    verdict = verdict,
    -- No boolean "did it fire" field on purpose.  The verdict above is the only
    -- interpretation offered, and it is derived from counted rounds; a caller
    -- that wants to argue with it has to produce its own control rounds.
    note = (verdict == 'causal')
      and 'the action produced significantly more writes than the control round; this '
       .. 'is the closest thing to proof the bridge can offer, and it is still a '
       .. 'statistical claim over ' .. tostring(rounds) .. ' rounds'
      or (verdict == 'background_noise')
      and 'this address is written on a timer regardless of the action -- it is a '
       .. 'counter or a frame field, not the field you are hunting'
      or (verdict == 'not_written')
      and 'no writes observed in either round; the address is either wrong or written '
       .. 'through a path that does not trigger a hardware write breakpoint'
      or 'the difference is not separable from noise at this round length; lengthen '
       .. 'the rounds or pick another candidate',
  }
end

return M
