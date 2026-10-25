--[[
  v2_policy.lua -- the strategy layer's enforcement half (S1/S2/S4 gates).

  The premise, taken from t5-architecture.md: any discipline a model is free to
  skip, a small model will skip.  v1 proved it -- `bp_hunt.py` armed one
  breakpoint, saw totalHits > 0 and printed "HIT", because nothing in the tool
  surface made "compare against a control" the only available move.

  So these checks live in Lua, on the server side, and they refuse:
    * scanning without a calibration ticket  (S2)
    * scanning without an open hypothesis    (S1)
    * a second failed experiment on the same hypothesis without recording why (S4)

  Each gate returns a structured refusal whose `nextStep` names the exact call to
  make.  A weak model reading "you must call anchor_calibrate first" can proceed;
  a weak model reading "calibration missing" tends to retry the same scan.
]]

local M = {}

local SCAN_CMDS = {
  scan_first = true, scan_next = true, cset_from_scan = true,
}

-- Calibration tickets expire so a ticket obtained for one target cannot be
-- reused after an attach to a different process.  A 10 minute window is long
-- enough for a real calibration run and short enough that a stale ticket cannot
-- float around the whole session.
local TICKET_TTL = 600

local state = {
  hypotheses = {},        -- hypId -> record
  hypOrder = {},
  tickets = {},           -- ticketId -> record
  refutedGlobal = 0,
  pidAtTicket = nil,
}

local hypCounter = 0
local ticketCounter = 0

local function newId(prefix, n)
  return string.format('%s%d', prefix, n)
end

local function nowTs() return os.time() end

local function tick()
  -- Expire tickets lazily; no timers in this environment.
  local now = nowTs()
  for id, t in pairs(state.tickets) do
    if now - t.createdAt > TICKET_TTL then state.tickets[id] = nil end
  end
end

--------------------------------------------------------------------------------
-- S1: hypothesis register
--------------------------------------------------------------------------------

local ANCHOR_FAMILIES = {
  exact = true, range = true, unknown = true, pointer = true, code = true,
}

function M.hypothesisOpen(statement, anchorFamily, anchorValue, expectField,
                          expectDelta, calibratedBy)
  if statement == nil or tostring(statement) == '' then
    return nil, { code = 'VALIDATION_FAILED',
                  message = 'statement is required: one sentence naming the field you '
                         .. 'believe this address holds (e.g. "ammo count drops by 1 per shot")' }
  end
  anchorFamily = anchorFamily or 'exact'
  if not ANCHOR_FAMILIES[anchorFamily] then
    return nil, { code = 'VALIDATION_FAILED',
                  message = 'anchorFamily must be one of exact/range/unknown/pointer/code, got '
                         .. tostring(anchorFamily) }
  end

  hypCounter = hypCounter + 1
  local id = newId('h', hypCounter)
  local rec = {
    hypId = id,
    statement = tostring(statement),
    anchorFamily = anchorFamily,
    anchorValue = anchorValue,
    expectField = expectField,
    expectDelta = expectDelta,
    calibratedBy = calibratedBy,
    status = 'open',              -- open | refuted | confirmed | superseded
    failures = 0,
    evidence = {},
    createdAt = nowTs(),
    updatedAt = nowTs(),
  }
  state.hypotheses[id] = rec
  state.hypOrder[#state.hypOrder + 1] = id
  return rec
end

function M.hypothesisGet(hypId)
  local rec = state.hypotheses[tostring(hypId)]
  if rec == nil then
    return nil, { code = 'NOT_FOUND', message = 'no hypothesis ' .. tostring(hypId),
                  nextStep = 'hypothesis_open(...) starts one; hypothesis_list shows the open ones' }
  end
  return rec
end

-- S4: a hypothesis that fails twice must be replaced, not retried.  The counter
-- is what makes "try the same idea again with a slightly different number" cost
-- something.  Recording the reason is mandatory because the reason is the only
-- thing that makes the next hypothesis different.
function M.hypothesisRefute(hypId, reason)
  local rec, err = M.hypothesisGet(hypId)
  if rec == nil then return nil, err end
  if reason == nil or tostring(reason) == '' then
    return nil, { code = 'VALIDATION_FAILED',
                  message = 'reason is required: what observation killed this hypothesis? '
                         .. 'An unrecorded refutation is indistinguishable from giving up.' }
  end
  if rec.status ~= 'open' then
    return nil, { code = 'HYPOTHESIS_CLOSED',
                  message = 'hypothesis ' .. rec.hypId .. ' is already ' .. rec.status }
  end

  rec.failures = rec.failures + 1
  rec.lastReason = tostring(reason)
  rec.updatedAt = nowTs()

  if rec.failures >= 2 then
    rec.status = 'refuted'
    state.refutedGlobal = state.refutedGlobal + 1
  end

  return {
    hypId = rec.hypId, failures = rec.failures, status = rec.status,
    refutedGlobal = state.refutedGlobal,
    nextStep = rec.status == 'refuted'
      and 'hypothesis_open(...) with a DIFFERENT anchorFamily -- repeating this anchor '
       .. 'is what v1 did eight times'
      or 'one more attempt is allowed on this hypothesis',
  }
end

function M.hypothesisConfirm(hypId, evidenceNote)
  local rec, err = M.hypothesisGet(hypId)
  if rec == nil then return nil, err end
  rec.status = 'confirmed'
  rec.confirmedAt = nowTs()
  if evidenceNote then rec.evidence[#rec.evidence + 1] = tostring(evidenceNote) end
  return { hypId = rec.hypId, status = rec.status }
end

function M.hypothesisList(statusFilter)
  local items = {}
  for _, id in ipairs(state.hypOrder) do
    local rec = state.hypotheses[id]
    if statusFilter == nil or rec.status == statusFilter then
      items[#items + 1] = {
        hypId = rec.hypId, status = rec.status, statement = rec.statement,
        anchorFamily = rec.anchorFamily, anchorValue = rec.anchorValue,
        failures = rec.failures, lastReason = rec.lastReason,
        evidenceCount = #rec.evidence,
      }
    end
  end
  return { count = #items, items = items,
           refutedGlobal = state.refutedGlobal,
           caveat = state.refutedGlobal >= 4
             and 'four hypotheses refuted: the anchor family itself is probably wrong, '
              .. 'not the individual values'
             or nil }
end

--------------------------------------------------------------------------------
-- S2: anchor calibration
--------------------------------------------------------------------------------

-- A ticket is only issued when the caller states, up front, what the action is
-- supposed to do to the calibration field.  That expectation is what makes the
-- later scan falsifiable.

-- The MCP layer spells arguments snake_case and the bridge spells them
-- camelCase.  Accepting both here keeps the two ends from having to agree on a
-- translation that neither of them can see.
local function pick(args, camel, snake)
  if args == nil then return nil end
  if args[camel] ~= nil then return args[camel] end
  if args[snake] ~= nil then return args[snake] end
  return nil
end

function M.calibrate(pid, calibrateField, action, expectedDelta, observedBefore,
                     observedAfter)
  tick()
  if calibrateField == nil or tostring(calibrateField) == '' then
    return nil, { code = 'VALIDATION_FAILED',
      message = 'calibrateField is required: name the quantity you are observing '
             .. '(e.g. "shots_fired") so the ticket records what was proven' }
  end
  if action == nil or tostring(action) == '' then
    return nil, { code = 'VALIDATION_FAILED', message = 'action is required' }
  end

  local delta = tonumber(expectedDelta)
  local actual = nil
  if tonumber(observedBefore) ~= nil and tonumber(observedAfter) ~= nil then
    actual = tonumber(observedAfter) - tonumber(observedBefore)
  end

  -- The calibration is only usable if the pipeline actually saw the change the
  -- caller predicted.  A ticket issued on a failed prediction would certify a
  -- scanner that cannot see the one thing it is being calibrated on.
  local passed = (delta ~= nil and actual ~= nil and (
      (delta >= 0 and actual >= delta) or (delta < 0 and actual <= delta)))
  if actual == nil then
    return nil, { code = 'CALIBRATION_INCOMPLETE',
                  message = 'observedBefore/observedAfter are both required: predict the '
                         .. 'delta, perform the action, then report what you measured',
                  nextStep = 'read the calibration field before the action, act, read it '
                          .. 'again, then call anchor_calibrate with both numbers' }
  end
  if not passed then
    return nil, { code = 'CALIBRATION_FAILED',
                  message = string.format(
                    'expected delta %s but observed %s; the scan pipeline or the anchor is '
                    .. 'wrong, so nothing downstream can be trusted yet', tostring(delta),
                    tostring(actual)),
                  nextStep = 'do not scan yet. Verify the calibration field by hand '
                          .. '(read it twice around the action) and check the delta sign' }
  end

  ticketCounter = ticketCounter + 1
  local id = newId('cal', ticketCounter)
  state.tickets[id] = {
    ticketId = id, pid = pid, calibrateField = tostring(calibrateField),
    action = tostring(action), expectedDelta = delta, observedDelta = actual,
    createdAt = nowTs(),
  }
  state.pidAtTicket = pid

  return { ticketId = id, expectedDelta = delta, observedDelta = actual,
           ttlSeconds = TICKET_TTL,
           validFor = 'scan_first / scan_next / cset_from_scan on pid ' .. tostring(pid) }
end

function M.validateTicket(ticketId, pid)
  tick()
  if ticketId == nil then
    return nil, { code = 'CALIBRATION_REQUIRED',
      message = 'this bridge requires an anchor calibration before scanning',
      nextStep = 'anchor_calibrate(calibrateField, action, expectedDelta, '
              .. 'observedBefore, observedAfter) returns a ticketId; pass it as '
              .. 'calibrationTicket',
      why = 'v1 spent its whole run narrowing an anchor it never verified -- the '
         .. 'first scan found 34k addresses because the anchor was wrong, and every '
         .. 'later scan inherited that error' }
  end
  local t = state.tickets[tostring(ticketId)]
  if t == nil then
    return nil, { code = 'CALIBRATION_INVALID',
      message = 'ticket ' .. tostring(ticketId) .. ' is unknown or expired',
      nextStep = 'call anchor_calibrate again; tickets expire after '
              .. TICKET_TTL .. ' seconds' }
  end
  if pid ~= nil and t.pid ~= nil and tonumber(pid) ~= tonumber(t.pid) then
    return nil, { code = 'CALIBRATION_INVALID',
      message = string.format('ticket was issued for pid %s, scanning pid %s',
        tostring(t.pid), tostring(pid)),
      nextStep = 'calibrate again in the current process' }
  end
  return t
end

-- Called from handlers.scan_first / scan_next.  Kept as one function so both
-- scan entry points cannot drift apart.
function M.gateScan(cmd, args, currentPid)
  local hypId = args.hypothesisId
  local ticketId = args.calibrationTicket

  local rec, hypErr = M.hypothesisGet(hypId)
  if rec == nil then
    return nil, {
      code = 'HYPOTHESIS_REQUIRED',
      message = hypErr.message,
      nextStep = 'hypothesis_open(statement="...", anchorFamily="exact|range|unknown") '
              .. 'then pass hypothesisId to ' .. cmd,
    }
  end
  if rec.status ~= 'open' then
    return nil, {
      code = 'HYPOTHESIS_CLOSED',
      message = 'hypothesis ' .. rec.hypId .. ' is ' .. rec.status,
      nextStep = 'hypothesis_open(...) a new one; a closed hypothesis cannot be '
              .. 'reused, or the failure count would stop meaning anything',
    }
  end

  local t, ticketErr = M.validateTicket(ticketId, currentPid)
  if t == nil then return nil, ticketErr end

  return { hypothesis = rec, ticket = t }
end

function M.stats()
  tick()
  return {
    hypotheses = #state.hypOrder,
    openHypotheses = (function()
      local n = 0
      for _, id in ipairs(state.hypOrder) do
        if state.hypotheses[id].status == 'open' then n = n + 1 end
      end
      return n
    end)(),
    refutedGlobal = state.refutedGlobal,
    activeTickets = (function() local n = 0 for _ in pairs(state.tickets) do n = n + 1 end return n end)(),
  }
end

return M
