#!/usr/bin/env python3
"""Cheat Engine AI Agent -- MCP server.

A single-file MCP server that exposes Cheat Engine's memory analysis to any
MCP-capable AI agent. It talks to Cheat Engine over a local named pipe; the
matching Lua half lives in ce/ce_ai_bridge.lua and is loaded by CE's autorun.

Run directly:
    python ce_mcp_server.py                 # read-only tools
    set CE_AI_ENABLE_WRITES=1 && python ce_mcp_server.py

Or let an MCP client launch it (see config/mcp-example.json).

Design rules:
  * Deny by default -- attach_process only accepts allowlisted executables.
  * Every side effect is audited before its result is trusted.
  * Failures are typed, never silent: a bad address says so instead of
    returning a fake zero.
  * Deliberately small tool surface; that is what lets a small fast model
    drive this reliably.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from fastmcp import FastMCP
except ImportError:  # pragma: no cover - guidance for a bare Python install
    print("Missing dependency: fastmcp.  Install it with:\n"
          "    python -m pip install fastmcp\n", file=sys.stderr)
    raise SystemExit(1)

PIPE_PATH = os.environ.get("CE_AI_PIPE", r"\\.\pipe\CE_AI_Bridge_v1_0")
MAX_PAYLOAD = 8 * 1024 * 1024

# ---------------------------------------------------------------- policy

DEFAULT_TARGETS = [
    "Tutorial-x86_64.exe",
    "gtutorial-x86_64.exe",
    "Tutorial-i386.exe",
    "gtutorial-i386.exe",
]


def allowlist() -> list[str]:
    extra = [p.strip() for p in os.environ.get("CE_AI_EXTRA_TARGETS", "").split(";") if p.strip()]
    return DEFAULT_TARGETS + extra


# ---------------------------------------------------------------- audit

AUDIT_DIR = Path(os.environ.get(
    "CE_AI_AUDIT_DIR",
    str(Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "CheatEngineAI" / "audit"),
))


def _audit_file() -> Path:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    return AUDIT_DIR / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"


def _sha(data: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def audit_write(tool: str, args: dict, result: dict) -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "args": args,
        "ok": bool(result.get("ok")),
        "error": (result.get("error") or {}).get("code") if not result.get("ok") else None,
    }
    if isinstance(result.get("data"), (dict, list)):
        entry["result_sha256"] = _sha(result["data"])
    try:
        with _audit_file().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # auditing must never break a tool call


def audit_tail(n: int = 20) -> list[dict]:
    path = _audit_file()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ---------------------------------------------------------------- pipe client

class BridgeError(RuntimeError):
    pass


class BridgeClient:
    def __init__(self, pipe_path: str = PIPE_PATH) -> None:
        self.pipe_path = pipe_path
        self._handle = None
        self._next_id = 0
        # A single scan over the whole address space can legitimately take
        # minutes, so this is deliberately generous.  It exists to stop an
        # unbounded hang, not to cap normal work.
        self.read_timeout_s = float(os.environ.get("CE_AI_READ_TIMEOUT", "300"))

    def connect(self, retries: int = 2, delay: float = 0.3) -> None:
        import time
        import win32file
        import win32pipe

        last: Exception | None = None
        for attempt in range(retries):
            try:
                self._handle = win32file.CreateFile(
                    self.pipe_path,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING, 0, None,
                )
                win32pipe.SetNamedPipeHandleState(
                    self._handle, win32pipe.PIPE_READMODE_BYTE, None, None)
                return
            except Exception as exc:
                last = exc
                if attempt + 1 < retries:
                    time.sleep(delay)
        raise BridgeError(
            f"cannot connect to {self.pipe_path}: {last}. "
            "Is Cheat Engine running with the bridge loaded?"
        )

    def close(self) -> None:
        if self._handle is not None:
            import win32file
            try:
                win32file.CloseHandle(self._handle)
            finally:
                self._handle = None

    def _read_exact(self, size: int) -> bytes:
        import time

        import pywintypes
        import win32file

        chunks, remaining = [], size
        deadline = time.monotonic() + self.read_timeout_s
        while remaining > 0:
            try:
                _, chunk = win32file.ReadFile(self._handle, remaining)
            except pywintypes.error as exc:
                # A non-overlapped pipe read cannot be given a timeout, so a
                # wedged Cheat Engine would block this server forever and every
                # later tool call would hang too.  ERROR_NO_DATA means "nothing
                # yet"; poll until the deadline instead of trusting the pipe.
                if exc.winerror == 232:
                    if time.monotonic() > deadline:
                        raise BridgeError(
                            f"bridge did not answer within {self.read_timeout_s:.0f}s; "
                            "Cheat Engine is busy or the scan is still running"
                        ) from exc
                    time.sleep(0.01)
                    continue
                raise
            if not chunk:
                raise BridgeError("pipe closed by Cheat Engine")
            chunks.append(chunk)
            remaining -= len(chunk)
            if time.monotonic() > deadline and remaining > 0:
                raise BridgeError(
                    f"bridge reply stalled after {size - remaining}/{size} bytes "
                    f"(timeout {self.read_timeout_s:.0f}s)")
        return b"".join(chunks)

    def call(self, cmd: str, **args: Any) -> dict:
        import win32file
        if self._handle is None:
            raise BridgeError("not connected")
        self._next_id += 1
        req = {"id": self._next_id, "cmd": cmd, "args": args}
        payload = json.dumps(req, ensure_ascii=False).encode("utf-8")
        if len(payload) > MAX_PAYLOAD:
            raise BridgeError(f"request too large: {len(payload)} bytes")
        win32file.WriteFile(self._handle, struct.pack("<I", len(payload)) + payload)
        (length,) = struct.unpack("<I", self._read_exact(4))
        if length == 0 or length > MAX_PAYLOAD:
            raise BridgeError(f"bad response length {length}")
        resp = json.loads(self._read_exact(length).decode("utf-8"))
        if resp.get("id") != req["id"]:
            raise BridgeError(f"response id mismatch: {resp.get('id')} != {req['id']}")
        return resp


def unwrap(resp: dict) -> Any:
    if resp.get("ok"):
        return resp.get("data")
    err = resp.get("error") or {}
    raise BridgeError(f"{err.get('code', 'UNKNOWN')}: {err.get('message', 'no message')}")


# ---------------------------------------------------------------- mcp

mcp = FastMCP("cheat-engine")
_client: BridgeClient | None = None

WRITES_ENABLED = os.environ.get("CE_AI_ENABLE_WRITES", "").strip() in ("1", "true", "yes")


def _get() -> BridgeClient:
    global _client
    if _client is not None:
        return _client
    c = BridgeClient()
    c.connect()
    c.call("set_whitelist", images=allowlist())
    _client = c
    return _client


def _call(cmd: str, *, audit_as: str | None = None, **args: Any) -> dict:
    global _client
    try:
        result = {"ok": True, "data": unwrap(_get().call(cmd, **args))}
    except BridgeError as exc:
        _client = None
        text = str(exc)
        code, _, message = text.partition(": ")
        if "cannot connect" in text or "pipe closed" in text:
            code = "CE_NOT_RUNNING"
            message = ("Cheat Engine is not reachable. Start Cheat Engine first; "
                       f"the autorun bridge must be loaded. Detail: {message or text}")
        result = {"ok": False, "error": {"code": code, "message": message or text}}
    except Exception as exc:
        _client = None
        result = {"ok": False, "error": {"code": "TRANSPORT", "message": str(exc)}}
    if audit_as:
        audit_write(audit_as, args, result)
    return result


def _no_writes() -> dict | None:
    if not WRITES_ENABLED:
        return {"ok": False, "error": {
            "code": "WRITES_DISABLED",
            "message": "Writing is disabled. Set CE_AI_ENABLE_WRITES=1 in the MCP "
                       "server environment to enable write and breakpoint tools."}}
    return None


# ---- process


@mcp.tool
def ping() -> dict:
    """Check the bridge is alive and report the Cheat Engine version."""
    return _call("ping")


@mcp.tool
def allowlist_info() -> dict:
    """Show which executables this session may attach to."""
    return {"ok": True, "data": {"allowlist": allowlist(),
                                 "policy": "deny by default"}}

@mcp.tool
def attach_process(pid: int) -> dict:
    """Attach Cheat Engine to a process by PID.

    Refused unless the executable is allowlisted. Every later tool operates on
    this process, so treat it as a deliberate, state-changing action.
    """
    return _call("attach", audit_as="attach_process", pid=pid)


@mcp.tool
def process_info() -> dict:
    """Describe the attached target: pid, name, bitness, modules, image base."""
    return _call("proc_info")


# ---- reading


@mcp.tool
def read_memory(addr: str, type: str = "dword") -> dict:
    """Read one typed value at a hex address.

    type: byte/word/dword/qword/float/double/pointer/utf8/utf16.
    An unmapped address returns ADDRESS_NOT_MAPPED rather than a fake zero --
    treat that as "the address is wrong", not as data.
    """
    return _call("read", audit_as="read_memory", addr=addr, type=type)


@mcp.tool
def read_chain(base: str, offsets: list[int]) -> dict:
    """Follow a multi-level pointer chain and return every hop.

    base is a hex address; each offset is added after a dereference. A broken
    chain shows up as the hop whose pointer is not mapped.
    """
    return _call("read_chain", audit_as="read_chain", base=base, offsets=offsets)


@mcp.tool
def module_of(addr: str) -> dict:
    """Find the module owning an address, returning name, base and offset.

    Prefer reporting module+offset over a raw address: it survives ASLR.
    """
    return _call("module_of", addr=addr)


# ---- scanning


@mcp.tool
def scan_first(type: str, value: str | None = None, protect: str = "+W-C",
               op: str | None = None, value2: str | None = None,
               start: str | None = None, stop: str | None = None,
               aligned: bool = False, hex: bool = False) -> dict:
    """Start a value scan. Returns a scanId and the hit count only.

    Page through with scan_results, narrow with scan_next.

    value="unknown" records every address when the current value is unknown
    (then narrow with scan_next op=decreased/changed). Those results live on
    disk and take minutes to narrow across the whole address space, so prefer
    a range scan when the quantity has a plausible bound.

    op="between" needs value and value2; op="bigger"/"smaller" need value.
    start/stop limit the scanned range (hex "0x..." or decimal) which is the
    cheapest way to keep a scan fast.
    """
    args: dict[str, Any] = {"type": type, "protect": protect}
    for key, val in (("value", value), ("op", op), ("value2", value2),
                     ("start", start), ("stop", stop)):
        if val is not None:
            args[key] = val
    if aligned:
        args["aligned"] = True
    if hex:
        args["hex"] = True
    return _call("scan_first", audit_as="scan_first", **args)



@mcp.tool
def scan_next(scanId: str, op: str = "exact", value: str | None = None,
              value2: str | None = None) -> dict:
    """Narrow an existing scan.

    op: exact/changed/unchanged/increased/decreased/bigger/smaller/between.
    A narrowing scan must not grow the result set; SCAN_GREW means the scan
    state is untrustworthy, so start over.
    """
    args: dict[str, Any] = {"scanId": scanId, "op": op}
    if value is not None:
        args["value"] = value
    if value2 is not None:
        args["value2"] = value2
    return _call("scan_next", audit_as="scan_next", **args)


@mcp.tool
def scan_results(scanId: str, offset: int = 0, limit: int = 50) -> dict:
    """Page through scan hits. limit is capped at 200 server-side."""
    return _call("scan_results", scanId=scanId, offset=offset, limit=limit)


@mcp.tool
def scan_stats(scanId: str) -> dict:
    """Report a scan's size and progress."""
    return _call("scan_stats", scanId=scanId)


@mcp.tool
def release_scan(scanId: str) -> dict:
    """Free a scan's result set when it is no longer needed."""
    return _call("release_scan", audit_as="release_scan", scanId=scanId)


@mcp.tool
def aob_scan(pattern: str, limit: int = 50) -> dict:
    """Scan for a byte pattern such as "48 8B 05 ?? ?? ?? ??".

    Returns the count and whether the match is unique. More than one hit is
    reported as non-unique instead of silently returning one of them.
    """
    return _call("aob_scan", audit_as="aob_scan", pattern=pattern, limit=limit)


# ---- analysis


@mcp.tool
def enum_modules(offset: int = 0, limit: int = 100) -> dict:
    """List loaded modules with base address and size."""
    return _call("enum_modules", offset=offset, limit=limit)


@mcp.tool
def module_sections(name: str) -> dict:
    """List one module's sections with ranges and sizes."""
    return _call("module_sections", name=name)


@mcp.tool
def memory_regions(writable: bool = True, offset: int = 0, limit: int = 100) -> dict:
    """List committed memory regions, optionally only writable ones."""
    return _call("regions", writable=writable, offset=offset, limit=limit)


@mcp.tool
def disassemble(addr: str, count: int = 10) -> dict:
    """Disassemble up to 64 instructions starting at an address."""
    return _call("disasm", addr=addr, count=count)


@mcp.tool
def function_range(addr: str) -> dict:
    """Estimate the start and end of the function containing an address."""
    return _call("func_range", addr=addr)


@mcp.tool
def find_pointer_chains(target: str, maxDepth: int = 3, maxResults: int = 20,
                        maxOffset: int = 4096) -> dict:
    """Search for module-based pointer chains reaching a target address.

    Heuristic reverse scan: repeatedly looks for stored pointers landing near
    the target, walking one level up per round until it reaches a module.
    Results reflect current memory. Confirm a chain with read_chain before use.
    """
    return _call("chain_build", audit_as="find_pointer_chains", target=target,
                 maxDepth=maxDepth, maxResults=maxResults, maxOffset=maxOffset)


@mcp.tool
def dissect_structure(addr: str, maxFields: int = 32) -> dict:
    """Guess a struct's layout at an address, 4 bytes at a time.

    Reports int, float and whether each field looks like a pointer. A guess for
    orientation, not a substitute for analysis.
    """
    return _call("struct_dissect", addr=addr, maxFields=maxFields)


# ---- writing (gated)


@mcp.tool
def write_value(addr: str, value: float, type: str = "dword", expect: float | None = None) -> dict:
    """Write a number to memory, then read it back to prove the write landed.

    Requires CE_AI_ENABLE_WRITES=1. `expect` is an optimistic lock and is
    effectively mandatory: a differing current value is refused as STALE, and
    omitting it is refused as EXPECT_REQUIRED unless CE_AI_UNSAFE_WRITES=1.
    float and double are supported. verified=false means the read-back did not
    match.

    There is NO page-protection refusal on this path. On CE 7.7 the bridge has
    no working Lua call to change a page's protection, so CE's own writeBytes
    performs the change internally when the target page needs it. `expect` is
    therefore the only guard against writing a stale address. For an explicit,
    verified protection change that is restored afterwards, use write_readonly.
    """
    gate = _no_writes()
    if gate:
        return gate
    args: dict[str, Any] = {"addr": addr, "value": value, "type": type}
    if expect is not None:
        args["expect"] = expect
    return _call("write", audit_as="write_value", **args)


@mcp.tool
def write_bytes(addr: str, hex: str) -> dict:
    """Write raw bytes (e.g. "90 90 90") and verify by reading them back.

    Requires CE_AI_ENABLE_WRITES=1. Max 4096 bytes per call.
    """
    gate = _no_writes()
    if gate:
        return gate
    return _call("write_bytes", audit_as="write_bytes", addr=addr, hex=hex)


@mcp.tool
def undo_writes(count: int = 1) -> dict:
    """Roll back the most recent writes, newest first.

    Requires CE_AI_ENABLE_WRITES=1. A write is skipped and reported as a
    conflict if memory no longer holds what we last wrote.
    """
    gate = _no_writes()
    if gate:
        return gate
    return _call("undo", audit_as="undo_writes", count=count)


@mcp.tool
def write_history() -> dict:
    """List writes made this session (the undo stack), newest last."""
    return _call("write_log")


# ---- breakpoints (gated)


@mcp.tool
def set_breakpoint(addr: str, trigger: str = "write", size: int = 8) -> dict:
    """Set a hardware breakpoint and start recording hits.

    Requires CE_AI_ENABLE_WRITES=1. trigger: execute/write/access. The debugger
    attaches automatically. Each hit records the instruction pointer and general
    registers, then the target is resumed.
    """
    gate = _no_writes()
    if gate:
        return gate
    return _call("set_breakpoint", audit_as="set_breakpoint",
                 addr=addr, trigger=trigger, size=size)


@mcp.tool
def breakpoint_hits(bpId: str, limit: int = 50) -> dict:
    """Read recorded breakpoint hits: ip, registers, hit count."""
    return _call("bp_hits", bpId=bpId, limit=limit)


@mcp.tool
def clear_breakpoint(bpId: str) -> dict:
    """Remove a breakpoint and stop recording."""
    gate = _no_writes()
    if gate:
        return gate
    return _call("clear_breakpoint", audit_as="clear_breakpoint", bpId=bpId)


@mcp.tool
def debug_state() -> dict:
    """Report whether the debugger is attached and which breakpoints are live."""
    return _call("debug_state")


# ---- audit


@mcp.tool
def audit_log(count: int = 20) -> dict:
    """Show recent audit entries for this machine."""
    return {"ok": True, "data": {"entries": audit_tail(count)}}


# ---- v2: hypotheses and anchor calibration (S1 / S2)
#
# These exist so the discipline is not optional prose.  scan_first and scan_next
# refuse to run without a hypothesis id and a calibration ticket, which means a
# caller that skips straight to "let me just scan for 100" gets a structured
# refusal instead of thirty thousand addresses it cannot explain.

@mcp.tool
def hypothesis_open(statement: str, anchor_family: str, anchor_value: str = "",
                    expect_field: str = "", expect_delta: str = "",
                    calibrated_by: str = "") -> dict:
    """Register what you are looking for and why, before scanning.

    statement: one sentence, falsifiable ("ammo count is a 4-byte int in the heap
    and drops by exactly 1 per shot"). anchor_family: exact | range | unknown |
    pointer | code. Returns hypothesisId, which scan_first/scan_next require.
    """
    return _call("hypothesis_open", audit_as="hypothesis_open",
                 statement=statement, anchorFamily=anchor_family,
                 anchorValue=anchor_value, expectField=expect_field,
                 expectDelta=expect_delta, calibratedBy=calibrated_by)


@mcp.tool
def anchor_calibrate(calibrate_field: str, action: str, expected_delta: str,
                     observed_before: str, observed_after: str) -> dict:
    """Prove the observation pipeline works before trusting it on the real target.

    Use a quantity whose behaviour you already know (for example "shots fired"
    goes 5 -> 4). Observe it twice, around the action, and pass both readings.
    If the pipeline cannot reproduce a change you can prove, no later scan is
    trustworthy. Returns calibrationTicket, which scan_first/scan_next require.
    """
    return _call("anchor_calibrate", audit_as="anchor_calibrate",
                 calibrateField=calibrate_field, action=action,
                 expectedDelta=expected_delta,
                 observedBefore=observed_before, observedAfter=observed_after)


@mcp.tool
def hypothesis_refute(hypothesis_id: str, reason: str) -> dict:
    """Mark a hypothesis dead. Two refutations close it; the counter is global."""
    return _call("hypothesis_refute", audit_as="hypothesis_refute",
                 hypothesisId=hypothesis_id, reason=reason)


@mcp.tool
def hypothesis_confirm(hypothesis_id: str, evidence: str) -> dict:
    """Close a hypothesis as confirmed, citing the evidence that closed it."""
    return _call("hypothesis_confirm", audit_as="hypothesis_confirm",
                 hypothesisId=hypothesis_id, evidence=evidence)


@mcp.tool
def hypothesis_list(status: str = "") -> dict:
    """List hypotheses (optionally only one status: open/refuted/confirmed)."""
    return _call("hypothesis_list", status=status)


@mcp.tool
def policy_stats() -> dict:
    """Hypothesis/calibration counters -- how close this session is to STUCK."""
    return _call("policy_stats")


# ---- v2: candidate sets (T6)

@mcp.tool
def cset_from_scan(name: str, scan_id: str = "", addrs: list[str] | None = None,
                   kind: str = "explicit", note: str = "") -> dict:
    """Freeze a scan's results (or an explicit address list) into a paged set.

    Always page it with cset_page instead of dumping every address: a set of
    30k candidates is not more informative than 50 of them plus a plan.
    """
    args: dict[str, Any] = {"name": name, "kind": kind, "note": note}
    if scan_id:
        args["scanId"] = scan_id
    if addrs:
        args["addrs"] = addrs
    return _call("cset_from_scan", audit_as="cset_from_scan", **args)


@mcp.tool
def cset_page(cset_id: str, offset: int = 0, limit: int = 20) -> dict:
    """Read one page of a candidate set, with live values."""
    return _call("cset_page", csetId=cset_id, offset=offset, limit=limit)


@mcp.tool
def cset_exclude(cset_id: str, tag: str, reason: str) -> dict:
    """Drop a candidate with a stated reason. Excluded candidates are counted."""
    return _call("cset_exclude", csetId=cset_id, tag=tag, reason=reason)


@mcp.tool
def cset_stats(cset_id: str) -> dict:
    """tested / excluded / untested counts for a candidate set."""
    return _call("cset_stats", csetId=cset_id)


@mcp.tool
def cset_list() -> dict:
    """All candidate sets in this session."""
    return _call("cset_list")


# ---- v2: causal probe (T5) -- the only thing that can call something causal

@mcp.tool
def probe_causal(action: str, rounds: int = 3, baseline_ms: int = 800,
                 experiment_ms: int = 1200, addr: str = "", size: int = 4,
                 trigger: str = "write", cset_id: str = "", tag: str = "") -> dict:
    """Watch an address through alternating control/experiment rounds.

    Control rounds do nothing; experiment rounds perform `action` in between.
    The tool reports raw write counts per round and a verdict, and the verdict
    is only 'causal' when the experiment rounds exceed the control rounds by more
    than three baseline standard deviations. A breakpoint hit count alone is
    never evidence -- background code writes to memory constantly.

    Target the address directly (addr) or a candidate (cset_id + tag).
    """
    args: dict[str, Any] = {"action": action, "rounds": rounds,
                            "baselineMs": baseline_ms, "experimentMs": experiment_ms,
                            "size": size, "trigger": trigger}
    if addr:
        args["addr"] = addr
    if cset_id:
        args["csetId"] = cset_id
    if tag:
        args["tag"] = tag
    return _call("probe_causal", audit_as="probe_causal", **args)


# ---- v2: multi-breakpoint registry (T4)

@mcp.tool
def bps_arm(entries: list[dict], auto_debug: bool = True) -> dict:
    """Arm up to four hardware watchpoints at once.

    entries: [{"addr": "1F2A3040", "size": 4, "trigger": "write", "label": "c1"}].
    x86 has four debug registers, shared by execute and write breakpoints, so
    more than four is physically impossible -- refused rather than half-armed.
    Arm first, then act, then read bps_hits.
    """
    return _call("bps_arm", audit_as="bps_arm", entries=entries, autoDebug=auto_debug)


@mcp.tool
def bps_hits(bp_id: str = "", addr: str = "", limit: int = 20) -> dict:
    """Raw hit log for one watchpoint: registers, written value, faulting instruction.

    This deliberately reports no boolean "it was written when I acted" field.
    Reading hits as causation is the mistake probe_causal exists to prevent.
    """
    args: dict[str, Any] = {"limit": limit}
    if bp_id:
        args["bpId"] = bp_id
    if addr:
        args["addr"] = addr
    return _call("bps_hits", **args)


@mcp.tool
def bps_clear(bp_id: str = "", addr: str = "", all_bps: bool = False) -> dict:
    """Disarm one watchpoint, or all of them."""
    if all_bps:
        return _call("bps_clear", all=True)
    args: dict[str, Any] = {}
    if bp_id:
        args["bpId"] = bp_id
    if addr:
        args["addr"] = addr
    return _call("bps_clear", **args)


@mcp.tool
def bp_snapshot() -> dict:
    """Every armed watchpoint plus debug-register usage."""
    return _call("bp_snapshot")


@mcp.tool
def read_registers() -> dict:
    """Current register values (only meaningful while the debugger is stopped)."""
    return _call("read_registers")


@mcp.tool
def enum_threads() -> dict:
    """Threads of the attached process, so a render thread can be excluded."""
    return _call("enum_threads")


# ---- v2: static analysis (T9 / B1)

@mcp.tool
def disasm_decode(addr: str, count: int = 10, stop_at_jump: bool = False) -> dict:
    """Decode instructions with their operand meaning.

    Unlike disasm, this reports modrmValueType (address vs value) and the memory
    operand's address, which is what "which object does this instruction touch"
    actually needs.
    """
    return _call("disasm_decode", addr=addr, count=count, stopAtJump=stop_at_jump)


@mcp.tool
def xref_find(addr: str, module: str = "", refresh: bool = False) -> dict:
    """Find code/data references to an address via CE's dissect-code database."""
    args: dict[str, Any] = {"refresh": refresh}
    if module:
        args["module"] = module
    return _call("xref_find", addr=addr, **args)


@mcp.tool
def ptr_trace_static(addr: str, max_depth: int = 4) -> dict:
    """Walk xrefs backwards from a data address toward module code.

    Static and deterministic: this is what makes a pointer chain provable rather
    than plausible. It terminates with a stated reason when the references run
    out, rather than inventing a base.
    """
    return _call("ptr_trace_static", addr=addr, maxDepth=max_depth)


# ---- v2: guarded writes (T7)

@mcp.tool
def write_bytes_guarded(addr: str, hex: str, expect_hex: str = "") -> dict:
    """Overwrite bytes, with expectHex=<bytes you just read> as the lock."""
    args: dict[str, Any] = {"addr": addr, "hex": hex}
    if expect_hex != "":
        args["expectHex"] = expect_hex
    return _call("write_bytes", audit_as="write_bytes", **args)


@mcp.tool
def write_readonly(addr: str, hex: str, expect_hex: str = "") -> dict:
    """Patch bytes on a non-writable page, restoring protection afterwards.

    This is the only command that changes page protection, and it says so
    explicitly. Use it for code patching, not for data.
    """
    args: dict[str, Any] = {"addr": addr, "hex": hex}
    if expect_hex != "":
        args["expectHex"] = expect_hex
    return _call("write_readonly", audit_as="write_readonly", **args)


def main() -> None:
    # Not requiring CE at startup is deliberate: an MCP client that cannot
    # connect must still see the tool list and get a clear error on call,
    # otherwise the server looks broken rather than "CE is not running".
    mcp.run()


if __name__ == "__main__":
    main()
