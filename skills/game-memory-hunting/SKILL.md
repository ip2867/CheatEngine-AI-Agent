---
name: game-memory-hunting
description: Locate game state (health, ammo, position, side flags) in a live process through the CE bridge. Use when a value on screen must be traced back to memory, when a scan converges to hundreds of candidates and none of them move the screen, when a write is silently overwritten, or when a shared routine has to be patched to affect only one side of a fight.
---

# Game memory hunting

Every rule here was paid for in a real session on `gtutorial-x86_64.exe`.
Follow them in order; each one exists because skipping it cost a day.

## 0. The one thing that decides everything: the hypothesis type

A scan is only as good as the type you declare. In this project **five full
converging runs were wasted** looking for a float boss health that was a plain
`dword` the entire time, sitting inside the window that was being scanned.

Before you scan, answer: what does the *code* do with this value? A bar drawn
from a ratio is a float; an integer counter decremented by a fixed damage is a
`dword`. If you cannot answer, run **both** as separate hypotheses instead of
guessing once.

    hypothesis_open(statement="boss health is a dword decremented by damage",
                    anchorFamily="exact", anchorValue=76)
    anchor_calibrate(calibrateField="healthText", action="baseline",
                     expectedDelta=0, observedBefore=76, observedAfter=76)
    scan_first(type="dword", op="unknown", start=..., stop=...,
               hypothesisId=..., calibrationTicket=...)

`scan_first` requires all three: a `hypothesisId`, a `calibrationTicket`, and a
bounded window. Missing one returns `HYPOTHESIS_REQUIRED` or
`CALIBRATION_REQUIRED`, not a result.

## 1. Only `increased` across a reload removes timers

`decreased` is the obvious filter and it is nearly useless on its own: frame
counters, particle timers and animation clocks decrement forever and survive
every `decreased` pass. The filter that actually cuts is the **reversal** — shoot
until the display resets, then keep only addresses that went **up** at that
moment. Measured on a real level:

    33,632,256 baseline  ->  116,873 after one `decreased`
                         ->    2,183 after one `increased`   (-98% in one step)
                         ->       31 after a value-range filter

That `-98%` is the whole technique. Without the reload reversal you are picking
through 116k addresses.

## 2. Narrow with live reads, not with scan-time snapshots

The single cause of every false convergence in this project. `scan_next`
compares against **the value recorded at scan time**, while `read` returns the
**live** value. Anything that changed between the two scans dominates the
survivor set instead of the field you are hunting.

Correct narrowing, in this order:

    scan_results(page)  ->  read each address now
                        ->  keep only live && chk == target
                        ->  discard staleReason != nil

`scan_results` already tells you the truth per row: `live`, `staleReason`,
`changedSinceScan`. Read those fields; do not infer them.

## 3. A `verified: true` write proves nothing about retention

`write` returning `verified: true` means the bytes landed and read back. It
says nothing about whether the game keeps them. Three separate addresses in this
project accepted writes and were overwritten on the next frame:

| address | what it looked like | what it was |
|---|---|---|
| `0x167C1B0` | float health 76.0, bar followed a write | a per-frame display copy |
| `0x6EF0129` + 20 slots | exact per-shot stride, returned to start on reload | a copy array, not the source |
| `0x15E4BD0` | `+0x60` inside the enemy struct | not the value the bar reads |

The test is not "did the write land", it is **"is it still there after 1.5 s, and
does the screen move when you change it"**. Both conditions, every time.

## 4. Structural filters beat numeric filters

When a numeric sweep leaves thousands of rows, drop by **shape** before
spending shots:

- paired equal values at a fixed stride (`0x78`) are arrays — discard
- a value that returns to its exact initial value after a reload is a copy, not
  the authority
- if the whole heap has no pointer to it, nothing writes it — it is a mirror

On one hunt this took 372 candidates down to 40 in one pass, and all 40 were the
same copy array.

Better still, start from shape. If you suspect the field is a hit-point pair, say
so and scan for it directly instead of narrowing values:

```
find_struct(base=<window>, size=<window>, maxValues=[100,200,300,500])
```

It returns every adjacent `(hp, maxhp)` dword pair with `hp <= max`. On a real
4 MB window that is **6 candidates in 0.9 s with no shot fired**, versus ~159
without the `hp <= max` constraint and thousands from any numeric sweep.

Two lessons worth keeping:

- **`hp <= max` is a logical constraint, not a numeric pattern.** Timers, frame
  counters and per-object float parameters cannot satisfy it by accident, which
  is exactly why it is the cheapest filter available.
- **Prefer shape predicates over identity predicates.** Keying a sweep on a fixed
  vtable value is tempting for "find every entity of type X", but polymorphic
  objects need not share one. A vtable sweep found two of three entities and led
  to the false conclusion that the third lived outside the window — it never did.

Numeric narrowing remains correct when you do not yet know the shape. But the
moment you do, switch: continuing to narrow numbers against timers is spending
shots to fight the wrong population.

Also: never enumerate a multi-megabyte window one address at a time. A per-offset
`read_memory` walk is a million round trips — it exceeds any timeout and, measured,
crashed the target process. Use `read_bytes` in 64 KiB chunks and advance by its
`returned` field, not by `requested`, or every page boundary becomes a silent hole.

## 5. Writes into a copy are silently reverted — check who else writes it

If writing an address gets overwritten within a frame, do not keep hunting for a
"better" version of that address. Set a **write breakpoint** on it and read the
instruction pointer. Either you are looking at a mirror, or you have found the
real field and something else is the authority upstream.

## 6. Breakpoints need `debugProcess()`, and they need to be re-armed

This was misdiagnosed for days as "hardware breakpoints do not work on this
machine". They do. Two facts:

- `set_breakpoint` calls `debugProcess()` internally and therefore attaches the
  debugger; `bps_arm` does not, which is why every earlier attempt reported
  `hitCount: 0` with the breakpoint visibly installed.
- The debugger drops back to `canBreak: false` on its own between calls. To
  catch a write that happens during a shot you must run a **second connection**
  that polls `debug_state` and re-issues `set_breakpoint` in a loop while the
  shot is fired:

      while not stop:
          st = cl2("debug_state")
          if isinstance(st, dict) and not st.get("canBreak"):
              cl2("set_breakpoint", addr=..., size=4, trigger="write", label="hp")
          time.sleep(0.05)

Measured: `armed 1 times`, `bp2.hits = 82`.

`bp_hits` requires an explicit `bpId`; without one it answers
`NOT_FOUND: unknown bpId: nil`. Read the registers off the returned items —
`rcx` is `this`, `rdx` is the argument.

## 7. Discrimination lives in a real flag, not in a coincidence

When a shared routine must be split between two sides, find the field that
actually carries the distinction. On this build three candidates were available:

    0x15E4B70  +0x24 = 0.205 (float)   +0x70 = 1   enemy
    0x15E4CB0  +0x24 = 0.0   (float)   +0x70 = 0   player

`+0x24` happens to correlate, but it is a **float**. `cmp dword [rax+0x24], 0`
compares the bit pattern `0x3E51EB85` against zero, never matches, and treats
every object as an enemy. The correct test is the integer flag:

    cmp dword [rax+0x70], 0
    jne enemy

## 8. Patching `.text` may be detected — find the check before you rely on it

The one-shot kill injection (see `docs/code-injection.md`) worked on the first
shot, and the window title immediately changed to
`Step 2 (Integrity check error)`. In that state the whole combat loop freezes:
bullets pass through enemies, enemy fire does nothing, bars stop moving. That
looked exactly like "the aim is wrong" and cost an hour of chasing geometry that
was never the problem.

Before relying on a code patch, check whether the build verifies its own code,
and plan for the window it gives you. Restoring the original bytes and zeroing
the cave cleared the error **without restarting the game** — so an experiment can
be undone, but it cannot be left in place.

## 9. Bound the scan to the heap that actually holds the game

A baseline over the whole address space returns about 104,000,000 unknowns, of
which the overwhelming majority are reserved pages. The real writable heap of
this build was about **123 MB** across four regions. Scanning the full space is
not thorough, it is just slow. Enumerate the regions, skip reserved ones, and
scan the rest.

## 10. When the screen and memory disagree, believe neither until both agree

Instrumentation that reports a value must be verified against the render. On
this project the pixel reader, not the memory reader, was the thing that was
lying: a value that tracked the bar's *width in pixels* (188) was repeatedly
misread as the health itself, and "five shots kill it" was misread as "health is
5" when the real maximum was 100 and the last shot only *looked* lethal because
of a reload that healed the target.

Two independent channels, or no conclusion.
