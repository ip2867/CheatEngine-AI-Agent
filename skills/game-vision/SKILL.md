---
name: game-vision
description: Read a game's state off the screen when memory is unknown, blocked, or being written by the engine every frame. Use for health bars, ammo counters, sprite positions, aim geometry, and any time a value must be measured from pixels rather than read from the process.
---

# Reading a game from pixels

Memory gives you a number. Pixels give you the state the player sees. When those
two disagree you have found a bug in your instrument, and that is the most
valuable result either channel can produce. Every rule below is from a session
where the pixel channel was the only one that worked, and later the one that was
caught lying.

## 0. Know which capture path actually returns pixels

On this build, `PrintWindow` returns **black**, with or without
`PW_RENDERFULLCONTENT = 0x2`. The only path that returns real pixels is a
`BitBlt` from the **screen** DC at the client origin:

    pt = POINT(0, 0); ClientToScreen(hwnd, pt)
    screen = GetDC(0)
    BitBlt(mem, 0, 0, w, h, screen, pt.x, pt.y, SRCCOPY)

That means the window must be on top and unoccluded. Prove it before you trust a
frame — a stale or half-painted frame is how you end up "measuring" 744 KB of
garbage:

    if GetForegroundWindow() != hwnd: abort, do not save a frame

**Foreground is necessary but not sufficient.** `BitBlt` copies the *screen*, and
being foreground only means the input queue points at us — an overlay, a
notification, or a second app stacked above the game still lands in the PNG. One
"capture the win screen" step silently saved an unrelated chat window this way,
and nothing downstream noticed because the file was a perfectly valid PNG.

Walk the z-order and refuse when anything else intersects the client rect:

    r = GetClientRect; pt = (0,0); ClientToScreen(hwnd, pt)
    for h in EnumWindows():
        if h is us or not IsWindowVisible(h): continue
        if GetWindowRect(h) intersects client rect: return ABORT + names

Ignore windows of our own process (the game's own popups belong to the frame).
On refusal, **delete the previous file** rather than leaving a stale one. A
self-consistent wrong frame is worse than no frame, because every downstream step
believes it.

`AttachThreadInput` + `ShowWindow(SW_RESTORE)` + `BringWindowToTop` +
`SetForegroundWindow` + `SetActiveWindow` is the sequence that wins the
foreground. `SetForegroundWindow` alone loses to whatever holds focus.

## 1. Delete the old file before grabbing

A failed capture that leaves yesterday's PNG in place is indistinguishable from a
successful capture of the current screen. Remove the target path first, then
capture, then assert the file exists. Normal frames on this game were 19–33 KB;
a 744 KB frame was a half-painted window and was silently accepted for a while.

## 2. Two grabs, keep the denser one

Grabbing twice ~0.8 s apart and taking the frame with more ink filters out the
transitional frame when the window has just been raised. Cheap, and it removed a
whole class of false readings.

## 3. Find the bar, and reject the frame when you cannot

A health bar is a horizontal run of saturated pixels with a fixed track. Do not
assume the geometry; **validate** it and refuse the frame when it fails:

    track_px >= 120
    10 <= ymid <= max(60, min(120, h/10))
    filled <= track_px

Return `bar = None` with a reason rather than a guess. A numeric fallback that
always returns something is worse than no answer, because it gets recorded as an
observation.

Measured baseline for this game: `y = 29`, track `200 px`, full `188 px`.

## 4. Right-half, bottom-band, rightmost-glyph — the ammo box

A naive search for the counter picks up the help panel's large red circle and
merges it with the digits into one useless 100 px block. What worked:

1. scan only `x >= 0.55 * w` and `y >= 0.80 * h`
2. group red pixels into row segments, `gap > 6` splits
3. take the **lowest** counter-sized band (`22 <= band_h <= 44`)
4. inside it, column histogram, `gap > 4` splits into glyphs
5. take the **rightmost** glyph, `14 <= width <= 70`

The box is not stable across a session: it drifted from `x1552` to `x1430` when
an overlay panel toggled and moved the whole bottom HUD by ~86 px. Recompute it
per frame; keep the constant only as a last resort.

## 5. Glyph identity: ink count first, template only as a tiebreak

Digit recognition by template scored 0.6–0.8 on hand-written templates and
produced confident garbage. What worked was a tiny ink-count table built from
**real captured glyphs**:

    ink 140 -> '5'      ink 136 -> '3'      ink 128 -> '4'      ink 108 -> '1'

Ink alone cannot separate 5 from 6, so keep the bitmap comparison as a tiebreak
for those pairs — but never hand-draw the templates. Extract them from frames
whose value you already know.

## 6. A glyph cut by the bar is not a wrong glyph

The player's health number is drawn inside the health bar, so losing health moves
the bar's left edge over the leading digit. Detect this rather than misreading it:

    clipped = any(row[0] for row in mask[:4])

Only the first glyph may be low-confidence **and** clipped; every other glyph must
score well or the whole frame is rejected. Without this, a clipped `5` reads as a
confident `6`.

## 7. Sprite geometry is a measurement, not an assumption

"When the bullet passes through it" is a claim about pixels. Measure both sprites
and compare centres before believing it:

    right enemy   x  884..1049   centre 966.5   y    0..213
    player        x  714.. 873   centre 799.5   y  984..1169
    horizontal gap 167 px over 985 px vertical  =>  needs 9.6 degrees of lead

A shot fired straight up from `x = 799.5` cannot reach `x = 966.5`. "It passes
through the body" was, in fact, the bullet travelling nowhere near it — and the
apparent pass-through was caused by a separate integrity-check freeze
(see `skills/game-memory-hunting`, rule 8).

## 8. Colour is per-object; do not hardcode one

The left enemy's bar is **green** (`g > 120, r < 100, b < 100`) and the right
enemy's is **blue** (`b > 120, r < 100, g < 100`). A detector that only looks for
green silently reports the blue bar as absent — which reads as "the enemy is
dead" rather than "the detector cannot see it". Detect per colour, and report
which colour found what.

## 9. Grabbing from a subprocess is not free

Launching a new Python process per frame is too slow and, worse, the launches
fight over the foreground and the capture starts failing with `拒绝访问`
(access denied). The working pattern is a **single long-lived process** that
raises the window, blits, and measures in a loop. `grab2.capture()` returns
`((bgra, w, h), why)` — unpack both, never `bgra, w, h`.
