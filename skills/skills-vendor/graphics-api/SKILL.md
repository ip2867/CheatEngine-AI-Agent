---
name: graphics-api-hooking
description: Analyze Direct3D, DXGI, OpenGL, or Vulkan rendering, overlays, presentation, capture, and measurement evidence. Use when the graphics pipeline or frame-observation boundary is central.
---

# Graphics API hooking and rendering

Record the API, backend, driver, compositor, capture path, synchronization model, and tool version before interpreting rendering evidence.

## Topic routing

- [APIs and rendering](references/apis-and-rendering.md) for DirectX, OpenGL, Vulkan, hook points, swap chains, and ImGui.
- [Overlays, capture, and measurement](references/overlays-capture-and-measurement.md) for overlay methods, shaders, screenshots, OBS, profiling, and anti-detection claims.
- [Repository resources](references/repository-resources.md) and [repository map](references/repository-map.md) for source selection.

Use `game-hacking-techniques` for the broader attacker model and `game-engine-resources` for engine-owned rendering structures. Separate observed capture behavior from assumed anti-cheat enforcement.
