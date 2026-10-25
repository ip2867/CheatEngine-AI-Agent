---
name: game-hacking-techniques
description: Classify game-cheat capabilities and their defensive implications across memory, injection, rendering, input, engines, kernels, DMA, and remote transports. Use for authorized threat modeling, not operational deployment.
---

# Game-hacking techniques

Map what an attacker observes or controls, the required capability, the trust boundary crossed, and where defenders have evidence or authority.

## Topic routing

- [Capabilities and core techniques](references/capabilities-and-core-techniques.md) for privilege levels, manipulation, injection, and cheat categories.
- [Rendering, memory, and input](references/rendering-memory-and-input.md) for overlays, access paths, driver communication, world-to-screen, and input.
- [Platform and evasion](references/platform-and-evasion.md) for EFI, device identity, stack behavior, and anti-detection concepts.
- [Engines and workflow](references/engines-and-workflow.md) for engine-specific surfaces and representative research workflows.
- [Attack-surface map](references/attack-surface-map.md), [repository resources](references/repository-resources.md), and [repository map](references/repository-map.md) for evidence and source selection.

Use the narrower engine, graphics, DMA, kernel, mobile, server, or supply-chain skill when one boundary dominates. Keep recommendations defensive and within the user's authorized scope.
