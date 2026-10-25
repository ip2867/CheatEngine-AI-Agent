---
name: windows-kernel-security
description: Analyze Windows driver trust, callbacks, IRQL, kernel memory, DSE, PatchGuard, VBS/HVCI, ETW, crash evidence, and build-specific internals for authorized game-security research.
---

# Windows kernel security

Match undocumented structures, offsets, globals, and allocator behavior to the exact Windows build and symbols. Separate documented contracts, observed state, and inference.

## Topic routing

- [Foundations and security](references/foundations-and-security.md) for driver surfaces, symbols, PatchGuard, DSE, VBS/HVCI, and Secure Boot.
- [Drivers and observation](references/drivers-and-observation.md) for callbacks, IRQL, APCs, driver structure, hooking, and ETW.
- [Memory and forensics](references/memory-and-forensics.md) for pool architecture, memory access, dumps, and tools.
- [Threats and virtualization](references/threats-and-virtualization.md) for vulnerable drivers, boot threats, PatchGuard research, and hypervisor defenses.
- [Repository resources](references/repository-resources.md) and [repository map](references/repository-map.md) for source selection.

Use `dma-attack-techniques` for device-originated memory access and `game-security-research-rigor` for version-sensitive conclusions.
