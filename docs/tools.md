# 工具清单

54 个 MCP 工具。返回统一信封：`{"ok": true, "data": {...}}` 或 `{"ok": false, "error": {"code": "...", "message": "..."}}`。

错误码：`CE_NOT_RUNNING` `NOT_ATTACHED` `ADDRESS_NOT_MAPPED` `NOT_FOUND` `VALIDATION_FAILED` `PERMISSION_DENIED` `STALE` `EXPECT_REQUIRED` `SCAN_GREW` `WRITES_DISABLED` `DEBUGGER_UNAVAILABLE` `DEBUGGER_NOT_ATTACHED` `HYPOTHESIS_REQUIRED` `CALIBRATION_REQUIRED` `PROTECTION_FAILED` `WRITE_FAILED` `UNKNOWN_COMMAND`

> 参数名以本表为准。JSON 里用 MCP 的驼峰名（如 `maxDepth`、`scanId`），
> Python 侧用下划线名（如 `anchor_family`、`hypothesis_id`）。

---

## 进程（4）

| 工具 | 参数 | 说明 |
|---|---|---|
| `ping` | — | 探活，返回 CE 版本 |
| `allowlist_info` | — | 显示当前白名单 |
| `attach_process` | `pid` | 附加进程（白名单强制，**副作用**） |
| `process_info` | — | pid、名称、位宽、模块数、镜像基址 |

## 读取（4）

| 工具 | 参数 | 说明 |
|---|---|---|
| `read_memory` | `addr`, `type=dword` | 读一个值。type: byte/word/dword/qword/float/double/pointer/utf8/utf16 |
| `read_bytes` | `addr`, `count=256` | **一次读一整块**，返回十六进制串。count 上限 262144。按 `returned` 推进而不是 `requested`（跨页会提前停） |
| `read_chain` | `base`, `offsets[]` | 多级指针链，返回每一跳 |
| `module_of` | `addr` | 地址归属的模块 + 偏移 |

`read_bytes` 是给「按结构形状找字段」用的：找遍 4 MB 堆里的每个 `(hp, maxhp)` 相邻 dword 对，逐地址调用是两百万次往返，任何超时都跑不完；分块读是 64 次调用，**0.9 秒**出结果。逐地址轮询不是慢，是会失败 —— 实测把游戏进程轮询到崩溃。

## 扫描（6）

| 工具 | 参数 | 说明 |
|---|---|---|
| `scan_first` | `type`, `value`, `protect="+W-C"`, `op`, `value2`, `start`, `stop`, `aligned`, `hex` | 首扫，返回 scanId 与命中数。`value` 省略走未知初值扫描；`start`/`stop` 限定范围（强烈建议给，见下） |
| `scan_next` | `scanId`, `op`, `value?`, `value2?` | 收窄。op: exact/changed/unchanged/increased/decreased/bigger/smaller/between |
| `scan_results` | `scanId`, `offset=0`, `limit=50` | 分页读结果，limit 上限 200。**返回里带 `live` / `staleReason` / `changedSinceScan`，收窄要以这些为准** |
| `scan_stats` | `scanId` | 扫描规模与进度 |
| `release_scan` | `scanId` | 释放结果集 |
| `aob_scan` | `pattern`, `limit=50` | 特征码扫描，如 `"48 8B 05 ?? ?? ?? ??"` |

## 分析（11）

| 工具 | 参数 | 说明 |
|---|---|---|
| `enum_modules` | `offset`, `limit` | 模块列表 |
| `module_sections` | `name` | 模块区段 |
| `memory_regions` | `writable=true`, `offset`, `limit` | 内存区枚举。**先跑这个，把扫描限制在真实堆里** |
| `disassemble` | `addr`, `count=10` | 反汇编，最多 64 条 |
| `disasm_decode` | `addr`, `count=10`, `stop_at_jump=false` | 带操作数语义的反汇编 |
| `function_range` | `addr` | 估算函数边界 |
| `find_pointer_chains` | `target`, `maxDepth=3`, `maxResults=20`, `maxOffset=4096` | 反向扫描找指向目标的模块级指针链 |
| `dissect_structure` | `addr`, `maxFields=32` | 按 4 字节推断结构体布局 |
| `find_struct` | `base`, `size`, `maxValues[]`, `hpMin`, `hpMax`, `hpLeMax=true`, `limit=200` | **按结构形状扫全窗口**：找所有 `(hp, maxhp)` 相邻 dword 对。CE 内部 64 KiB 分块，整窗一次管道调用 |
| `xref_find` | `addr`, `module`, `refresh=false` | 经 CE 的 dissect-code 数据库找代码/数据引用 |
| `ptr_trace_static` | `addr`, `max_depth=4` | 从数据地址沿 xref 反向走到模块代码 |

## 写入（6，需 `CE_AI_ENABLE_WRITES=1`）

| 工具 | 参数 | 说明 |
|---|---|---|
| `write_value` | `addr`, `value`, `type`, `expect?` | 写入 + 回读验证。`expect` 不符 → `STALE`；省略 → `EXPECT_REQUIRED`（除非 `CE_AI_UNSAFE_WRITES=1`） |
| `write_bytes` | `addr`, `hex` | 写原始字节，最多 4096 |
| `write_bytes_guarded` | `addr`, `hex`, `expect_hex?` | 同上，但用 `expectHex`（你刚读到的字节）做乐观锁 |
| `write_readonly` | `addr`, `hex`, `expect_hex?` | 显式改页保护写代码页，**写后还原保护**。页本来可写则拒绝，让你改用 `write_bytes` |
| `undo_writes` | `count=1` | 回滚最近写入 |
| `write_history` | — | 本次会话的写入栈 |

> **重要**：`write_value` / `write_bytes` 这条路径**没有页保护拦截**。
> CE 7.7 的 Lua 侧没有任何可用的改保护函数（`virtualprotect`、
> `VirtualProtectEx` 均为 nil），CE 自带的 `writeBytes` 会在需要时内部改保护。
> 所以这条路径唯一守卫是 `expect` / `expectHex`。
> 需要「显式、可验证、事后还原」的改保护，用 `write_readonly`。

## 断点（10，需 `CE_AI_ENABLE_WRITES=1`）

| 工具 | 参数 | 说明 |
|---|---|---|
| `set_breakpoint` | `addr`, `trigger="write"`, `size=8` | 硬件断点，**会自己调 `debugProcess()` 附加调试器** |
| `breakpoint_hits` | `bpId`, `limit=50` | 命中记录：IP、寄存器、次数 |
| `clear_breakpoint` | `bpId` | 移除断点 |
| `debug_state` | — | 调试器状态与活跃断点（`canBreak`、`debugging`） |
| `bps_arm` | `entries[]`, `auto_debug=true` | 一次装最多 4 个硬件观察点 |
| `bps_hits` | `bp_id`, `addr`, `limit=20` | 原始命中日志：寄存器、被写值、faulting 指令 |
| `bps_clear` | `bp_id`, `addr`, `all_bps` | 卸观察点 |
| `bp_snapshot` | — | 所有已装观察点 + 调试寄存器占用 |
| `read_registers` | — | 当前寄存器（仅在调试器停住时有意义） |
| `enum_threads` | — | 目标线程列表 |

> **踩过的坑**：`bps_arm` **不**调 `debugProcess()`，所以它装出来的断点
> `hitCount` 恒为 0。要么用 `set_breakpoint`，要么 `bps_arm` 之后自己确认
> `debug_state.canBreak == true`。调试器还会在两次调用之间自己掉回
> `canBreak: false`，要抓开火瞬间的写入必须**另开一个连接循环重装**。
> `bps_hits` 必须显式带 `bp_id`，否则报 `unknown bpId: nil`。

## 假设与标定（6）

这一组是「防止模型自欺」的强制流程，不是可选项。

| 工具 | 参数 | 说明 |
|---|---|---|
| `hypothesis_open` | `statement`, `anchor_family`, `anchor_value`, `expect_field`, `expect_delta`, `calibrated_by` | 扫之前先登记「我在找什么、为什么」 |
| `anchor_calibrate` | `calibrate_field`, `action`, `expected_delta`, `observed_before`, `observed_after` | 先证明观测链路本身是对的 |
| `hypothesis_refute` | `hypothesis_id`, `reason` | 判死。两次反驳即关闭，计数是全局的 |
| `hypothesis_confirm` | `hypothesis_id`, `evidence` | 结案，必须引用证据 |
| `hypothesis_list` | `status` | 列假设（open/refuted/confirmed） |
| `policy_stats` | — | 假设/标定计数，以及离 `STUCK` 还有多远 |

`scan_first` 需要 `hypothesisId` + `calibrationTicket` 两者，缺一个就是
`HYPOTHESIS_REQUIRED` / `CALIBRATION_REQUIRED`。

## 候选集（5）

| 工具 | 参数 | 说明 |
|---|---|---|
| `cset_from_scan` | `name`, `scan_id`, `addrs[]`, `kind`, `note` | 把扫描结果（或显式地址表）冻成分页集合 |
| `cset_page` | `cset_id`, `offset=0`, `limit=20` | 读一页候选，**带实时值** |
| `cset_exclude` | `cset_id`, `tag`, `reason` | 带理由剔除一个候选 |
| `cset_stats` | `cset_id` | tested / excluded / untested |
| `cset_list` | — | 本次会话所有候选集 |

> 收窄要用 `cset_page` 的**实时值**，不要用 `scan_next` 的扫描期快照。

## 因果探针（1）

| 工具 | 参数 | 说明 |
|---|---|---|
| `probe_causal` | `action`, `rounds=3`, `baseline_ms=800`, `experiment_ms=1200`, `addr`, `size`, `trigger`, `cset_id`, `tag` | 对照/实验轮交替观测一个地址 |

## 审计（1）

| 工具 | 参数 | 说明 |
|---|---|---|
| `audit_log` | `count=20` | 最近的审计记录 |

---

## 典型工作流

**找血量并改动**

```
scan_first(type="dword", value="100")   → {scanId:"s1", total:34908}
（游戏内触发一次掉血）
scan_next(scanId="s1", op="decreased")  → {total:23}
scan_results(scanId="s1", limit=20)     → 候选 + live 标志
write_value(addr="0x...", value=0, type="dword", expect=当前值)
                                        → {before:12, after:0, verified:true}
```

**不确定初始值时**

```
memory_regions(writable=true)               → 拿到真实堆范围，别扫整个地址空间
scan_first(type="dword", value="unknown", start="0x10000", stop="0x10000000")
（触发变化）
scan_next(scanId="s1", op="decreased")      → 只保留变小的
（等到换弹/回满那一刻）
scan_next(scanId="s1", op="increased")      → ★ 一步砍掉 98% 的计时器噪声
```

第二步的 `increased` 是整套方法的灵魂：`decreased` 单用砍不掉帧计数器
和动画时钟，它们永远在递减；只有「反向那一刻」能把它们一次清掉。

**找指针链**

```
find_pointer_chains(target="0x1234ABCD")    → {base:"game.exe+0x1D3070", offsets:[1,8]}
read_chain(base="0x...", offsets=[1,8])     → 验证链能走通
```

**用断点反查「谁在写这个地址」**

```
set_breakpoint(addr="0x...", trigger="write")   → 自动附加调试器
（触发游戏行为 —— 需要第二个连接循环重装才能抓到瞬时写入）
breakpoint_hits(bpId="bp1")                     → {ip:"0x...", rcx:"this", rdx:"参数"}
clear_breakpoint(bpId="bp1")
```

**改代码（区分敌我）**

```
bps_arm / set_breakpoint 抓共享函数的 rcx      → 拿到实体指针
read_memory(addr="实体+0x70", type="dword")     → 0=我方 1=敌方
disassemble(addr="函数首部")                    → 确认可覆盖的前几字节
aob_scan(pattern="<尾部一串 00>")               → 找代码洞
write_readonly(addr="函数首部", hex="<jmp>", expect_hex="<原字节>")
write_readonly(addr="代码洞", hex="<注入体>")
```
