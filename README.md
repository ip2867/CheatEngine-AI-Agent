# Cheat Engine AI Agent

让 AI agent 直接驱动 Cheat Engine 做内存分析。装好后，任何支持 MCP 的 AI 客户端（Claude Desktop、Cursor、ZCode 等）都能读取内存、扫描数值、找指针链、下断点、读寄存器、改代码。

**52 个工具**，覆盖从"扫一个数值"到"注入代码区分敌我"的完整链路。
额外带 **15 个技能**：2 个是这一轮实战里被打出来的，13 个 vendored 自
[awesome-game-security](https://github.com/gmh5225/awesome-game-security)。

这个工具详细介绍与解题实战观看blog：https://ip2867.github.io/
## 先说清楚它不是什么

这份文档里有两类话，请分开读：

- **能核对的**：工具数量、参数名、错误码、注入的字节序列、实测到的地址和读数。
  这些都有代码或运行记录对应。
- **做不到的**：Step 2 的第二个敌人没有找到血量，那一关没打通。见
  `docs/walkthrough.md` 的「没做到的部分」。

写这份东西的原则是：宁可说"这条我错了，原因是 X"，也不把失败包装成成功。
具体踩过的坑都在 `docs/walkthrough.md` 里，包括那些让我绕了很远的错判。

## 组成

```
CheatEngine-AI-Agent/
├─ install.ps1              ← 一键安装（无需管理员）
├─ ce/ce_ai_bridge.lua      ← CE 内执行层，由 autorun 自动加载
│  ce/v2_*.lua              ← 策略 / 断点 / 指令 / 因果四个模块
├─ mcp/ce_mcp_server.py     ← MCP 服务端，52 个工具
├─ config/                  ← 安装时生成的 MCP 配置（不入库）
├─ docs/
│  ├─ tools.md              ← 52 个工具的完整参数与错误码
│  ├─ walkthrough.md        ← 实战记录：换弹死局、注入、以及所有失败
│  └─ skills.md             ← 15 个技能的索引与来历
└─ skills/
   ├─ game-memory-hunting/  ← 自研：定位字段的 10 条铁律
   ├─ game-vision/          ← 自研：从像素读状态的 10 条铁律
   └─ skills-vendor/        ← 13 个上游技能（MIT，附 LICENSE）
```

工作方式：

```
AI 客户端 ──stdio/JSON-RPC──▶ ce_mcp_server.py
                                    │ 命名管道
                                    ▼
                            ce_ai_bridge.lua（CE 进程内）
                                    │
                                    ▼
                              目标进程内存
```

## 安装

```powershell
# 在解压后的目录里执行
powershell -ExecutionPolicy Bypass -File install.ps1
```

脚本会：
1. 自动找到 Cheat Engine（Program Files / 注册表 / 运行中的进程）
2. 往 CE 的 `autorun\` 放一个 5 行的 loader
3. 生成 `config/mcp-generated.json`，里面是本机的真实路径

CE 装在非默认位置时：

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -CePath "D:\Cheat Engine"
```

卸载：

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall
```

## 接入 AI 客户端

重启 Cheat Engine，Lua 引擎窗口应打印：

```
[CE-AI] listening on CE_AI_Bridge_v1_0 (v0.4.0)
```

然后把 `config/mcp-generated.json` 里的 `mcpServers` 段落复制进你的客户端配置。

**Claude Desktop** — `%APPDATA%\Claude\claude_desktop_config.json`
**Cursor** — `%USERPROFILE%\.cursor\mcp.json`
**ZCode** — `%USERPROFILE%\.mcp.json`

格式：

```json
{
  "mcpServers": {
    "cheatengine": {
      "command": "python",
      "args": ["C:\\...\\CheatEngine-AI-Agent\\mcp\\ce_mcp_server.py"],
      "env": { "CE_AI_ENABLE_WRITES": "1" },
      "timeout": 120
    }
  }
}
```

## 依赖

- Windows
- Python 3.10+
- `python -m pip install fastmcp pywin32`
- Cheat Engine 7.x

## 安全边界

默认只读。写入和断点需要显式开启 `CE_AI_ENABLE_WRITES=1`。

即使开启，也有四道闸：

| 闸门 | 行为 |
|---|---|
| 白名单 | 只允许附加 `Tutorial-x86_64.exe`、`gtutorial-*` 及 `CE_AI_EXTRA_TARGETS` 里的程序 |
| 乐观锁 | `write_value` 必须带 `expect`，值不符则拒绝（`STALE`）；省略则 `EXPECT_REQUIRED` |
| 写后回读 | 写完立即读回比对，返回 `verified` —— **只证明字节落地，不证明游戏保留了它** |
| 页保护 | 仅 `write_readonly` 显式改保护并在写后还原；普通写入路径不检查页权限（见下） |

关于页保护，需要如实说明：CE 7.7 的 Lua 侧没有任何可用的改保护函数
（`virtualprotect`、`VirtualProtect`、`VirtualProtectEx` 全是 nil，
`setMemoryProtection` 对 GUI 未 open 的进程无效）。桥原来在这里有一道
只读拒绝，结果是**挡住了 CE 自己本来能写的页，却什么也没保护住**，所以
那道检查被有意删掉了。普通写入靠 CE 自带的 `writeBytes` 内部处理保护，
唯一守卫是 `expect` / `expectHex`。要显式、可验证、写后还原的改保护，
用 `write_readonly`。

地址解析也做了防护：CE 对未映射地址会静默返回 0，桥接层会先用 `getMemoryRegionInfo` 校验，拒绝时返回 `ADDRESS_NOT_MAPPED` 而不是假数据。

所有副作用操作记入 `%LOCALAPPDATA%\CheatEngineAI\audit\YYYY-MM-DD.jsonl`。

## 常见问题

**连接不上？**
1. 确认 CE 在运行，Lua 引擎里看到 `[CE-AI] listening`
2. 确认 `autorun\zz_ce_ai_agent.lua` 存在
3. 重启 AI 客户端（配置在启动时读取）

**`CE_NOT_RUNNING`？**
CE 没开，或 autorun 没加载。看 CE 的 Lua 引擎窗口有没有报错。

**`PERMISSION_DENIED`？**
目标不在白名单里。用 `CE_AI_EXTRA_TARGETS` 环境变量加，多个用分号分隔。

**CE 是绿色便携版，没有 autorun 目录？**
手动在 CE 的 Lua 引擎里执行：

```lua
dofile([[完整路径\ce\ce_ai_bridge.lua]])
```

## 适用范围

用于 CTF、自有程序、书面授权的测试目标。白名单默认只放开 CE 自带的教程程序。不适用于联机游戏或未授权系统。

## 工具清单

**52 个工具**，分九组：进程(4)、读取(3)、扫描(6)、分析(10)、写入(6)、
断点(10)、假设与标定(6)、候选集与因果(6)、审计(1)。完整参数与返回值见
`docs/tools.md`。

两组值得单独说：

- **假设与标定**（`hypothesis_open` / `anchor_calibrate` / …）：`scan_first`
  强制要求先登记"我在找什么、为什么"并证明观测链路本身是对的，缺一个就是
  `HYPOTHESIS_REQUIRED` / `CALIBRATION_REQUIRED`。这不是形式主义 —— 它防的是
  "扫描收敛到几百个候选、然后挑一个看起来对的去写"这种事。
- **候选集**（`cset_*`）：把候选冻成分页集合，读的时候带**实时值**。
  因为 `scan_next` 比较的是扫描期快照，而你要找的字段可能已经变了，
  这个差别是假收敛的根源。

## 已知限制

- 验证过 Cheat Engine **7.7** / Windows。其它版本未测；改保护相关的
  工具在 7.7 上是用 `getMemoryProtection` + `setMemoryProtection` 绕出来的。
- `bps_arm` **不**调 `debugProcess()`，用它装出来的断点 `hitCount` 恒为 0。
  用 `set_breakpoint`，或自己确认 `debug_state.canBreak == true`。
- 调试器会在两次调用之间掉回 `canBreak: false`。抓瞬时写入必须另开一个
  连接循环重装（见 `docs/walkthrough.md` 第四节）。
- 上游 13 个技能是**纯路由索引**：它们的 `references/` 指向一份 18.61 GB
  的第三方快照，那份东西没有随本仓库分发，相关链接已改成上游 URL。
  引用它们引用的是方法论，不是可用实现。
