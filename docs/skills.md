# 技能索引

本仓库带 15 个技能：**2 个自研**（这一轮实战里被打出来的）+ **13 个上游**
（来自 [gmh5225/awesome-game-security](https://github.com/gmh5225/awesome-game-security)
的 `.claude/skills/`，原样 vendored）。

技能是给 AI agent 读的操作约束，不是给人看的教程。它们存在的理由是同一件事：
**凡是模型可以选不做的纪律，弱模型一定不做。** 所以能写进代码的写进代码
（桥里的 `HYPOTHESIS_REQUIRED` / `CALIBRATION_REQUIRED`），写不进代码的写进技能。

---

## 一、自研技能（本项目实战产出）

这两个技能的每一条都对应一次真实的失败。

### `skills/game-memory-hunting/SKILL.md`

在活进程里定位游戏状态（血量、弹药、位置、阵营标志），以及用代码注入
把共享逻辑拆成两半。

10 条铁律，摘要：

| # | 铁律 | 代价来源 |
|---|---|---|
| 0 | 类型假设决定成败，答不出来就并行跑两个 | 五轮 float 全落空，真值是 dword |
| 1 | 只有跨回满的 `increased` 能砍掉计时器 | `decreased` 单独用永远留几百个 |
| 2 | 用实时读收窄，不用扫描期快照 | 所有假收敛的根因 |
| 3 | `verified: true` 不证明保留 | 三个地址写进去都被覆盖 |
| 4 | 结构筛选优于数值筛选 | 372 → 40，全是副本数组 |
| 5 | 写副本会被静默还原 | 写 20 槽全 0，血条不动 |
| 6 | 断点要 `debugProcess()` + 第二个连接重装 | 「硬件断点不可用」误判数天 |
| 7 | 阵营判据用真标志位 `+0x70`，不是 `+0x24` | float 位模式比较永不相等 |
| 8 | 改 `.text` 可能被完整性检测 | `Integrity check error` 冻结战斗循环 |
| 9 | 扫描限制到真实堆 | 全空间 1.04 亿候选，多数是保留页 |
| 10 | 屏幕和内存必须双通道一致 | 把血条宽度 188 当成血量 |

### `skills/game-vision/SKILL.md`

从像素读游戏状态：血条、弹药计数、精灵位置、瞄准几何。

10 条，摘要：`PrintWindow` 全黑只能屏幕 DC `BitBlt`；抓图前删旧文件；
抓两次取墨多者；血条三道拒绝而不是硬读；弹药框「右半屏 + 底部 band +
最右字形」；墨量查表取代手写模板；被血条裁掉的首位要单独识别；精灵几何
靠实测而不是假设；颜色按对象区分（左敌绿、右敌蓝）；单进程循环抓帧。

---

## 二、上游技能（vendor）

位置：`skills/skills-vendor/<dir>/`，共 82 个文件。

| 目录 | 技能名 | 什么时候用 |
|---|---|---|
| `overview` | `awesome-game-security-overview` | 导航那份清单：分类、去重、生成描述、选哪个域技能 |
| `game-hacking` | `game-hacking-techniques` | 给作弊能力分类：内存、注入、渲染、输入、内核、DMA、远程 |
| `reverse-engineering` | `reverse-engineering-tools` | 反汇编/反编译/调试/差分，重建接口 |
| `anti-cheat` | `anti-cheat-systems` | 反作弊分层、检测证据、遥测、处置权衡 |
| `windows-kernel` | `windows-kernel-security` | 驱动信任、回调、IRQL、DSE、PatchGuard、VBS/HVCI、ETW |
| `graphics-api` | `graphics-api-hooking` | D3D/DXGI/OpenGL/Vulkan 的覆盖层、捕获、测量 |
| `game-engine` | `game-engine-resources` | Unreal/Unity/Source/Godot 的对象模型与资产 |
| `game-server-security` | `game-server-security` | 服务端权威、RPC、会话、复制、经济 |
| `dma-attack` | `dma-attack-techniques` | PCIe DMA、IOMMU、FPGA、主机中介采集 |
| `mobile-security` | `mobile-security` | Android/iOS 包、原生代码、平台完整性、证明 |
| `linux-platform-security` | `linux-platform-security` | ELF/进程证据、权限、命名空间、seccomp、LSM |
| `game-supply-chain-security` | `game-supply-chain-security` | 构建、启动器、更新、mod、签名、溯源 |
| `research-rigor` | `game-security-research-rigor` | 用一手来源与可复现证据验证有争议的结论 |

### 关于这些上游技能的三个须知

1. **它们是纯路由索引。** 上游仓库有一个 18.61 GB 的 `archive/` 目录，
   存放 2666 个作者仓库的正文快照。那个目录**没有**随本仓库分发（也不该
   分发）。所以技能里指向正文的路径在此处不可达，剩下的是分类框架、
   判断标准和外部链接。引用它们引用的是**方法论**，不是具体实现。

2. **收录不等于可信。** 上游 `AGENTS.md` 自己写的：
   "Collection membership is not an endorsement or proof of capability."
   清单里出现一个项目，不证明它可用、不证明它在你的版本上有效、
   更不证明它描述的机制是真的。用之前自己验证。

3. **它们和自研技能的分工。** 上游技能回答「这类问题该怎么想、该看哪里」；
   自研技能回答「在这台机器、这个 CE 版本上，什么做法真的会失败」。
   前者是地图，后者是雷区标记。**先看雷区。**

---

## 三、怎么安装这些技能

自研技能和上游技能格式一致（`SKILL.md` + 可选 `references/`），可直接放进
支持 Claude 风格技能的目录：

```powershell
# 项目级
Copy-Item skills\game-memory-hunting  .\your-project\.claude\skills\ -Recurse
Copy-Item skills\game-vision          .\your-project\.claude\skills\ -Recurse

# 用户级（所有项目可见）
Copy-Item skills\skills-vendor\*  $env:USERPROFILE\.claude\skills\ -Recurse
```

在 DSH harness 里对应的是 `%USERPROFILE%\.dsh\skills\`。装完不需要重启，
技能目录在会话内动态发现。

---

## 四、这套技能是怎么长出来的

不是设计出来的，是**被打出来然后沉淀**的：

```
跑通关 → 撞墙 → 记录撞墙原因 → 写进 SKILL.md 的一条铁律
```

具体的沉淀路径：

- 连续五轮 float 扫描落空 → 铁律 0（类型假设）
- 116k → 2k 那一步 → 铁律 1（`increased` 跨回满）
- 每次收窄都剩几百个且全不跟血条 → 铁律 2（实时读）
- 三个地址写进去被覆盖 → 铁律 3 / 5
- 「硬件断点不可用」被推翻 → 铁律 6
- `cmp dword [rax+0x24],0` 永不相等 → 铁律 7
- `Integrity check error` 冻结战斗 → 铁律 8
- 把血条宽度 188 当成血量 → 铁律 10

下一次遇到新墙，就再长一条。**技能文件是这份项目记忆的载体**，
对话可以丢，它不能丢。
