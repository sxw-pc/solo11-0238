# 配置漂移收敛控制庭

面向私有云平台的离线配置控制面。它分别处理策略目标的发布、代理观察的可信度，以及修复命令的波次和确认。所有状态留在本地 SQLite；无需真实 Kubernetes 集群、外部凭据或网络服务。

## 运行

需要 Python 3.10+，只使用标准库。在仓库根目录执行：

```powershell
python fixtures/make.py
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db demo.sqlite
python -m unittest discover -s tests -v
```

`demo` 从 `fixtures/demo.json` 执行策略发布、副本观察、修复计划、执行回执和独立观察确认，并在最后重放全部事件核对数据库。重复演示可先删除 `demo.sqlite`（及可能存在的 WAL/SHM 文件），或改用新的数据库路径。

三个入口可以分别运行。`--fixture` 接受单次操作的 JSON，也接受含 `steps` 的完整场景；单次操作必须携带 `request_id` 或用 `--request-id`。例如：

```powershell
python -m cloudctl policy publish --db state.sqlite --input '{"policy_id":"p1","revision":1}' --request-id publish-p1-1
python -m cloudctl agent observe --db state.sqlite --fixture fixtures/副本观察-normal.json
python -m cloudctl drift plan --db state.sqlite --input '{"plan_id":"fix1","policy_id":"p1","service":"api","min_healthy":1,"at":20}' --request-id plan-fix1
python -m cloudctl report --db state.sqlite
```

入库设计审查中使用的三个场景入口也可直接执行：`python -m cloudctl policy publish --fixture fixtures/策略发布.json`、`python -m cloudctl agent observe --fixture fixtures/副本观察.json`、`python -m cloudctl drift reconcile --fixture fixtures/修复执行.json`。`reconcile` 是 `plan` 的命令别名；三个场景均在各自新数据库中运行。

命令输出 JSON。输入错误退出码 1，业务拒绝或暂停退出码 2，完成或待后续业务步骤退出码 0。示例 `publish` 需先有对应草案；单条命令的请求 ID 同输入重试幂等，不同输入复用同 ID 会报错。

## 三个子系统

| 子系统 | 独立入口 | 持久化对象 | 实际裁定 |
| --- | --- | --- | --- |
| 策略发布 | `policy create/draft/publish/rollback/retire` | policies、revisions、retirements | 依赖是否有效、作用域是否唯一、旧目标如何回退、仍有引用时能否退役 |
| 副本观察 | `agent register/observe/exception/expire/inspect` | inventories、observations、exceptions | 代理代次和事件时间是否可信、差异来自目标变化还是私改、例外期间是否仍需修复 |
| 修复执行 | `drift plan/dispatch/receipt/confirm/rollback/inspect` | plans、actions、receipts | 可用性预算允许哪些修复波次、回执能否受理、观察是否足以宣告收敛、失败后选择哪个目标 |

`events` 保存每次请求的原始输入与决定。`report` 在新的内存数据库中按事件顺序重新执行所有命令，对照每个结果及九张状态表；返回 `consistent` 或列出分歧。业务拒绝也写入事件，因此报告能解释为什么某个目标、观察或修复没有生效。

## 正常、失败与跨系统样例

`fixtures/策略发布-normal.json` 展示不可改写的修订及回退新版本；失败样例展示缺少活跃依赖时的阻断。`fixtures/副本观察-normal.json` 展示私改、限时例外、到期后重新待修复；失败样例展示旧代次与迟到观察只存历史证据。`fixtures/修复执行-normal.json` 展示回执后仍待独立观察、观察确认后才收敛；失败样例展示旧代次回执暂停计划。

测试另外核对三条因果链：发布新版本让原先收敛的副本变成待修复；例外租约让同一差异暂时不入修复计划，到期后重新入计划；失败回执暂停后回退创建新策略修订，但不能把失败计划写成收敛。每条都断言真实数据库状态和事件重放结果。

## 订单 WAL 故障切主与写入围栏

`wal_capture.capture` 与 `leader_lease.issue` 保持原契约不变（增强种子测试 `tests/test_wal_seed.py` 仍要求 a/2/7 被写成候选主节点）。但最大任期租约只是**候选证据**，不能证明已确认前缀完整，也不能隔离旧主。新增模块把“前缀—围栏—开放写入”做成同一条可恢复决定：

| 模块 | 职责 |
| --- | --- |
| `cloudctl/wal_chain.py` | 带物理节点、启动代次、`prev_digest`、签收者与 HMAC 签名的链式 WAL 页；同位置摘要冲突检测；以客户端 ACK 回执 + 见证链为准的前缀修复（高任期不得覆盖异摘要） |
| `cloudctl/wal_capture.py` / `wal_rich.py` | 原 `capture` 五字段契约逐字保留；`capture_rich` 采录/校验富签名页 |
| `cloudctl/fence.py` | 钟差感知的租约受理、旧主围栏回执、租约关闭回执、独立网关阻断/关闭证明与全路径覆盖判定 |
| `cloudctl/cluster.py` | SQLite 持久化的可执行模拟：节点钟差/启动代次/围栏高水位、真正拦截写入的网关与客户端入口路径、围栏 RPC（可丢请求/丢 ACK）、实时可达写入者扫描 |
| `cloudctl/failover.py` | `fo_decisions` 状态机（`INIT→PREFIX_READY→FENCE_READY→OPEN`）、不可改原始 WAL 页/证据表、单例主节点行、原子 `commit_open`（同事务翻转路由并校验可达集合恰为新主）、幂等客户端 `OrderClient` |
| `cloudctl/drill.py` | A/B/W、x11/y11、本地 30/真实 34、任期票 29 的演练原件；两套可重入恢复预案 `run_plan_b` / `run_plan_a`、重启续跑 `resume_decision`、朴素最大任期双写窗口负证据 |

关键不变量（均由 `tests/test_tx_prefix.py`、`tests/test_network_fence.py`、`tests/test_client_retry.py`、`tests/test_failover_recovery.py` 实际执行断言）：

- 收到成功回执的事务必在新主与复制链上；同 index 异 digest 记为 `LogConflict`，B 的任期 4/y11 不能覆盖 ACK 的 x11，只能作为冲突原件隔离保留。
- 新主 OPEN 前必须拿到旧主任期 5 围栏回执，**或**旧主全部客户端入口路径的独立签名网关阻断证明；控制庭里的新租约行不满足任何一项。
- A 本地钟慢 4：真实时刻 29–34 其任期 3 租约仍受理；朴素“`issue(B)` + 切流量”会在 29–34 扫出 `[A, B]` 两个可达写入者，安全预案在开放前先完成物理围栏，任何时刻可达写入者不超过一个。
- 复制项与客户端回执绑定同一任期和同一提交前缀（`term=5,prefix_index=11,prefix_digest=x11`）。
- 围栏后、OPEN 前崩溃：重开库后决定停在 `FENCE_READY`、单例主节点行为空、可达写入者为 `[]`，续跑后恰有一个主；两边原始 WAL 页（含 y11）、隔离件和决定事件都保留。W 的 x11 可在重启后迟到；围栏 ACK 丢失可幂等重试；客户端在停写窗的重试得到可重试错误，OPEN 后同一 `request_id` 恰好生效一次，ACK 丢失重启后返回同一回执且不重复落盘。
- 预案 B：全网关隔离 A → 废弃/隔离 y11 → W 补 x11 → B 任期 5 开放并承接 B→W 复制，A 待重同步。预案 A：先阻断 B 分区写入 → A 与 W 校验 x11 后进入任期 5 但暂停写入 → 同时取得 B 旧租约关闭回执与网关关闭证明 → A 恢复，y11 原样留在 B。两者零已确认事务丢失、始终至多一个可达写入主，但主节点、复制方向与停写窗口不同。

运行可执行证据报告（打印朴素双写窗口与两套预案结果）：

```bash
python -m cloudctl.drill
```

## 首版边界

本仓目前不处理跨集群策略层级继承、策略语义差异解释、Git 双向同步冲突、敏感配置轮换通道、自动修复风险预算、离线边缘节点回补、合规证据时间封卷、多租户策略委派与撤回。这些是产品后续范围，不代表已有实现。
