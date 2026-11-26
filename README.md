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

## 物理链路与切流协议

`capacity_probe.capture` / `failover_reserve.issue` 的原始种子契约保持不变；前者仍保存 `{node,capacity}` 探测页和 SHA-256 摘要，后者仍生成原来的 `failover_orders` 结果。跨入口物理接管由两个新模块负责：

- `physical_topology.py`（同时提供 `topology.py`、`failover_topology.py` 等导入别名）：故障域、节点/物理资源、端口别名、物理链路等价关系、相容拓扑假设、链路探测原件，以及“所有相容映射均可行”的容量校验。
- `traffic_switch.py`（同时提供 `traffic_failover.py`、`traffic_takeover.py`、`switchover.py`、`failover.py` 等别名）：计划、两阶段容量预留、带代次和全局顺序的预留/撤销命令、控制器回执、独立探测确认、客户实际链路视图、实物容量占用和只追加 SLA 凭证。

核心约束直接落在 SQLite 状态中：

1. 路由按入口、出口和每个中间物理资源逐段计量；同一物理链路的端口别名或等价观测只对应一条预留。
2. 计划必须在全部未排除的拓扑假设中可行。甲（`N1/N2` 共享 6 单位上游）会拒绝 `A=5+B=3` 同时切 `N1/N2`；乙（`U1=6,U2=4` 独立）在端到端测试确认后允许该方案。
3. 已存在的预留会与新路由合并计算，因此先安全接管 `A→N1`、之后才收到“共纤”标签时，`A` 仍合法，而 `B→N2` 会被同一本实物账拒绝；`B` 可继续使用独立计量、延迟增加 20ms 的应急代理。
4. 同一故障域的备用节点或共享上游不能作为独立冗余；`require_independent=True` 会要求路径在所有相容映射中均无共享物理资源/故障域（共同核心出口除外，但其容量仍受校验）。
5. 控制器 ACK 只把命令推进到 `written`/`revoke_written`；只有独立探测通过后，客户链路才是 `taken_over`。旧代次 ACK/探测只存证据，不改变当前状态；重复 ACK/探测不产生第二条容量。
6. 所有状态都在 SQLite。关闭重开后可继续接收回执/探测并恢复同一账本；部分成功时失败命令保留为 `failed` 且释放其预留，已确认的另一条连接和旧 SLA 凭证仍可审计。

演练原件可由 `cloudctl.drill.build_drill(db)` 一键构造，包含 `E/A/B/N1/N2/PROXY-B`、两页端口探测、甲乙两个拓扑假设以及 E 上的旧 SLA 连接。测试 `tests/test_traffic_failover.py` 覆盖两条授权恢复路线、共纤晚到标签、旧撤销 ACK 晚到、部分命令成功、断电重开和审计重放。

## 首版边界

本仓目前不处理跨集群策略层级继承、策略语义差异解释、Git 双向同步冲突、敏感配置轮换通道、自动修复风险预算、离线边缘节点回补、合规证据时间封卷、多租户策略委派与撤回。这些是产品后续范围，不代表已有实现。
