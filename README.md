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
| 凭据轮换 | `rotation prepare/deliver/issue_activation/activation_receipt/issue_trust/trust_receipt/route/inspect` | rotations、rotation_commands、key_trust_ledger、activation_ledger、routing_ledger、secret_envelopes、secret_activations | 密封信封是否匹配声明副本的当前设备代次、设备持钥/上游信任/流量路由三者在每个中断点是否共同成立、双键重叠或隔离证明、撤旧钥前的服务法定人数与最晚撤销时刻 |

`events` 保存每次请求的原始输入与决定。`report` 在新的内存数据库中按事件顺序重新执行所有命令，对照每个结果及九张状态表；返回 `consistent` 或列出分歧。业务拒绝也写入事件，因此报告能解释为什么某个目标、观察或修复没有生效。

## 正常、失败与跨系统样例

`fixtures/策略发布-normal.json` 展示不可改写的修订及回退新版本；失败样例展示缺少活跃依赖时的阻断。`fixtures/副本观察-normal.json` 展示私改、限时例外、到期后重新待修复；失败样例展示旧代次与迟到观察只存历史证据。`fixtures/修复执行-normal.json` 展示回执后仍待独立观察、观察确认后才收敛；失败样例展示旧代次回执暂停计划。

测试另外核对三条因果链：发布新版本让原先收敛的副本变成待修复；例外租约让同一差异暂时不入修复计划，到期后重新入计划；失败回执暂停后回退创建新策略修订，但不能把失败计划写成收敛。每条都断言真实数据库状态和事件重放结果。

## 凭据轮换：跨设备持钥、上游信任与流量路由的可恢复提交

`rotation_coordinator` 把临时的信封/激活账本升级为可执行轮换，围绕一次 `prepare` 授权（携带 `old_key_id`、`new_key_id`、`min_serving` 和 `revoke_deadline`，可选 `suspected_compromise`）协同三个实体，使它们在每个断电/中断点共同成立：

- **设备持钥**：`deliver` 只保存密封信封的材料摘要与所封设备代次，密钥正文从不入库；`issue_activation` 仅当信封所封代次等于副本当前代次、且信封确实密封给该副本时才发出 `sent` 命令，`activation_receipt` 校验通过后才把键身份追加进 `activation_ledger` 与 `secret_activations`。命令/回执分离保证“已发送”不等于“已生效”；失败回执把命令置 `failed`，重试沿同一命令 ID 和同一实物密钥身份（`resent`）继续。
- **上游信任**：`issue_trust`/`trust_receipt` 以同样的两段式提交维护只追加的 `key_trust_ledger`。新钥受信与旧钥仍受信之间形成可验证的双键重叠；旧钥一旦有 `revoke` 记录，晚到的激活回执无法重新打开它（包括离线副本携旧密封信封回来）。
- **流量路由**：只追加的 `routing_ledger` 记录每台副本 `serve`/`isolate` 的最新成员关系。每次路由变更都投影变更后的服务集合，保证持有上游认可密钥的健康副本不少于 `min_serving`；未持认可密钥的副本不能进入路由。撤旧钥前要求每个仍接流量的健康副本都持有认可密钥，并附 `overlap`、`ready_serving`、`isolated` 等可验证证明。

当 `suspected_compromise` 为真时，任何晚于 `revoke_deadline` 且旧钥仍受信的状态变更都被拒绝，过渡重叠不得超过授权的最晚撤销时刻。所有激活、信任变更、路由动作和吊销回执只追加、不可改写；事件重放（`report`）会重建全部轮换表并核对一致性。轮换激活后，`reconcile` 的健康预算按路由成员集合计算，并把 `sent` 未回执的激活命令冻结在可服务计数之外。

## 首版边界

本仓目前不处理跨集群策略层级继承、策略语义差异解释、Git 双向同步冲突、敏感配置轮换通道、自动修复风险预算、离线边缘节点回补、合规证据时间封卷、多租户策略委派与撤回。这些是产品后续范围，不代表已有实现。
