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

## 首版边界

本仓目前不处理跨集群策略层级继承、策略语义差异解释、Git 双向同步冲突、敏感配置轮换通道、自动修复风险预算、离线边缘节点回补、多租户策略委派与撤回。这些是产品后续范围，不代表已有实现。

## 合规时间封卷与选择性披露

`compliance_capture.py` 固定保存 `{service,at}` 原件页与摘要；`compliance_seal.py` 在其上构建可复查的时间封卷，`verifier.py` 是不依赖平台数据库的本地独立验证器。

- **因果闭包而非按 id/到达时间截断**：`seal window` 封存业务时间落在 `[start,end)` 的事件，并沿 `policy_id/replica_id/action_id/plan_id/dependencies` 引用做 BFS，把窗前草案、计划、派发等最小前置证明一并纳入。签卷时已知的事件前缀（`prefix_event_id`）显式落库。
- **迟到证据只入附卷**：窗内采样、签卷后才入库的事件（如分钟 29 采样、41 入库）由 `seal attach` 绑定为独立附卷，附卷用锚点叶子回指原封卷根，原封卷的根摘要、窗口成员与命题永不改写。
- **原件承诺与按权限证明**：所有叶子进入 Merkle 清单，根只取决于 `(key,digest)`。事件叶子对敏感字段使用占位承诺，监管员拿到明文并可逐字段核对值承诺，客户只拿到脱敏叶子与包含/不包含证明，双方复现**同一个根**；“按角色删字段再重新哈希”会因摘要不符被验证器拒绝。
- **命题分离、不伪造收敛**：`receipt_applied_only`（仅回执）与 `independently_confirmed`（回执加后续独立观察）是不同命题；签卷时新观察未到，只出具 applied 并附确认断言的不包含证明。`reconcile.action_claims` 按证据前缀裁定，前缀外的确认不会被回溯。
- **撤销与追补**：`seal revoke` 撤销见证密钥并签发撤销凭证，旧证书留档；`seal supplement` 针对附卷签发收敛升级凭证，客户补卷只含脱敏命题。
- **健壮性**：同一 `(service,window)` 有唯一封卷身份，双人并发与崩溃重试都返回同一身份；重复页面幂等、同页冲突拒绝；`seal archive` 压缩叶子正文后清单根不变，已发出的证书仍可独立验证。`seal audit` 重放事件前缀并核对所有承诺，删行或改写会报 `diverged` 而不是误报 `consistent`。

```powershell
python -m cloudctl seal window  --db state.sqlite --input '{"service":"a","start":20,"end":30,"at":35}'
python -m cloudctl seal attach  --db state.sqlite --input '{"seal_id":"seal:...","at":41}'
python -m cloudctl seal certify --db state.sqlite --input '{"seal_id":"seal:...","audience":"cust","role":"customer"}'
python -m cloudctl seal audit   --db state.sqlite
python -m cloudctl verify --bundle cert.json --key <issuer-hex>
```
