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

`events` 保存每次请求的原始输入与决定。`report` 在新的内存数据库中按事件顺序重新执行所有命令，对照每个结果及十三张状态表（含 `nodes`、`effective_targets`、`pins`、`health_samples`）；返回 `consistent` 或列出分歧。业务拒绝也写入事件，因此报告能解释为什么某个目标、观察或修复没有生效。

## 组织 → 集群 → namespace 的可验证继承

> 说明：首版 `policy.target()` 只按单个 `namespace + service` 从 active policies 取唯一候选，**它本身不支持继承**；该旧路径对单集群输入原样保留。层级能力是新增的独立合成路径，仅在输入显式带 `layer/node/cluster` 或该 namespace 已登记为层级节点时启用，因此旧 `edge` 单集群结果与旧 SQLite 事件库重放完全不变。

层级模型为 `org → cluster → namespace`（`policy node` / `policy topology` 登记与校验，拒绝环形父链和同层双 owner）。层级策略的修订 `value` 使用 JSON 对象；解析时从根到叶逐层合并，**近层只覆盖它明确给出的键**，未给出的键仍来自祖先。每个展开目标得到可复演身份：

- `values`：最终展开的键值；
- `digest = sha256(canonical(values))`：展开值摘要；
- `vector = {policy_id: active_revision}`：祖先及局部修订向量；
- `target_uid = T…`：由 `(digest, vector)` 决定的内容身份。

演练原件：组织策略 `p@1={tls:old,log:info}`，west 局部 `w@1={log:warn}`，每集群 3 副本、`min_healthy=2`。发布 `p@2`（仅 `tls=new`）后：

- east → `{tls:new,log:info}`，vector `{p:2}`；
- west → `{tls:new,log:warn}`，vector `{p:2,w:1}`（不会漏修 tls，也不会整包覆盖把 log 降成 info）。

```bash
python -m cloudctl demo --db route-a.sqlite --fixture fixtures/跨集群继承.json
python -m cloudctl demo --db route-b.sqlite --fixture fixtures/跨集群钉住.json
```

常用层级命令（均走统一幂等事件入口）：

| 目的 | 操作 |
| --- | --- |
| 登记/查看层级 | `policy node`（别名 `bind`）、`policy topology`（`verify`/`hierarchy`） |
| 发布组织/集群策略 | `policy create` 带 `layer:"org"|"cluster"|"namespace"` 与 `cluster`，其余 `draft/publish/rollback/retire` 不变 |
| 解析唯一目标 | `policy target`（别名 `resolve`）带 `cluster`/`namespace`/`service` |
| 签发/释放/撤销钉住 | `policy pin`、`policy release_pin`（别名 `unpin`）、`policy revoke_pin` |
| 集群健康证据/窗口 | `agent health`、`agent health_window` |
| 预算证明/维护窗 | `drift preflight`（`budget`/`guard`）、`drift schedule` |
| 关闭旧身份波次 | `drift supersede`（`cancel`/`abandon`） |

### 两条事前授权的发布路线

- **路线 A 动态继承**：`p@2` 发布即生效，两集群分别按本地目标身份生成计划。3 健康对 `min_healthy=2` 只有 1 个串行槽，故 3 副本排成 3 波；预算查询按集群隔离，east 的健康副本不能填 west 的下限。
- **路线 B 可撤销钉住**：先 `policy pin` 冻结 west 当前展开身份，再发 `p@2`：east 转 new，west 仍为 `{tls:old,log:warn}`。只有 west **本集群**的 `agent health` 样本连续满足 `min_healthy` 与 `window_minutes` 后，`release_pin` 才放行新目标计划；`revoke_pin` 可立即撤销。

### 展开身份贯穿 plan / action / receipt / observation / confirm

层级 `plans` 冻结 `target_uid/target_digest/revision_vector/target_values`；`actions` 在派发时写入同一身份与 `binding`（摘要+向量+副本代次的哈希）。

- `dispatch` 重新解析当前身份并与冻结身份逐字段比较；祖先任一键变化使 `target_uid` 改变后，即使局部 `w.active_revision` 仍是 `1`，旧计划的**新派发**也会被 `target identity changed` 阻断。
- 已派出的旧命令仍按旧身份受理：`receipt` 校验的是冻结的展开值摘要，新值回执判失败并暂停。
- 层级 `confirm` 用回执之后的**独立观察**去匹配该 action 冻结的摘要；旧回执/旧观察只能确认旧 `target_uid`，不能确认新目标。
- 旧身份剩余未派动作可用 `drift supersede` 标记 `obsolete`（行与证据保留，不删除），随后才能为新身份建计划。已派/`applied` 未结清的 action 会阻止 supersede，因为它们仍占用预算。

祖先退役只在“存在失去全部 owner 的键”时阻断（west 的 `log` 有局部覆写兜底，但 `tls` 与 east 两键会 ownerless）；局部覆写 `w` 退役是允许的，west 随即回落到组织 `log:info` 并产生 `policy_changed`。祖先回退照旧产生新修订号，配合完整 vector 形成新身份。

## 正常、失败与跨系统样例

`fixtures/策略发布-normal.json` 展示不可改写的修订及回退新版本；失败样例展示缺少活跃依赖时的阻断。`fixtures/副本观察-normal.json` 展示私改、限时例外、到期后重新待修复；失败样例展示旧代次与迟到观察只存历史证据。`fixtures/修复执行-normal.json` 展示回执后仍待独立观察、观察确认后才收敛；失败样例展示旧代次回执暂停计划。

测试另外核对三条因果链：发布新版本让原先收敛的副本变成待修复；例外租约让同一差异暂时不入修复计划，到期后重新入计划；失败回执暂停后回退创建新策略修订，但不能把失败计划写成收敛。每条都断言真实数据库状态和事件重放结果。

## 能力边界

跨集群组织层级继承、键级局部覆写、修订向量/展开摘要身份、可撤销钉住、集群本地可用性预算与身份切换状态迁移已在本版实现并由 `tests/test_hierarchy.py`（含祖先回退、局部退役、两层冲突、单集群故障与重放）覆盖。

仍不处理：策略语义差异解释、Git 双向同步冲突、敏感配置轮换通道、自动修复风险预算、离线边缘节点回补、合规证据时间封卷、多租户策略委派与撤回。层级合并目前是“显式键近层覆盖”的浅层 map 合并，不做嵌套结构深合并。
