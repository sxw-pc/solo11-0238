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
| 镜像来源 | `image build/origin/layer_evidence/retract_evidence/layer_finding/key/revoke_key/scanner_rule/scan` | image_builds、image_build_layers、image_layers、image_layer_evidence、image_origins、image_signing_keys、image_scanner_rules、image_scans | 构建单是否绑定源码提交、环境摘要、基础层、产物层哈希与签署密钥代次；每条相容层路径是否都止于可信来源 |
| 生产许可与命令 | `permit license/order/retag` | image_permits、image_orders、image_tag_history | 许可是否在全部相容层来源下成立、全层扫描与签名是否覆盖最终摘要、撤签或新规则只追加停发/召回/补签命令 |
| 节点切换 | `rollout register_node/rollout/switch/probe/confirm/rollback/retire/inspect` | image_nodes、image_rollouts、image_rollout_nodes、image_node_probes | 仓库可发布与节点实际运行分别记账、波次健康下限、独立探测确认切换与退出、重启后同一请求不重复下发 |

`events` 保存每次请求的原始输入与决定。`report` 在新的内存数据库中按事件顺序重新执行所有命令，对照每个结果及九张状态表；返回 `consistent` 或列出分歧。业务拒绝也写入事件，因此报告能解释为什么某个目标、观察或修复没有生效。

## 正常、失败与跨系统样例

`fixtures/策略发布-normal.json` 展示不可改写的修订及回退新版本；失败样例展示缺少活跃依赖时的阻断。`fixtures/副本观察-normal.json` 展示私改、限时例外、到期后重新待修复；失败样例展示旧代次与迟到观察只存历史证据。`fixtures/修复执行-normal.json` 展示回执后仍待独立观察、观察确认后才收敛；失败样例展示旧代次回执暂停计划。

测试另外核对三条因果链：发布新版本让原先收敛的副本变成待修复；例外租约让同一差异暂时不入修复计划，到期后重新入计划；失败回执暂停后回退创建新策略修订，但不能把失败计划写成收敛。每条都断言真实数据库状态和事件重放结果。

## 镜像供应链：来源图、生产许可与节点切换

`image_attest.capture` 与 `image_promote.promote` 保留首版离线采集与临时发布接口；正式控制面由三个新子系统承担，三者各管一份证据，不能互相代替：

1. **来源图（`image` 子系统）**：构建单带源码提交、构建环境摘要、基础层列表、产物层哈希、签署密钥代次和扫描器数据版本；层证据把每个层哈希连到物理上游层和为其背书的来源，来源可标记可信或撤证，证据可撤回但撤回本身留痕。同一标签可指向不同摘要，不同构建号也可能复用同一受污染基础层——这些都是图里的显式事实。
2. **生产许可（`permit` 子系统）**：许可沿整条层依赖遍历**每一条**相容路径，任一路径止于不可信来源、命中裁定时刻已生效的扫描规则、签署密钥代次已撤销，或缺覆盖最终摘要的全层扫描，都只能得到不可改写的 `blocked` 记录；只有全部相容来源都干净才签发 `permitted`。迟到的构建证明在基础层证据到达前保持阻断，后来补到的漏洞规则或撤销的密钥不倒改旧许可，只允许追加 `stop`/`recall`/`resign` 命令和新的许可裁定。
3. **节点切换（`rollout` 子系统）**：仓库标签改指（`permit retag`）与节点实际运行清单分表维护。切换按健康下限分波，下发是自然键幂等的，重启重放同一请求只会读回 `dispatched`/`switched`，不会二次下发；切换与回退都必须有节点自身证据加独立探测确认；旧镜像退役要求每台节点在请求时刻之后有独立缺席探测，标签移动不算退出。

演练场景（`tests/test_image_supply_chain.py`）在同一输入下证明：b2/d2 因 L0/L1 双上游证据且只有顶层扫描而不可发布，b1/d1 凭完整 Lold 链继续可服务；并落地两条已批准替代路线——用可复核 L1 源重建 b3/d3 后逐台切换再撤 b1，以及在 b1 上单独获签最小补层形成 b1h/d1h 分波替换。另覆盖切换中撤签冻结后续波次、新扫描规则不追溯旧许可、以及全部事件重放与 14 张新状态表的一致性。


## 首版边界

本仓目前不处理跨集群策略层级继承、策略语义差异解释、Git 双向同步冲突、敏感配置轮换通道、自动修复风险预算、离线边缘节点回补、合规证据时间封卷、多租户策略委派与撤回。这些是产品后续范围，不代表已有实现。
