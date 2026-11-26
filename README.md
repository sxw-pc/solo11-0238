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

## 电气限额、拓扑与热窗口（power）

`power_sensor.py` 在原有摘要页 `capture(db,page,rows)` 之外，保留每张钳表纸的设备编号、共享互感器倍率、采样起止、校时票、相位与接线照片，并登记 PDU 相位上限、冷却支路（容量/最低冷却量/热惯性）和 UPS 放电窗口。`calibrate_device` 的一次共享倍率校准会统一重算该设备的全部读数。

`power_topology.py`（实现于 `power_core.py`）按测点包含关系去重：PDU 输入钳表已包含同一支路下游钳表的能量，因此 A 排是 **7 kW 而不是两页相加的 10 kW**；互不为祖先的支路根读数才相加。`common_clock_range` 用校时票偏移求共同采样范围，`evaluate`/`evaluate_options` 给出每个方案在整段分钟窗口内的进线/PDU/相位峰值与温度轨迹，并守住 12 kW 进线、相位上限、最低冷却量与最少健康主机。

典型裁定（18:00 起，分钟为相对时间）：

| 方案 | 进线峰值 | A/B PDU 限额 (W) | 关键命令 |
| --- | --- | --- | --- |
| 不动作（含 18:10–18:20 UPS +2 kW） | 13 kW，超限 | — | 被进线限额阻断 |
| `migrate`：迁 2 kW 批机 A→B，B 在放电前停 2 kW 非关键 | 11 kW | A=5000 / B=6000 | 迁机+重排、停非关键、保留加速器、确认 UPS 窗口 |
| `shed`：A 关 2 kW 加速器，UPS 校验推迟到低谷 | 9 kW | A=5000 / B=4000 | 关加速器、推迟 UPS、批作业不变 |

8 分钟热惯性意味着 UPS 18:10 窗口前的关载最晚须在 18:02 生效；18:00 下发来得及，拖到 18:10 才关载会因 `thermal_timing` 被判不可行。

`rack_budget.py` 的原 `issue(db,subject)` 与两瓦种子行为不变；`issue_order` 写出不可改写的签署限额与递增代次，`controller_receipt` 成功只表示“限额已写入”，必须再有更晚的独立功率与温度采样并经 `confirm_stable` 才宣布 `stable`。`recover` 保留原限额并给出新的命令代次，调度/削减命令用幂等键保证断电恢复或异终端重试不会多削减一次主机负载；`next_safe_command` 处理部分失败与迟到校准（原令保留，另给下一条安全命令）。这些操作也接入统一执行器，可用 `self.do("power", "<op>", ...)` 调用并通过 `audit.report` 复演。

## 首版边界

本仓目前不处理跨集群策略层级继承、策略语义差异解释、Git 双向同步冲突、敏感配置轮换通道、自动修复风险预算、离线边缘节点回补、合规证据时间封卷、多租户策略委派与撤回。这些是产品后续范围，不代表已有实现。
