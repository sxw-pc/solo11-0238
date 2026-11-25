"""Build deterministic normal, failure and cross-subsystem event scenarios."""

import json
from pathlib import Path


HERE = Path(__file__).parent


def step(subsystem, operation, request_id, **payload):
    return {"subsystem": subsystem, "operation": operation,
            "request_id": request_id, "payload": payload}


def save(name, steps):
    (HERE / name).write_text(json.dumps({"name": name.removesuffix(".json"), "steps": steps},
                                      ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def foundation(prefix="base", value="safe", revision=1):
    return [
        step("policy", "create", f"{prefix}:create", policy_id="p1", namespace="edge",
             scope="api", owner="platform"),
        step("policy", "draft", f"{prefix}:draft", policy_id="p1", revision=revision,
             value=value, dependencies=[], at=1),
        step("policy", "publish", f"{prefix}:publish", policy_id="p1", revision=revision),
    ]


def replica(prefix="replica", replica_id="r1", value="old", revision=0, at=5):
    return [
        step("agent", "register", f"{prefix}:register", replica_id=replica_id, service="api",
             namespace="edge", generation=1, healthy=True),
        step("agent", "observe", f"{prefix}:observe", observation_id=f"{prefix}:obs",
             replica_id=replica_id, generation=1, observed_at=at, received_at=at + 1,
             policy_id="p1", revision=revision, value=value, origin="agent"),
    ]


save("策略发布-normal.json", foundation("pn") + [
    step("policy", "draft", "pn:draft2", policy_id="p1", revision=2,
         value="hardened", dependencies=[], at=10),
    step("policy", "publish", "pn:publish2", policy_id="p1", revision=2),
    step("policy", "rollback", "pn:rollback", policy_id="p1", source_revision=1, at=15),
])
save("策略发布-failure.json", [
    step("policy", "create", "pf:create", policy_id="p1", namespace="edge",
         scope="api", owner="team-a"),
    step("policy", "draft", "pf:draft", policy_id="p1", revision=1,
         value="safe", dependencies=["missing"], at=1),
    step("policy", "publish", "pf:blocked", policy_id="p1", revision=1),
    step("policy", "retire", "pf:retire", policy_id="p1", at=10),
])
save("副本观察-normal.json", foundation("an") + replica("an", value="manual", revision=1) + [
    step("agent", "exception", "an:exception", exception_id="ex1", replica_id="r1",
         policy_id="p1", approved_by="service-owner", expires_at=15, at=8,
         reason="emergency hotfix"),
    step("agent", "expire", "an:expire", at=16),
    step("agent", "observe", "an:fixed", observation_id="an:fixed-observation",
         replica_id="r1", generation=1, observed_at=17, received_at=18,
         policy_id="p1", revision=1, value="safe", origin="agent"),
])
save("副本观察-failure.json", foundation("af") + replica("af", at=9) + [
    step("agent", "register", "af:rebuild", replica_id="r1", service="api",
         namespace="edge", generation=2, healthy=True),
    step("agent", "observe", "af:oldgen", observation_id="af:oldgen-obs",
         replica_id="r1", generation=1, observed_at=20, received_at=21,
         policy_id="p1", revision=1, value="safe", origin="agent"),
    step("agent", "observe", "af:newgen", observation_id="af:newgen-obs",
         replica_id="r1", generation=2, observed_at=30, received_at=31,
         policy_id="p1", revision=0, value="old", origin="agent"),
    step("agent", "observe", "af:late", observation_id="af:late-obs",
         replica_id="r1", generation=2, observed_at=25, received_at=35,
         policy_id="p1", revision=1, value="safe", origin="agent"),
])

drift_base = foundation("dn") + replica("dn", at=5)
save("修复执行-normal.json", drift_base + [
    step("drift", "plan", "dn:plan", plan_id="fix1", policy_id="p1",
         service="api", min_healthy=0, at=10),
    step("drift", "dispatch", "dn:dispatch", action_id="fix1:r1"),
    step("drift", "receipt", "dn:receipt", receipt_id="rec1", action_id="fix1:r1",
         replica_id="r1", generation=1, revision=1, value="safe", at=11, success=True),
    step("drift", "confirm", "dn:premature", action_id="fix1:r1"),
    step("agent", "observe", "dn:observed", observation_id="dn:fixed",
         replica_id="r1", generation=1, observed_at=12, received_at=13,
         policy_id="p1", revision=1, value="safe", origin="agent"),
    step("drift", "confirm", "dn:confirm", action_id="fix1:r1"),
])
save("修复执行-failure.json", foundation("df") + replica("df") + [
    step("drift", "plan", "df:plan", plan_id="fix1", policy_id="p1",
         service="api", min_healthy=0, at=10),
    step("drift", "dispatch", "df:dispatch", action_id="fix1:r1"),
    step("drift", "receipt", "df:bad", receipt_id="bad1", action_id="fix1:r1",
         replica_id="r1", generation=0, revision=1, value="safe", at=11, success=True),
    step("drift", "dispatch", "df:retry", action_id="fix1:r1"),
])
save("demo.json", drift_base + [
    step("drift", "plan", "demo:plan", plan_id="fix1", policy_id="p1",
         service="api", min_healthy=0, at=10),
    step("drift", "dispatch", "demo:dispatch", action_id="fix1:r1"),
    step("drift", "receipt", "demo:receipt", receipt_id="rec1", action_id="fix1:r1",
         replica_id="r1", generation=1, revision=1, value="safe", at=11, success=True),
    step("agent", "observe", "demo:observed", observation_id="demo:fixed",
         replica_id="r1", generation=1, observed_at=12, received_at=13,
         policy_id="p1", revision=1, value="safe", origin="agent"),
    step("drift", "confirm", "demo:confirm", action_id="fix1:r1"),
])
save("路径-例外窗口.json", foundation("path-ex") + replica("path-ex", value="custom", revision=1) + [
    step("agent", "exception", "path-ex:grant", exception_id="ex1", replica_id="r1",
         policy_id="p1", approved_by="service-owner", expires_at=20, at=10,
         reason="approved operational deviation"),
    step("drift", "plan", "path-ex:skip", plan_id="during", policy_id="p1",
         service="api", min_healthy=0, at=11),
    step("agent", "expire", "path-ex:expire", at=20),
    step("drift", "plan", "path-ex:resume", plan_id="after", policy_id="p1",
         service="api", min_healthy=0, at=21),
])
save("路径-失败回退.json", foundation("path-rb") + replica("path-rb") + [
    step("policy", "draft", "path-rb:draft2", policy_id="p1", revision=2,
         value="strict", dependencies=[], at=7),
    step("policy", "publish", "path-rb:publish2", policy_id="p1", revision=2),
    step("drift", "plan", "path-rb:plan", plan_id="fix1", policy_id="p1",
         service="api", min_healthy=0, at=10),
    step("drift", "dispatch", "path-rb:dispatch", action_id="fix1:r1"),
    step("drift", "receipt", "path-rb:failed", receipt_id="failed1", action_id="fix1:r1",
         replica_id="r1", generation=1, revision=2, value="strict", at=11, success=False),
    step("drift", "rollback", "path-rb:rollback", plan_id="fix1", source_revision=1, at=12),
])
