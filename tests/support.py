import itertools
import tempfile
import unittest
from pathlib import Path

import cloudctl
from cloudctl.audit import report
from cloudctl.db import connect, initialize, row, rows
from cloudctl.executor import execute

print(f"cloudctl.__file__={cloudctl.__file__}")


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dbfile = Path(self.temp.name) / "state.sqlite"
        self.db = connect(self.dbfile)
        initialize(self.db)
        self.numbers = itertools.count(1)
        self.assertTrue(Path(cloudctl.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1]))

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def do(self, subsystem, operation, **payload):
        return execute(self.db, subsystem, operation, payload,
                       f"test:{next(self.numbers)}:{subsystem}.{operation}")

    def policy(self, value="safe", revision=1, policy_id="p1", scope="api", namespace="edge",
               dependencies=None):
        self.do("policy", "create", policy_id=policy_id, scope=scope, namespace=namespace,
                owner="platform")
        self.do("policy", "draft", policy_id=policy_id, revision=revision, value=value,
                dependencies=dependencies or [], at=1)
        return self.do("policy", "publish", policy_id=policy_id, revision=revision)

    def replica(self, replica_id="r1", generation=1, revision=0, value="old", at=5,
                service="api", policy_id="p1", healthy=True):
        self.do("agent", "register", replica_id=replica_id, service=service,
                namespace="edge", generation=generation, healthy=healthy)
        return self.do("agent", "observe", observation_id=f"{replica_id}:{at}",
                       replica_id=replica_id, generation=generation, observed_at=at,
                       received_at=at + 1, policy_id=policy_id, revision=revision,
                       value=value, origin="agent")

    def audit(self):
        result = report(self.db)
        self.assertEqual(result["audit"], "consistent", result["mismatches"])
        return result
