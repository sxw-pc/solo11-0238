import sqlite3,unittest
from cloudctl.object_scan import capture
from cloudctl.object_replicate import issue
class SeedTest(unittest.TestCase):
    def test_capture_changes_written_result(self):
        db=sqlite3.connect(':memory:')
        rows=[{'bucket':'x','shards':2}]
        self.assertEqual(capture(db,'p1',rows),'captured')
        self.assertEqual(issue(db,'x')['metric'],2)
        self.assertEqual(capture(db,'p1',rows),'replayed')
        with self.assertRaises(ValueError):capture(db,'p1',[{'bucket':'x','shards':3}])
