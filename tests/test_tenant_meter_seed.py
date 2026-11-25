import sqlite3,unittest
from cloudctl.tenant_meter import capture
from cloudctl.tenant_charge import issue
class SeedTest(unittest.TestCase):
    def test_capture_changes_written_result(self):
        db=sqlite3.connect(':memory:')
        rows=[{'tenant':'x','units':2}]
        self.assertEqual(capture(db,'p1',rows),'captured')
        self.assertEqual(issue(db,'x')['metric'],2)
        self.assertEqual(capture(db,'p1',rows),'replayed')
        with self.assertRaises(ValueError):capture(db,'p1',[{'tenant':'x','units':3}])
