import sqlite3,unittest
from cloudctl.power_sensor import capture
from cloudctl.rack_budget import issue
class SeedTest(unittest.TestCase):
    def test_capture_changes_written_result(self):
        db=sqlite3.connect(':memory:')
        rows=[{'rack':'x','watts':2}]
        self.assertEqual(capture(db,'p1',rows),'captured')
        self.assertEqual(issue(db,'x')['metric'],2)
        self.assertEqual(capture(db,'p1',rows),'replayed')
        with self.assertRaises(ValueError):capture(db,'p1',[{'rack':'x','watts':3}])
