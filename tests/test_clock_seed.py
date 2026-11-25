import sqlite3,unittest
from cloudctl.clock_capture import capture
from cloudctl.time_lease import issue
class ClockSeed(unittest.TestCase):
 def test_capture_changes_certificate(self):
  db=sqlite3.connect(':memory:');r=[{'source':'gps','local_tick':20,'reference_tick':22,'uncertainty':1}]
  self.assertEqual(capture(db,'p1',r),'captured');self.assertEqual(issue(db,'gps')['offset'],2)
  self.assertEqual(capture(db,'p1',r),'replayed')
  with self.assertRaises(ValueError):capture(db,'p1',[{**r[0],'reference_tick':23}])
