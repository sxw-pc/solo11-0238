import sqlite3,unittest
from cloudctl.wal_capture import capture
from cloudctl.leader_lease import issue
class WalSeed(unittest.TestCase):
 def test_capture_changes_leader_record(self):
  db=sqlite3.connect(':memory:');r=[{'node':'a','term':2,'index':7,'digest':'d7','ack':True}]
  self.assertEqual(capture(db,'p1',r),'captured');self.assertEqual(issue(db,'a')['index'],7)
  self.assertEqual(capture(db,'p1',r),'replayed')
  with self.assertRaises(ValueError):capture(db,'p1',[{**r[0],'index':8}])
