import sqlite3,unittest
from cloudctl import image_attest,image_promote,retention_capture,delete_gate,gpu_trace,gpu_admit
class InfraSeed(unittest.TestCase):
 def test_image(self):
  db=sqlite3.connect(':memory:');r=[{'image':'api','build':'b2','builder':'ci','digest':'d2'}]
  self.assertEqual(image_attest.capture(db,'p1',r),'captured');self.assertEqual(image_promote.promote(db,'api')['build'],'b2')
 def test_retention(self):
  db=sqlite3.connect(':memory:');r=[{'object':'o1','expires':20,'hold':False}]
  self.assertEqual(retention_capture.capture(db,'n1',r),'captured');self.assertEqual(delete_gate.issue(db,'o1',21)['object_id'],'o1')
 def test_gpu(self):
  db=sqlite3.connect(':memory:');r=[{'device':'g1','memory':40,'slices':2}]
  self.assertEqual(gpu_trace.capture(db,'p1',r),'captured');self.assertEqual(gpu_admit.issue(db,'g1')['slices'],2)
