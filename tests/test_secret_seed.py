import sqlite3,unittest
from cloudctl.secret_bundle import capture
from cloudctl.secret_activation import activate
class SecretSeedTest(unittest.TestCase):
    def test_envelope_changes_actual_activation(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(capture(db,'e1','a','k2','sealed-key-2'),'captured')
        self.assertEqual(activate(db,'a')['key_id'],'k2')
        self.assertEqual(capture(db,'e1','a','k2','sealed-key-2'),'replayed')
        with self.assertRaises(ValueError):capture(db,'e1','a','k3','different')
