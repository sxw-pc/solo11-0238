import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudctl import host_counter, supplier_settlement, tenant_charge, tenant_meter

PERIOD = '2026-11'

C1 = [{'host': 'h1', 'boot': 0, 'at': 0, 'counter': 1000, 'multiplier': 1},
      {'host': 'h1', 'boot': 0, 'at': 30, 'counter': 1800, 'multiplier': 1}]
C2 = [{'host': 'h1', 'boot': 0, 'at': 30, 'counter': 1800, 'multiplier': 1},
      {'host': 'h1', 'boot': 0, 'at': 60, 'counter': 2600, 'multiplier': 1}]
M1 = [{'id': 'a-boot', 'host': 'h1', 'seconds': 600, 'candidates': ['A']},
      {'id': 'b-boot', 'host': 'h1', 'seconds': 600, 'candidates': ['B']},
      {'id': 'pid7-reuse', 'host': 'h1', 'seconds': 400, 'candidates': ['A', 'B']}]
R1 = [{'slice': 'pid7-reuse', 'tenant': 'A', 'inode': 'ns/4021', 'signature': 'sched-dual-sig-7'}]


def counter(host, boot, at, value, multiplier=1, slice_id=0):
    return {'host': host, 'boot': boot, 'at': at, 'counter': value,
            'multiplier': multiplier, 'slice': slice_id}


def drill_evidence(db):
    """Host h1 counter 1000..2600 = 1600 CPU seconds; a PID reuse leaves 400
    seconds disputed between tenants A and B (readings 甲 A=1000/B=600 and
    乙 A=600/B=1000, both conserving the host total 1600)."""
    return [host_counter.capture(db, 'c1', C1),
            host_counter.capture(db, 'c2', C2),
            tenant_meter.capture_originals(db, 'm1', M1)]


class CounterTest(unittest.TestCase):
    def test_cross_page_boundary_counts_once(self):
        db = sqlite3.connect(':memory:')
        self.assertEqual(drill_evidence(db), ['captured'] * 3)
        self.assertEqual(host_counter.cpu_seconds(db, 'h1'), 1600)

    def test_boot_reset_multiplier_and_migration_slice(self):
        db = sqlite3.connect(':memory:')
        host_counter.capture(db, 'p1', [
            counter('h1', 0, 0, 500), counter('h1', 0, 10, 900),    # 400 before reboot
            counter('h1', 1, 20, 100), counter('h1', 1, 30, 300)])  # 200 after reset to zero
        self.assertEqual(host_counter.cpu_seconds(db, 'h1'), 600)
        host_counter.capture(db, 'p2', [counter('h2', 0, 0, 100, multiplier=2),
                                        counter('h2', 0, 10, 200, multiplier=2)])
        self.assertEqual(host_counter.cpu_seconds(db, 'h2'), 200)
        host_counter.capture(db, 'p3', [
            counter('h3', 0, 0, 0, slice_id=0), counter('h3', 0, 10, 100, slice_id=0),
            counter('h3', 0, 10, 0, slice_id=1), counter('h3', 0, 20, 50, slice_id=1)])
        self.assertEqual(host_counter.cpu_seconds(db, 'h3'), 150)  # per-slice restart is not a regression

    def test_counter_regression_rejected(self):
        db = sqlite3.connect(':memory:')
        host_counter.capture(db, 'p1', [counter('h1', 0, 0, 100), counter('h1', 0, 10, 50)])
        with self.assertRaises(ValueError):
            host_counter.cpu_seconds(db, 'h1')

    def test_conflicting_boundary_point_rejected(self):
        db = sqlite3.connect(':memory:')
        host_counter.capture(db, 'p1', [counter('h1', 0, 0, 100), counter('h1', 0, 10, 200)])
        host_counter.capture(db, 'p2', [counter('h1', 0, 10, 250), counter('h1', 0, 20, 400)])
        with self.assertRaises(ValueError):
            host_counter.cpu_seconds(db, 'h1')

    def test_capture_validation_and_replay(self):
        db = sqlite3.connect(':memory:')
        samples = [counter('h1', 0, 0, 100)]
        self.assertEqual(host_counter.capture(db, 'p1', samples), 'captured')
        self.assertEqual(host_counter.capture(db, 'p1', samples), 'replayed')
        with self.assertRaises(ValueError):
            host_counter.capture(db, 'p1', [counter('h1', 0, 0, 101)])
        with self.assertRaises(ValueError):
            host_counter.capture(db, 'p2', [{'host': 'h1', 'boot': 0, 'at': 0}])


class DrillTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        drill_evidence(self.db)

    def test_two_compatible_readings_conserve_physical_total(self):
        readings = tenant_meter.interpretations(self.db)
        self.assertEqual(len(readings), 2)
        self.assertIn({'A': 1000, 'B': 600}, readings)   # 甲
        self.assertIn({'A': 600, 'B': 1000}, readings)   # 乙
        for reading in readings:
            self.assertEqual(sum(reading.values()), 1600)  # 同一主机总量守恒
        self.assertEqual(tenant_meter.proven(self.db), {'A': 600, 'B': 600})
        for tenant, bound in tenant_meter.proven(self.db).items():
            self.assertEqual(bound, min(r.get(tenant, 0) for r in readings))
        self.assertEqual(tenant_meter.common_total(self.db), 1600)
        self.assertEqual(tenant_meter.verified_usage(self.db), {'h1': 1600})

    def test_disputed_seconds_billed_to_nobody(self):
        # 不明归属不按最后标签或平均数开票：两户各只计有证下界 600，不是 800/800
        a = tenant_charge.invoice(self.db, 'A', PERIOD)
        b = tenant_charge.invoice(self.db, 'B', PERIOD)
        self.assertEqual((a['event'], a['proven'], a['billed']), ('issued', 600, 600))
        self.assertEqual((b['event'], b['proven'], b['billed']), ('issued', 600, 600))
        self.assertEqual(a['status'], 'payable')   # 达到合同最低 600
        self.assertEqual(b['status'], 'payable')

    def test_supplier_pays_full_physical_and_carries_difference(self):
        tenant_charge.invoice(self.db, 'A', PERIOD)
        tenant_charge.invoice(self.db, 'B', PERIOD)
        result = supplier_settlement.settle(self.db, PERIOD)
        self.assertEqual((result['event'], result['physical'], result['paid']),
                         ('payment', 1600, 1600))          # 不得因归属待核少结成 1200
        self.assertEqual(result['unallocated'], 400)       # 未分清的 400 记入待分配差额
        again = supplier_settlement.settle(self.db, PERIOD)
        self.assertEqual((again['event'], again['paid']), ('unchanged', 1600))

    def test_resolution_appends_recovery_without_rewriting(self):
        tenant_charge.invoice(self.db, 'A', PERIOD)
        tenant_charge.invoice(self.db, 'B', PERIOD)
        supplier_settlement.settle(self.db, PERIOD)
        before_invoices = self.db.execute('SELECT * FROM tenant_invoices ORDER BY seq').fetchall()
        before_payments = self.db.execute('SELECT * FROM supplier_settlements ORDER BY seq').fetchall()
        # 补到容器命名空间 inode 与调度迁移双签，确定解释甲：400 秒归 A
        self.assertEqual(tenant_meter.resolve(self.db, 'r1', R1), 'captured')
        self.assertEqual(tenant_meter.proven(self.db), {'A': 1000, 'B': 600})
        a = tenant_charge.invoice(self.db, 'A', PERIOD)
        self.assertEqual((a['event'], a['delta'], a['billed']), ('recovery', 400, 1000))  # 向 A 追收 400
        b = tenant_charge.invoice(self.db, 'B', PERIOD)
        self.assertEqual((b['event'], b['billed']), ('unchanged', 600))                   # B 原 600 不变
        settled = supplier_settlement.settle(self.db, PERIOD)
        self.assertEqual((settled['event'], settled['paid'], settled['unallocated']),
                         ('adjustment', 1600, 0))
        # 旧凭证未被改写，只追加事件；平台已付 1600 不重复付款
        after_invoices = self.db.execute('SELECT * FROM tenant_invoices ORDER BY seq').fetchall()
        after_payments = self.db.execute('SELECT * FROM supplier_settlements ORDER BY seq').fetchall()
        self.assertEqual(after_invoices[:len(before_invoices)], before_invoices)
        self.assertEqual(after_payments[:len(before_payments)], before_payments)
        self.assertEqual(self.db.execute('SELECT COALESCE(SUM(paid),0) FROM supplier_settlements'
                                         ).fetchone()[0], 1600)
        report = supplier_settlement.reconcile(self.db, PERIOD)
        self.assertTrue(report['reconciled'], report)
        self.assertEqual(report['tenants']['A'], {'billed': 1000, 'events': ['issued', 'recovery'],
                                                  'proven': 1000})
        self.assertEqual(report['tenants']['B']['billed'], 600)
        self.assertEqual(report['supplier'], {'paid': 1600, 'events': ['payment', 'adjustment']})
        self.assertEqual(report['unallocated'], 0)

    def test_reconcile_before_resolution(self):
        tenant_charge.invoice(self.db, 'A', PERIOD)
        tenant_charge.invoice(self.db, 'B', PERIOD)
        supplier_settlement.settle(self.db, PERIOD)
        report = supplier_settlement.reconcile(self.db, PERIOD)
        self.assertTrue(report['reconciled'], report)
        self.assertTrue(report['conserved'])
        self.assertTrue(report['tenants_not_overbilled'])
        self.assertEqual(report['physical_total'], 1600)
        self.assertEqual(report['allocated'], 1200)
        self.assertEqual(report['unallocated'], 400)
        self.assertEqual(report['supplier']['paid'], 1600)


class MinimumTest(unittest.TestCase):
    def seed(self, db):
        host_counter.capture(db, 'c1', [counter('h2', 0, 0, 0), counter('h2', 0, 10, 700)])
        tenant_meter.capture_originals(db, 'm1', [
            {'id': 'c-run', 'host': 'h2', 'seconds': 500, 'candidates': ['C']},
            {'id': 'd-run', 'host': 'h2', 'seconds': 200, 'candidates': ['D']}])

    def test_below_minimum_not_payable_until_proven(self):
        db = sqlite3.connect(':memory:')
        self.seed(db)
        low = tenant_charge.invoice(db, 'C', PERIOD)
        self.assertEqual((low['event'], low['billed'], low['status']), ('issued', 0, 'below_minimum'))
        self.assertEqual(tenant_charge.invoice(db, 'D', PERIOD)['status'], 'below_minimum')
        # 后证据把 C 推过合同最低 600：整额形成应付
        host_counter.capture(db, 'c2', [counter('h2', 0, 10, 700), counter('h2', 0, 20, 900)])
        tenant_meter.capture_originals(db, 'm2', [
            {'id': 'c-more', 'host': 'h2', 'seconds': 200, 'candidates': ['C']}])
        up = tenant_charge.invoice(db, 'C', PERIOD)
        self.assertEqual((up['event'], up['proven'], up['billed']), ('recovery', 700, 700))
        still_low = tenant_charge.invoice(db, 'D', PERIOD)
        self.assertEqual((still_low['event'], still_low['billed']), ('unchanged', 0))

    def test_supplier_pays_only_physical_delta_on_growth(self):
        db = sqlite3.connect(':memory:')
        self.seed(db)
        first = supplier_settlement.settle(db, PERIOD)
        self.assertEqual((first['paid'], first['unallocated']), (700, 0))
        host_counter.capture(db, 'c2', [counter('h2', 0, 10, 700), counter('h2', 0, 20, 900)])
        tenant_meter.capture_originals(db, 'm2', [
            {'id': 'c-more', 'host': 'h2', 'seconds': 200, 'candidates': ['C']}])
        second = supplier_settlement.settle(db, PERIOD)
        self.assertEqual((second['event'], second['paid']), ('payment', 900))
        self.assertEqual(db.execute('SELECT COALESCE(SUM(paid),0) FROM supplier_settlements'
                                    ).fetchone()[0], 900)


class ConsistencyTest(unittest.TestCase):
    def test_slices_without_counters_cannot_settle(self):
        db = sqlite3.connect(':memory:')
        tenant_meter.capture_originals(db, 'm1', [
            {'id': 'a-run', 'host': 'ghost', 'seconds': 600, 'candidates': ['A']}])
        with self.assertRaises(ValueError):
            tenant_meter.verified_usage(db)
        with self.assertRaises(ValueError):
            tenant_charge.invoice(db, 'A', PERIOD)
        with self.assertRaises(ValueError):
            supplier_settlement.settle(db, PERIOD)

    def test_slices_must_reconcile_with_counters(self):
        db = sqlite3.connect(':memory:')
        host_counter.capture(db, 'c1', [counter('h1', 0, 0, 0), counter('h1', 0, 10, 1600)])
        tenant_meter.capture_originals(db, 'm1', [
            {'id': 'a-run', 'host': 'h1', 'seconds': 900, 'candidates': ['A']}])
        with self.assertRaises(ValueError):
            tenant_meter.verified_usage(db)


class EvidenceTest(unittest.TestCase):
    def test_originals_validation_replay_and_id_uniqueness(self):
        db = sqlite3.connect(':memory:')
        records = [{'id': 's1', 'host': 'h1', 'seconds': 10, 'candidates': ['A', 'B']}]
        self.assertEqual(tenant_meter.capture_originals(db, 'm1', records), 'captured')
        self.assertEqual(tenant_meter.capture_originals(db, 'm1', records), 'replayed')
        with self.assertRaises(ValueError):
            tenant_meter.capture_originals(db, 'm1', [
                {'id': 's1', 'host': 'h1', 'seconds': 11, 'candidates': ['A']}])
        with self.assertRaises(ValueError):  # 同一 slice id 不能跨页重复
            tenant_meter.capture_originals(db, 'm2', records)
        with self.assertRaises(ValueError):
            tenant_meter.capture_originals(db, 'm3', [
                {'id': 's2', 'host': 'h1', 'seconds': -1, 'candidates': ['A']}])
        with self.assertRaises(ValueError):
            tenant_meter.capture_originals(db, 'm3', [
                {'id': 's2', 'host': 'h1', 'seconds': 1, 'candidates': []}])

    def test_resolution_rules(self):
        db = sqlite3.connect(':memory:')
        tenant_meter.capture_originals(db, 'm1', [
            {'id': 'def', 'host': 'h1', 'seconds': 10, 'candidates': ['A']},
            {'id': 'dis', 'host': 'h1', 'seconds': 20, 'candidates': ['A', 'B']}])
        resolution = [{'slice': 'dis', 'tenant': 'B', 'inode': 'ns/1', 'signature': 'sig-1'}]
        with self.assertRaises(ValueError):  # 未知 slice
            tenant_meter.resolve(db, 'r0', [
                {'slice': 'ghost', 'tenant': 'B', 'inode': 'i', 'signature': 's'}])
        with self.assertRaises(ValueError):  # 非争议 slice 不能签章
            tenant_meter.resolve(db, 'r0', [
                {'slice': 'def', 'tenant': 'A', 'inode': 'i', 'signature': 's'}])
        with self.assertRaises(ValueError):  # 只能判给原候选
            tenant_meter.resolve(db, 'r0', [
                {'slice': 'dis', 'tenant': 'C', 'inode': 'i', 'signature': 's'}])
        self.assertEqual(tenant_meter.resolve(db, 'r1', resolution), 'captured')
        self.assertEqual(tenant_meter.resolve(db, 'r1', resolution), 'replayed')
        with self.assertRaises(ValueError):  # 同一争议不能改判
            tenant_meter.resolve(db, 'r2', [
                {'slice': 'dis', 'tenant': 'A', 'inode': 'i2', 'signature': 's2'}])
        self.assertEqual(tenant_meter.proven(db), {'A': 10, 'B': 20})


class LabelIndependenceTest(unittest.TestCase):
    def test_raw_label_pages_do_not_drive_new_ledgers(self):
        db = sqlite3.connect(':memory:')
        drill_evidence(db)
        # 旧入口按标签行求和，A、B 各 1000，合计 2000 超过物理用量 1600
        tenant_meter.capture(db, 'u1', [{'tenant': 'A', 'units': 1000}])
        tenant_meter.capture(db, 'u2', [{'tenant': 'B', 'units': 1000}])
        a = tenant_charge.invoice(db, 'A', PERIOD)
        b = tenant_charge.invoice(db, 'B', PERIOD)
        self.assertEqual((a['billed'], b['billed']), (600, 600))  # 逐租户有证下界，不受标签支配
        settled = supplier_settlement.settle(db, PERIOD)
        self.assertEqual(settled['paid'], 1600)                   # 物理总量，不受标签支配


class PersistenceTest(unittest.TestCase):
    def test_replay_and_reopen_never_rewrite_vouchers(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = sqlite3.connect(Path(tmp) / 'settle.sqlite')
            drill_evidence(db)
            tenant_charge.invoice(db, 'A', PERIOD)
            tenant_charge.invoice(db, 'B', PERIOD)
            supplier_settlement.settle(db, PERIOD)
            tenant_meter.resolve(db, 'r1', R1)
            tenant_charge.invoice(db, 'A', PERIOD)
            supplier_settlement.settle(db, PERIOD)
            vouchers = db.execute('SELECT * FROM tenant_invoices ORDER BY seq').fetchall()
            payments = db.execute('SELECT * FROM supplier_settlements ORDER BY seq').fetchall()
            db.close()

            db = sqlite3.connect(Path(tmp) / 'settle.sqlite')  # 数据库重开
            self.assertEqual(drill_evidence(db), ['replayed'] * 3)          # 整页重复导入
            self.assertEqual(tenant_meter.resolve(db, 'r1', R1), 'replayed')
            self.assertEqual(tenant_charge.invoice(db, 'A', PERIOD)['event'], 'unchanged')
            self.assertEqual(tenant_charge.invoice(db, 'B', PERIOD)['event'], 'unchanged')
            self.assertEqual(supplier_settlement.settle(db, PERIOD)['event'], 'unchanged')
            self.assertEqual(db.execute('SELECT * FROM tenant_invoices ORDER BY seq').fetchall(),
                             vouchers)
            self.assertEqual(db.execute('SELECT * FROM supplier_settlements ORDER BY seq').fetchall(),
                             payments)
            self.assertEqual(tenant_charge.billed(db, 'A', PERIOD), 1000)
            self.assertEqual(tenant_charge.billed(db, 'B', PERIOD), 600)
            db.close()


if __name__ == '__main__':
    unittest.main()
