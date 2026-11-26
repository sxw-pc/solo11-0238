"""Platform consumed-capacity settlement with the resource supplier.

The supplier is paid for the physical total rebuilt from host counters —
the usage present in every compatible tenant attribution — while the
remainder that no tenant is yet proven to own stays an open difference.
Tenant labels never drive this ledger, and an issued payment is never
rewritten: later evidence only appends payment-delta or adjustment events,
so the platform never underpays a certain physical cost while tenant
attribution is still pending, and never pays the same seconds twice.
"""
from . import tenant_meter


def _ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS supplier_settlements (seq INTEGER PRIMARY KEY AUTOINCREMENT,'
               'period TEXT,event TEXT,physical INTEGER,paid INTEGER,unallocated INTEGER)')


def settle(db, period):
    """Settle one period: pay the verified physical total exactly once."""
    usage = tenant_meter.verified_usage(db)
    physical = sum(usage.values())
    allocated = sum(tenant_meter.proven(db).values())
    unallocated = physical - allocated
    _ensure(db)
    history = db.execute('SELECT event,physical,paid,unallocated FROM supplier_settlements '
                         'WHERE period=? ORDER BY seq', (period,)).fetchall()
    paid = sum(row[2] for row in history)
    if not history:
        with db:
            db.execute('INSERT INTO supplier_settlements(period,event,physical,paid,unallocated) '
                       'VALUES (?,?,?,?,?)', (period, 'payment', physical, physical, unallocated))
        return {'period': period, 'event': 'payment', 'physical': physical, 'allocated': allocated,
                'paid': physical, 'unallocated': unallocated}
    if physical > paid:
        event, delta = 'payment', physical - paid
    elif unallocated != history[-1][3]:
        event, delta = 'adjustment', 0
    else:
        return {'period': period, 'event': 'unchanged', 'physical': physical, 'allocated': allocated,
                'paid': paid, 'unallocated': unallocated}
    with db:
        db.execute('INSERT INTO supplier_settlements(period,event,physical,paid,unallocated) '
                   'VALUES (?,?,?,?,?)', (period, event, physical, delta, unallocated))
    return {'period': period, 'event': event, 'physical': physical, 'allocated': allocated,
            'paid': paid + delta, 'unallocated': unallocated}


def reconcile(db, period):
    """Cross-check real money flow against resource usage accounts."""
    usage = tenant_meter.verified_usage(db)
    physical = sum(usage.values())
    certain = tenant_meter.proven(db)
    allocated = sum(certain.values())
    readings = tenant_meter.interpretations(db)
    _ensure(db)
    db.execute('CREATE TABLE IF NOT EXISTS tenant_invoices (seq INTEGER PRIMARY KEY AUTOINCREMENT,'
               'period TEXT,tenant TEXT,event TEXT,proven INTEGER,delta INTEGER)')
    tenants = {}
    for name, event, _, delta in db.execute(
            'SELECT tenant,event,proven,delta FROM tenant_invoices WHERE period=? ORDER BY seq', (period,)):
        account = tenants.setdefault(name, {'billed': 0, 'events': []})
        account['billed'] += delta
        account['events'].append(event)
    for name, account in tenants.items():
        account['proven'] = certain.get(name, 0)
    payments = db.execute('SELECT event,physical,paid,unallocated FROM supplier_settlements '
                          'WHERE period=? ORDER BY seq', (period,)).fetchall()
    paid = sum(row[2] for row in payments)
    slice_total = tenant_meter.common_total(db)
    conserved = all(sum(reading.values()) == slice_total for reading in readings)
    not_overbilled = all(
        account['billed'] <= min((reading.get(name, 0) for reading in readings), default=0)
        for name, account in tenants.items())
    return {'period': period,
            'physical': usage,
            'physical_total': physical,
            'allocated': allocated,
            'unallocated': physical - allocated,
            'readings': readings,
            'tenants': tenants,
            'supplier': {'paid': paid, 'events': [row[0] for row in payments]},
            'conserved': conserved,
            'tenants_not_overbilled': not_overbilled,
            'supplier_covered': paid == physical,
            'reconciled': conserved and not_overbilled and paid == physical}
