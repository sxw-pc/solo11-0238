"""Tenant billing: legacy label-sum entry and indisputable invoices.

issue() is the pinned legacy entry that sums raw label rows; it can bill
past physical usage and must not drive settlement.  invoice() bills only
the per-tenant lower bound proven by every compatible reading of the
captured originals, forming a payable amount once the contract minimum of
600 CPU seconds is reached.  Vouchers are append-only: later evidence can
only add a recovery or reversal event, never rewrite issued rows.
"""
import json

from . import tenant_meter

MINIMUM = 600  # contract minimum CPU seconds before an invoice becomes payable


def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS tenant_charges (subject TEXT,metric INTEGER)')
    value=sum(r['units'] for (raw,) in db.execute('SELECT rows_json FROM usage_pages') for r in json.loads(raw) if r['tenant']==subject)
    with db:db.execute('INSERT INTO tenant_charges VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}


def _payable(seconds):
    return seconds if seconds >= MINIMUM else 0


def _ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS tenant_invoices (seq INTEGER PRIMARY KEY AUTOINCREMENT,'
               'period TEXT,tenant TEXT,event TEXT,proven INTEGER,delta INTEGER)')


def invoice(db, tenant, period):
    """Indisputable tenant invoice for one settlement period.

    Only usage proven in every compatible reading is billed, never a share
    of disputed seconds by label or by average.  Re-issuing after later
    evidence appends a recovery or reversal event for the payable delta."""
    tenant_meter.verified_usage(db)
    _ensure(db)
    certain = tenant_meter.proven(db).get(tenant, 0)
    due = _payable(certain)
    history = db.execute('SELECT event,proven,delta FROM tenant_invoices WHERE period=? AND tenant=? '
                         'ORDER BY seq', (period, tenant)).fetchall()
    billed = sum(row[2] for row in history)
    status = 'payable' if due else 'below_minimum'
    if not history:
        with db:
            db.execute('INSERT INTO tenant_invoices(period,tenant,event,proven,delta) VALUES (?,?,?,?,?)',
                       (period, tenant, 'issued', certain, due))
        return {'subject': tenant, 'period': period, 'event': 'issued', 'proven': certain,
                'delta': due, 'billed': due, 'status': status}
    delta = due - billed
    if delta == 0:
        return {'subject': tenant, 'period': period, 'event': 'unchanged', 'proven': certain,
                'delta': 0, 'billed': billed, 'status': status}
    event = 'recovery' if delta > 0 else 'reversal'
    with db:
        db.execute('INSERT INTO tenant_invoices(period,tenant,event,proven,delta) VALUES (?,?,?,?,?)',
                   (period, tenant, event, certain, delta))
    return {'subject': tenant, 'period': period, 'event': event, 'proven': certain,
            'delta': delta, 'billed': billed + delta, 'status': status}


def billed(db, tenant, period):
    """Cumulative payable CPU seconds invoiced to a tenant for a period."""
    _ensure(db)
    return db.execute('SELECT COALESCE(SUM(delta),0) FROM tenant_invoices WHERE period=? AND tenant=?',
                      (period, tenant)).fetchone()[0]
