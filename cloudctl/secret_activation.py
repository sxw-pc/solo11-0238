"""Provisional activation ledger from captured envelopes."""

def activate(db,replica):
    db.execute('CREATE TABLE IF NOT EXISTS secret_activations (replica TEXT,key_id TEXT)')
    row=db.execute('SELECT key_id FROM secret_envelopes WHERE replica=? ORDER BY rowid DESC LIMIT 1',(replica,)).fetchone()
    if not row:raise ValueError('missing_envelope')
    with db:db.execute('INSERT INTO secret_activations VALUES (?,?)',(replica,row[0]))
    return {'replica':replica,'key_id':row[0]}
