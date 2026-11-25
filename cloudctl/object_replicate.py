"""Provisional written business result for object storage replication."""
import json

def issue(db,subject):
    db.execute('CREATE TABLE IF NOT EXISTS replication_commits (subject TEXT,metric INTEGER)')
    value=sum(r['shards'] for (raw,) in db.execute('SELECT rows_json FROM object_pages') for r in json.loads(raw) if r['bucket']==subject)
    with db:db.execute('INSERT INTO replication_commits VALUES (?,?)',(subject,value))
    return {'subject':subject,'metric':value}
