"""Provisional promotion from captured image attestations."""
import json

def promote(db,image):
    db.execute('CREATE TABLE IF NOT EXISTS image_promotions (image TEXT, build TEXT, digest TEXT)')
    rows=[r for (raw,) in db.execute('SELECT rows_json FROM image_packets') for r in json.loads(raw) if r['image']==image]
    if not rows:raise ValueError('missing_image')
    row=rows[-1]
    with db:db.execute('INSERT INTO image_promotions VALUES (?,?,?)',(image,row['build'],row['digest']))
    return {'image':image,'build':row['build'],'digest':row['digest']}
