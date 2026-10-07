from __future__ import annotations
import json, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from .scanner import scan_file

BASE = Path(__file__).resolve().parents[1]
STORE = BASE / 'data'; STORE.mkdir(exist_ok=True)
DB = STORE / 'neurofence.sqlite3'; REPORTS = BASE / 'reports'; REPORTS.mkdir(exist_ok=True)
app = FastAPI(title='NeuroFence', version='1.0.0', description='Defensive static model artifact risk scanner')
app.mount('/static', StaticFiles(directory=BASE / 'frontend'), name='static')

def db():
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
    con.execute('CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, filename TEXT, sha256 TEXT, created_at TEXT, score INTEGER, level TEXT, result_json TEXT)')
    return con

@app.get('/', response_class=HTMLResponse)
def home(): return (BASE / 'frontend' / 'index.html').read_text(encoding='utf-8')

@app.get('/health')
def health(): return {'status':'ok','scanner':'NeuroFence','version':'1.0.0'}

@app.post('/scan')
async def scan(upload: UploadFile = File(...)):
    name = Path(upload.filename or 'upload.bin').name
    if name in {'', '.', '..'}: raise HTTPException(400, 'Invalid filename')
    tmp = STORE / f'{uuid.uuid4().hex}.upload'; size = 0
    try:
        with tmp.open('wb') as f:
            while chunk := await upload.read(1024*1024):
                size += len(chunk)
                if size > 512*1024*1024: raise HTTPException(413, 'File exceeds 512 MiB upload limit')
                f.write(chunk)
        result = scan_file(tmp, original_name=name)
        result['scan_id'] = uuid.uuid4().hex[:12]; result['created_at'] = datetime.now(timezone.utc).isoformat()
        con = db(); con.execute('INSERT INTO scans VALUES(?,?,?,?,?,?,?)', (result['scan_id'], name, result['file']['sha256'], result['created_at'], result['risk']['score'], result['risk']['level'], json.dumps(result))); con.commit(); con.close()
        (REPORTS / f"{result['scan_id']}.json").write_text(json.dumps(result, indent=2), encoding='utf-8')
        return result
    except HTTPException: raise
    except Exception as e: raise HTTPException(400, f'Scan failed safely: {e}')
    finally:
        tmp.unlink(missing_ok=True); await upload.close()

@app.get('/scans')
def history():
    con = db(); rows = con.execute('SELECT id,filename,sha256,created_at,score,level FROM scans ORDER BY created_at DESC LIMIT 100').fetchall(); con.close()
    return [dict(r) for r in rows]

@app.get('/dashboard')
def dashboard():
    con = db()
    total = con.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    bands = {r['level'].lower(): r['n'] for r in con.execute('SELECT level,COUNT(*) AS n FROM scans GROUP BY level').fetchall()}
    latest = con.execute('SELECT filename,created_at,score,level FROM scans ORDER BY created_at DESC LIMIT 1').fetchone()
    con.close()
    return {'total_scans': total, 'risk_counts': {k: bands.get(k, 0) for k in ('low','medium','high','critical')}, 'latest': dict(latest) if latest else None}

@app.get('/scan/{scan_id}')
def get_scan(scan_id: str):
    con = db(); row = con.execute('SELECT result_json FROM scans WHERE id=?', (scan_id,)).fetchone(); con.close()
    if not row: raise HTTPException(404, 'Scan not found')
    return json.loads(row['result_json'])

@app.get('/report/{scan_id}')
def report(scan_id: str):
    path = REPORTS / f'{scan_id}.json'
    if not path.exists(): raise HTTPException(404, 'Report not found')
    return FileResponse(path, media_type='application/json', filename=f'neurofence-{scan_id}.json')
