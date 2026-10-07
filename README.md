# NeuroFence — LLM Weight Poisoning & Backdoor Scanner

A defensive, static-first scanner for untrusted model artifacts. Findings are risk indicators; they do not prove a model is poisoned. The prototype includes SHA-256 hashing, safe format identification, NPZ/safetensors tensor statistics, archive checks, selected configuration indicators, heuristic scoring, SQLite scan history, a browser dashboard and JSON/PDF report helpers.

## Quick start (Windows)
1. Install Python 3.10 or newer.
2. Run `run_windows.bat` from this folder. It creates `.venv` and installs dependencies.
3. Open http://127.0.0.1:8000.
4. Select a sample in `demo/` and scan it.

Manual setup: `python -m venv .venv`, activate it, `pip install -r requirements.txt`, then `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`.

## API
- `GET /health` service status
- `POST /scan` multipart upload field `upload`
- `GET /scans` latest 100 records
- `GET /dashboard` total saved scans and risk-band counts
- `GET /scan/{id}` full result
- `GET /report/{id}` JSON report download
- `GET /docs` interactive API documentation

PDF helper: `from backend.reports import write_pdf; write_pdf(result, 'report.pdf')`.

## Safety and scope
Uploads are capped at 512 MiB and removed after scanning. No content is deserialized using pickle, and no model code is run. ZIP paths and extreme compression ratios are flagged. NPZ reading uses `allow_pickle=False`. Behavioral trigger testing is not connected to an inference engine; it requires a reviewed test set and explicitly isolated adapter. Do not scan sensitive models on a shared or exposed server. The demo binds to loopback.

## Interpretation
The score sums severity weights and caps at 100; it is not a probability. Magnitude and distribution thresholds can flag legitimate models. Compare findings with provenance and an authenticated, architecture-matched baseline. Hashes identify byte equality only when compared with a trusted known hash.

## Contents
The dashboard explains findings in plain English, shows tensor statistics, and lets you search/filter the latest 100 saved records. Full scan results and aggregate risk totals are stored in the local SQLite database at `data/neurofence.sqlite3`; they remain available after restarting the service.

`backend/` scanner and API · `frontend/` dashboard · `demo/` synthetic files · `docs/` report and design · `evaluation/` protocol and expected results · `presentation/` internship slides.
