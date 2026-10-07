# Technical design

## Purpose
NeuroFence performs initial security triage on model artifacts before they enter a deployment pipeline. The design prioritizes non-execution and clear evidence.

## Pipeline
1. Stream upload to a uniquely named temporary file, enforce 512 MiB, and calculate SHA-256.
2. Identify format from the file extension.
3. Inspect supported safe structures: NPZ (`allow_pickle=False`), safetensors when installed, and ZIP members.
4. Inspect adjacent `config.json` files for selected custom-code keys.
5. Map findings to a capped heuristic score and risk band.
6. Save scan metadata and result JSON in SQLite; retain downloadable JSON.

## Components
`backend/main.py` contains FastAPI routes and the upload lifecycle. `backend/scanner.py` performs static checks and risk scoring. `backend/reports.py` exports JSON and PDF. `frontend/index.html` is the dashboard.

## Data handling
Uploads are removed from `data/` after the request. The database retains filename, hash, timestamp, score, band and result. JSON reports remain in `reports/`. Set retention rules before production use. Authentication, remote storage, multi-user controls, antivirus integration and deployment hardening are out of scope.

## Threat model and limitations
Input is treated as hostile. The scanner does not unpickle `.pt`/`.pth` or execute custom model code. ZIP and numeric container parsers still have attack surface; run the service in an isolated, resource-limited environment. Static statistics cannot reliably find stealthy backdoors. Behavioral checks need safe inference isolation and architecture-specific evaluation; this build marks them as not run.

## Extensions
Add signed baseline manifests, architecture-aware comparison, calibrated checks, sandboxed inference, authentication, retention controls and resource isolation. Record scanner version with each result.
