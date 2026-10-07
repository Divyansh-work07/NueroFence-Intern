"""Defensive static scanner. Never unpickles or executes uploaded content."""
from __future__ import annotations
import hashlib, json, zipfile
from pathlib import Path

MAX_ARCHIVE_MEMBERS = 100_000
SUSPICIOUS_CONFIG_KEYS = {'auto_map', 'trust_remote_code', 'custom_code', 'init_hook', 'entrypoint'}

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()

def finding(code, title, severity, detail, recommendation):
    explanations = {
        'NONFINITE_WEIGHT': ('A tensor contains NaN or infinity instead of ordinary numeric values.', 'This can break inference and may indicate corruption or an intentional modification.'),
        'EXTREME_MAGNITUDE': ('At least one weight is much larger than this scanner’s conservative threshold.', 'Very large weights can destabilize a model, but some legitimate models may also contain large values.'),
        'DISTRIBUTION_SHIFT': ('A tensor mean is unusually large compared with its spread.', 'A shift can result from model design, training, conversion, or tampering; compare it with a trusted copy.'),
        'CONFIG_CUSTOM_CODE': ('The configuration includes a key associated with custom or remote code.', 'The key alone does not run code. Review the source and keep custom-code execution disabled.'),
        'CONFIG_INVALID': ('The nearby configuration could not be read as valid JSON.', 'A damaged or unexpected configuration can prevent reliable model review.'),
        'UNSAFE_SERIALIZATION': ('This extension is commonly associated with Python pickle serialization.', 'Opening pickle files can execute code. NeuroFence deliberately refuses to deserialize this file.'),
        'UNKNOWN_FORMAT': ('The file extension is not one of the formats this scanner recognizes.', 'The scanner cannot reliably inspect its internal structure.'),
        'ARCHIVE_PATH_TRAVERSAL': ('An archive member name attempts to refer outside its containing folder.', 'Extracting such an archive carelessly can overwrite or place files in unintended locations.'),
        'ARCHIVE_RATIO': ('An archive entry expands to far more data than its compressed size.', 'This may exhaust storage or memory if extracted.'),
        'ARCHIVE_MEMBER_LIMIT': ('The archive contains an unusually large number of entries.', 'Processing a very large archive can consume excessive resources.'),
        'INVALID_ARCHIVE': ('The file looks like a ZIP archive but could not be read as one.', 'It may be incomplete, corrupted, or mislabeled.'),
        'EMPTY_FILE': ('The uploaded file contains no bytes.', 'There is no model content to inspect.'),
        'NPZ_PARSE_ERROR': ('The file could not be read as a safe NumPy archive.', 'It may be damaged or may not be a valid NPZ file.'),
        'SAFETENSORS_PARSE_ERROR': ('The file could not be read as a valid safetensors artifact.', 'It may be damaged or mislabeled.'),
        'SAFETENSORS_UNAVAILABLE': ('Tensor contents were not inspected because safetensors support is unavailable.', 'Install the optional package before relying on tensor-level findings.'),
        'NON_NUMERIC_ARRAY': ('An array contains non-numeric data and was excluded from weight statistics.', 'Review this content if the model is expected to contain only numeric tensors.'),
    }
    explanation, why = explanations.get(code, ('The scanner found a condition that deserves review.', 'This indicator is not proof that the model is malicious.'))
    return {'code': code, 'title': title, 'severity': severity, 'detail': detail, 'explanation': explanation, 'why_it_matters': why, 'recommendation': recommendation}

def inspect_config(path):
    found, configs = [], []
    for p in path.parent.glob('config.json'):
        try:
            data = json.loads(p.read_text(encoding='utf-8')); configs.append({'file': p.name, 'keys': sorted(data)})
            for key in SUSPICIOUS_CONFIG_KEYS & set(data):
                found.append(finding('CONFIG_CUSTOM_CODE', 'Custom-code configuration', 'MEDIUM', f'{key} is present. This is a review indicator, not evidence of execution.', 'Review provenance and keep remote/custom code disabled.'))
        except Exception:
            found.append(finding('CONFIG_INVALID', 'Invalid JSON configuration', 'LOW', 'Adjacent config.json could not be parsed.', 'Verify configuration integrity and source.'))
    return configs, found

def inspect_numeric(arrays):
    import numpy as np
    records, found, total = [], [], 0
    for key, a in arrays:
        if a.dtype.kind not in 'biuf':
            found.append(finding('NON_NUMERIC_ARRAY', 'Non-numeric array', 'LOW', f'{key} uses dtype {a.dtype}.', 'Review array content and provenance.')); continue
        total += int(a.size); finite = np.isfinite(a); bad = int(a.size - finite.sum()); sample = a.ravel()[:200000]; vals = sample[np.isfinite(sample)]
        if bad: found.append(finding('NONFINITE_WEIGHT', 'NaN or infinity in weights', 'HIGH', f'{key}: {bad} non-finite value(s).', 'Quarantine and compare with a trusted checkpoint.'))
        if vals.size:
            mean, std, mx = float(vals.mean()), float(vals.std()), float(np.max(np.abs(vals)))
            records.append({'name': key, 'shape': list(a.shape), 'dtype': str(a.dtype), 'elements': int(a.size), 'mean': mean, 'std': std, 'min': float(vals.min()), 'max': float(vals.max()), 'max_abs': mx, 'zero_fraction': float(np.mean(vals == 0))})
            if mx > 100: found.append(finding('EXTREME_MAGNITUDE', 'Extreme weight magnitude', 'HIGH', f'{key}: max absolute value {mx:.4g} exceeds threshold 100.', 'Compare tensor statistics against an authenticated baseline.'))
            elif std and abs(mean) > max(5.0, 10 * std): found.append(finding('DISTRIBUTION_SHIFT', 'Unusual tensor distribution', 'MEDIUM', f'{key}: mean {mean:.4g}, standard deviation {std:.4g}.', 'Review this layer against a trusted checkpoint.'))
    return records, total, found

def inspect_archive(path):
    found, members = [], []
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS: found.append(finding('ARCHIVE_MEMBER_LIMIT', 'Archive has too many members', 'MEDIUM', f'{len(infos)} members exceeds limit.', 'Inspect in an isolated environment.'))
            for i in infos[:MAX_ARCHIVE_MEMBERS]:
                n = i.filename.replace('\\', '/')
                if n.startswith('/') or '..' in Path(n).parts: found.append(finding('ARCHIVE_PATH_TRAVERSAL', 'Unsafe archive member path', 'HIGH', n, 'Do not extract this archive; review its origin.'))
                if i.compress_size and i.file_size / i.compress_size > 1000: found.append(finding('ARCHIVE_RATIO', 'Extreme compression ratio', 'MEDIUM', n, 'Avoid extracting until reviewed.'))
                members.append({'name': n, 'size': i.file_size})
    except zipfile.BadZipFile:
        found.append(finding('INVALID_ARCHIVE', 'Invalid ZIP container', 'MEDIUM', 'ZIP signature found but archive could not be read.', 'Verify file integrity.'))
    return members, found

def risk(findings, fmt):
    weights = {'LOW': 5, 'MEDIUM': 18, 'HIGH': 35, 'CRITICAL': 50}; score = min(100, sum(weights.get(x['severity'], 0) for x in findings))
    if fmt in {'pickle', 'unknown'}: score = min(100, score + 15)
    level = 'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 20 else 'LOW'
    descriptions = {
        'LOW': 'No major configured indicators were found. This is not a safety certification.',
        'MEDIUM': 'One or more review indicators were found. Check the evidence and provenance before use.',
        'HIGH': 'Several or serious indicators were found. Hold the artifact while you investigate it.',
        'CRITICAL': 'The combined indicators warrant immediate quarantine and expert review.',
    }
    return {'score': score, 'level': level, 'summary': descriptions[level], 'interpretation': 'Heuristic risk indicator; not a probability and does not prove poisoning.', 'scoring': 'LOW=5, MEDIUM=18, HIGH=35, CRITICAL=50 points per finding; points are added and capped at 100. Unknown and pickle formats receive 15 additional points.'}

def scan_file(file_path, original_name=None):
    import numpy as np
    p = Path(file_path); name = original_name or p.name; ext = Path(name).suffix.lower()
    fmt = {'.safetensors':'safetensors','.npz':'npz','.zip':'zip','.pt':'pickle','.pth':'pickle','.pkl':'pickle','.bin':'binary','.gguf':'gguf'}.get(ext, 'unknown')
    found, tensors, total, members = [], [], 0, []
    configs, cf = inspect_config(p); found.extend(cf)
    if fmt == 'npz':
        try:
            with np.load(p, allow_pickle=False) as data: tensors, total, ff = inspect_numeric((key, data[key]) for key in data.files)
            found.extend(ff)
        except Exception as e: found.append(finding('NPZ_PARSE_ERROR', 'NPZ inspection failed', 'MEDIUM', str(e), 'Verify format; do not enable pickle loading.'))
    elif fmt == 'safetensors':
        try:
            from safetensors import safe_open
            with safe_open(str(p), framework='np') as f: tensors, total, ff = inspect_numeric((key, f.get_tensor(key)) for key in f.keys())
            found.extend(ff)
        except ImportError: found.append(finding('SAFETENSORS_UNAVAILABLE', 'Safetensors support unavailable', 'LOW', 'Install safetensors to inspect tensor contents.', 'Install the optional dependency in an isolated environment.'))
        except Exception as e: found.append(finding('SAFETENSORS_PARSE_ERROR', 'Safetensors inspection failed', 'MEDIUM', str(e), 'Verify source and integrity.'))
    if fmt in {'zip', 'npz'}:
        members, af = inspect_archive(p); found.extend(af)
    if fmt == 'pickle': found.append(finding('UNSAFE_SERIALIZATION', 'Pickle-based model format', 'HIGH', 'This file type can carry executable serialization payloads. It was not deserialized.', 'Do not load it. Prefer safetensors or use a disposable sandbox.'))
    if fmt == 'unknown': found.append(finding('UNKNOWN_FORMAT', 'Unknown model format', 'MEDIUM', f'Extension {ext or "(none)"} is not recognized.', 'Verify expected format and provenance before use.'))
    if p.stat().st_size == 0: found.append(finding('EMPTY_FILE', 'Empty file', 'MEDIUM', 'The file contains no data.', 'Check transfer integrity.'))
    return {'file': {'filename': name, 'size_bytes': p.stat().st_size, 'format': fmt, 'sha256': sha256(p)}, 'model': {'tensor_count': len(tensors), 'parameter_count': total, 'configs': configs, 'archive_members': members[:500]}, 'tensors': tensors[:2000], 'findings': found, 'risk': risk(found, fmt), 'scope': {'static_only': True, 'behavioral_testing': 'Not run: requires an explicitly configured sandboxed inference adapter.', 'limitations': ['Anomalies are indicators, not proof of a backdoor.', 'The scanner does not execute model code or unpickle files.', 'Distribution thresholds may flag legitimate models.']}}
