from pathlib import Path
import numpy as np

out = Path(__file__).resolve().parents[1] / 'demo'
out.mkdir(exist_ok=True)
rng = np.random.default_rng(20260929)
np.savez_compressed(out / 'clean_demo.npz', layer_0=rng.normal(0, .15, (16,16)).astype('float32'), layer_1=rng.normal(0, .08, (16,8)).astype('float32'))
a = rng.normal(0, .15, (16,16)).astype('float32'); a[0,0] = np.nan; a[1,1] = 250.0
np.savez_compressed(out / 'anomalous_demo.npz', layer_0=a, layer_1=rng.normal(0, .08, (16,8)).astype('float32'))
(out / 'unsafe_format_demo.pt').write_text('Demonstration placeholder. NeuroFence must not deserialize this file.', encoding='utf-8')
print(f'Demo artifacts written to {out}')
