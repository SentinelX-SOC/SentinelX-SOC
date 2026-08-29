import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path('.').resolve()))
from src.features import build_feature_dataset_streaming

auth = Path('data/raw/auth.txt.gz')
for end in [10, 20, 50, 100, 300]:
    print('START', end, flush=True)
    t = time.perf_counter()
    features = build_feature_dataset_streaming(auth, window_seconds=300, start_timestamp=0, end_timestamp=end, timestamp_step=60, chunk_size=100000)
    dt = time.perf_counter() - t
    print('END', end, 'seconds', round(dt, 4), 'rows', len(features), 'entities', features['entity'].nunique() if not features.empty else 0, flush=True)
