import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.features import build_feature_dataset_streaming, chronological_split
from src.data_loader import load_redteam_events

project_root = Path(__file__).resolve().parent
auth = project_root / 'data' / 'raw' / 'auth.txt.gz'
redteam = load_redteam_events(project_root / 'data' / 'raw' / 'redteam.txt.gz')

for end in [300, 600, 1200, 3600]:
    start = time.perf_counter()
    tracemalloc.start()
    features = build_feature_dataset_streaming(
        auth,
        window_seconds=300,
        start_timestamp=0,
        end_timestamp=end,
        timestamp_step=60,
        chunk_size=100_000,
    )
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    elapsed = time.perf_counter() - start
    train, validation, test = chronological_split(features)
    redtimes = set(int(v) for v in redteam['timestamp'])
    print(f'BENCH_END={end}')
    print('runtime_seconds', round(elapsed, 4))
    print('rows', len(features))
    print('entities', features['entity'].nunique())
    print('timestamp_min', int(features['timestamp'].min()) if not features.empty else None)
    print('timestamp_max', int(features['timestamp'].max()) if not features.empty else None)
    print('memory_current_bytes', current)
    print('memory_peak_bytes', peak)
    print('missing_values', int(features.isna().sum().sum()))
    print('duplicate_rows', int(features.duplicated().sum()))
    print('duplicate_entity_timestamp_keys', int(features.duplicated(['entity', 'timestamp']).sum()))
    print('window_end_equals_timestamp', bool(features['window_end'].eq(features['timestamp']).all()))
    print('window_end_gt_timestamp', bool((features['window_end'] > features['timestamp']).any()))
    print('train_rows', len(train))
    print('validation_rows', len(validation))
    print('test_rows', len(test))
    print('train_range', (int(train['timestamp'].min()), int(train['timestamp'].max())) if not train.empty else None)
    print('validation_range', (int(validation['timestamp'].min()), int(validation['timestamp'].max())) if not validation.empty else None)
    print('test_range', (int(test['timestamp'].min()), int(test['timestamp'].max())) if not test.empty else None)
    print('redteam_overlap', {name: len(sorted(set(int(v) for v in frame['timestamp']) & redtimes)) for name, frame in {'train': train, 'validation': validation, 'test': test}.items()})
    print('split_order_ok', bool(train['timestamp'].max() < validation['timestamp'].min() < test['timestamp'].min()))
    print('leakage_violations', int((features['window_end'] > features['timestamp']).sum()))
    print('---')
