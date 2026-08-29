import time
import tracemalloc
from pathlib import Path
import sys

sys.path.insert(0, str(Path('.').resolve()))
from src.features import build_feature_dataset_streaming, chronological_split

auth = Path('data/raw/auth.txt.gz')
print('starting', flush=True)
for end in [300, 600, 1200]:
    print('before benchmark', end, flush=True)
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
    print('BENCH_END=%d RUNTIME_SECONDS=%.4f ROWS=%d ENTITIES=%d MEMORY_CURRENT_BYTES=%d MEMORY_PEAK_BYTES=%d TRAIN=%d VALID=%d TEST=%d' % (
        end,
        elapsed,
        len(features),
        features['entity'].nunique(),
        current,
        peak,
        len(train),
        len(validation),
        len(test),
    ), flush=True)
    print('done', end, flush=True)
print('all complete', flush=True)
