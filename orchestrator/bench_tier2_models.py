"""Shim — implementation lives in scripts/bench_tier2_models.py."""
from scripts import bench_tier2_models as _impl
from scripts._reexport import into

into(_impl, globals())

if __name__ == '__main__':
    import runpy
    runpy.run_module('scripts.bench_tier2_models', run_name='__main__')
