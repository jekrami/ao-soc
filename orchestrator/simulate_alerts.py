"""Shim — implementation lives in scripts/simulate_alerts.py."""
from scripts import simulate_alerts as _impl
from scripts._reexport import into

into(_impl, globals())

if __name__ == '__main__':
    import runpy
    runpy.run_module('scripts.simulate_alerts', run_name='__main__')
