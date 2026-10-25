"""Shim — implementation lives in scripts/pilot_report.py."""
from scripts import pilot_report as _impl
from scripts._reexport import into

into(_impl, globals())

if __name__ == '__main__':
    import runpy
    runpy.run_module('scripts.pilot_report', run_name='__main__')
