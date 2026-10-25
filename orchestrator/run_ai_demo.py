"""Shim — implementation lives in scripts/run_ai_demo.py."""
from scripts import run_ai_demo as _impl
from scripts._reexport import into

into(_impl, globals())

if __name__ == '__main__':
    import runpy
    runpy.run_module('scripts.run_ai_demo', run_name='__main__')
