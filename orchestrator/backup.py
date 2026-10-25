"""Shim — implementation lives in scripts/backup.py."""
from scripts import backup as _impl
from scripts._reexport import into

into(_impl, globals())

if __name__ == '__main__':
    import runpy
    runpy.run_module('scripts.backup', run_name='__main__')
