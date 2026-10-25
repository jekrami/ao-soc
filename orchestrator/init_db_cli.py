"""Shim — implementation lives in scripts/init_db_cli.py."""
if __name__ == '__main__':
    import runpy
    runpy.run_module('scripts.init_db_cli', run_name='__main__')
