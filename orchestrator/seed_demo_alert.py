"""Shim — implementation lives in scripts/seed_demo_alert.py."""
from scripts import seed_demo_alert as _impl
from scripts._reexport import into

into(_impl, globals())

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
