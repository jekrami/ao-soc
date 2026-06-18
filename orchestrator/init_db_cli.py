import asyncio
import sqlite3

from db import init_db

asyncio.run(init_db())
tables = [r[0] for r in sqlite3.connect('soc_matrix.db').execute("SELECT name FROM sqlite_master WHERE type='table'")]
print('Tables:', tables)
