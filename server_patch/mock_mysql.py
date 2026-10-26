"""
mock_mysql.py -- Sandboxed, disposable stand-in for the real MySQL 'brics' DB
==============================================================================
Used only when server.py is launched with --db-engine mock (the GUI's
default). Every table this module creates lives in a single SQLite file
inside the simulator's pinned working directory -- never in a real MySQL
instance, and it never touches a MySQL install if one happens to exist on
the host at all.

Interface goal: expose just enough of the mysql-connector-python surface
that server.py's existing run_sql()/format_rows() code (see server.py's
patched _connect_db / run_sql) can call it interchangeably with a real
mysql.connector connection:

    conn.is_connected() -> bool
    conn.cursor()       -> MockCursor
    conn.close()

    cursor.execute(sql)
    cursor.with_rows    -> bool (True if the statement produced rows)
    cursor.description  -> sequence of (name, ...) tuples, like DB-API
    cursor.fetchall()   -> list[tuple]
    cursor.rowcount     -> int
    cursor.close()

This module never runs anything DESTRUCT-tier itself -- that hard block
already happens one layer up in server.py's run_sql(), before a mock or
real connection is ever touched.
"""

from __future__ import annotations

import os
import sqlite3

DB_FILENAME = "mock_brics.db"

# Small, clearly-fake seed data so demos have something to SELECT/UPDATE
# without needing any real dataset or network access.
_SEED_GDP = [
    ("BRA", "Brazil", 2024, 2170.0),
    ("RUS", "Russia", 2024, 2020.0),
    ("IND", "India", 2024, 3940.0),
    ("CHN", "China", 2024, 18560.0),
    ("ZAF", "South Africa", 2024, 405.0),
]
_SEED_TRADE = [
    ("BRA", 74.5, 22.1),
    ("RUS", 21.0, 118.4),
    ("IND", 84.2, -35.7),
    ("CHN", 66.8, 594.3),
    ("ZAF", 41.0, 3.2),
]


class MockCursor:
    """Adapts a sqlite3.Cursor to the small subset of DB-API 2 surface
    server.py's run_sql()/format_rows() actually use."""

    def __init__(self, sqlite_cursor: sqlite3.Cursor):
        self._cur = sqlite_cursor
        self.rowcount = 0
        self.description = None
        self.with_rows = False

    def execute(self, sql: str):
        self._cur.execute(sql)
        self.description = self._cur.description
        self.with_rows = self.description is not None
        self.rowcount = self._cur.rowcount if self._cur.rowcount is not None else 0

    def fetchall(self):
        return self._cur.fetchall()

    def close(self):
        self._cur.close()


class MockConnection:
    """Adapts a sqlite3.Connection to the small subset of the
    mysql.connector connection surface server.py already calls."""

    def __init__(self, db_path: str):
        self._path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._seed_schema()

    def _seed_schema(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS gdp_data (
                country_id TEXT,
                country_name TEXT,
                year INTEGER,
                gdp_usd_billion REAL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS brics_debt_trade (
                country_id TEXT,
                debt_to_gdp_pct REAL,
                trade_balance_usd_billion REAL
            )
        """)
        gdp_count = self._conn.execute("SELECT COUNT(*) FROM gdp_data").fetchone()[0]
        if gdp_count == 0:
            self._conn.executemany(
                "INSERT INTO gdp_data VALUES (?, ?, ?, ?)", _SEED_GDP
            )
        trade_count = self._conn.execute("SELECT COUNT(*) FROM brics_debt_trade").fetchone()[0]
        if trade_count == 0:
            self._conn.executemany(
                "INSERT INTO brics_debt_trade VALUES (?, ?, ?)", _SEED_TRADE
            )
        self._conn.commit()

    def is_connected(self) -> bool:
        try:
            self._conn.execute("SELECT 1")
            return True
        except sqlite3.Error:
            return False

    def cursor(self) -> MockCursor:
        return MockCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def connect(working_dir: str) -> MockConnection:
    """Opens (creating if needed) the disposable mock database file inside
    the simulator's pinned working directory. Never writes anywhere else
    on the host."""
    os.makedirs(working_dir, exist_ok=True)
    db_path = os.path.join(working_dir, DB_FILENAME)
    return MockConnection(db_path)
