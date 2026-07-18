from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

DB_PATH = Path("data/sentinelforge.db")

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT UNIQUE NOT NULL, title TEXT NOT NULL,
 severity TEXT NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL, detected_at TEXT NOT NULL,
 summary TEXT NOT NULL, root_cause TEXT DEFAULT '', containment TEXT DEFAULT '',
 recommendations TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS timeline (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, event_time TEXT NOT NULL,
 source TEXT NOT NULL, event TEXT NOT NULL, evidence_ref TEXT DEFAULT '',
 FOREIGN KEY(case_id) REFERENCES incidents(case_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS iocs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, type TEXT NOT NULL,
 value TEXT NOT NULL, context TEXT DEFAULT '', FOREIGN KEY(case_id) REFERENCES incidents(case_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS attack_map (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, technique_id TEXT NOT NULL,
 technique TEXT NOT NULL, evidence TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES incidents(case_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vendors (
 id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 service TEXT NOT NULL, data_classification TEXT NOT NULL, business_owner TEXT NOT NULL,
 inherent_risk INTEGER NOT NULL, control_score INTEGER NOT NULL, residual_risk INTEGER NOT NULL,
 decision TEXT NOT NULL, gaps TEXT NOT NULL, remediation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
 department TEXT NOT NULL, employment_status TEXT NOT NULL, account_enabled INTEGER NOT NULL,
 mfa_enabled INTEGER NOT NULL, privileged INTEGER NOT NULL, last_sign_in TEXT,
 manager TEXT DEFAULT '', groups_csv TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS identity_findings (
 id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL,
 finding_type TEXT NOT NULL, severity TEXT NOT NULL, detail TEXT NOT NULL, recommendation TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialise() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def rows(query: str, params: Iterable[object] = ()) -> list[dict]:
    with connect() as conn:
        return [dict(row) for row in conn.execute(query, tuple(params)).fetchall()]


def execute(query: str, params: Iterable[object] = ()) -> None:
    with connect() as conn:
        conn.execute(query, tuple(params))
        conn.commit()


def execute_many(query: str, values: Iterable[Iterable[object]]) -> None:
    with connect() as conn:
        conn.executemany(query, values)
        conn.commit()
