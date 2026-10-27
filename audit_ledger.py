"""Append-only, hash-chained decision metadata ledger for AT-JM.

Stores a digest of policy inputs rather than the raw payload. Mount
ATJM_DATA_DIR on durable storage before using it for pilots. SQLite is for a
single application replica; use PostgreSQL before horizontal scaling. A local
hash chain detects edits and interior deletion/reordering, but not deletion of
a tail without an independently retained checkpoint or external anchor.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _db_path() -> Path:
    directory = Path(os.environ.get("ATJM_DATA_DIR", "data")).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "atjm-ledger.sqlite3"


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(str(_db_path()), timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            event_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE
        )"""
    )
    return connection


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_hash(sequence: int, event_json: str, previous_hash: str) -> str:
    payload = f"{sequence}\n{previous_hash}\n{event_json}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def append_decision(decision: dict[str, Any], input_payload: Any) -> dict[str, Any]:
    """Persist minimal decision metadata and a digest of the supplied inputs."""
    input_digest = hashlib.sha256(_canonical(input_payload).encode("utf-8")).hexdigest()
    event = {
        "event_id": decision["decision_id"],
        "timestamp": decision["timestamp"],
        "decision": decision["decision"],
        "reason": decision.get("reason", ""),
        "input_sha256": input_digest,
        "schema_version": decision.get("schema_version", "0.1"),
    }
    event_json = _canonical(event)
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        last = connection.execute(
            "SELECT sequence, entry_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = last["entry_hash"] if last else GENESIS
        sequence = (last["sequence"] + 1) if last else 1
        digest = _entry_hash(sequence, event_json, previous_hash)
        connection.execute(
            "INSERT INTO audit_events(event_id,event_json,previous_hash,entry_hash) VALUES(?,?,?,?)",
            (event["event_id"], event_json, previous_hash, digest),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {"sequence": sequence, "entry_hash": digest, "input_sha256": input_digest}


def verify_chain() -> dict[str, Any]:
    """Recompute the entire chain; detect modified, removed, or reordered rows."""
    connection = _connect()
    try:
        rows = connection.execute(
            "SELECT sequence,event_id,event_json,previous_hash,entry_hash FROM audit_events ORDER BY sequence"
        ).fetchall()
    finally:
        connection.close()
    previous_hash = GENESIS
    expected_sequence = 1
    for row in rows:
        if row["sequence"] != expected_sequence or row["previous_hash"] != previous_hash:
            return {"valid": False, "event_count": len(rows), "failed_sequence": row["sequence"]}
        try:
            event = json.loads(row["event_json"])
        except (TypeError, json.JSONDecodeError):
            return {"valid": False, "event_count": len(rows), "failed_sequence": row["sequence"]}
        if event.get("event_id") != row["event_id"]:
            return {"valid": False, "event_count": len(rows), "failed_sequence": row["sequence"]}
        expected_hash = _entry_hash(row["sequence"], row["event_json"], previous_hash)
        if expected_hash != row["entry_hash"]:
            return {"valid": False, "event_count": len(rows), "failed_sequence": row["sequence"]}
        previous_hash = row["entry_hash"]
        expected_sequence += 1
    return {
        "valid": True,
        "event_count": len(rows),
        "last_hash": previous_hash if rows else GENESIS,
        "storage": "sqlite_hash_chain",
    }
