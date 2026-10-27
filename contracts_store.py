"""Tenant-scoped, immutable versioned intent contract storage."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _db_path() -> Path:
    directory = Path(os.environ.get("ATJM_DATA_DIR", "data")).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "atjm-ledger.sqlite3"


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(str(_db_path()), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS intent_contract_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            contract_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            status TEXT NOT NULL,
            content_json TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            approved_by TEXT,
            approved_at TEXT,
            UNIQUE(tenant_id, contract_id, version)
        )"""
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_contract_tenant_latest "
        "ON intent_contract_versions(tenant_id, contract_id, version DESC)"
    )
    return connection


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "tenant_id": row["tenant_id"],
        "contract_id": row["contract_id"],
        "version": row["version"],
        "status": row["status"],
        "content": json.loads(row["content_json"]),
        "content_sha256": row["content_sha256"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
    }


def _insert_version(connection, tenant_id: str, contract_id: str, version: int,
                    content: dict[str, Any], actor: str, approved_by: str | None = None) -> None:
    content_json = _canonical(content)
    digest = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    connection.execute(
        """INSERT INTO intent_contract_versions
           (tenant_id,contract_id,version,status,content_json,content_sha256,
            created_by,created_at,approved_by,approved_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (tenant_id, contract_id, version, content["status"], content_json, digest,
         actor, now, approved_by, now if approved_by else None),
    )


def create_draft(tenant_id: str, content: dict[str, Any], actor: str) -> dict[str, Any]:
    contract_id = content["contract_id"]
    draft = json.loads(_canonical(content))
    draft["status"] = "draft"
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        latest = connection.execute(
            "SELECT version FROM intent_contract_versions WHERE tenant_id=? AND contract_id=? ORDER BY version DESC LIMIT 1",
            (tenant_id, contract_id),
        ).fetchone()
        version = (latest["version"] + 1) if latest else 1
        _insert_version(connection, tenant_id, contract_id, version, draft, actor)
        row = connection.execute(
            "SELECT * FROM intent_contract_versions WHERE tenant_id=? AND contract_id=? AND version=?",
            (tenant_id, contract_id, version),
        ).fetchone()
        connection.commit()
        return _row(row)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_latest(tenant_id: str, contract_id: str) -> dict[str, Any] | None:
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT * FROM intent_contract_versions WHERE tenant_id=? AND contract_id=? ORDER BY version DESC LIMIT 1",
            (tenant_id, contract_id),
        ).fetchone()
        return _row(row) if row else None
    finally:
        connection.close()


def list_latest(tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
    connection = _connect()
    try:
        rows = connection.execute(
            """SELECT c.* FROM intent_contract_versions c
               JOIN (SELECT contract_id, MAX(version) AS version
                     FROM intent_contract_versions WHERE tenant_id=? GROUP BY contract_id) latest
                 ON c.contract_id=latest.contract_id AND c.version=latest.version
               WHERE c.tenant_id=? ORDER BY c.created_at DESC LIMIT ?""",
            (tenant_id, tenant_id, limit),
        ).fetchall()
        return [_row(row) for row in rows]
    finally:
        connection.close()


def approve_latest(tenant_id: str, contract_id: str, approver: str) -> dict[str, Any]:
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM intent_contract_versions WHERE tenant_id=? AND contract_id=? ORDER BY version DESC LIMIT 1",
            (tenant_id, contract_id),
        ).fetchone()
        if row is None:
            raise LookupError("Contract not found.")
        if row["status"] != "draft":
            raise ValueError("Only the latest draft can be approved.")
        if row["created_by"] == approver:
            raise PermissionError("A different authorized user must approve this contract.")
        content = json.loads(row["content_json"])
        content["status"] = "approved"
        version = row["version"] + 1
        _insert_version(connection, tenant_id, contract_id, version, content, approver, approved_by=approver)
        approved = connection.execute(
            "SELECT * FROM intent_contract_versions WHERE tenant_id=? AND contract_id=? AND version=?",
            (tenant_id, contract_id, version),
        ).fetchone()
        connection.commit()
        return _row(approved)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
