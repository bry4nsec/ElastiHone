"""Persistent storage for ElastiHone analysis history.

Uses SQLite (default) via aiosqlite for async access. Stores analysis results,
exceptions applied, and scheduled rules. All data survives container restarts.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

# Default database path — overridable via SDA_DATABASE_URL env var
_DEFAULT_DB_PATH = os.environ.get("SDA_DB_PATH", "data/sda.db")
_db: aiosqlite.Connection | None = None


async def get_db() -> aiosqlite.Connection:
    """Get or create the database connection."""
    global _db
    if _db is None:
        db_path = _DEFAULT_DB_PATH
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        _db = await aiosqlite.connect(db_path)
        _db.row_factory = aiosqlite.Row
        await _init_tables(_db)
        logger.info("Database connected: %s", db_path)
    return _db


async def close_db() -> None:
    """Close the database connection."""
    global _db
    if _db is not None:
        await _db.close()
        _db = None


async def _init_tables(db: aiosqlite.Connection) -> None:
    """Create tables if they don't exist."""
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            rule_name TEXT NOT NULL,
            rule_type TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            verdict TEXT DEFAULT '',
            noise_hits INTEGER DEFAULT 0,
            actual_alert_count INTEGER DEFAULT -1,
            fpr REAL DEFAULT 0.0,
            alerts_per_day REAL DEFAULT 0.0,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            duration_seconds REAL DEFAULT 0.0,
            source TEXT DEFAULT 'manual'
        );

        CREATE INDEX IF NOT EXISTS idx_analyses_rule_name
            ON analyses(rule_name);
        CREATE INDEX IF NOT EXISTS idx_analyses_created_at
            ON analyses(created_at);
        CREATE INDEX IF NOT EXISTS idx_analyses_verdict
            ON analyses(verdict);

        CREATE TABLE IF NOT EXISTS exceptions_applied (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            kql_query TEXT NOT NULL,
            entries_json TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            kibana_list_id TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (analysis_id) REFERENCES analyses(id)
        );

        CREATE TABLE IF NOT EXISTS scheduled_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL UNIQUE,
            rule_source TEXT DEFAULT '',
            rule_content TEXT DEFAULT '',
            schedule_cron TEXT DEFAULT '0 2 * * 1',
            enabled INTEGER DEFAULT 1,
            last_run_at TEXT DEFAULT '',
            last_verdict TEXT DEFAULT '',
            last_alert_count INTEGER DEFAULT -1,
            created_at TEXT NOT NULL
        );
    """)
    await db.commit()


# ── Analysis CRUD ─────────────────────────────────────────────────────────────

async def save_analysis(analysis_id: str, report: dict) -> None:
    """Save a completed analysis to the database."""
    db = await get_db()
    await db.execute(
        """INSERT OR REPLACE INTO analyses
           (id, rule_name, rule_type, severity, verdict, noise_hits,
            actual_alert_count, fpr, alerts_per_day, report_json,
            created_at, duration_seconds, source)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            analysis_id,
            report.get("rule_name", "Unknown"),
            report.get("rule_type", ""),
            report.get("severity", ""),
            report.get("verdict", ""),
            report.get("noise_hits", 0),
            report.get("actual_alert_count", -1),
            report.get("fpr", 0.0),
            report.get("estimated_alerts_per_day", 0.0),
            json.dumps(report, default=str),
            datetime.now(tz=timezone.utc).isoformat(),
            report.get("analysis_duration_seconds", 0.0),
            report.get("source", "manual"),
        ),
    )
    await db.commit()
    logger.info("Analysis %s saved to database", analysis_id)


async def get_analysis(analysis_id: str) -> dict | None:
    """Retrieve an analysis by ID."""
    db = await get_db()
    async with db.execute(
        "SELECT report_json FROM analyses WHERE id = ?", (analysis_id,)
    ) as cursor:
        row = await cursor.fetchone()
        if row:
            return json.loads(row["report_json"])
    return None


async def list_analyses(
    page: int = 1,
    per_page: int = 20,
    search: str = "",
    verdict: str = "",
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> dict[str, Any]:
    """List analyses with pagination, search, and filtering."""
    db = await get_db()
    conditions = []
    params: list[Any] = []

    if search:
        conditions.append("rule_name LIKE ?")
        params.append(f"%{search}%")
    if verdict:
        conditions.append("verdict = ?")
        params.append(verdict)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Validate sort_by to prevent SQL injection
    allowed_sorts = {"created_at", "rule_name", "verdict", "noise_hits", "alerts_per_day", "fpr"}
    if sort_by not in allowed_sorts:
        sort_by = "created_at"
    order = "DESC" if sort_order.lower() == "desc" else "ASC"

    # Count total
    async with db.execute(f"SELECT COUNT(*) as cnt FROM analyses {where}", params) as cur:
        total = (await cur.fetchone())["cnt"]

    # Fetch page
    offset = (page - 1) * per_page
    async with db.execute(
        f"""SELECT id, rule_name, rule_type, severity, verdict, noise_hits,
                   actual_alert_count, fpr, alerts_per_day, created_at, duration_seconds
            FROM analyses {where}
            ORDER BY {sort_by} {order}
            LIMIT ? OFFSET ?""",
        [*params, per_page, offset],
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]

    return {"analyses": rows, "total": total, "page": page, "per_page": per_page}


async def delete_analysis(analysis_id: str) -> bool:
    """Delete an analysis by ID."""
    db = await get_db()
    cursor = await db.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    await db.commit()
    return cursor.rowcount > 0


async def load_recent_analyses(limit: int = 100) -> dict[str, dict]:
    """Load recent analyses from DB into a dict (for hydrating in-memory store on startup).

    Returns:
        Dict mapping analysis_id → report dict (ready to merge into the analyses store).
    """
    db = await get_db()
    async with db.execute(
        "SELECT id, report_json FROM analyses ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ) as cursor:
        result = {}
        async for row in cursor:
            try:
                report = json.loads(row["report_json"])
                report["analysis_id"] = row["id"]
                report["status"] = "done"
                result[row["id"]] = report
            except (json.JSONDecodeError, KeyError):
                continue
        logger.info("Loaded %d analyses from database", len(result))
        return result


# ── Exception Tracking ────────────────────────────────────────────────────────

async def save_exception(
    analysis_id: str, rule_name: str, kql_query: str,
    entries_json: str, kibana_list_id: str = "", status: str = "pending",
) -> int:
    """Record an exception that was applied."""
    db = await get_db()
    cursor = await db.execute(
        """INSERT INTO exceptions_applied
           (analysis_id, rule_name, kql_query, entries_json, applied_at, kibana_list_id, status)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (analysis_id, rule_name, kql_query, entries_json,
         datetime.now(tz=timezone.utc).isoformat(), kibana_list_id, status),
    )
    await db.commit()
    return cursor.lastrowid


async def list_exceptions(rule_name: str = "") -> list[dict]:
    """List applied exceptions, optionally filtered by rule name."""
    db = await get_db()
    if rule_name:
        sql = "SELECT * FROM exceptions_applied WHERE rule_name = ? ORDER BY applied_at DESC"
        params = [rule_name]
    else:
        sql = "SELECT * FROM exceptions_applied ORDER BY applied_at DESC LIMIT 100"
        params = []
    async with db.execute(sql, params) as cur:
        return [dict(r) for r in await cur.fetchall()]


# ── Scheduled Rules ───────────────────────────────────────────────────────────

async def save_scheduled_rule(
    rule_name: str, rule_source: str = "", rule_content: str = "",
    schedule_cron: str = "0 2 * * 1",
) -> None:
    """Add or update a scheduled rule."""
    db = await get_db()
    await db.execute(
        """INSERT OR REPLACE INTO scheduled_rules
           (rule_name, rule_source, rule_content, schedule_cron, enabled, created_at)
           VALUES (?, ?, ?, ?, 1, ?)""",
        (rule_name, rule_source, rule_content, schedule_cron,
         datetime.now(tz=timezone.utc).isoformat()),
    )
    await db.commit()


async def list_scheduled_rules() -> list[dict]:
    """List all scheduled rules."""
    db = await get_db()
    async with db.execute("SELECT * FROM scheduled_rules ORDER BY rule_name") as cur:
        return [dict(r) for r in await cur.fetchall()]


async def update_scheduled_run(
    rule_name: str, verdict: str, alert_count: int,
) -> None:
    """Update the last run results for a scheduled rule."""
    db = await get_db()
    await db.execute(
        """UPDATE scheduled_rules
           SET last_run_at = ?, last_verdict = ?, last_alert_count = ?
           WHERE rule_name = ?""",
        (datetime.now(tz=timezone.utc).isoformat(), verdict, alert_count, rule_name),
    )
    await db.commit()
