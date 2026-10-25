"""SQLite storage for flows, alerts and investigation history.

All SQL lives here so the UI and the AI tools never build their own queries.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pandas as pd

from backend import config
from backend.models import Alert, Investigation

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    dataset TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    window_start TEXT NOT NULL,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
    protocol INTEGER, duration_us REAL, fwd_packets REAL, bwd_packets REAL,
    fwd_bytes REAL, bwd_bytes REAL, syn_flags REAL,
    label TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_lookup ON flows (dataset, src_ip, window_start);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset TEXT NOT NULL,
    created_at TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity_label TEXT NOT NULL,
    source TEXT NOT NULL,
    measured_value INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    window_count INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    ai_report TEXT
);
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    report_json TEXT NOT NULL,
    tool_calls_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL,
    duration_seconds REAL,
    tokens_generated INTEGER,
    tokens_per_second REAL,
    error TEXT
);
CREATE TABLE IF NOT EXISTS datasets (
    dataset TEXT PRIMARY KEY,
    loaded_at TEXT NOT NULL,
    rows_read INTEGER, rows_kept INTEGER,
    load_report_json TEXT
);
"""

FLOW_COLUMNS = ["timestamp", "window_start", "src_ip", "src_port", "dst_ip", "dst_port",
                "protocol", "duration_us", "fwd_packets", "bwd_packets", "fwd_bytes",
                "bwd_bytes", "syn_flags", "label"]


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


@contextmanager
def connect(db_path: Path | str | None = None):
    conn = sqlite3.connect(db_path or config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_analysis(dataset: str, flows: pd.DataFrame, alerts: list[Alert],
                  load_report: dict | None = None, db_path=None) -> list[Alert]:
    """Replace any earlier analysis of `dataset` with these flows and alerts."""
    rows = flows.copy()
    if "window_start" not in rows.columns:
        rows["window_start"] = rows["timestamp"].dt.floor(f"{config.WINDOW_SECONDS}s")
    for col in ("timestamp", "window_start"):
        rows[col] = rows[col].dt.strftime("%Y-%m-%dT%H:%M:%S")
    rows = rows[[c for c in FLOW_COLUMNS if c in rows.columns]].astype(object)
    rows = rows.where(rows.notna(), None)
    rows.insert(0, "dataset", dataset)

    created = now_iso()
    with connect(db_path) as conn:
        conn.execute("DELETE FROM alerts WHERE dataset = ?", (dataset,))
        conn.execute("DELETE FROM flows WHERE dataset = ?", (dataset,))
        placeholders = ",".join("?" * len(rows.columns))
        conn.executemany(
            f"INSERT INTO flows ({','.join(rows.columns)}) VALUES ({placeholders})",
            rows.itertuples(index=False, name=None),
        )
        for alert in alerts:
            cur = conn.execute(
                """INSERT INTO alerts (dataset, created_at, rule_name, severity_label, source,
                   measured_value, threshold, window_start, window_end, window_count, evidence_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (dataset, created, alert.rule_name, alert.severity_label, alert.source,
                 alert.measured_value, alert.threshold, alert.window_start, alert.window_end,
                 alert.window_count, json.dumps(alert.evidence)),
            )
            alert.alert_id = cur.lastrowid
            alert.dataset = dataset
            alert.created_at = created
        conn.execute(
            "INSERT OR REPLACE INTO datasets VALUES (?,?,?,?,?)",
            (dataset, created, (load_report or {}).get("rows_read"),
             (load_report or {}).get("rows_kept"), json.dumps(load_report or {})),
        )
    return alerts


def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(
        alert_id=row["alert_id"], dataset=row["dataset"], created_at=row["created_at"],
        rule_name=row["rule_name"], severity_label=row["severity_label"], source=row["source"],
        measured_value=row["measured_value"], threshold=row["threshold"],
        window_start=row["window_start"], window_end=row["window_end"],
        window_count=row["window_count"], evidence=json.loads(row["evidence_json"]),
        status=row["status"],
    )


def list_alerts(dataset: str, db_path=None) -> list[Alert]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE dataset = ? ORDER BY window_start, alert_id", (dataset,)
        ).fetchall()
    return [_row_to_alert(r) for r in rows]


def get_alert(alert_id: int, db_path=None) -> Alert | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    return _row_to_alert(row) if row else None


def set_alert_status(alert_id: int, status: str, db_path=None) -> None:
    with connect(db_path) as conn:
        conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))


def flows_for_alert(alert: Alert, include_label: bool = False, db_path=None) -> pd.DataFrame:
    """Flows from the alert's source inside the alert's time range.

    The ground-truth label is excluded unless explicitly requested, so it can
    never leak into anything shown to the model.
    """
    columns = [c for c in FLOW_COLUMNS if include_label or c != "label"]
    with connect(db_path) as conn:
        df = pd.read_sql_query(
            f"SELECT {','.join(columns)} FROM flows WHERE dataset = ? AND src_ip = ? "
            "AND window_start >= ? AND window_start < ?",
            conn, params=(alert.dataset, alert.source, alert.window_start, alert.window_end),
        )
    return df


def flows_in_range(dataset: str, start: str, end: str, db_path=None) -> pd.DataFrame:
    """All sources' flows in a time range (no labels). Used for comparison."""
    with connect(db_path) as conn:
        return pd.read_sql_query(
            "SELECT src_ip, window_start FROM flows WHERE dataset = ? "
            "AND window_start >= ? AND window_start < ?",
            conn, params=(dataset, start, end),
        )


def load_flows_with_labels(dataset: str, db_path=None) -> pd.DataFrame:
    """Every flow incl. label. Only used by the evaluation tab, never the AI."""
    with connect(db_path) as conn:
        return pd.read_sql_query(
            "SELECT src_ip, window_start, label FROM flows WHERE dataset = ?",
            conn, params=(dataset,),
        )


def flow_count(dataset: str, db_path=None) -> int:
    with connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM flows WHERE dataset = ?", (dataset,)).fetchone()[0]


def get_dataset_info(dataset: str, db_path=None) -> dict | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM datasets WHERE dataset = ?", (dataset,)).fetchone()
    return dict(row) | {"load_report": json.loads(row["load_report_json"] or "{}")} if row else None


def flows_per_window(dataset: str, db_path=None) -> pd.DataFrame:
    with connect(db_path) as conn:
        return pd.read_sql_query(
            "SELECT window_start, COUNT(*) AS flows FROM flows WHERE dataset = ? "
            "GROUP BY window_start ORDER BY window_start",
            conn, params=(dataset,),
        )


def save_investigation(inv: Investigation, db_path=None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO investigations (alert_id, started_at, model, status, report_json,
               tool_calls_json, warnings_json, duration_seconds, tokens_generated,
               tokens_per_second, error) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (inv.alert_id, inv.started_at, inv.model, inv.status, json.dumps(inv.report),
             json.dumps([tc.__dict__ for tc in inv.tool_calls]), json.dumps(inv.warnings),
             inv.duration_seconds, inv.tokens_generated, inv.tokens_per_second, inv.error),
        )
        conn.execute("UPDATE alerts SET ai_report = ? WHERE alert_id = ?",
                     (json.dumps(inv.report), inv.alert_id))
        inv.investigation_id = cur.lastrowid
    return inv.investigation_id


def list_investigations(alert_id: int, db_path=None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM investigations WHERE alert_id = ? ORDER BY investigation_id DESC",
            (alert_id,),
        ).fetchall()
    result = []
    for r in rows:
        item = dict(r)
        item["report"] = json.loads(item.pop("report_json"))
        item["tool_calls"] = json.loads(item.pop("tool_calls_json"))
        item["warnings"] = json.loads(item.pop("warnings_json"))
        result.append(item)
    return result
