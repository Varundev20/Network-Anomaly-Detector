"""Read-only analysis tools the AI investigator is allowed to call.

Each tool takes an alert_id, reads stored data through storage.py and
returns a small JSON-able dict. The app (not the model) decides which tools
exist, validates the arguments and only allows the alert being investigated.
None of the tools return the ground-truth Label column.
"""
from typing import Any, Callable

import pandas as pd

from backend import config, storage
from backend.data_loader import PROTOCOL_NAMES


class ToolError(ValueError):
    pass


def _alert_or_error(alert_id: int, db_path):
    alert = storage.get_alert(alert_id, db_path=db_path)
    if alert is None:
        raise ToolError(f"Alert {alert_id} does not exist.")
    return alert


def get_alert_details(alert_id: int, db_path=None) -> dict[str, Any]:
    """The facts the detector recorded when the alert fired."""
    alert = _alert_or_error(alert_id, db_path)
    return {
        "alert_id": alert.alert_id,
        "rule_name": alert.rule_name,
        "rule_description": config.RULE_DESCRIPTIONS[alert.rule_name],
        "source_ip": alert.source,
        "window_start": alert.window_start,
        "window_end": alert.window_end,
        "window_seconds": config.WINDOW_SECONDS,
        "windows_triggered": alert.window_count,
        "metric": alert.evidence["metric"],
        "peak_value": alert.measured_value,
        "threshold": alert.threshold,
        "times_over_threshold": round(alert.measured_value / alert.threshold, 1),
        "value_per_window": alert.evidence["per_window"],
        "total_flows_in_alert": alert.evidence["total_flows"],
        "severity_label": alert.severity_label,
    }


def count_distinct_ports(alert_id: int, db_path=None) -> dict[str, Any]:
    """Which destination hosts and ports the source contacted."""
    alert = _alert_or_error(alert_id, db_path)
    flows = storage.flows_for_alert(alert, db_path=db_path)
    ports = flows["dst_port"]
    service = ports[ports < config.SERVICE_PORT_LIMIT]
    top_ports = ports.value_counts().head(10)
    top_dsts = flows["dst_ip"].value_counts().head(5)
    return {
        "alert_id": alert_id,
        "flows_examined": int(len(flows)),
        "distinct_destination_ports": int(ports.nunique()),
        "distinct_service_ports_below_1024": int(service.nunique()),
        "lowest_port": int(ports.min()) if len(ports) else None,
        "highest_port": int(ports.max()) if len(ports) else None,
        "top_ports": [{"port": int(p), "flows": int(n)} for p, n in top_ports.items()],
        "distinct_destination_hosts": int(flows["dst_ip"].nunique()),
        "top_destination_hosts": [{"ip": str(ip), "flows": int(n)} for ip, n in top_dsts.items()],
    }


def summarize_time_window(alert_id: int, db_path=None) -> dict[str, Any]:
    """How the flows behaved, and how the source compares with other hosts."""
    alert = _alert_or_error(alert_id, db_path)
    flows = storage.flows_for_alert(alert, db_path=db_path)
    n = len(flows)
    if n == 0:
        raise ToolError("No stored flows for this alert.")
    protocols = flows["protocol"].map(lambda p: PROTOCOL_NAMES.get(int(p), str(int(p))) if pd.notna(p) else "unknown")
    no_reply = (flows["bwd_packets"].fillna(0) == 0).mean()
    tiny = (flows["fwd_packets"].fillna(0) <= 2).mean()

    others = storage.flows_in_range(alert.dataset, alert.window_start, alert.window_end, db_path=db_path)
    others = others[others["src_ip"] != alert.source]
    per_source = others.groupby(["src_ip", "window_start"]).size()
    return {
        "alert_id": alert_id,
        "flows": int(n),
        "flows_per_60s_window": [{"window_start": k, "flows": int(v)}
                                 for k, v in flows.groupby("window_start").size().items()],
        "protocol_share": {k: round(float(v), 3) for k, v in protocols.value_counts(normalize=True).items()},
        "median_flow_duration_ms": round(float(flows["duration_us"].median()) / 1000, 2),
        "median_forward_packets": float(flows["fwd_packets"].median()),
        "median_backward_packets": float(flows["bwd_packets"].median()),
        "share_of_flows_with_no_reply_packets": round(float(no_reply), 3),
        "share_of_flows_with_at_most_2_forward_packets": round(float(tiny), 3),
        # SYN Flag Count is left out on purpose: in CICIDS2017 it is
        # unreliable (almost always 0) and would mislead the model.
        "other_sources_active_in_same_windows": int(others["src_ip"].nunique()),
        "other_sources_median_flows_per_minute": float(per_source.median()) if len(per_source) else 0.0,
        "other_sources_max_flows_per_minute": int(per_source.max()) if len(per_source) else 0,
    }


TOOLS: dict[str, Callable[..., dict[str, Any]]] = {
    "get_alert_details": get_alert_details,
    "count_distinct_ports": count_distinct_ports,
    "summarize_time_window": summarize_time_window,
}

TOOL_DESCRIPTIONS = {
    "get_alert_details": "Get the facts the rule-based detector recorded for the alert: rule, source IP, time windows, measured values and threshold. Call this first.",
    "count_distinct_ports": "Count the destination ports and hosts the alert's source contacted during the alert, with the most frequent ports.",
    "summarize_time_window": "Summarise the alert's flows (protocols, durations, packets, replies, flows per minute) and compare the source with other hosts in the same minutes.",
}


def ollama_tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": TOOL_DESCRIPTIONS[name],
                "parameters": {
                    "type": "object",
                    "properties": {"alert_id": {"type": "integer", "description": "ID of the alert"}},
                    "required": ["alert_id"],
                },
            },
        }
        for name in TOOLS
    ]


def run_tool(name: str, arguments: dict[str, Any], allowed_alert_id: int, db_path=None) -> dict[str, Any]:
    """Validate and run one tool call. Errors are returned, not raised,
    so the model can see what went wrong."""
    if name not in TOOLS:
        return {"error": f"Unknown tool '{name}'. Allowed: {', '.join(TOOLS)}"}
    try:
        alert_id = int(arguments.get("alert_id"))
    except (TypeError, ValueError):
        return {"error": "alert_id must be an integer."}
    if alert_id != allowed_alert_id:
        return {"error": f"Only alert {allowed_alert_id} may be investigated in this session."}
    try:
        return TOOLS[name](alert_id, db_path=db_path)
    except ToolError as exc:
        return {"error": str(exc)}
