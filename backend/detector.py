"""Rule-based anomaly detection over fixed time windows.

The detector is fully deterministic: the same flows and thresholds always
produce the same alerts. The AI never decides whether an alert exists.
"""
import pandas as pd

from backend import config
from backend.models import Alert


def add_windows(flows: pd.DataFrame, window_seconds: int = config.WINDOW_SECONDS) -> pd.DataFrame:
    """Add a window_start column (timestamp rounded down to the window)."""
    flows = flows.copy()
    flows["window_start"] = flows["timestamp"].dt.floor(f"{window_seconds}s")
    return flows


def window_stats(flows: pd.DataFrame, service_port_limit: int = config.SERVICE_PORT_LIMIT) -> pd.DataFrame:
    """Per source and window: flow count and distinct service ports."""
    service_port = flows["dst_port"].where(flows["dst_port"] < service_port_limit)
    stats = (
        flows.assign(service_port=service_port)
        .groupby(["src_ip", "window_start"])
        .agg(flow_count=("dst_port", "size"),
             distinct_service_ports=("service_port", "nunique"),
             distinct_ports=("dst_port", "nunique"),
             distinct_destinations=("dst_ip", "nunique"))
        .reset_index()
    )
    return stats


def severity_label(measured: int, threshold: int) -> str:
    """Rough label for sorting only; it is not a statement of danger."""
    ratio = measured / threshold if threshold else 0
    if ratio >= 5:
        return "high"
    if ratio >= 2:
        return "medium"
    return "low"


def _merge_windows(hits: pd.DataFrame, gap: pd.Timedelta) -> list[pd.DataFrame]:
    """Split one source's triggering windows into runs of nearby windows."""
    hits = hits.sort_values("window_start")
    new_group = hits["window_start"].diff() > gap
    return [g for _, g in hits.groupby(new_group.cumsum())]


def detect(flows: pd.DataFrame,
           burst_threshold: int = config.CONNECTION_BURST_THRESHOLD,
           port_spread_threshold: int = config.PORT_SPREAD_THRESHOLD,
           window_seconds: int = config.WINDOW_SECONDS) -> list[Alert]:
    """Run every rule and return merged alerts, oldest first."""
    if flows.empty:
        return []
    windowed = add_windows(flows, window_seconds)
    stats = window_stats(windowed)
    window = pd.Timedelta(seconds=window_seconds)
    gap = window * (config.MERGE_GAP_WINDOWS + 1)

    rules = [
        ("connection_burst", "flow_count", burst_threshold),
        ("port_spread", "distinct_service_ports", port_spread_threshold),
    ]
    alerts: list[Alert] = []
    for rule_name, metric, threshold in rules:
        triggered = stats[stats[metric] > threshold]
        for source, source_hits in triggered.groupby("src_ip"):
            for run in _merge_windows(source_hits, gap):
                peak = int(run[metric].max())
                start = run["window_start"].min()
                end = run["window_start"].max() + window
                per_window = [
                    {"window_start": ws.isoformat(), "value": int(v)}
                    for ws, v in zip(run["window_start"], run[metric])
                ]
                evidence = {
                    "metric": metric,
                    "per_window": per_window,
                    "total_flows": int(run["flow_count"].sum()),
                    "max_distinct_destinations": int(run["distinct_destinations"].max()),
                }
                alerts.append(Alert(
                    rule_name=rule_name,
                    severity_label=severity_label(peak, threshold),
                    source=str(source),
                    measured_value=peak,
                    threshold=threshold,
                    window_start=start.isoformat(),
                    window_end=end.isoformat(),
                    window_count=len(run),
                    evidence=evidence,
                ))
    alerts.sort(key=lambda a: (a.window_start, a.rule_name, a.source))
    return alerts
