"""Score the detector against the dataset's ground-truth labels.

CICIDS2017 labels every flow (BENIGN, PortScan, DDoS, ...). The labels are
never used for detection or shown to the AI; they are only used here to
measure how well the rules work.
"""
import pandas as pd

from backend import storage
from backend.models import Alert


def _in_alert(flows: pd.DataFrame, alert: Alert) -> pd.Series:
    return ((flows["src_ip"] == alert.source)
            & (flows["window_start"] >= alert.window_start)
            & (flows["window_start"] < alert.window_end))


def evaluate(dataset: str, alerts: list[Alert], db_path=None) -> dict:
    flows = storage.load_flows_with_labels(dataset, db_path=db_path)
    if flows.empty or flows["label"].isna().all():
        return {"available": False}
    is_attack = flows["label"].fillna("BENIGN") != "BENIGN"

    covered = pd.Series(False, index=flows.index)
    per_alert = []
    for alert in alerts:
        mask = _in_alert(flows, alert)
        covered |= mask
        labels = flows.loc[mask, "label"].value_counts()
        per_alert.append({
            "alert_id": alert.alert_id,
            "rule": alert.rule_name,
            "source": alert.source,
            "flows": int(mask.sum()),
            "attack_flows": int((mask & is_attack).sum()),
            "attack_share": round(float((mask & is_attack).sum() / mask.sum()), 3) if mask.any() else 0.0,
            "labels": {str(k): int(v) for k, v in labels.items()},
        })

    by_label = []
    for label, group in flows[is_attack].groupby("label"):
        by_label.append({"label": label, "attack_flows": len(group),
                         "flows_inside_alerts": int(covered[group.index].sum())})

    flows_in_alerts = int(covered.sum())
    attack_total = int(is_attack.sum())
    attack_caught = int((covered & is_attack).sum())
    return {
        "available": True,
        "total_flows": len(flows),
        "attack_flows": attack_total,
        "flows_in_alerts": flows_in_alerts,
        "attack_flows_in_alerts": attack_caught,
        # Share of flows inside alerts that really were attacks.
        "precision": attack_caught / flows_in_alerts if flows_in_alerts else None,
        # Share of attack flows that fell inside some alert.
        "recall": attack_caught / attack_total if attack_total else None,
        "per_alert": per_alert,
        "by_label": by_label,
    }
