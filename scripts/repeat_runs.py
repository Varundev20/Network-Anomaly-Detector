"""Run the full workflow N times and write a results log for the submission.

Each run: load sample -> detect -> store -> investigate one alert with the
local model. Results go to results/repeat_runs.md and results/repeat_runs.json.

Usage:
    python scripts/repeat_runs.py --dataset portscan_sample.csv --rule port_spread --runs 3
"""
import argparse
import json
import platform
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend import config  # noqa: E402
from agent import investigator  # noqa: E402
from backend import storage  # noqa: E402
from backend.data_loader import load_flows  # noqa: E402
from backend.detector import detect  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="portscan_sample.csv")
    parser.add_argument("--rule", default="port_spread")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--model", default=config.OLLAMA_MODEL)
    parser.add_argument("--out", default=ROOT / "results")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)
    db_path = out_dir / "repeat_runs.db"
    db_path.unlink(missing_ok=True)

    runs = []
    for i in range(1, args.runs + 1):
        flows, report = load_flows(config.SAMPLE_DIR / args.dataset, name=args.dataset)
        alerts = storage.save_analysis(args.dataset, flows, detect(flows), report.__dict__, db_path=db_path)
        alert = next(a for a in alerts if a.rule_name == args.rule)
        print(f"Run {i}: {len(alerts)} alert(s); investigating #{alert.alert_id} "
              f"({alert.rule_name}, peak {alert.measured_value}) with {args.model}...", flush=True)
        inv = investigator.investigate(alert.alert_id, model=args.model, db_path=db_path)
        print(f"  -> {inv.status} in {inv.duration_seconds}s, {inv.tokens_per_second} tok/s, "
              f"tools: {[tc.name for tc in inv.tool_calls]}", flush=True)
        runs.append({
            "run": i,
            "alerts_detected": len(alerts),
            "alert": {k: getattr(alert, k) for k in ("rule_name", "source", "measured_value",
                                                     "threshold", "window_start", "window_end")},
            "investigation": inv.to_dict(),
        })

    meta = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": args.dataset, "model": args.model, "runtime": "Ollama",
        "options": config.MODEL_OPTIONS,
        "machine": {"os": platform.platform(), "cpu": platform.processor()},
    }
    (out_dir / "repeat_runs.json").write_text(json.dumps({"meta": meta, "runs": runs}, indent=2))

    lines = [
        f"# Repeated-run results ({args.runs} runs)", "",
        f"- Generated: {meta['generated_at']}",
        f"- Dataset: `data/sample_data/{args.dataset}`, alert rule: `{args.rule}`",
        f"- Model: `{args.model}` via Ollama, options `{json.dumps(config.MODEL_OPTIONS)}`",
        f"- Machine: {meta['machine']['os']}, {meta['machine']['cpu']}", "",
        "| Run | Alerts | Peak / threshold | Status | Tool calls (by model) | Confidence | Time (s) | Tokens/s | Guardrail notes |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in runs:
        inv = r["investigation"]
        tools_used = ", ".join(f"{tc['name']}{'' if tc['requested_by'] == 'model' else ' (app)'}"
                               for tc in inv["tool_calls"])
        lines.append(
            f"| {r['run']} | {r['alerts_detected']} | {r['alert']['measured_value']} / {r['alert']['threshold']} "
            f"| {inv['status']} | {tools_used} | {inv['report'].get('confidence')} "
            f"| {inv['duration_seconds']} | {inv['tokens_per_second']} | {'; '.join(inv['warnings']) or '-'} |")
    for r in runs:
        lines += ["", f"## Run {r['run']} report", "", "```json",
                  json.dumps(r["investigation"]["report"], indent=2), "```"]
    (out_dir / "repeat_runs.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    db_path.unlink(missing_ok=True)
    print(f"Wrote {out_dir / 'repeat_runs.md'}")


if __name__ == "__main__":
    main()
