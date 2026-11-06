"""End-to-end ITDR pipeline: load logs -> detect -> ML -> score -> evaluate -> export.

Usage:  python run_pipeline.py --logs data/auth_logs.csv
"""
import argparse
import json
from pathlib import Path

import pandas as pd

from detections import impossible_travel, mfa_fatigue, session_hijack
from evaluate import evaluate
from ml import anomaly, features
from scoring import risk


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--logs", default="data/auth_logs.csv")
    p.add_argument("--out", default="output")
    a = p.parse_args()
    out = Path(a.out); out.mkdir(exist_ok=True)

    logs = pd.read_csv(a.logs, parse_dates=["timestamp"])
    print(f"[+] Loaded {len(logs):,} events for {logs.user_id.nunique()} users")

    results = []
    for name, mod in [("impossible travel", impossible_travel), ("MFA fatigue", mfa_fatigue),
                      ("session hijack", session_hijack)]:
        r = mod.detect(logs)
        print(f"[+] {name:18s} -> {len(r)} alerts")
        results.append(r)

    feats = features.build(logs)
    ml_alerts, scored = anomaly.detect(feats)
    print(f"[+] {'ML anomaly':18s} -> {len(ml_alerts)} alerts")
    results.append(ml_alerts)

    alerts = pd.concat(results, ignore_index=True).sort_values("timestamp")
    users = risk.score(alerts)

    # exports
    alerts.to_csv(out / "alerts.csv", index=False)
    users.to_csv(out / "user_risk.csv", index=False)
    scored.to_csv(out / "ml_scores.csv", index=False)
    with open(out / "alerts.json", "w") as f:  # SOAR / ticketing friendly
        for rec in alerts.to_dict("records"):
            rec["timestamp"] = str(rec["timestamp"])
            f.write(json.dumps(rec) + "\n")

    if "label" in logs.columns:  # only possible with labeled (synthetic) data
        det, hybrid = evaluate(logs, alerts)
        print("\n=== Detector performance ===")
        print(det.to_string(index=False, float_format=lambda x: f"{x:.2f}"))
        print("\n=== Coverage with all detectors combined ===")
        print(hybrid.to_string(index=False))
        (out / "evaluation.md").write_text(det.to_markdown(index=False) + "\n\n" + hybrid.to_markdown(index=False)
                                           if hasattr(det, "to_markdown") else det.to_string())

    print("\n=== Top 10 risky users ===")
    print(users.head(10).to_string(index=False))
    print(f"\n[+] Outputs written to {out}/")


if __name__ == "__main__":
    main()
