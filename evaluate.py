"""Precision / recall per detector against the injected ground-truth labels.

Precision: an alert is a true positive if it involves ANY attack event (an MFA-fatigue
attacker logging in from Lagos is also impossible travel, and that is a correct alert).
Recall: share of attacks of the detector's own type that it caught."""
import pandas as pd

TARGET = {"impossible_travel": "impossible_travel", "mfa_fatigue": "mfa_fatigue",
          "session_hijack": "session_hijack", "ml_anomaly": None}  # None = any attack


def evaluate(logs, alerts):
    by_id = logs.set_index("event_id")
    attacks = logs[logs.label == 1].groupby("attack_id").attack_type.first()
    rows, caught_any = [], set()

    for det, target in TARGET.items():
        a = alerts[alerts.alert_type == det]
        tp_alerts, caught = 0, set()
        for ids in a.event_ids:
            ev = by_id.loc[ids]
            hits = ev[ev.label == 1]
            if len(hits):              # alert touched a real attack (any type) -> true positive
                tp_alerts += 1
            if target:                 # recall only counts attacks of the detector's own type
                hits = hits[hits.attack_type == target]
            caught |= set(hits.attack_id)
        caught_any |= caught
        pool = attacks if target is None else attacks[attacks == target]
        rows.append({
            "detector": det, "alerts": len(a), "true_pos": tp_alerts, "false_pos": len(a) - tp_alerts,
            "precision": tp_alerts / len(a) if len(a) else 0.0,
            "attacks_caught": f"{len(caught & set(pool.index))}/{len(pool)}",
            "recall": len(caught & set(pool.index)) / len(pool) if len(pool) else 0.0,
        })

    # recall of every detector combined, broken down by attack type
    hybrid = []
    for t, ids in attacks.groupby(attacks).groups.items():
        hybrid.append({"attack_type": t, "caught_by_any": f"{len(set(ids) & caught_any)}/{len(ids)}"})
    return pd.DataFrame(rows), pd.DataFrame(hybrid)
