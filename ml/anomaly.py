"""Isolation Forest trained on the baseline period, then used to score later logins."""
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import config
from detections.common import make_alerts
from ml.features import FEATURES


def detect(features):
    cutoff = features.timestamp.min().normalize() + pd.Timedelta(days=config.BASELINE_DAYS)
    train = features[features.timestamp < cutoff]
    test = features[features.timestamp >= cutoff].copy()

    scaler = StandardScaler().fit(train[FEATURES])
    model = IsolationForest(n_estimators=300, contamination=config.ISOLATION_CONTAMINATION, random_state=0)
    model.fit(scaler.transform(train[FEATURES]))

    test["anomaly_score"] = -model.score_samples(scaler.transform(test[FEATURES]))
    threshold = -model.offset_
    flagged = test[test.anomaly_score > threshold]

    out = []
    for _, r in flagged.iterrows():
        reasons = [f for f in ["new_device", "new_country", "new_asn", "new_ua"] if r[f]]
        if r.fails_1h: reasons.append(f"{r.fails_1h} failed logins/1h")
        if r.mfa_denials_1h: reasons.append(f"{r.mfa_denials_1h} MFA denials/1h")
        if r.hour < 6 or r.hour >= 22: reasons.append(f"login at {r.hour:02d}:00")
        out.append({
            "alert_type": "ml_anomaly", "user_id": r.user_id, "timestamp": r.timestamp,
            "severity": "high" if r.anomaly_score > threshold + 0.1 else "medium", "mitre": "T1078",
            "evidence": f"anomaly score {r.anomaly_score:.3f} (thr {threshold:.3f}); " + (", ".join(reasons) or "unusual combination"),
            "event_ids": [int(r.event_id)],
        })
    return make_alerts(out), test
