"""MFA fatigue / push bombing: a burst of denied or timed-out pushes followed by an approval.
MITRE ATT&CK T1621 (Multi-Factor Authentication Request Generation)."""
from datetime import timedelta

import config
from detections.common import make_alerts


def detect(df):
    pushes = df[df.event_type == "mfa_push"].sort_values(["user_id", "timestamp"])
    window = timedelta(minutes=config.MFA_WINDOW_MINUTES)
    out = []
    for user, g in pushes.groupby("user_id"):
        for i in g.index[g.mfa_result == "approved"]:
            t = g.at[i, "timestamp"]
            burst = g[(g.timestamp >= t - window) & (g.timestamp <= t)]
            denials = burst.mfa_result.isin(["denied", "timeout"]).sum()
            if len(burst) < config.MFA_MIN_PUSHES or denials < config.MFA_MIN_DENIALS:
                continue
            hour = t.hour
            off_hours = hour < 6 or hour >= 22
            sev = "critical" if off_hours else "high"
            out.append({
                "alert_type": "mfa_fatigue", "user_id": user, "timestamp": t, "severity": sev,
                "mitre": "T1621",
                "evidence": (f"{len(burst)} pushes / {denials} denied-or-timeout in "
                             f"{config.MFA_WINDOW_MINUTES} min, then APPROVED from "
                             f"{g.at[i,'city']},{g.at[i,'country']} ({g.at[i,'asn']})"
                             + ("; off-hours" if off_hours else "")),
                "event_ids": [int(x) for x in burst.event_id],
            })
    return make_alerts(out)
