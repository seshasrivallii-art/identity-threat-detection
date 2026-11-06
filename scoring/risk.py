"""Combine alerts into a 0-100 risk score per user (like Entra ID Protection 'risky users')."""
import pandas as pd

import config

SEV_MULT = {"medium": 0.6, "high": 1.0, "critical": 1.3}


def score(alerts):
    if alerts.empty:
        return pd.DataFrame(columns=["user_id", "risk_score", "alert_types", "alerts"])
    a = alerts.copy()
    a["points"] = a.alert_type.map(config.WEIGHTS) * a.severity.map(SEV_MULT)
    # count each alert type once per user (max), so 10 duplicate alerts don't max out the score
    per_type = a.groupby(["user_id", "alert_type"]).points.max().reset_index()
    users = per_type.groupby("user_id").agg(risk_score=("points", "sum"),
                                            alert_types=("alert_type", lambda s: ", ".join(sorted(s))))
    users["risk_score"] = users.risk_score.clip(upper=100).round().astype(int)
    users["alerts"] = a.groupby("user_id").size()
    return users.reset_index().sort_values("risk_score", ascending=False)
