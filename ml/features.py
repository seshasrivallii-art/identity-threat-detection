"""Per-login behavioral features for UEBA-style anomaly detection.
Each feature is computed only from that user's PAST events (no leakage)."""
from datetime import timedelta

import numpy as np
import pandas as pd

from detections.common import haversine_km

FEATURES = ["hour", "is_weekend", "new_device", "new_country", "new_asn", "new_ua",
            "km_from_home", "speed_kmh", "fails_1h", "mfa_denials_1h"]


def build(df):
    df = df.sort_values("timestamp")
    rows = []
    for user, g in df.groupby("user_id"):
        seen = {"device_id": set(), "country": set(), "asn": set(), "user_agent": set()}
        home = None
        prev_login = None
        fails = g[(g.event_type == "login") & (g.result == "failure")].timestamp
        denials = g[(g.event_type == "mfa_push") & g.mfa_result.isin(["denied", "timeout"])].timestamp
        for _, e in g[(g.event_type == "login") & (g.result == "success")].iterrows():
            t = e.timestamp
            if home is None:
                home = (e.lat, e.lon)
            speed = 0.0
            if prev_login is not None:
                d = haversine_km(prev_login.lat, prev_login.lon, e.lat, e.lon)
                hrs = max((t - prev_login.timestamp).total_seconds() / 3600, 1 / 60)
                speed = d / hrs
            rows.append({
                "event_id": e.event_id, "user_id": user, "timestamp": t,
                "hour": t.hour, "is_weekend": int(t.weekday() >= 5),
                "new_device": int(bool(seen["device_id"]) and e.device_id not in seen["device_id"]),
                "new_country": int(bool(seen["country"]) and e.country not in seen["country"]),
                "new_asn": int(bool(seen["asn"]) and e.asn not in seen["asn"]),
                "new_ua": int(bool(seen["user_agent"]) and e.user_agent not in seen["user_agent"]),
                "km_from_home": float(haversine_km(home[0], home[1], e.lat, e.lon)),
                "speed_kmh": float(speed),
                "fails_1h": int(((fails > t - timedelta(hours=1)) & (fails <= t)).sum()),
                "mfa_denials_1h": int(((denials > t - timedelta(hours=1)) & (denials <= t)).sum()),
            })
            for k in seen:
                seen[k].add(e[k])
            prev_login = e
    f = pd.DataFrame(rows)
    f["km_from_home"] = np.log1p(f.km_from_home)
    f["speed_kmh"] = np.log1p(f.speed_kmh)
    return f
