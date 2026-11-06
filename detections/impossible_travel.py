"""Impossible travel: consecutive successful logins whose implied speed is unrealistic.
MITRE ATT&CK T1078 (Valid Accounts)."""
import config
from detections.common import haversine_km, make_alerts


def detect(df):
    logins = df[(df.event_type == "login") & (df.result == "success")].sort_values(["user_id", "timestamp"])
    out = []
    for user, g in logins.groupby("user_id"):
        prev = g.shift(1)
        dist = haversine_km(prev.lat, prev.lon, g.lat, g.lon)
        hours = (g.timestamp - prev.timestamp).dt.total_seconds() / 3600
        speed = dist / hours.clip(lower=1 / 60)  # avoid div-by-zero
        for i in g.index[1:]:
            p = prev.loc[i]
            if p.asn in config.TRUSTED_ASNS or g.at[i, "asn"] in config.TRUSTED_ASNS:
                continue
            if dist[i] < config.MIN_TRAVEL_DISTANCE_KM or speed[i] < config.MAX_TRAVEL_SPEED_KMH:
                continue
            history = g.loc[:i].iloc[:-1]
            if config.SUPPRESS_FAMILIAR_ASN and g.at[i, "asn"] in set(history.asn):
                continue  # familiar network (e.g. the user's own consumer VPN)
            new_country = g.at[i, "country"] not in set(history.country)
            sev = "high" if new_country else "medium"
            out.append({
                "alert_type": "impossible_travel", "user_id": user, "timestamp": g.at[i, "timestamp"],
                "severity": sev, "mitre": "T1078",
                "evidence": (f"{p.city},{p.country} -> {g.at[i,'city']},{g.at[i,'country']}: "
                             f"{dist[i]:,.0f} km in {hours[i]*60:.0f} min ({speed[i]:,.0f} km/h)"
                             + ("; never-seen country" if new_country else "")),
                "event_ids": [int(p.event_id), int(g.at[i, "event_id"])],
            })
    return make_alerts(out)
