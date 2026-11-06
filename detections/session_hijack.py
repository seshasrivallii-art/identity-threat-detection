"""Session hijacking: a session token used with attributes different from the ones it was issued with.
MITRE ATT&CK T1539 (Steal Web Session Cookie) / T1550.004 (Use Alternate Auth Material: Web Session Cookie)."""
from detections.common import make_alerts


def detect(df):
    ev = df[df.session_id.notna() & df.event_type.isin(["login", "token_use"])].sort_values("timestamp")
    out = []
    for sid, g in ev.groupby("session_id"):
        issued = g[g.event_type == "login"]
        if issued.empty:
            continue  # token with no interactive login in our data window
        base = issued.iloc[0]
        for _, e in g[g.timestamp > base.timestamp].iterrows():
            changed = [a for a in ["asn", "country", "user_agent", "device_id"] if e[a] != base[a]]
            if not changed:
                continue
            # an ASN-only change in the same country is usually wifi -> cellular
            if changed == ["asn"]:
                continue
            sev = "critical" if "country" in changed and "user_agent" in changed else "high"
            out.append({
                "alert_type": "session_hijack", "user_id": e.user_id, "timestamp": e.timestamp,
                "severity": sev, "mitre": "T1539",
                "evidence": (f"session {sid} issued in {base.city},{base.country} on "
                             f"'{base.user_agent[:30]}' reused from {e.city},{e.country}; changed: "
                             + ", ".join(changed)),
                "event_ids": [int(base.event_id), int(e.event_id)],
            })
    alerts = make_alerts(out)
    # one alert per session is enough for an analyst
    if not alerts.empty:
        alerts["sid"] = alerts.evidence.str.extract(r"session (\S+)")
        alerts = alerts.sort_values("timestamp").groupby("sid", as_index=False).first().drop(columns="sid")
    return alerts
