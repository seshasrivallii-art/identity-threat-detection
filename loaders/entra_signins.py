"""
Convert a Microsoft Entra ID sign-in log export (JSON, from the portal's
Sign-in logs > Download, or Graph /auditLogs/signIns) into this project's schema.

Usage:  python -m loaders.entra_signins SignIns.json data/real_logs.csv
        python run_pipeline.py --logs data/real_logs.csv

Field names follow the Graph signIn resource. Some (sessionId,
autonomousSystemNumber) are only in the beta endpoint, so check your export
and adjust the .get() paths if a column comes out empty.
"""
import json
import sys

import pandas as pd


def g(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
    return default if d is None else d


def convert(records):
    rows = []
    for r in records:
        ok = g(r, "status", "errorCode", default=0) == 0
        base = {
            "timestamp": r.get("createdDateTime"), "user_id": r.get("userPrincipalName"),
            "src_ip": r.get("ipAddress"), "city": g(r, "location", "city"),
            "country": g(r, "location", "countryOrRegion"),
            "lat": g(r, "location", "geoCoordinates", "latitude"),
            "lon": g(r, "location", "geoCoordinates", "longitude"),
            "asn": str(r.get("autonomousSystemNumber") or "unknown"),
            "user_agent": r.get("userAgent") or f"{g(r,'deviceDetail','browser')} / {g(r,'deviceDetail','operatingSystem')}",
            "device_id": g(r, "deviceDetail", "deviceId") or "unregistered",
            "session_id": r.get("sessionId") or r.get("correlationId"),
            "app": r.get("appDisplayName"),
        }
        # MFA steps, if present in authenticationDetails
        for step in r.get("authenticationDetails") or []:
            if "notification" in (step.get("authenticationMethod") or "").lower() or "push" in (step.get("authenticationStepResultDetail") or "").lower():
                res = "approved" if step.get("succeeded") else (
                    "timeout" if "respond" in (step.get("authenticationStepResultDetail") or "").lower() else "denied")
                rows.append({**base, "timestamp": step.get("authenticationStepDateTime") or base["timestamp"],
                             "event_type": "mfa_push", "mfa_result": res,
                             "result": "success" if res == "approved" else "failure"})
        rows.append({**base, "event_type": "login" if r.get("isInteractive", True) else "token_use",
                     "mfa_result": None, "result": "success" if ok else "failure"})
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df.timestamp, utc=True).dt.tz_localize(None)
    df = df.dropna(subset=["lat", "lon"]).sort_values("timestamp").reset_index(drop=True)
    df.insert(0, "event_id", range(len(df)))
    return df


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    data = json.load(open(src, encoding="utf-8-sig"))
    records = data.get("value", data) if isinstance(data, dict) else data
    df = convert(records)
    df.to_csv(dst, index=False)
    print(f"Wrote {len(df):,} events to {dst}")
