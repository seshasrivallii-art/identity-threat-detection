"""Small hand-built cases for each rule.  Run:  python -m pytest tests  (or python tests/test_detections.py)"""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detections import impossible_travel, mfa_fatigue, session_hijack  # noqa: E402

BASE = dict(user_id="u@x", src_ip="1.1.1.1", asn="AS1", user_agent="UA", device_id="d1",
            session_id="s1", app="O365", mfa_result=None, result="success")
BOS = dict(city="Boston", country="US", lat=42.36, lon=-71.06)
LAG = dict(city="Lagos", country="NG", lat=6.52, lon=3.38)


def frame(rows):
    df = pd.DataFrame([{**BASE, **r} for r in rows])
    df["timestamp"] = pd.to_datetime(df.timestamp)
    df.insert(0, "event_id", range(len(df)))
    return df


def test_impossible_travel_fires():
    df = frame([{**BOS, "timestamp": "2026-10-20 09:00", "event_type": "login"},
                {**LAG, "timestamp": "2026-10-20 10:00", "event_type": "login", "asn": "AS9", "session_id": "s2"}])
    assert len(impossible_travel.detect(df)) == 1


def test_realistic_flight_is_quiet():
    df = frame([{**BOS, "timestamp": "2026-10-20 09:00", "event_type": "login"},
                {**LAG, "timestamp": "2026-10-21 09:00", "event_type": "login", "asn": "AS9", "session_id": "s2"}])
    assert impossible_travel.detect(df).empty


def test_mfa_fatigue_fires():
    rows = [{**LAG, "timestamp": f"2026-10-20 02:0{i}", "event_type": "mfa_push", "mfa_result": "denied"} for i in range(5)]
    rows.append({**LAG, "timestamp": "2026-10-20 02:06", "event_type": "mfa_push", "mfa_result": "approved"})
    a = mfa_fatigue.detect(frame(rows))
    assert len(a) == 1 and a.severity.iloc[0] == "critical"


def test_session_hijack_fires_and_ignores_cellular_switch():
    hijack = frame([{**BOS, "timestamp": "2026-10-20 09:00", "event_type": "login"},
                    {**LAG, "timestamp": "2026-10-20 09:30", "event_type": "token_use", "asn": "AS9", "user_agent": "curl"}])
    cellular = frame([{**BOS, "timestamp": "2026-10-20 09:00", "event_type": "login"},
                      {**BOS, "timestamp": "2026-10-20 09:30", "event_type": "token_use", "asn": "AS-MOBILE"}])
    assert len(session_hijack.detect(hijack)) == 1
    assert session_hijack.detect(cellular).empty


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)
