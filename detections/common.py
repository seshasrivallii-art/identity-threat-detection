import numpy as np
import pandas as pd

ALERT_COLUMNS = ["alert_type", "user_id", "timestamp", "severity", "mitre", "evidence", "event_ids"]


def haversine_km(lat1, lon1, lat2, lon2):
    lat1, lon1, lat2, lon2 = map(np.radians, (lat1, lon1, lat2, lon2))
    a = np.sin((lat2 - lat1) / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * np.arcsin(np.sqrt(a))


def make_alerts(records):
    return pd.DataFrame(records, columns=ALERT_COLUMNS)
