"""
Synthetic authentication log generator with labeled attack injection.

Schema is loosely modeled on Entra ID / Okta sign-in logs so detections
transfer to real data. Every attack event gets label=1, an attack_type and
an attack_id, which makes precision/recall measurable later.

Usage:  python -m data_generator.generate_logs --users 60 --days 30
"""
import argparse
import random
import uuid
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

# city, country, lat, lon, home ASN
CITIES = [
    ("Boston", "US", 42.36, -71.06, "AS7922"),
    ("New York", "US", 40.71, -74.01, "AS701"),
    ("Chicago", "US", 41.88, -87.63, "AS7018"),
    ("Austin", "US", 30.27, -97.74, "AS11427"),
    ("Seattle", "US", 47.61, -122.33, "AS20115"),
    ("London", "GB", 51.51, -0.13, "AS2856"),
    ("Toronto", "CA", 43.65, -79.38, "AS577"),
    ("Bangalore", "IN", 12.97, 77.59, "AS24560"),
]
ATTACKER_LOCATIONS = [
    ("Lagos", "NG", 6.52, 3.38, "AS37148"),
    ("Moscow", "RU", 55.76, 37.62, "AS8359"),
    ("Sao Paulo", "BR", -23.55, -46.63, "AS28573"),
    ("Jakarta", "ID", -6.21, 106.85, "AS17974"),
    ("Bucharest", "RO", 44.43, 26.10, "AS8708"),
]
VPN = ("Frankfurt", "DE", 50.11, 8.68, "AS-CORP-VPN")              # corporate VPN (trusted)
PERSONAL_VPN = ("Amsterdam", "NL", 52.37, 4.90, "AS-CONSUMER-VPN")  # benign noise, NOT trusted
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/17.4",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
]
ATTACKER_UAS = [
    "python-requests/2.31.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/99.0",
    "curl/8.4.0",
]
APPS = ["Office365", "Salesforce", "Slack", "GitHub", "Workday", "AWS Console"]


def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


class Generator:
    def __init__(self, n_users, days, seed, attacks_per_type, evasive=0.0):
        random.seed(seed)
        np.random.seed(seed)
        self.start = datetime(2026, 10, 1)
        self.days = days
        self.attacks_per_type = attacks_per_type
        self.evasive = evasive  # share of attacks that try to dodge the rules
        self.rows = []
        self.attack_counter = 0
        self.users = []
        for i in range(n_users):
            city = random.choice(CITIES)
            self.users.append({
                "user_id": f"user{i:03d}@corp.example",
                "home": city,
                "home_ip": rand_ip(),
                "device_id": f"dev-{uuid.uuid4().hex[:8]}",
                "user_agent": random.choice(USER_AGENTS),
                "start_hour": random.randint(6, 10),
                "uses_vpn": random.random() < 0.15,
                "personal_vpn": random.random() < 0.08,
                "traveler": random.random() < 0.10,
            })

    # ------------------------------------------------------------------ helpers
    def _row(self, ts, event_type, user, loc, ip, ua, device, session,
             mfa_result=None, result="success", app=None,
             label=0, attack_type="benign", attack_id=None):
        self.rows.append({
            "timestamp": ts, "event_type": event_type, "user_id": user["user_id"],
            "src_ip": ip, "city": loc[0], "country": loc[1], "lat": loc[2], "lon": loc[3],
            "asn": loc[4], "user_agent": ua, "device_id": device, "session_id": session,
            "app": app or random.choice(APPS), "mfa_result": mfa_result, "result": result,
            "label": label, "attack_type": attack_type, "attack_id": attack_id,
        })

    def _session(self, ts, user, loc, ip, ua, device, n_token_uses=None, mobile_switch=False):
        """Normal interactive login: MFA push approved -> login -> token reuse."""
        sid = f"sess-{uuid.uuid4().hex[:12]}"
        # occasional slow user: 1-2 timeouts before approving (benign noise)
        for _ in range(np.random.choice([0, 0, 0, 0, 1, 2])):
            self._row(ts, "mfa_push", user, loc, ip, ua, device, sid, mfa_result="timeout", result="pending")
            ts += timedelta(seconds=random.randint(40, 90))
        self._row(ts, "mfa_push", user, loc, ip, ua, device, sid, mfa_result="approved")
        self._row(ts + timedelta(seconds=3), "login", user, loc, ip, ua, device, sid)
        t = ts
        for k in range(n_token_uses or random.randint(2, 6)):
            t += timedelta(minutes=random.randint(10, 60))
            use_loc, use_ip = loc, ip
            if mobile_switch and k == 1:
                # wifi -> cellular in same country: new ASN, same everything else
                use_loc = (loc[0], loc[1], loc[2], loc[3], "AS-MOBILE-" + loc[1])
                use_ip = rand_ip()
            self._row(t, "token_use", user, use_loc, use_ip, ua, device, sid)
        return sid, t

    # ---------------------------------------------------------- normal traffic
    def generate_normal(self):
        for user in self.users:
            travel_day = random.randint(5, self.days - 5) if user["traveler"] else None
            for d in range(self.days):
                day = self.start + timedelta(days=d)
                if day.weekday() >= 5 and random.random() < 0.8:
                    continue
                loc, ip = user["home"], user["home_ip"]
                if travel_day is not None and travel_day <= d < travel_day + 3:
                    # legit trip to another office (realistic flight gap)
                    loc = [c for c in CITIES if c != user["home"]][user_id_hash(user) % (len(CITIES) - 1)]
                    ip = rand_ip()
                elif user["uses_vpn"] and random.random() < 0.3:
                    loc, ip = VPN, "10.200.0.1"
                n_logins = random.randint(1, 3)
                hour = user["start_hour"]
                for _ in range(n_logins):
                    ts = day + timedelta(hours=hour, minutes=random.randint(0, 59))
                    if user["personal_vpn"] and random.random() < 0.3:
                        loc, ip = PERSONAL_VPN, rand_ip()  # toggles a consumer VPN mid-day
                    elif loc == PERSONAL_VPN:
                        loc, ip = user["home"], user["home_ip"]
                    if random.random() < 0.05:  # fat-fingered password
                        self._row(ts - timedelta(minutes=1), "login", user, loc, ip,
                                  user["user_agent"], user["device_id"], None, result="failure")
                    self._session(ts, user, loc, ip, user["user_agent"], user["device_id"],
                                  mobile_switch=random.random() < 0.05)
                    hour += random.randint(2, 4)

    # ---------------------------------------------------------------- attacks
    def _attack_window(self):
        # attacks only after the ML baseline period (first 14 days)
        d = random.randint(15, self.days - 1)
        return self.start + timedelta(days=d, hours=random.randint(0, 23), minutes=random.randint(0, 59))

    def _new_attack_id(self):
        self.attack_counter += 1
        return f"ATK-{self.attack_counter:03d}"

    def inject_impossible_travel(self):
        for _ in range(self.attacks_per_type):
            user, aid = random.choice(self.users), self._new_attack_id()
            ts = self._attack_window()
            # legit login, then attacker login from far away ~1-2h later
            self._session(ts, user, user["home"], user["home_ip"], user["user_agent"], user["device_id"], n_token_uses=1)
            atk = random.choice(ATTACKER_LOCATIONS)
            if self._evade():  # residential proxy near the victim defeats geo checks
                h = user["home"]
                atk = (h[0], h[1], h[2], h[3], "AS-RESI-PROXY")
            t2 = ts + timedelta(minutes=random.randint(45, 120))
            sid = f"sess-{uuid.uuid4().hex[:12]}"
            dev, ua, ip = f"dev-{uuid.uuid4().hex[:8]}", random.choice(ATTACKER_UAS), rand_ip()
            kw = dict(label=1, attack_type="impossible_travel", attack_id=aid)
            self._row(t2, "mfa_push", user, atk, ip, ua, dev, sid, mfa_result="approved", **kw)
            self._row(t2 + timedelta(seconds=4), "login", user, atk, ip, ua, dev, sid, **kw)
            self._row(t2 + timedelta(minutes=5), "token_use", user, atk, ip, ua, dev, sid, app="Office365", **kw)

    def inject_mfa_fatigue(self):
        for _ in range(self.attacks_per_type):
            user, aid = random.choice(self.users), self._new_attack_id()
            ts = self._attack_window().replace(hour=random.choice([1, 2, 3, 23]))  # off-hours
            atk = random.choice(ATTACKER_LOCATIONS)
            dev, ua, ip = f"dev-{uuid.uuid4().hex[:8]}", random.choice(ATTACKER_UAS), rand_ip()
            sid = f"sess-{uuid.uuid4().hex[:12]}"
            kw = dict(label=1, attack_type="mfa_fatigue", attack_id=aid)
            n_push = random.randint(6, 15)
            gap = (120, 300) if self._evade() else (20, 50)  # slow bombing stays under burst thresholds
            t = ts
            for i in range(n_push - 1):
                self._row(t, "mfa_push", user, atk, ip, ua, dev, sid,
                          mfa_result=random.choice(["denied", "timeout"]), result="failure", **kw)
                t += timedelta(seconds=random.randint(*gap))
            self._row(t, "mfa_push", user, atk, ip, ua, dev, sid, mfa_result="approved", **kw)
            self._row(t + timedelta(seconds=5), "login", user, atk, ip, ua, dev, sid, **kw)

    def inject_session_hijack(self):
        for _ in range(self.attacks_per_type):
            user, aid = random.choice(self.users), self._new_attack_id()
            ts = self._attack_window()
            sid, last = self._session(ts, user, user["home"], user["home_ip"],
                                      user["user_agent"], user["device_id"], n_token_uses=2)
            atk = random.choice(ATTACKER_LOCATIONS)
            ua, ip = random.choice(ATTACKER_UAS), rand_ip()
            evade = self._evade()
            if evade:  # attacker clones the victim's UA and proxies through their country
                h = user["home"]
                atk, ua = (h[0], h[1], h[2] + 0.3, h[3] + 0.3, "AS-RESI-PROXY"), user["user_agent"]
            kw = dict(label=1, attack_type="session_hijack", attack_id=aid)
            t = last
            for _ in range(random.randint(2, 5)):  # replayed cookie, no new login/MFA
                t += timedelta(minutes=random.randint(1, 15))
                # stolen cookie keeps the victim device id claim? sometimes spoofed
                dev = user["device_id"] if (evade or random.random() < 0.5) else f"dev-{uuid.uuid4().hex[:8]}"
                self._row(t, "token_use", user, atk, ip, ua, dev, sid,
                          app=random.choice(["Office365", "AWS Console"]), **kw)

    def _evade(self):
        return random.random() < self.evasive

    def build(self):
        self.generate_normal()
        self.inject_impossible_travel()
        self.inject_mfa_fatigue()
        self.inject_session_hijack()
        df = pd.DataFrame(self.rows).sort_values("timestamp").reset_index(drop=True)
        df.insert(0, "event_id", range(len(df)))
        return df


def user_id_hash(user):
    return sum(ord(c) for c in user["user_id"])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--users", type=int, default=60)
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--attacks", type=int, default=8, help="attacks per type")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--evasive", type=float, default=0.25,
                   help="share of attacks using evasion (residential proxy, slow MFA bombing, cloned UA)")
    p.add_argument("--out", default="data/auth_logs.csv")
    a = p.parse_args()
    df = Generator(a.users, a.days, a.seed, a.attacks, a.evasive).build()
    df.to_csv(a.out, index=False)
    print(f"Wrote {len(df):,} events to {a.out}")
    print(df.groupby("attack_type")["attack_id"].nunique().rename("attacks").to_string())


if __name__ == "__main__":
    main()
