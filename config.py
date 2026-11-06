"""Central thresholds. Tune these during evaluation (Step 6 in README)."""

# Impossible travel
MAX_TRAVEL_SPEED_KMH = 900          # faster than a commercial jet = suspicious
MIN_TRAVEL_DISTANCE_KM = 500        # ignore short hops (GeoIP noise, mobile carriers)
TRUSTED_ASNS = {"AS-CORP-VPN"}      # corporate VPN egress, ignore for travel
SUPPRESS_FAMILIAR_ASN = True        # skip if user already logged in from this ASN before
                                    # (set False to see how many FPs consumer VPNs cause)

# MFA fatigue
MFA_WINDOW_MINUTES = 10
MFA_MIN_PUSHES = 5                  # pushes in window to count as a burst
MFA_MIN_DENIALS = 3                 # denials/timeouts before an approval

# Session hijacking
SESSION_ATTRS = ["asn", "country", "user_agent", "device_id"]

# ML
ISOLATION_CONTAMINATION = 0.02
BASELINE_DAYS = 14

# Risk scoring weights (0-100 scale)
WEIGHTS = {"impossible_travel": 40, "mfa_fatigue": 50, "session_hijack": 60, "ml_anomaly": 25}
