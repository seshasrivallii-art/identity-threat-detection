"""ITDR analyst dashboard.  Run:  streamlit run dashboard/app.py"""
import ast
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
SEV_COLOR = {"critical": "#B3261E", "high": "#D9822B", "medium": "#C9A227"}
TYPE_LABEL = {"impossible_travel": "Impossible travel", "mfa_fatigue": "MFA fatigue",
              "session_hijack": "Session hijack", "ml_anomaly": "ML anomaly"}

st.set_page_config(page_title="Identity threat detection", page_icon="🛡️", layout="wide")


@st.cache_data
def load():
    logs = pd.read_csv(ROOT / "data/auth_logs.csv", parse_dates=["timestamp"])
    alerts = pd.read_csv(ROOT / "output/alerts.csv", parse_dates=["timestamp"])
    alerts["event_ids"] = alerts.event_ids.apply(ast.literal_eval)
    risk = pd.read_csv(ROOT / "output/user_risk.csv")
    return logs, alerts, risk


try:
    logs, alerts, risk = load()
except FileNotFoundError:
    st.error("No pipeline output found. Run `python -m data_generator.generate_logs` "
             "and then `python run_pipeline.py` from the project folder.")
    st.stop()

# ---------------------------------------------------------------- sidebar
st.sidebar.header("Filters")
types = st.sidebar.multiselect("Alert type", list(TYPE_LABEL), default=list(TYPE_LABEL),
                               format_func=TYPE_LABEL.get)
sevs = st.sidebar.multiselect("Severity", list(SEV_COLOR), default=list(SEV_COLOR))
view = alerts[alerts.alert_type.isin(types) & alerts.severity.isin(sevs)]

# ---------------------------------------------------------------- header
st.title("Identity threat detection")
st.caption(f"{len(logs):,} authentication events, {logs.user_id.nunique()} users, "
           f"{logs.timestamp.min():%b %d} to {logs.timestamp.max():%b %d %Y}")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts", len(view))
c2.metric("Critical", int((view.severity == "critical").sum()))
c3.metric("Users with risk ≥ 70", int((risk.risk_score >= 70).sum()))
c4.metric("Rule alerts vs ML", f"{(view.alert_type != 'ml_anomaly').sum()} / {(view.alert_type == 'ml_anomaly').sum()}")

tab_queue, tab_map, tab_user = st.tabs(["Alert queue", "Login map", "User investigation"])

# ---------------------------------------------------------------- queue
with tab_queue:
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Alerts, newest first")
        q = view.sort_values("timestamp", ascending=False)[["timestamp", "severity", "alert_type", "user_id", "mitre", "evidence"]]
        q["alert_type"] = q.alert_type.map(TYPE_LABEL)
        st.dataframe(q, hide_index=True, use_container_width=True, height=460)
    with right:
        st.subheader("Riskiest users")
        st.dataframe(risk.head(15), hide_index=True, use_container_width=True, height=460,
                     column_config={"risk_score": st.column_config.ProgressColumn(
                         "Risk", min_value=0, max_value=100, format="%d")})
    daily = view.assign(day=view.timestamp.dt.date).groupby(["day", "alert_type"]).size().reset_index(name="n")
    daily["alert_type"] = daily.alert_type.map(TYPE_LABEL)
    st.plotly_chart(px.bar(daily, x="day", y="n", color="alert_type", title="Alerts per day",
                           labels={"n": "alerts", "day": "", "alert_type": ""}), use_container_width=True)

# ---------------------------------------------------------------- map
with tab_map:
    st.subheader("Successful logins, with impossible-travel jumps drawn as lines")
    logins = logs[(logs.event_type == "login") & (logs.result == "success")]
    by_city = logins.groupby(["city", "country", "lat", "lon"]).size().reset_index(name="logins")
    fig = go.Figure(go.Scattergeo(lat=by_city.lat, lon=by_city.lon, text=by_city.city + ": " + by_city.logins.astype(str),
                                  marker=dict(size=(by_city.logins ** 0.5) * 1.5 + 4, color="#1F5FAD", opacity=0.6),
                                  hoverinfo="text", name="logins"))
    idx = logs.set_index("event_id")
    for _, a in view[view.alert_type == "impossible_travel"].iterrows():
        pair = idx.loc[a.event_ids[:2]]
        fig.add_trace(go.Scattergeo(lat=pair.lat, lon=pair.lon, mode="lines",
                                    line=dict(width=1.5, color=SEV_COLOR[a.severity]),
                                    hoverinfo="text", text=a.user_id + "<br>" + a.evidence, showlegend=False))
    fig.update_layout(height=560, margin=dict(l=0, r=0, t=0, b=0),
                      geo=dict(projection_type="natural earth", showcountries=True, countrycolor="#C8D1DC"))
    st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------------------- user drilldown
with tab_user:
    default = risk.user_id.iloc[0] if len(risk) else logs.user_id.iloc[0]
    users = sorted(logs.user_id.unique())
    user = st.selectbox("User", users, index=users.index(default))
    u_logs = logs[logs.user_id == user]
    u_alerts = alerts[alerts.user_id == user]
    r = risk[risk.user_id == user]
    st.metric("Risk score", int(r.risk_score.iloc[0]) if len(r) else 0)

    st.markdown("**Alerts for this user**")
    st.dataframe(u_alerts[["timestamp", "severity", "alert_type", "evidence"]], hide_index=True, use_container_width=True)

    st.markdown("**MFA pushes over time**")
    pushes = u_logs[u_logs.event_type == "mfa_push"]
    st.plotly_chart(px.scatter(pushes, x="timestamp", y="mfa_result", color="mfa_result",
                               color_discrete_map={"approved": "#2E7D32", "denied": "#B3261E", "timeout": "#D9822B"},
                               hover_data=["city", "src_ip", "asn"]).update_layout(height=260, showlegend=False),
                    use_container_width=True)

    st.markdown("**Known profile**")
    p1, p2, p3 = st.columns(3)
    p1.write("Countries"); p1.write(u_logs.country.value_counts())
    p2.write("Devices"); p2.write(u_logs.device_id.value_counts())
    p3.write("Networks (ASN)"); p3.write(u_logs.asn.value_counts())

    st.markdown("**Raw events**")
    st.dataframe(u_logs.drop(columns=["label", "attack_type", "attack_id"], errors="ignore")
                 .sort_values("timestamp", ascending=False), hide_index=True, use_container_width=True)
