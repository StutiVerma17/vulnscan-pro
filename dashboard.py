import streamlit as st
import subprocess
import xml.etree.ElementTree as ET
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os
import smtplib                                  
from email.mime.text import MIMEText            
from email.mime.multipart import MIMEMultipart  
from datetime import datetime
from dotenv import load_dotenv

#Loading .env
load_dotenv(override=True)

checks = {
    "VT_API_KEY"      : os.environ.get("VT_API_KEY",       ""),
    "GMAIL_SENDER"    : os.environ.get("GMAIL_SENDER",     ""),
    "GMAIL_PASSWORD"  : os.environ.get("GMAIL_PASSWORD",   ""),
    "GMAIL_RECIPIENT" : os.environ.get("GMAIL_RECIPIENT",  ""),
}

#Page Config
st.set_page_config(
    page_title="VulnScan Pro",
    page_icon="🛡️",
    layout="wide"
)

#Theme
st.title("🛡️ VulnScan Pro")
st.caption("Web Application Vulnerability Scanning, Risk Evaluation & Alert System")

#Last Refreshed Banner
col_ref, col_btn = st.columns([6, 1])
with col_ref:
    if st.session_state.get("last_refreshed"):
        st.info(f"🕐 Last refreshed: {st.session_state.last_refreshed}")
    else:
        st.info("🕐 No scan run yet — click **Run Full Scan** in the sidebar.")
with col_btn:
    # Inline refresh button at top it is same as sidebar refresh button
    if st.button("🔄 Refresh", use_container_width=True):
        st.session_state.df             = None
        st.session_state.scan_time      = None
        st.session_state.last_refreshed = None
        st.rerun()

st.divider()

#Sidebar - API KEY
st.sidebar.title("🛡️ VulnScan Pro")
st.sidebar.divider()

#Credentials from environment variables
load_dotenv()

VT_API_KEY      = os.environ.get("VT_API_KEY",      "")
sender_email    = os.environ.get("GMAIL_SENDER",     "")
app_password    = os.environ.get("GMAIL_PASSWORD",   "")
recipient_email = os.environ.get("GMAIL_RECIPIENT",  "")
targets_env     = os.environ.get("SCAN_TARGETS",     "")

#Default targets
DEFAULT_TARGETS = "testasp.vulnweb.com,testphp.vulnweb.com,zero.webappsecurity.com"
targets = [t.strip() for t in (targets_env or DEFAULT_TARGETS).split(",") if t.strip()]

#Custom target from Sidebar
st.sidebar.subheader("🎯 Scan Target")
custom_target = st.sidebar.text_input(
    "Add custom target (test/lab only)",
    placeholder="e.g. testphp.vulnweb.com"
)
if custom_target.strip():
    if custom_target.strip() not in targets:
        targets.append(custom_target.strip())

#Sidebar Status
st.sidebar.subheader("⚙️ Status")
if VT_API_KEY and not VT_API_KEY.startswith("your_"):
    st.sidebar.success("VirusTotal API key ready ✅")
else:
    st.sidebar.error("❌ VT_API_KEY not set")

if sender_email and app_password and recipient_email:
    st.sidebar.success("Email ready ✅")
else:
    st.sidebar.warning("⚠️ Email credentials not set")

st.sidebar.caption("Default targets:")
for t in targets:
    st.sidebar.caption(f"  • {t}")

st.sidebar.divider()

#Scan Controls
st.sidebar.subheader("🚀 Scan Controls")
scan_button = st.sidebar.button(
    "🚀 Run Full Scan",
    use_container_width=True,
    type="primary"
)
refresh_button = st.sidebar.button(
    "🔄 Refresh Scan",
    use_container_width=True
)

st.sidebar.divider()
st.sidebar.subheader("🔍 Filter Results")

#Pipeline functions - Scan Directory
SCAN_DIR = "scan_results"
os.makedirs(SCAN_DIR, exist_ok=True)

VULN_MAP = {
    "ftp":        {"risk_bonus": 3, "vuln_name": "Cleartext FTP",          "cve_ref": "CVE-1999-0497", "action": "Disable FTP; use SFTP or FTPS instead."},
    "telnet":     {"risk_bonus": 4, "vuln_name": "Cleartext Telnet",       "cve_ref": "CVE-1999-0619", "action": "Disable Telnet; replace with SSH."},
    "ssh":        {"risk_bonus": 1, "vuln_name": "SSH Exposed",            "cve_ref": "CVE-2023-38408","action": "Restrict SSH access; enforce key-based auth only."},
    "smtp":       {"risk_bonus": 2, "vuln_name": "Open SMTP Relay",        "cve_ref": "CVE-2020-7247", "action": "Disable open relay; restrict to authenticated users."},
    "rdp":        {"risk_bonus": 4, "vuln_name": "RDP Exposed",            "cve_ref": "CVE-2019-0708", "action": "Disable RDP or restrict via VPN; apply BlueKeep patch."},
    "vnc":        {"risk_bonus": 3, "vuln_name": "VNC Exposed",            "cve_ref": "CVE-2006-2369", "action": "Restrict VNC to internal network; enforce strong passwords."},
    "http":       {"risk_bonus": 1, "vuln_name": "Unencrypted HTTP",       "cve_ref": "CWE-319",       "action": "Force HTTPS; install a valid TLS certificate."},
    "http-proxy": {"risk_bonus": 2, "vuln_name": "Open HTTP Proxy",       "cve_ref": "CWE-441",       "action": "Disable or restrict HTTP proxy to authorised users."},
    "mysql":      {"risk_bonus": 3, "vuln_name": "MySQL Exposed",          "cve_ref": "CVE-2012-2122", "action": "Restrict MySQL to localhost or internal network only."},
    "ms-sql":     {"risk_bonus": 3, "vuln_name": "MSSQL Exposed",         "cve_ref": "CVE-2020-0618", "action": "Block port 1433/1434 at firewall; patch to latest."},
    "smb":        {"risk_bonus": 4, "vuln_name": "SMB Exposed (EternalBlue)","cve_ref": "CVE-2017-0144","action": "Block SMB ports 139/445 at perimeter; apply MS17-010."},
    "pop3":       {"risk_bonus": 2, "vuln_name": "Cleartext POP3",         "cve_ref": "CWE-523",       "action": "Use POP3S (port 995) with TLS enabled."},
    "imap":       {"risk_bonus": 2, "vuln_name": "Cleartext IMAP",         "cve_ref": "CWE-523",       "action": "Use IMAPS (port 993) with TLS enabled."},
    "dns":        {"risk_bonus": 2, "vuln_name": "Open DNS Resolver",      "cve_ref": "CVE-2008-1447", "action": "Restrict recursive DNS; implement response-rate limiting."},
}

HIGH_RISK_SERVICES = {"ftp": 3, "telnet": 4, "ssh": 1, "smtp": 2, "rdp": 4, "vnc": 3}

DEFAULT_VULN = {"risk_bonus": 0, "vuln_name": "Unknown Service", "cve_ref": "N/A", "action": "Investigate and close if not required."}

DISPLAY_PORTS = {"21", "22", "23", "25", "53", "80", "110", "143",
                 "443", "445", "1433", "3306", "3389", "5900", "8080"}

def run_nmap_scan(target):
    xml_file = os.path.join(SCAN_DIR, target.replace("/","_")+".xml")

    subprocess.run(["nmap", "-Pn", "-sv", "--open", "-oX", xml_file, target], capture_output=True)
    return xml_file

def parse_nmap_xml(xml_file):
    rows = []
    try:
        root = ET.parse(xml_file).getroot()
        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "unknown")
            for port_el in host.findall(".//port"):
                portid = port_el.get("portid", "0")
                svc_el = port_el.find("service")
                svc    = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                rows.append({"ip": ip, "port": portid, "service": svc})
    except Exception:
        pass
    return rows

def check_virustotal(ip, api_key):
    """Return number of malicious engine reports for an IP from VirusTotal."""
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10
        )
        return r.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except Exception:
        return 0

def get_vuln_info(service):
    """Return the VULN_MAP entry for a service, or the default."""
    return VULN_MAP.get(service.lower(), DEFAULT_VULN)

def calculate_risk(row):
    """Base score 1 + service risk bonus + VirusTotal malicious count."""
    bonus = get_vuln_info(row["service"])["risk_bonus"]
    return min(10, 1 + bonus + int(row["malicious_reports"]))


def classify_severity(score):
    """Map numeric risk_score to severity label."""
    if score >= 9:    return "Critical"
    elif score >= 6:  return "High"
    elif score >= 3:  return "Medium"
    elif score >= 1:  return "Low"
    else:             return "Informational"

#Email Alert Function
def send_alert_email(sender, password, recipient, alert_df, scan_time, overall_risk):
    max_sev = "Critical" if (alert_df["severity"] == "Critical").any() else "High"
    targets_str = ", ".join(sorted(alert_df["ip"].unique()))
    subject = f"🚨 [{max_sev}] VulnScan Alert — {targets_str}"

    body  = "=" * 60 + "\n"
    body += "  VULNSCAN PRO — HIGH RISK ALERT\n"
    body += "=" * 60 + "\n\n"
    body += f"Scan completed : {scan_time}\n"
    body += f"High risk entries found : {len(alert_df)}\n"
    body += f"Affected hosts : {alert_df['ip'].nunique()}\n\n"
    body += "-" * 60 + "\n"
    body += "AFFECTED HOSTS — IMMEDIATE ACTION REQUIRED\n"
    body += "-" * 60 + "\n\n"

    for _, row in alert_df.iterrows():
        body += f"  Host    : {row['ip']}\n"
        body += f"  Port    : {row['port']}\n"
        body += f"  Service : {row['service']}\n"
        body += f"  Risk    : {row['risk_score']}\n"
        body += f"  VT Hits : {row['malicious_reports']}\n"
        body += "\n"

    body += "-" * 60 + "\n"
    body += "Please review your network security immediately.\n"
    body += "Generated by VulnScan Pro\n"

    msg             = MIMEMultipart("alternative")
    msg["From"]     = sender
    msg["To"]       = recipient
    msg["Subject"]  = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        return str(e)

#Session State
for key in ("df", "scan_time", "last_refreshed", "auto_alert_sent"):
    if key not in st.session_state:
        st.session_state[key] = None

#Run Scan
if scan_button or refresh_button:
    if refresh_button:
        st.session_state.df             = None
        st.session_state.scan_time      = None
        st.session_state.last_refreshed = None
        st.session_state.auto_alert_sent = None

    if not VT_API_KEY or VT_API_KEY.startswith("your_"):
        st.error("❌ VT_API_KEY not set. Open .env, fill it in, save, and re-run.")
    elif not targets:
        st.error("❌ No targets configured.")
    else:
        all_rows = []
        bar      = st.progress(0)
        status   = st.empty()
        total    = len(targets) * 2 

        for i, target in enumerate(targets):
            status.info(f"🔍 Nmap scanning {target} ... ({i+1}/{len(targets)})")
            xml = run_nmap_scan(target)
            rows = parse_nmap_xml(xml)
            # Keep only the limited port set defined above
            rows = [r for r in rows if r["port"] in DISPLAY_PORTS]
            all_rows.extend(rows)
            bar.progress((i + 1) / total)

        df_raw = pd.DataFrame(all_rows)

        if df_raw.empty or "ip" not in df_raw.columns:
            bar.empty()
            status.warning(
                "⚠️ Nmap returned no open ports for any target. "
                "Run VS Code / your terminal as Administrator on Windows, "
                "confirm Nmap is installed (nmap --version), "
                "and ensure the targets are reachable."
            )
            st.stop()

        unique_ips = df_raw["ip"].unique()
        vt = {}
        for j, ip in enumerate(unique_ips):
            status.info(f"🦠 VirusTotal checking {ip} ... ({j+1}/{len(unique_ips)})")
            vt[ip] = check_virustotal(ip, VT_API_KEY)
            bar.progress((len(targets) + j + 1) / total)
            if j < len(unique_ips) - 1:
                time.sleep(15)

        df_raw["malicious_reports"] = df_raw["ip"].map(vt).fillna(0).astype(int)
        df_raw["risk_score"]        = df_raw.apply(calculate_risk, axis=1)
        df_raw["severity"]          = df_raw["risk_score"].apply(classify_severity)
        df_raw["vulnerability"]     = df_raw["service"].apply(
            lambda s: get_vuln_info(s)["vuln_name"])
        df_raw["malicious_score"]   = df_raw["malicious_reports"]

        st.session_state.df              = df_raw
        st.session_state.scan_time       = time.strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.last_refreshed  = datetime.now().strftime("%d %b %Y  %H:%M:%S")
        st.session_state.auto_alert_sent = False

        bar.empty()
        status.success(f"✅ Scan complete — {len(df_raw)} ports found across {len(unique_ips)} host(s).")

    #Auto Trigger email alert if High/Critical found
    alert_df = df_raw[df_raw["severity"].isin(["High", "Critical"])]
    if not alert_df.empty and sender_email and app_password and recipient_email:
            overall_risk = int(df_raw["risk_score"].max())
            with st.spinner("📧 Auto-sending alert email for High/Critical findings..."):
                result = send_alert_email(
                    sender_email, app_password, recipient_email,
                    alert_df, st.session_state.scan_time, overall_risk
                )
            if result is True:
                st.success(f"✅ Alert email auto-sent to {recipient_email} — {len(alert_df)} High/Critical findings.")
                st.session_state.auto_alert_sent = True
            else:
                st.warning(f"⚠️ Auto-email failed: {result}")

#Load data - real scan or sample
if st.session_state.df is None:
    st.info("ℹ️ No scan run yet — showing sample data. Click **🚀 Run Full Scan** in the sidebar.")
    df = pd.DataFrame({
        "ip":                ["192.168.1.1","192.168.1.1","192.168.1.2",
                              "192.168.1.2","192.168.1.3","192.168.1.3","192.168.1.3","192.168.1.4","192.168.1.4"],
        "port":              ["22",   "80",   "8080",
                              "21",   "23",   "443",
                              "80",   "443",  "3306"],
        "service":           ["ssh",  "http", "http-proxy",
                              "ftp",  "telnet","https",
                              "http", "https","mysql"],
        "malicious_reports": [0, 0, 0, 2, 5, 0, 0, 0, 3],
        "malicious_score":   [0, 0, 0, 2, 5, 0, 0, 0, 3],
        "risk_score":        [2, 2, 3, 6, 10, 1, 2, 1, 7],
    })
    df["severity"]      = df["risk_score"].apply(classify_severity)
    df["vulnerability"] = df["service"].apply(lambda s: get_vuln_info(s)["vuln_name"])
else:
    df = st.session_state.df
    if st.session_state.scan_time:
        st.caption(f"Scan completed: {st.session_state.scan_time}")

#Sidebar Filters
sel_ip  = st.sidebar.selectbox("Filter by IP",
              ["All"] + sorted(df["ip"].unique().tolist()))
sel_svc = st.sidebar.selectbox("Filter by Service",
              ["All"] + sorted(df["service"].unique().tolist()))
sel_sev = st.sidebar.multiselect("Filter by Severity",
              ["Critical", "High", "Medium", "Low", "Informational"],
              default=["Critical", "High", "Medium", "Low", "Informational"])
min_r = int(df["risk_score"].min())
max_r = int(df["risk_score"].max())
if min_r == max_r:
    max_r = min_r + 1
risk_min = st.sidebar.slider("Min Risk Score", min_r, max_r, min_r)

filt = df.copy()
if sel_ip  != "All": filt = filt[filt["ip"]      == sel_ip]
if sel_svc != "All": filt = filt[filt["service"] == sel_svc]
if sel_sev:          filt = filt[filt["severity"].isin(sel_sev)]
filt = filt[filt["risk_score"] >= risk_min]


#KPI Cards
st.subheader("📊 Key Metrics")
high_count     = len(df[df["severity"].isin(["High", "Critical"])])
overall_risk   = int(df["risk_score"].max())
k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("🖥️ Total Hosts",         df["ip"].nunique())
k2.metric("🔓 Open Ports",          len(df))
k3.metric("⚙️ Unique Services",     df["service"].nunique())
k4.metric("💀 Max Risk Score",      overall_risk)
k5.metric("🚨 High/Critical",       high_count)
k6.metric("🦠 Max VT Malicious",    int(df["malicious_reports"].max()))
st.divider()

#Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📋  Scan Data",
    "📈  Charts",
    "🚨  Threat Intel & Alerts",
    "💾  Export"
])

#Tab 1 - Scan Data
with tab1:
    st.subheader("📋 Scan Results")
    st.caption(f"Showing {len(filt)} of {len(df)} rows after filters")

    display_cols = ["ip", "port", "service", "vulnerability",
                    "malicious_score", "risk_score", "severity"]
    st.write(filt[display_cols].to_html(index=False), unsafe_allow_html=True)

    st.divider()

    #Host Summary
    st.subheader("📌 Host Summary")
    st.caption("Aggregated stats per host")
    summary = df.groupby("ip").agg(
        total_ports       = ("port",             "count"),
        services          = ("service",           lambda x: ", ".join(sorted(x.unique()))),
        malicious_score   = ("malicious_reports", "max"),
        risk_score        = ("risk_score",        "max"),
        severity          = ("severity",          lambda x: x.value_counts().index[0]),
    ).reset_index()
    summary.columns = ["IP", "Total Ports", "Services", "Malicious Score",
                       "Max Risk Score", "Dominant Severity"]
    summary = summary.sort_values("Max Risk Score", ascending=False)
    st.write(summary.to_html(index=False), unsafe_allow_html=True)

#Tab 2 - Charts
with tab2:
    st.subheader("📈 Interactive Charts")
    st.caption("Hover for details  •  Drag to zoom  •  Double-click to reset  •  Click legend to toggle")

    CHART_BG = "#1e2130"
    GRID_COL = "#2d3148"

    c1, c2 = st.columns(2)

    #Chart 1 - Open Ports per host
    with c1:
        pc = df.groupby("ip")["port"].count().reset_index()
        pc.columns = ["IP", "Open Ports"]
        fig1 = px.bar(pc, x="IP", y="Open Ports",
                      title="Open Ports per Host",
                      color="Open Ports",
                      color_continuous_scale="Blues",
                      text="Open Ports")
        fig1.update_traces(textposition="outside")
        fig1.update_layout(height=380, showlegend=False,
                           paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                           font_color="#e2e8f0",
                           xaxis=dict(gridcolor=GRID_COL),
                           yaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig1, use_container_width=True)

    #Chart 2 - Risk Score per Host
    with c2:
        rs = df.groupby("ip")["risk_score"].max().reset_index()
        rs.columns = ["IP", "Max Risk Score"]
        fig2 = px.bar(rs, x="IP", y="Max Risk Score",
                      title="Max Risk Score per Host",
                      color="Max Risk Score",
                      color_continuous_scale="Reds",
                      text="Max Risk Score")
        fig2.update_traces(textposition="outside")
        fig2.update_layout(height=380, showlegend=False,
                           paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                           font_color="#e2e8f0",
                           xaxis=dict(gridcolor=GRID_COL),
                           yaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig2, use_container_width=True)

    c3, c4 = st.columns(2)

    #Chart 3 - Services Exposed
    with c3:
        sc = df["service"].value_counts().reset_index()
        sc.columns = ["Service", "Count"]
        fig3 = px.bar(sc, x="Count", y="Service", orientation="h",
                      title="Services Exposed",
                      color="Count",
                      color_continuous_scale="Purples",
                      text="Count")
        fig3.update_layout(height=380, showlegend=False,
                           paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                           font_color="#e2e8f0",
                           yaxis=dict(categoryorder="total ascending", gridcolor=GRID_COL),
                           xaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig3, use_container_width=True)

    #Chart 4 - Severity Donut Pie
    with c4:
        sev = df["severity"].value_counts().reset_index()
        sev.columns = ["Severity", "Count"]
        fig4 = px.pie(
            sev, names="Severity", values="Count",
            title="Severity Distribution",
            color="Severity",
            color_discrete_map={
                "Critical":      "#7f1d1d",
                "High":          "#ef4444",
                "Medium":        "#f97316",
                "Low":           "#4ade80",
                "Informational": "#60a5fa"
            },
            hole=0.5
        )
        fig4.update_traces(textinfo="percent+label+value")
        fig4.update_layout(
            height=380,
            paper_bgcolor=CHART_BG,
            font_color="#e2e8f0",
            legend=dict(bgcolor=CHART_BG)
        )
        st.plotly_chart(fig4, use_container_width=True)

    #Chart 5 - Scatter: Risk vs Exposure
    st.subheader("🎯 Risk vs Exposure")
    st.caption("Bubble size = VirusTotal malicious reports. Hover each bubble for details.")
    sc_df = df.groupby("ip").agg(
        open_ports = ("port",             "count"),
        total_risk = ("risk_score",        "sum"),
        malicious  = ("malicious_reports", "max"),
        services   = ("service",           lambda x: ", ".join(sorted(x.unique())))
    ).reset_index()
    sc_df.columns = ["IP", "Open Ports", "Total Risk", "Malicious Reports", "Services"]
    sc_df["size_col"] = sc_df["Malicious Reports"].apply(lambda x: max(x, 1))

    fig5 = px.scatter(sc_df,
        x="Open Ports", y="Total Risk",
        size="size_col", size_max=70,
        color="Total Risk",
        color_continuous_scale="RdYlGn_r",
        hover_name="IP",
        hover_data={"Services": True, "Malicious Reports": True,
                    "Open Ports": True, "Total Risk": True, "size_col": False},
        text="IP",
        title="Total Risk Score vs Number of Open Ports")
    fig5.update_traces(textposition="top center",
                       marker=dict(line=dict(width=1, color="#4f8ef7")))
    fig5.update_layout(height=500,
                       paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                       font_color="#e2e8f0",
                       xaxis=dict(gridcolor=GRID_COL),
                       yaxis=dict(gridcolor=GRID_COL))
    st.plotly_chart(fig5, use_container_width=True)

    #Chart 6 - VirusTotal Grouped bar
    st.subheader("🦠 VirusTotal Intelligence")
    vt_df = df.groupby("ip").agg(
        malicious = ("malicious_reports", "max"),
        risk      = ("risk_score",        "sum")
    ).reset_index()
    vt_df.columns = ["IP", "Malicious Reports", "Total Risk"]
    vt_df["Status"] = vt_df["Malicious Reports"].apply(
        lambda x: "Clean" if x == 0 else ("Suspicious" if x < 5 else "Malicious"))

    fig6 = go.Figure()
    fig6.add_trace(go.Bar(
        name="Malicious Reports",
        x=vt_df["IP"],
        y=vt_df["Malicious Reports"],
        marker_color=vt_df["Status"].map({"Clean": "#4fca74", "Suspicious": "#f97316", "Malicious": "#ef4444"}),
        text=vt_df["Malicious Reports"],
        textposition="outside"
    ))
    fig6.add_trace(go.Bar(
        name="Total Risk Score",
        x=vt_df["IP"],
        y=vt_df["Total Risk"],
        marker_color="#4f8ef7",
        text=vt_df["Total Risk"],
        textposition="outside",
        opacity=0.7
    ))
    fig6.update_layout(
        barmode="group",
        title="VirusTotal Detections vs Risk Score per Host",
        height=400,
        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
        font_color="#e2e8f0",
        xaxis=dict(gridcolor=GRID_COL),
        yaxis=dict(gridcolor=GRID_COL),
        legend=dict(bgcolor=CHART_BG)
    )
    st.plotly_chart(fig6, use_container_width=True)

    #Chart 7 - Vulnerability tyoe heatmap per host
    st.subheader("🔥 Vulnerability Heatmap (Host × Service)")
    pivot = df.pivot_table(
        index="ip", columns="service",
        values="risk_score", aggfunc="max"
    ).fillna(0)
    fig7 = px.imshow(
        pivot,
        color_continuous_scale="RdYlGn_r",
        title="Max Risk Score per Host × Service",
        labels=dict(color="Risk Score")
    )
    fig7.update_layout(height=350,
                       paper_bgcolor=CHART_BG,
                       font_color="#e2e8f0")
    st.plotly_chart(fig7, use_container_width=True)

#Tab 3 - Threat Intel & Alerts
with tab3:
    st.subheader("🚨 Threat Intelligence")

    crit_risk = filt[filt["severity"] == "Critical"][
        ["ip", "port", "service", "vulnerability", "risk_score", "severity", "malicious_reports"]
    ].sort_values("risk_score", ascending=False)

    high_risk = filt[filt["severity"] == "High"][
        ["ip", "port", "service", "vulnerability", "risk_score", "severity", "malicious_reports"]
    ].sort_values("risk_score", ascending=False)

    med_risk = filt[filt["severity"] == "Medium"][
        ["ip", "port", "service", "vulnerability", "risk_score", "severity", "malicious_reports"]
    ].sort_values("risk_score", ascending=False)

    alert_df_combined = pd.concat([crit_risk, high_risk])

    if alert_df_combined.empty:
        st.success("✅ No Critical or High-risk entries detected in current filter.")
    else:
        st.error(
            f"⚠️ ALERT — {len(alert_df_combined)} Critical/High entries across "
            f"{alert_df_combined['ip'].nunique()} host(s). Immediate action required."
        )

    with st.expander(f"🔴 Critical Risk Entries ({len(crit_risk)})", expanded=True):
        if crit_risk.empty:
            st.write("None found.")
        else:
            st.write(crit_risk.to_html(index=False), unsafe_allow_html=True)

    with st.expander(f"🟠 High Risk Entries ({len(high_risk)})", expanded=True):
        if high_risk.empty:
            st.write("None found.")
        else:
            st.write(high_risk.to_html(index=False), unsafe_allow_html=True)

    with st.expander(f"🟡 Medium Risk Entries ({len(med_risk)})", expanded=False):
        if med_risk.empty:
            st.write("None found.")
        else:
            st.write(med_risk.to_html(index=False), unsafe_allow_html=True)

    st.divider()

    #Per - Host Risk Breakdown
    st.subheader("🔎 Per-Host Risk Breakdown")
    breakdown = df.groupby("ip").agg(
        total_ports       = ("port",             "count"),
        critical_ports    = ("severity",         lambda x: (x == "Critical").sum()),
        high_risk_ports   = ("severity",         lambda x: (x == "High").sum()),
        max_risk_score    = ("risk_score",        "max"),
        malicious_score   = ("malicious_reports", "max"),
        services          = ("service",           lambda x: ", ".join(sorted(x.unique())))
    ).reset_index()
    breakdown.columns = ["IP", "Total Ports", "Critical Ports", "High Risk Ports",
                         "Max Risk Score", "Malicious Score", "Services"]
    breakdown = breakdown.sort_values("Max Risk Score", ascending=False)
    st.write(breakdown.to_html(index=False), unsafe_allow_html=True)

    st.divider()

    #Email Alert Section
    st.subheader("📧 Manual Email Alert")

    if st.session_state.auto_alert_sent:
        st.info("ℹ️ Alert email was already auto-sent after this scan. You can re-send it manually below.")

    manual_alert_df = df[df["severity"].isin(["Critical", "High"])]

    if manual_alert_df.empty:
        st.info("✅ No Critical/High entries in current scan — no alert to send.")

    email_ready = bool(
        sender_email and not sender_email.startswith("your_") and
        app_password and not app_password.startswith("your_") and
        recipient_email and not recipient_email.startswith("your_")
    )

    if not email_ready:
        st.warning("⚠️ Fill in GMAIL_SENDER, GMAIL_PASSWORD, and GMAIL_RECIPIENT in .env first.")

    send_btn = st.button(
        f"🚨 Send Alert Email ({len(manual_alert_df)} High/Critical entries)"
        if not manual_alert_df.empty else "🚨 Send Alert Email (0 entries — all clear)",
        type="primary",
        disabled=not email_ready,
        use_container_width=True
    )

    if send_btn and email_ready:
        with st.spinner("Sending alert email..."):
            result = send_alert_email(
                sender_email, app_password, recipient_email,
                manual_alert_df if not manual_alert_df.empty else df.head(0),
                st.session_state.scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                int(df["risk_score"].max())
            )
        if result is True:
            st.success(f"✅ Alert email sent successfully to {recipient_email}!")
        else:
            st.error(f"❌ Failed: {result}")
            st.caption("Fixes: check App Password has no spaces, 2-Step Verification is ON in Gmail.")

#Tab 4 - Export
with tab4:
    st.subheader("💾 Export Results")

    ea, eb = st.columns(2)
    with ea:
        st.markdown("**Full Scan Results**")
        st.caption("All hosts and ports from the scan")
        st.download_button(
            label="⬇️ Download Full Results (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="full_scan_results.csv",
            mime="text/csv",
            use_container_width=True
        )
    with eb:
        st.markdown("**Filtered Results**")
        st.caption(f"Current filter — {len(filt)} rows")
        st.download_button(
            label="⬇️ Download Filtered Results (CSV)",
            data=filt.to_csv(index=False).encode("utf-8"),
            file_name="filtered_scan_results.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.divider()
    st.markdown("**Host Summary Report**")
    st.caption("One row per host with aggregated stats")
    summary_export = df.groupby("ip").agg(
        open_ports        = ("port",             "count"),
        max_risk          = ("risk_score",        "max"),
        malicious_score   = ("malicious_reports", "max"),
        dominant_severity = ("severity",          lambda x: x.value_counts().index[0]),
        services          = ("service",           lambda x: ", ".join(sorted(x.unique())))
    ).reset_index()
    summary_export.columns = ["IP", "Open Ports", "Max Risk",
                               "Malicious Score", "Dominant Severity", "Services"]
    st.download_button(
        label="⬇️ Download Host Summary (CSV)",
        data=summary_export.to_csv(index=False).encode("utf-8"),
        file_name="host_summary.csv",
        mime="text/csv"
    )
