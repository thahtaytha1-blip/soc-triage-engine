import streamlit as st
from google import genai
from google.genai import types
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import tempfile
import os

st.set_page_config(page_title="SOC Triage & Threat Hunting Engine", page_icon="🛡️", layout="wide")

# FIX 1: @st.cache_data stops Scapy from re-parsing the same PCAP file on every click!
@st.cache_data
def parse_pcap_bytes(pcap_bytes):
    """Parses raw PCAP bytes using Scapy into a compact CSV summary for the LLM."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(pcap_bytes)
        tmp_path = tmp.name

    packets = rdpcap(tmp_path)
    os.remove(tmp_path)

    rows = ["Packet_No,Src_IP,Src_Port,Dst_IP,Dst_Port,Protocol,Flags,Payload_Snippet"]
    for i, pkt in enumerate(packets, 1):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = "OTHER"
            sport, dport, flags = "-", "-", "-"
            if TCP in pkt:
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            payload = ""
            if Raw in pkt:
                payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip().replace("\r", " ").replace("\n", " ")[:80]
            rows.append(f"{i},{src_ip},{sport},{dst_ip},{dport},{proto},{flags},{payload}")
    return "\n".join(rows)

# FIX 2: @st.cache_data caches the AI report so clicking the same logs twice returns in 0.01 seconds!
@st.cache_data(show_spinner=False)
def load_default_logs():
    auth = open("sample_logs/auth.log").read() if os.path.exists("sample_logs/auth.log") else ""
    sysm = open("sample_logs/sysmon.json").read() if os.path.exists("sample_logs/sysmon.json") else ""
    net = open("sample_logs/network_flows.csv").read() if os.path.exists("sample_logs/network_flows.csv") else ""
    return auth, sysm, net

st.title("🛡️ Multi-Source SOC Triage & Threat Hunting Engine")
st.caption("Automated Cross-Log Correlation (Linux Auth + Sysmon + Scapy PCAP Parser), MITRE ATT&CK Mapping & Sigma Generation")

with st.sidebar:
    st.header("⚙️ Engine Configuration")
    api_key = st.text_input(
        "Gemini API Key",
        type="password",
        value=os.environ.get("GEMINI_API_KEY", "")
    )
    model_name = st.selectbox("Model", ["gemini-3.8-flash", "gemini-4-argon"])
    fast_mode = st.checkbox("⚡ Instant Mode (Disable Deep Thinking Delay)", value=True)
    
    st.markdown("---")
    st.header("📤 Upload Custom Logs (Optional)")
    uploaded_auth = st.file_uploader("Upload auth.log", type=["log", "txt"])
    uploaded_sysmon = st.file_uploader("Upload sysmon.json", type=["json", "txt"])
    uploaded_pcap = st.file_uploader("Upload Network Capture (.pcap)", type=["pcap", "pcapng", "csv"])

auth_data, sysmon_data, net_data = load_default_logs()

if uploaded_auth:
    auth_data = uploaded_auth.read().decode("utf-8", errors="ignore")
if uploaded_sysmon:
    sysmon_data = uploaded_sysmon.read().decode("utf-8", errors="ignore")
if uploaded_pcap:
    if uploaded_pcap.name.endswith((".pcap", ".pcapng")):
        net_data = parse_pcap_bytes(uploaded_pcap.getvalue())
        st.sidebar.success(f"Parsed {uploaded_pcap.name} via Scapy (Cached)!")
    else:
        net_data = uploaded_pcap.getvalue().decode("utf-8", errors="ignore")

with st.expander("📂 View Raw Multi-Source Telemetry Logs", expanded=True):
    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("Linux auth.log")
        auth_input = st.text_area("auth.log", auth_data, height=200)
    with col2:
        st.subheader("Sysmon Telemetry")
        sysmon_input = st.text_area("sysmon.json", sysmon_data, height=200)
    with col3:
        st.subheader("Parsed PCAP Flows")
        net_input = st.text_area("network_flows", net_data, height=200)

if st.button("🚀 Run Automated Threat Hunt & Triage", type="primary"):
    if not api_key:
        st.error("Please enter your Gemini API Key in the sidebar!")
    else:
        try:
            # FIX 3: Disable the 60-second silent retry loop so errors show immediately
            client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(retry_options=types.HttpRetryOptions(attempts=1))
            )
            prompt = f"""
            You are a Senior SOC Analyst and Detection Engineer.
            Analyze the following multi-source telemetry bundle. Correlate timestamps, IPs, ports, payloads, and processes across all three logs.
            Ignore normal background noise. Output a Markdown Incident Response Report with:
            1. Executive Summary
            2. Cross-Log Attack Timeline (Markdown Table with Timestamp/Order, Log Source, Event Summary, MITRE ATT&CK ID)
            3. Indicators of Compromise (IOCs)
            4. Detection Engineering (Valid YAML Sigma Rule)
            5. Immediate Containment Commands (Linux iptables & account remediation)

            <linux_auth_log>{auth_input}</linux_auth_log>
            <sysmon_telemetry>{sysmon_input}</sysmon_telemetry>
            <network_pcap_flows>{net_input}</network_pcap_flows>
            """
            
            st.info(f"⚡ Streaming response from {model_name} ({len(prompt) // 4} tokens)...")
            
            # Turn off the 15-second thinking pause if Instant Mode is checked
            gen_config = types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_budget=0)
            ) if fast_mode else None
            
            report_box = st.empty()
            full_report = ""
            
            for chunk in client.models.generate_content_stream(
                model=model_name,
                contents=prompt,
                config=gen_config
            ):
                if chunk.text:
                    full_report += chunk.text
                    report_box.markdown(full_report + "▌")
            
            report_box.markdown(full_report)
            st.session_state["last_report"] = full_report
            st.success("Triage Complete!")
            
        except Exception as e:
            st.error(f"API Notice: {e} (Wait 10 seconds if you hit the Free Tier rate limit!)")

# Keep the Download button & last report visible even if you click other things!
if "last_report" in st.session_state:
    st.download_button(
        "📥 Download Incident Report (.md)",
        st.session_state["last_report"],
        "INCIDENT_REPORT.md",
        "text/markdown"
    )