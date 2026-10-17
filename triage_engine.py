import os
from google import genai

# 1. Connect to Gemini API (key is read from the GEMINI_API_KEY environment variable)
client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

print("[*] Reading multi-source telemetry logs...")

# 2. Read the 3 log files from ./sample_logs/
with open("sample_logs/auth.log", "r") as f:
    auth_log = f.read()

with open("sample_logs/sysmon.json", "r") as f:
    sysmon_log = f.read()

with open("sample_logs/network_flows.csv", "r") as f:
    network_log = f.read()

# 3. Combine them into one unified context payload with clear XML boundaries
unified_telemetry = f"""
<telemetry_bundle>
  <linux_auth_log>
{auth_log}
  </linux_auth_log>

  <sysmon_telemetry>
{sysmon_log}
  </sysmon_telemetry>

  <network_pcap_flows>
{network_log}
  </network_pcap_flows>
</telemetry_bundle>
"""

# 4. Give the AI its Senior SOC Analyst & Detection Engineer instructions
soc_prompt = f"""
You are a Senior SOC Analyst and Detection Engineer.
Analyze the following multi-source telemetry bundle (Linux auth.log, Sysmon process events, and PCAP network flows).
Correlate the timestamps, IPs, and processes across all three logs to reconstruct the attack.
Ignore normal background admin/cron noise and focus strictly on the attack chain.

Generate a comprehensive Incident Response Report in Markdown with these exact sections:

1. **Executive Summary**: High-level summary of the compromise, attacker IP, compromised account, and final impact.
2. **Cross-Log Attack Timeline**: A Markdown table showing Timestamp, Log Source, Event Summary, and MITRE ATT&CK Technique ID (e.g., T1110, T1059, T1548).
3. **Indicators of Compromise (IOCs)**: Bullet list of malicious IPs, ports, URLs, and suspicious commands.
4. **Detection Engineering (Sigma Rule)**: Write a valid YAML Sigma rule to detect the privilege escalation or reverse shell seen in the Sysmon logs.
5. **Immediate Containment Commands**: Exact Linux `iptables` and account lock commands to contain the threat.

Here is the telemetry data:
{unified_telemetry}
"""

print("[*] Sending correlated logs to Gemini for Threat Hunting & Triage...")

# 5. Call the model
response = client.models.generate_content(
    model="gemini-3.8-flash",
    contents=soc_prompt
)

# 6. Save the output to a clean Markdown report and print it
os.makedirs("reports", exist_ok=True)
report_path = "reports/INCIDENT_REPORT.md"

with open(report_path, "w", encoding="utf-8") as f:
    f.write(response.text)

print("\n" + "="*60)
print(response.text)
print("="*60)
print(f"\n[+] Full Incident Report & Sigma Rule saved to: {report_path}")