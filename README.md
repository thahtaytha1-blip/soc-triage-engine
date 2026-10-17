# Multi-Source SOC Triage & Threat Hunting Engine

A Streamlit web app that correlates three telemetry sources with a Gemini model and produces an incident response report: executive summary, MITRE ATT&CK-mapped timeline, IOCs, a Sigma rule and containment commands.

![Incident report output](screenshot-report.png)

## What it does

| Input | Format |
|---|---|
| Linux authentication log | `auth.log` (SSH, sudo) |
| Windows/host process events | Sysmon-style `sysmon.json` |
| Network traffic | `.pcap`/`.pcapng` (parsed with Scapy) or pre-parsed flow CSV |

- Upload your own logs in the sidebar, or use the bundled sample attack scenario (SSH brute force, `linpeas.sh` download, privilege escalation, reverse shell on port 4444).
- Raw logs are shown and editable before analysis.
- The report streams live and can be downloaded as Markdown.
- Instant Mode disables model thinking time for faster output.
- Parsed PCAPs are cached so they are not re-parsed on every click.

## Setup

```bash
pip install -r requirements.txt
```

Get a Gemini API key from [Google AI Studio](https://aistudio.google.com/) and set it as an environment variable. **Never commit your key.**

```bash
# Mac/Linux
export GEMINI_API_KEY="your-key"
# Windows (cmd)
set GEMINI_API_KEY=your-key
```

## Run

```bash
streamlit run app.py          # web GUI (main entry point)
python triage_engine.py       # simple CLI: analyses sample_logs/ and writes reports/INCIDENT_REPORT.md
python test_api.py            # quick check that your API key works
```

The API key can also be pasted into the app's sidebar.

## Files

- `app.py`: Streamlit GUI
- `triage_engine.py`: minimal script version using the sample logs
- `generate_sample_logs.py`, `create_sample_pcap.py`: regenerate the sample data in `sample_logs/`
- `sample_logs/`: demo attack scenario

## Models

Default: `gemini-3.8-flash`. `gemini-4-argon` is selectable in the sidebar if your key has access.

## Planned improvements

- CLI flags `--auth`, `--sysmon`, `--pcap`
- Deterministic line-ID tagging (`[AUTH-00412]`) for evidence citation
- UTC timestamp normalization of all sources
- Full 5-tuple flow aggregation and L7 extraction (HTTP, DNS, TLS SNI, JA3)
- Gemini context caching with token/cost reporting
- Interactive threat-hunt REPL
- Sigma syntax validation

## Disclaimer

Sample data is synthetic. LLM output can be wrong, so verify findings against the raw logs before acting on them.
