from scapy.all import sniff, IP, TCP, Raw
from automata import is_valid_http_request

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = 'TCP' if TCP in packet else 'Other'
        
        if Raw in packet:
            payload = packet[Raw].load.decode(errors="ignore")
            if "HTTP" in payload or "GET" in payload or "POST" in payload:
                is_valid = is_valid_http_request(payload)
                status = "ALLOWED" if is_valid else "BLOCKED"

                print(f"[{proto}] {ip_src} --> {ip_dst} | Status: {status}")
                print(f"Payload: {payload}\n")

print("Finite Automata Firewall Running...")
sniff(prn=packet_callback, store=False)
