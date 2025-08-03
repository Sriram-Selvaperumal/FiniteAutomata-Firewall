from scapy.all import sniff, IP, TCP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = 'TCP' if TCP in packet else 'Other'
        
        if Raw in packet:
            payload = str(packet[Raw].load)
            if "HTTP" in payload or "GET" in payload or "POST" in payload:
                print(f"[{proto}] {ip_src} --> {ip_dst}")
                print(f"Payload: {payload}\n")

print("Protocol-Aware Sniffer Running...")
sniff(prn=packet_callback, store=False)
