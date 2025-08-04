from flask import Flask, render_template, jsonify
import threading
from scapy.all import sniff, IP, TCP, Raw
from automata import is_valid_http_request

app = Flask(__name__)

packet_logs = []

def packet_callback(packet):
    global packet_logs

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = 'TCP' if TCP in packet else 'Other'
        
        if Raw in packet:
            payload = packet[Raw].load.decode(errors="ignore")
            if "HTTP" in payload or "GET" in payload or "POST" in payload:
                is_valid = is_valid_http_request(payload)
                status = "ALLOWED" if is_valid else "BLOCKED"

                log_entry = {
                    "proto": proto,
                    "src": ip_src,
                    "dst": ip_dst,
                    "status": status,
                    "payload": payload[:100] + "..."
                }

                packet_logs.append(log_entry)

def start_sniffer():
    sniff(prn=packet_callback, store=False)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/logs")
def get_logs():
    return jsonify(packet_logs[-20:])

if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    app.run(debug=True)