from flask import Flask, render_template, jsonify
import threading
from scapy.all import sniff, IP, TCP, Raw
from automata import is_valid_http_request
from flask import request

blocked_ips = set() 
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

            
            if ip_src in blocked_ips or ip_dst in blocked_ips:
                status = "BLOCKED"

            elif payload.strip() != "":
                if ip_src.startswith("192.168.") or ip_src.startswith("10."):
                    
                    is_valid = is_valid_http_request(payload)
                    status = "ALLOWED" if is_valid else "BLOCKED"
                else:
                   
                    status = "ALLOWED"
            else:
                status = "ALLOWED"

            
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

@app.route("/block_ip", methods=["POST"])
def block_ip():
    ip = request.json.get("ip")
    if ip:
        blocked_ips.add(ip)
        return jsonify({"status": "success", "message": f"{ip} blocked"})
    return jsonify({"status": "error", "message": "No IP provided"}), 400

@app.route("/unblock_ip", methods=["POST"])
def unblock_ip():
    ip = request.json.get("ip")
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        return jsonify({"status": "success", "message": f"{ip} unblocked"})
    return jsonify({"status": "error", "message": "IP not found"}), 400

if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    app.run(debug=True)