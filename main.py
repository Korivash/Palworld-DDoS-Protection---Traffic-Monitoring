import os
import time
import requests
from collections import defaultdict
from scapy.all import sniff, IP, UDP

GAME_PORT = 2071  # Enter Game Port Here
BLOCK_THRESHOLD = 500  # Number of Packets sent before its added to the blocked list. 
WHITELIST = ["Personal IP", "Admin IPs"] 
DISCORD_WEBHOOK = ""


request_counts = defaultdict(int)
blocked_ips = set()


log_folder = r"" # Enter Path to Logs folder here
if not os.path.exists(log_folder):
    os.makedirs(log_folder)


log_file_path = os.path.join(log_folder, "blocked_ips.log")

def send_discord_alert(ip):
    """Send a Discord notification when an IP is blocked."""
    message = {
        "username": "Security Bot",
        "embeds": [{
            "title": "🚨 DDoS Attempt Blocked!",
            "description": f"IP **{ip}** exceeded the packet limit and has been permanently blocked.",
            "color": 16711680,  
            "footer": {"text": f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"}
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message)
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Discord alert: {e}")

def log_blocked_ip(ip):
    """Log blocked IPs to a file."""
    with open(log_file_path, "a") as log_file:
        log_file.write(f"{ip} - Blocked at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

def block_ip(ip):
    """Block an IP using Windows Firewall and notify Discord."""
    if ip in WHITELIST or ip in blocked_ips:
        return  

    print(f"Blocking {ip} due to excessive traffic...")
    os.system(f'netsh advfirewall firewall add rule name="Blocked {ip}" dir=in action=block remoteip={ip}')
    blocked_ips.add(ip)
    log_blocked_ip(ip)
    send_discord_alert(ip)

def packet_callback(packet):
    """Analyze each incoming packet."""
    if IP in packet and UDP in packet:
        ip_src = packet[IP].src

        if ip_src in WHITELIST or ip_src in blocked_ips:
            return

        request_counts[ip_src] += 1

        if request_counts[ip_src] > BLOCK_THRESHOLD:
            block_ip(ip_src)

def monitor_traffic():
    """Sniff incoming packets on the game port."""
    print(f"Monitoring traffic on UDP port {GAME_PORT}...")

    while True:
        sniff(filter=f"udp port {GAME_PORT}", prn=packet_callback, store=0, count=100)
        request_counts.clear() 
        time.sleep(1)

if __name__ == "__main__":
    try:
        monitor_traffic()
    except KeyboardInterrupt:
        print("Stopping script...")

