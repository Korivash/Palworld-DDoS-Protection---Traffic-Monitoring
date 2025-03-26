from scapy.all import sniff, IP, UDP, TCP, conf
import os
import requests
import time
from collections import defaultdict

# Configuration
GAME_PORTS = []  # Enter Port Here
BLOCK_THRESHOLD = 200  
WARN_THRESHOLD = 100  
WHITELIST = [""]  
DISCORD_WEBHOOK = ""


request_counts = defaultdict(int)
syn_counts = defaultdict(int)
blocked_ips = set()


interface = conf.iface  

def send_discord_alert(ip):
    """Send a Discord notification when an attack is detected."""
    message = {
        "username": "DDoS Monitor",
        "embeds": [{
            "title": "🚨 DDoS Attack Detected!",
            "description": f"IP **{ip}** has exceeded attack thresholds.",
            "color": 16711680
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message)
    except:
        pass

def block_ip(ip):
    """Block an IP using Windows Firewall (or Linux UFW)."""
    if ip in WHITELIST or ip in blocked_ips:
        return
    os.system(f'netsh advfirewall firewall add rule name="Blocked {ip}" dir=in action=block remoteip={ip}')
    blocked_ips.add(ip)
    send_discord_alert(ip)

def detect_ddos(packet):
    """Detect suspicious activity."""
    if IP in packet:
        ip_src = packet[IP].src
        if ip_src in WHITELIST:
            return
        
        request_counts[ip_src] += 1

        if TCP in packet and packet[TCP].flags == 2:  
            syn_counts[ip_src] += 1  

        if request_counts[ip_src] > BLOCK_THRESHOLD or syn_counts[ip_src] > BLOCK_THRESHOLD:
            block_ip(ip_src)

def monitor():
    """Start sniffing traffic on the active interface."""
    print(f"Monitoring {interface} on ports {GAME_PORTS}...")
    sniff(iface=interface, filter=" or ".join(f"port {p}" for p in GAME_PORTS), prn=detect_ddos, store=0)

if __name__ == "__main__":
    monitor()

