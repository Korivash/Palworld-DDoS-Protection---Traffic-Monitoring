# Palworld DDoS Protection & Traffic Monitoring

This repository contains a **DDoS protection** and **traffic monitoring system** specifically designed for the **Palworld** game server. It monitors incoming traffic on **UDP port 2025**, detects suspicious traffic patterns, and blocks IPs responsible for generating excessive traffic.

The system is designed to protect the server from DDoS attacks and ensure legitimate players can continue to connect and enjoy the game without interruptions.

## Features

- 🚀 **Real-time monitoring** of UDP traffic on port 2025.
- 🚨 **Traffic threshold detection**: Blocks IPs generating too many packets per second.
- 📢 **Discord Notifications**: Sends alerts to a Discord channel when an IP is blocked.
- ✅ **Whitelist Support**: Allows trusted IPs (e.g., server admin) to bypass blocking.
- 📝 **Log Generation**: Keeps track of blocked traffic and generates log files for review.

## Prerequisites

```Before running this script, make sure you have the following installed:

- **Python 3.x** (preferably Python 3.6+)
- **Scapy** library for packet sniffing
- **Npcap** for capturing network packets on Windows```

# To install the required dependencies, run:

```bash
pip install -r requirements.txt```

Installation
Step 1: Download Npcap
To capture network packets on Windows, you need to install Npcap:

```Download Npcap from Npcap's official website.

During installation, make sure to select the option "Install Npcap in WinPcap API-compatible Mode".```

# Step 2: Clone the Repository
```Clone the repository to your local machine:
git clone https://github.com/yourusername/palworld-ddos-protection.git
cd palworld-ddos-protection```

# Step 3: Set Up the Configuration
```Edit the main.py file to update the following configuration parameters:

GAME_PORT: Set this to the port your Palworld server is running on.

BLOCK_THRESHOLD: The number of packets per second that will trigger a block (default is 500).

BLOCK_DURATION: How long the IP will be blocked for (in seconds) (default is 600).

WHITELIST: List trusted IPs that are allowed to bypass the blocking mechanism (e.g., server admin IPs).```

DISCORD_WEBHOOK: Set your Discord webhook URL for notifications.

# Step 4: Run the Script
```Once the configuration is updated, you can run the script:
python main.py
This will start monitoring traffic and block suspicious IPs that exceed the packet threshold.

Logs
The script generates log files in the logs/ directory. Each time an IP is blocked, a new log entry is created. This will help you track suspicious activity and ensure that legitimate players are not incorrectly blocked.

Discord Notifications
When an IP is blocked due to excessive traffic, the script sends a real-time notification to your designated Discord channel. This allows you to stay up-to-date with any potential attacks and take quick action if necessary.```

#Troubleshooting
If players report connection issues: Check if their IP was mistakenly flagged by reviewing the logs or adjusting the traffic threshold.

Using a proxy or VPN: Ensure that the traffic from your proxy/VPN is not being flagged as suspicious.

License
This project is licensed under the MIT License - see the LICENSE file for details.

