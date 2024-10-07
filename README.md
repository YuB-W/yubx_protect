# YuB-X Protect V2

![YuB Protect Logo](yub.png)


# YuB Protect 
is optimized for Kali Linux, one of the most powerful penetration testing and network security operating systems. If you’re using YuB Protect on another Linux distribution, some features may need further adjustments to run smoothly.

![Kali Linux Focus](kali.png)

YuB Protect is a powerful, Python-based application designed exclusively for Kali Linux to effectively monitor and protect Wi-Fi networks from security threats. It provides real-time detection, response, and logging of various Wi-Fi attacks, helping you secure your wireless networks.

## Table of Contents
- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Features](#Features)

## About

YuB Protect is a comprehensive solution for monitoring and protecting Wi-Fi networks. It uses Python scripts to identify and log potential attacks such as deauthentication and PMKID attacks, providing enhanced security for users’ networks.

## Features

- **Wi-Fi Attack Detection:** Continuously monitors for common Wi-Fi attacks, logging incidents in real time.
- **Automatic Protection Mechanism:** Implements automated responses to mitigate detected threats.
- **Real-time Updates:** Displays live data and alerts through a user-friendly web interface.
- **Custom Audio Alerts:** Set up audio notifications for different attack types.
- **Easy Configuration:** Quick setup with simplified configuration options.

## Installation

To install and set up YuB Protect, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YuB-W/yubx_protect.git
   cd yubx_protect
   sudo python3 yub_x.py
Navigate to the project directory:
cd yubx_protect
Ensure Python 3 is installed (if not already installed on your system).

Run the main script:

sudo python3 yub_x.py
Starting the Application
Once the application is running, it will start monitoring your Wi-Fi networks for attacks. To interact with the tool:

Accessing the Web Interface
Open your web browser and navigate to [http://192.168.0.100:5000](http://192.168.0.100:5000) to access the YuB Protect web interface make sure is your local ip from kali linux.

Monitoring Logs
Real-time logs of detected attacks are provided, including details such as the type of attack, timestamp, and the affected network.

Files
Here’s an overview of the key files included in the project:

yub_x.py: The main script responsible for Wi-Fi network monitoring and protection.
wifi_protect.py: Implements the logic for automatic protection mechanisms.
fix_wlan.py: Troubleshoots and fixes issues with WLAN interfaces.
index.html: Provides the web interface layout.
cast.py: Handles functionalities related to TV casting.
sleep.py: Manages the application’s sleep functions for performance optimization.
tv_cast.py: Handles additional TV casting functionalities.
Audio Files: These files include various alerts, such as alert_r.m4a, detect.m4a, and welcome.m4a.
Configuration
Various aspects of the application can be configured in the config.py file. You can adjust settings such as:

Alert thresholds
Audio notifications
Logging options
Audio Alerts
YuB Protect supports audio notifications for different events. The default audio files are:

alert_r.m4a: Alert sound for detected threats.
detect.m4a: Sound for general detections.
welcome.m4a: Welcome message sound upon application startup.
These files can be customized by replacing them with your own audio files in the project directory.


Name: [Yub-X]
