import logging
import logging.handlers 

# Fixed Configuration
INTERFACE = "wlan0"  # Change this to your actual interface

# Configure logging properly
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create handlers
file_handler = logging.handlers.RotatingFileHandler(
    'wifi_monitor.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
console_handler = logging.StreamHandler()

# Create formatter and add to handlers
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

import subprocess
import sys

required_modules = [
    "subprocess", "threading", "time", "logging", "datetime", "scapy",
    "flask", "playsound", "random", "string", "socket", "fcntl",
    "struct", "requests", "json", "numpy", "termcolor", "netifaces"
]

def install_module(module_name):
    """Install the module via pip if it's not already installed."""
    try:
        print(f"[*] Checking if {module_name} is installed...")
        __import__(module_name)
        logger.info(f"[+] {module_name} is already installed.")
    except ImportError:
        logger.warning(f"[!] {module_name} not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
        logger.info(f"[+] {module_name} installed successfully.")

def check_and_install_modules():
    """Check if all required modules are installed, install them if missing."""
    for module in required_modules:
        install_module(module)

check_and_install_modules()

import os
from threading import Thread
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify, current_app
from scapy.all import (
    get_if_list,
    sniff, Dot11Deauth, RadioTap, Dot11, Dot11Auth, sendp,
    Dot11Beacon, Dot11Disas, Dot11ProbeReq  # <-- Add this
)
from playsound import playsound
import random
import string
import socket
import fcntl
import struct
import requests
import json
import numpy as np
import traceback


attacks = {
    "deauth": [],
    "auth": [],
    "probe": [],
    "disassoc": []
}
played_alerts = set()
sniff_thread = None
a_p = False  # Auto protection flag
bssid_under_attack = None
previous_bssid = ""
last_attack_time = {}
ALERT_COOLDOWN = 15
last_alert_time = 0

app = Flask(__name__)
url = "https://alerts-history.oref.org.il//Shared/Ajax/GetAlarmsHistory.aspx?lang=he&mode=2"  # 1 = In the past day 2 = In the past week 3 = In the past month
file_path = "alerts_history.json"
delay_seconds = 5  # Delay in seconds between each fetch and send operation




try:
    with open('website.html', 'r') as file:
        MAP_HTML = file.read()
    logger.debug("Website template loaded successfully.")
except Exception as e:
    logger.error(f"Error loading website template: {e}")
    MAP_HTML = ""



@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    """Clear the log file."""
    try:
        with open('wifi_monitor.log', 'w') as log_file:
            log_file.write('')
        return jsonify(status="success")
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        return jsonify(status="error")

def average_rssi(rssi_values):
    return np.mean(rssi_values)

def signal_strength_decay(rssi, band='2.4GHz'):
    # Adjust decay factor for 5GHz if necessary
    decay_factor = 2 if band == '5GHz' else 3
    return 10 ** ((-rssi - 30) / (10 * decay_factor))

def determine_attacker_proximity(rssi_values, band='2.4GHz'):
    avg_rssi = average_rssi(rssi_values)
    distance = signal_strength_decay(avg_rssi, band)
    if avg_rssi > -30:
        proximity = "Attacker is very close, within a few meters"
    elif -30 >= avg_rssi > -50:
        proximity = "Attacker is nearby, possibly within the same room"
    elif -50 >= avg_rssi > -70:
        proximity = "Attacker is in close proximity, likely within the same building"
    else:
        proximity = "Attacker is in the vicinity, but farther away"
    return proximity, distance

def determine_attacker_location(rssi_values, band='2.4GHz'):
    avg_rssi = average_rssi(rssi_values)
    distance = signal_strength_decay(avg_rssi, band)
    if avg_rssi > -30:
        location = "Attacker is located within Room A"
    elif -30 >= avg_rssi > -50:
        location = "Attacker is currently in Room B"
    elif -50 >= avg_rssi > -70:
        location = "Attacker's location is in the hallway outside Room C"
    else:
        location = "Attacker is potentially in an adjacent building"
    return location, distance
    
def extract_essid_from_bssid(bssid, iface=INTERFACE, timeout=10):
    essid_dict = {}
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            beacon = packet[Dot11Beacon]
            bssid_packet = packet[Dot11].addr3
            rssi = -(256 - ord(packet.notdecoded[-4:-3]))
            source = packet.addr2
            try:
                essid = beacon.info.decode()
                if essid:  # Check if ESSID is not empty
                    if bssid_packet not in essid_dict:
                        essid_dict[bssid_packet] = {"essid": essid, "rssi": [], "source": source}
                    essid_dict[bssid_packet]["rssi"].append(rssi)
                else:
                    logger.warning(f"Empty ESSID for BSSID {bssid_packet}")
            except UnicodeDecodeError:
                logger.error(f"Unable to decode ESSID for BSSID {bssid_packet}")
                essid = "[Unreadable ESSID]"
                if bssid_packet not in essid_dict:
                    essid_dict[bssid_packet] = {"essid": essid, "rssi": [], "source": source}
                essid_dict[bssid_packet]["rssi"].append(rssi)
    
    sniff(iface=iface, prn=packet_handler, timeout=timeout, store=0)
    if bssid in essid_dict:
        return {"essid": essid_dict[bssid]["essid"], "rssi": average_rssi(essid_dict[bssid]["rssi"]), "source": essid_dict[bssid]["source"]}
    else:
        logger.error(f"BSSID {bssid} not found in the sniffed data")
        return None

@app.route('/current_alert', methods=['GET'])
def current_alert():
    try:
        for attack_type in ["deauth", "auth", "probe", "disassoc"]:
            if attacks.get(attack_type) and len(attacks[attack_type]) > 0:
                latest_attack = attacks[attack_type][-1]
                essid_rssi_data = extract_essid_from_bssid(latest_attack[2])
                if essid_rssi_data and essid_rssi_data.get("essid"):
                    essid = essid_rssi_data["essid"]
                    rssi = essid_rssi_data["rssi"]
                    source = essid_rssi_data["source"]

                    # Determine band if available
                    band = '5GHz' if '5GHz' in essid else '2.4GHz'

                    # Calculate proximity and location
                    proximity, distance = determine_attacker_proximity([rssi], band)
                    location, _ = determine_attacker_location([rssi], band)
                    message = f"{latest_attack[1]} from {source} detected:\n BSSID: {latest_attack[2]}\n ESSID: {essid}\n RSSI: {rssi} dBm\n {proximity}\n Distance: {distance:.2f} meters\n Location: {location}"
                    return jsonify(alert={"message": message, "type": "red"})
                else:
                    logger.error(f"Invalid ESSID data for BSSID {latest_attack[2]}")
                    return jsonify(alert={"message": "Invalid ESSID data", "type": "red"})
        return jsonify(alert=None)
    except Exception as e:
        logger.exception("Error retrieving current alert")
        return jsonify(alert={"message": "An error occurred while retrieving the alert", "type": "red"})

@app.route('/auto_protect', methods=['POST'])
def auto_protect():
    """Enable or disable auto protection for the last attacked Wi-Fi network."""
    global a_p 

    try:
        if not a_p:
            a_p = True
            return jsonify({'status': 'auto_protected', 'message': 'Protection started!'}), 200
        else:
            a_p = False
            return jsonify({'status': 'Protection stopped!', 'message': 'Protection stopped!'}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/protect_wifi', methods=['POST'])
def protect_wifi():
    """Start an authentication DoS attack to protect the Wi-Fi network under attack."""
    global bssid_under_attack
    if bssid_under_attack:
        iface = INTERFACE
        if iface:
            with app.app_context():
                threading.Thread(target=start_auth_dos, args=(bssid_under_attack, iface)).start()
            return jsonify({'status': 'success', 'message': f'Protection started for BSSID {bssid_under_attack}'}), 200
        return jsonify({'status': 'error', 'message': 'Interface not provided'}), 303
    return jsonify({'status': 'error', 'message': 'No attack detected'}), 303


def detect_attack_patterns(packet):
    """Detect attack patterns and start auto protection."""
    global attacks, bssid_under_attack, last_alert_time

    if not packet.haslayer(Dot11):
        return

    bssid = packet[Dot11].addr2
    current_time = time.time()

    if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas) or packet.haslayer(Dot11ProbeReq):
        attack_type = "Deauth" if packet.haslayer(Dot11Deauth) else "Disassoc" if packet.haslayer(Dot11Disas) else "Probe"

        if bssid not in attack_timestamps:
            attack_timestamps[bssid] = []

        attack_timestamps[bssid].append(current_time)
        attack_timestamps[bssid] = [ts for ts in attack_timestamps[bssid] if current_time - ts <= attack_window_seconds]

        if len(attack_timestamps[bssid]) >= attack_threshold:
            if bssid_under_attack != bssid:
                logger.info(f"{attack_type} attack detected from {bssid} (rate: {len(attack_timestamps[bssid])}/sec)")
                attacks["deauth"].append((datetime.now(), f"{attack_type} attack", bssid))
                bssid_under_attack = bssid
                logger.info(f"bssid_under_attack Updated: {bssid_under_attack}")

                with app.app_context():
                    threading.Thread(target=protect_wifi).start()

                if current_time - last_alert_time >= ALERT_COOLDOWN:
                    threading.Thread(target=playsound, args=('detect.m4a',)).start()
                    logger.debug(f"Sound alert played for {attack_type} attack.")
                    last_alert_time = current_time

@app.route('/')
def index():
    return render_template_string(MAP_HTML)

@app.route('/logs')
def logs():
    """Retrieve logs."""
    try:
        with open('wifi_monitor.log', 'r') as log_file:
            log_lines = log_file.readlines()
        return jsonify({'logs': log_lines})
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
        return jsonify({'error': 'Failed to read logs'}), 500
    
@app.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    """Start sniffing."""
    try:
        iface = request.form.get('iface')
        if iface:
            start_sniffing_thread(iface)
            return jsonify(status="Sniffing started")
        return jsonify(status="Interface not provided"), 400
    except Exception as e:
        logger.exception("Error starting sniffing")
        return jsonify(status="Error starting sniffing"), 500

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    """Stop sniffing."""
    global sniff_thread
    try:
        if sniff_thread:
            sniff_thread.join(timeout=1)
            return jsonify(status="Sniffing stopped")
        return jsonify(status="No sniffing process found"), 400
    except Exception as e:
        logger.exception("Error stopping sniffing")
        return jsonify(status="Error stopping sniffing"), 500



@app.route('/api/geocode')
def geocode():
    city = request.args.get('city')
    if not city:
        return jsonify({'error': 'Missing city parameter'}), 400

    headers = {
        'Accept-Language': 'en',
        'User-Agent': 'yubx/1.0 (yubx@gmail.com)'  # required for Nominatim
    }

    def query_nominatim():
        try:
            url = "https://nominatim.openstreetmap.org/search"
            params = {
                'q': f"{city},Israel",
                'format': 'json',
                'limit': 1,
                'countrycodes': 'IL'
            }
            response = requests.get(url, params=params, headers=headers, timeout=5)
            print(f"[Nominatim] URL: {response.url}")
            response.raise_for_status()
            data = response.json()
            if data:
                return data
        except Exception as e:
            print(f"[Nominatim] Error: {e}")
        return None

    def query_locationiq():
        try:
            # Replace with your own LocationIQ token
            token = 'pk.836f35c4953de25fa9abbec72eaea5ce'
            url = f'https://us1.locationiq.com/v1/search.php'
            params = {
                'key': token,
                'q': f"{city},Israel",
                'format': 'json',
                'limit': 1,
                'countrycodes': 'IL'
            }
            response = requests.get(url, params=params, timeout=5)
            print(f"[LocationIQ] URL: {response.url}")
            response.raise_for_status()
            data = response.json()
            if data:
                return data
        except Exception as e:
            print(f"[LocationIQ] Error: {e}")
        return None

    try:
        # First try Nominatim
        data = query_nominatim()

        # If that fails, try LocationIQ
        if not data:
            data = query_locationiq()

        if not data:
            return jsonify({'error': f'City not found: {city}'}), 404

        return jsonify(data)

    except Exception as e:
        print(f"[API] Fatal error for city '{city}': {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

def verify_interface():
    """Check if the network interface exists"""
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        if INTERFACE not in interfaces:
            logger.error(f"Interface {INTERFACE} not found! Available interfaces: {', '.join(interfaces)}")
            sys.exit(1)
    except ImportError:
        logger.error("netifaces module required. Install with: pip install netifaces")
        sys.exit(1)

verify_interface()


def start_sniffing_thread(iface_name=INTERFACE, bpf_filter=None):
    """Start sniffing thread with error handling and optional BPF filter."""
    global sniff_thread, stop_sniffing

    if iface_name not in get_if_list():
        logger.error(f"Interface '{iface_name}' not found. Available: {get_if_list()}")
        return

    def sniff_loop():
        logger.info(f"Sniffing started on interface {iface_name}")
        while not stop_sniffing:
            try:
                sniff(
                    iface=iface_name,
                    prn=detect_attack_patterns,
                    store=0,
                    filter=bpf_filter or "",
                    monitor=True  # Ensure monitor mode is active
                )
            except Exception as e:
                logger.exception(f"[!] Sniffing error on interface {iface_name}: {e}")
                time.sleep(5)  # Wait before retry

    sniff_thread = threading.Thread(target=sniff_loop)
    sniff_thread.daemon = True
    sniff_thread.start()

def start_auth_dos(bssid, iface_name):
    def get_random_mac():
        return ':'.join([''.join(random.choices(string.hexdigits, k=2)) for _ in range(6)]).upper()

    def send_auth_frame():
        try:
            fake_mac = get_random_mac()
            auth_frame = RadioTap() / Dot11(addr1=bssid, addr2=fake_mac, addr3=bssid) / Dot11Auth(seqnum=1, status=0)
            sendp(auth_frame, iface=iface_name, verbose=False)
        except Exception as e:
            logger.exception("Error sending authentication frame")

    current_time = time.time()
    if bssid in last_attack_time and (current_time - last_attack_time[bssid]) < 20:
        logging.info(f"Skipping Auth DoS on BSSID {bssid}. Attack already performed recently.")
        return

    num_threads = 350  
    logging.info(f"Starting Auth DoS on BSSID {bssid} with {num_threads} threads...")
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_auth_frame, daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
    
    last_attack_time[bssid] = current_time
    logging.info(f"Auth DoS on BSSID {bssid} completed.")
   
def fetch_data(url):
    """Fetch data from the specified URL and return the JSON response."""
    try:
        logger.debug(f"Fetching data from {url}")
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        logger.debug(f"Data fetched: {data}")  # Log the fetched data
        return data
    except requests.exceptions.RequestException as e:
        logger.exception("Error fetching data")
        return None        
    
def load_existing_data(file_path):
    """Load existing data from the specified file."""
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    return None

def save_data(file_path, data):
    """Save data to the specified file."""
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(data)
        
def update_alert_data(file_path, new_data):
    logger.debug("Updating alert data...")
    existing_data = load_existing_data(file_path)
    new_data_str = json.dumps(new_data, indent=4, ensure_ascii=False)
    
    if existing_data is None or new_data_str != existing_data:
        logger.debug("Data has changed. Saving new data.")
        save_data(file_path, new_data_str)
        return True
    else:
        logger.debug("No new data. No update needed.")
    return False

@app.route('/alerts', methods=['GET'])
def get_alerts():
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            alerts = json.load(file)
        logger.debug("Returning alerts data")
        return jsonify(alerts)
    logger.debug("No alerts data found")
    return jsonify([])

def get_ip_address(interface):
    """Get the IP address of a specified network interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(('8.8.8.8', 80))  # Connect to an external address
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        logging.error(f"Unable to get IP address for interface {interface}: {e}")
        return "0.0.0.0"

def main():
    ip_address = get_ip_address('eth0')
    print("\nWebsite:", ip_address + ":5000\n") 
	
    global sniff_thread
    sniff_thread = Thread(target=start_sniffing_thread, args=(INTERFACE,))
    sniff_thread.start()
    def data_fetcher():
        while True:
            new_data = fetch_data(url)
            if new_data is not None:
                if update_alert_data(file_path, new_data):
                    logger.info("[+] Detected new alerts")
                    threading.Thread(target=playsound, args=('alert_r.m4a',)).start()
            time.sleep(delay_seconds)
    
    fetch_thread = Thread(target=data_fetcher, daemon=True)
    fetch_thread.start()
    threading.Thread(target=playsound, args=('welcome.m4a',)).start()
    app.run(debug=False, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    main()
