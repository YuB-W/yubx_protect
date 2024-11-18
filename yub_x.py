import os
import subprocess
import sys
import time
import urllib.request
from urllib.error import HTTPError, URLError
import hashlib
import itertools
from threading import Thread
from colorama import Fore, init

init(autoreset=True)

# Base directory where the script resides
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# List of required packages
required_packages = [
    "python3-pyqt6", "python3-rpds-py", "python3-ruamel.yaml.clib",
    "python3-setproctitle", "python3-smbc", "python3-snappy",
    "python3-twisted", "python3-ubjson", "python3-ujson",
    "python3-uvloop", "python3-wrapt", "python3-yara",
    "python3-zstandard", "sqlmap", "sslyze"
]

# Print the application banner
def print_banner():
    banner_lines = [
        "    ====================================",
        "          ██╗   ██╗██╗   ██╗██████╗ ",
        "          ██║   ██║██║   ██║██╔══██╗",
        "          ██║   ██║██║   ██║██████╔╝",
        "          ██║   ██║██║   ██║██╔═══╝ ",
        "          ╚██████╔╝╚██████╔╝██║     ",
        "           ╚═════╝  ╚═════╝ ╚═╝     ",
        "    ====================================",
        "               YuB-X Protect V2.1",
        "    ====================================",
    ]
    for line in banner_lines:
        print(Fore.GREEN + line)
        time.sleep(0.1)

# Ensure directory exists
def create_dir_if_missing(path):
    if not os.path.exists(path):
        os.makedirs(path)
        print(Fore.CYAN + f"[INFO] Created directory: {path}")

# Calculate checksum of a file
def calculate_checksum(filepath):
    hash_alg = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hash_alg.update(chunk)
    return hash_alg.hexdigest()

# Download and update files with checksum validation
def download_file(url, dest):
    try:
        temp_file = dest + ".tmp"
        urllib.request.urlretrieve(url, temp_file)
        temp_checksum = calculate_checksum(temp_file)
        
        if os.path.exists(dest):
            current_checksum = calculate_checksum(dest)
            if temp_checksum == current_checksum:
                os.remove(temp_file)
                print(Fore.CYAN + f"[INFO] {dest} is up-to-date.")
                return False  # No update was performed
        os.rename(temp_file, dest)
        print(Fore.GREEN + f"[SUCCESS] Updated or downloaded {dest}.")
        return True
    except (HTTPError, URLError) as e:
        print(Fore.RED + f"[ERROR] Failed to download {url}: {e}")
        return False

# Install required Python packages
def install_package(package):
    try:
        print(Fore.YELLOW + f"[INFO] Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print(Fore.GREEN + f"[SUCCESS] Installed {package}.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"[ERROR] Failed to install {package}.")

def install_required_packages():
    packages = ['flask', 'scapy', 'playsound', 'requests', 'numpy',
                'pychromecast', 'colorama']
    for package in packages:
        install_package(package)

# Check and update system packages
def check_and_update_system():
    try:
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        print(Fore.GREEN + "[SUCCESS] System package lists updated.")
        if input(Fore.YELLOW + "Do you want to upgrade packages? (y/n): ").lower() == 'y':
            subprocess.run(["sudo", "apt-get", "upgrade", "-y"], check=True)
            print(Fore.GREEN + "[SUCCESS] System packages upgraded.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[ERROR] Error updating system: {e}")

# Display animated loading
def animated_loading(message):
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    while getattr(animated_loading, "running", True):
        sys.stdout.write(Fore.CYAN + f"\r{message} " + next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)

# Stop loading animation
def stop_loading():
    animated_loading.running = False

# Update files
def update_files():
    files = {
        "website.html": "https://github.com/YuB-W/yubx_protect/raw/main/website.html",
        "wifi_protect.py": "https://github.com/YuB-W/yubx_protect/raw/main/wifi_protect.py",
        "sleep.py": "https://github.com/YuB-W/yubx_protect/raw/main/sleep.py",
        "fix_wlan.py": "https://github.com/YuB-W/yubx_protect/raw/main/fix_wlan.py",
        "cast.py": "https://github.com/YuB-W/yubx_protect/raw/main/cast.py",
        "index.html": "https://github.com/YuB-W/yubx_protect/raw/main/index.html",
        "detect.m4a": "https://github.com/YuB-W/yubx_protect/raw/main/detect.m4a",
        "welcome.m4a": "https://github.com/YuB-W/yubx_protect/raw/main/welcome.m4a",
        "alert_r.m4a": "https://github.com/YuB-W/yubx_protect/raw/main/alert_r.m4a"
    }

    updates_performed = False
    for filename, url in files.items():
        dest_path = os.path.join(BASE_DIR, filename)
        updated = download_file(url, dest_path)
        if updated:
            updates_performed = True

    if updates_performed:
        print(Fore.GREEN + "[SUCCESS] Files updated successfully.")
    else:
        print(Fore.CYAN + "[INFO] All files are already up-to-date.")

# Main execution
def main():
    print_banner()
    create_dir_if_missing(BASE_DIR)
    
    setup_flag = os.path.join(BASE_DIR, ".setup_complete")
    if not os.path.exists(setup_flag):
        print(Fore.YELLOW + "[INFO] Performing initial setup...")
        install_required_packages()
        check_and_update_system()
        update_files()
        with open(setup_flag, 'w') as f:
            f.write("Setup completed.")
        print(Fore.GREEN + "[SUCCESS] Setup complete.")
    else:
        print(Fore.CYAN + "[INFO] Setup already completed. Checking for updates...")
        update_files()

if __name__ == "__main__":
    main()
