import os
import sys
import subprocess
import time
import urllib.request
from urllib.error import HTTPError, URLError
from colorama import Fore, init
import hashlib

# Initialize colorama for colorful terminal output
init(autoreset=True)

def print_banner():
    """Print a cool cyber-style YuB-X banner."""
    banner = """
    ====================================
          ██╗   ██╗██╗   ██╗██████╗ 
          ██║   ██║██║   ██║██╔══██╗
          ██║   ██║██║   ██║██████╔╝
          ██║   ██║██║   ██║██╔═══╝ 
          ╚██████╔╝╚██████╔╝██║     
           ╚═════╝  ╚═════╝ ╚═╝     
    ====================================
               YuB-X Protect V1.3
    ====================================
    """
    print(Fore.GREEN + banner)

def create_dir_if_missing(path):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)
        print(Fore.CYAN + f"[INFO] Created directory: {path}")

def calculate_checksum(filepath):
    """Calculate and return the checksum of the file."""
    hash_alg = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hash_alg.update(chunk)
    return hash_alg.hexdigest()

def download_file(url, dest):
    """Download a file from a URL to a local destination."""
    try:
        temp_file = dest + ".tmp"
        urllib.request.urlretrieve(url, temp_file)
        temp_checksum = calculate_checksum(temp_file)
        if os.path.exists(dest):
            current_checksum = calculate_checksum(dest)
            if temp_checksum == current_checksum:
                os.remove(temp_file)
                print(Fore.CYAN + f"[INFO] {dest} is up-to-date.")
                return
        os.rename(temp_file, dest)
        print(Fore.GREEN + f"[SUCCESS] Downloaded and updated {dest}.")
    except HTTPError as e:
        print(Fore.RED + f"[ERROR] HTTP Error {e.code} while downloading {url}")
    except URLError as e:
        print(Fore.RED + f"[ERROR] URL Error {e.reason} while downloading {url}")

def is_package_installed(package):
    """Check if a Python package is installed."""
    try:
        subprocess.check_call([sys.executable, '-c', f'import {package}'])
        return True
    except subprocess.CalledProcessError:
        return False

def install_package(package):
    """Install a Python package using pip with sudo."""
    try:
        print(Fore.YELLOW + f"[INFO] Installing {package}...")
        subprocess.check_call(['sudo', 'pip3', 'install', package])
        print(Fore.GREEN + f"[SUCCESS] Installed {package}.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"[ERROR] Failed to install {package}.")

def uninstall_all_packages():
    """Uninstall all required Python packages."""
    required_packages = [
        'flask', 'scapy', 'playsound', 'requests', 'numpy',
        'pychromecast', 'logging'
    ]
    for package in required_packages:
        try:
            print(Fore.YELLOW + f"[INFO] Uninstalling {package}...")
            subprocess.check_call(['sudo', 'pip3', 'uninstall', '-y', package])
            print(Fore.GREEN + f"[SUCCESS] Uninstalled {package}.")
        except subprocess.CalledProcessError:
            print(Fore.RED + f"[ERROR] Failed to uninstall {package}.")

def remove_files_and_directories(base_dir):
    """Remove all files and directories in the base directory."""
    if os.path.exists(base_dir):
        try:
            print(Fore.YELLOW + f"[INFO] Deleting directory: {base_dir}...")
            subprocess.check_call(['sudo', 'rm', '-r', '-f', base_dir])
            print(Fore.GREEN + f"[SUCCESS] Removed directory: {base_dir}")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[ERROR] Failed to remove directory {base_dir}: {e}")

def install_packages():
    """Install required Python packages."""
    required_packages = [
        'flask', 'scapy', 'playsound', 'requests', 'numpy',
        'pychromecast', 'logging'
    ]
    for package in required_packages:
        install_package(package)

def reinstall_packages():
    """Reinstall required Python packages."""
    uninstall_all_packages()
    install_packages()

def open_terminal_windows():
    """Open terminal windows with different commands."""
    commands = [
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/website.html',
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/index.html',
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/wifi_protect.py',
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/cast.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/sleep.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/cast.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/wifi_protect.py'
    ]
    
    # Open terminal windows with the commands
    for command in commands:
        print(Fore.YELLOW + f"[INFO] Opening terminal for: {command}")
        subprocess.Popen(['xterm', '-hold', '-e', f'sh -c "{command}"'])
        time.sleep(1)  # Delay to ensure each terminal opens correctly

def main():
    print_banner()

    base_dir = '/home/kali/Desktop/Python/yubx_protect'
    create_dir_if_missing(base_dir)

    # Files to download from GitHub
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

    for filename, url in files.items():
        dest_path = os.path.join(base_dir, filename)
        download_file(url, dest_path)

    # User choices for managing packages and directories
    while True:
        print(Fore.MAGENTA + """
        ====================================
            1. Install packages
            2. Reinstall packages
            3. Delete folders (but keep Python packages)
            4. Start
            5. Exit
        ====================================
        """)
        choice = input("Enter your choice (1-5): ").strip()

        if choice == '1':
            print(Fore.MAGENTA + "[INFO] Installing required packages...")
            install_packages()
            break
        elif choice == '2':
            print(Fore.MAGENTA + "[INFO] Reinstalling required packages...")
            reinstall_packages()
            break
        elif choice == '3':
            print(Fore.MAGENTA + "[INFO] Deleting folders (but keeping Python packages)...")
            remove_files_and_directories(base_dir)
            break
        elif choice == '4':
            print(Fore.GREEN + "[INFO] Starting...")
            open_terminal_windows()
            break
        elif choice == '5':
            print(Fore.GREEN + "[INFO] Exiting.")
            break
        else:
            print(Fore.RED + "[ERROR] Invalid choice. Please select a valid option.")

if __name__ == '__main__':
    main()
