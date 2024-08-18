import os
import sys
import subprocess
import time
import urllib.request
from urllib.error import HTTPError, URLError
from colorama import Fore, Style, init
import logging

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
               YuB-X Protect
    ====================================
    """
    print(Fore.GREEN + banner)

def create_dir_if_missing(path):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)
        print(Fore.CYAN + f"[INFO] Created directory: {path}")

def download_file(url, dest):
    """Download a file from a URL to a local destination."""
    try:
        if not os.path.exists(dest):
            print(Fore.YELLOW + f"[INFO] {dest} is missing. Downloading...")
            urllib.request.urlretrieve(url, dest)
            print(Fore.GREEN + f"[SUCCESS] Downloaded {dest}.")
        else:
            print(Fore.CYAN + f"[INFO] {dest} already exists. Skipping download.")
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
    if not is_package_installed(package):
        try:
            print(Fore.YELLOW + f"[INFO] Installing {package}...")
            subprocess.check_call(['sudo', 'pip3', 'install', package])
            print(Fore.GREEN + f"[SUCCESS] Installed {package}.")
        except subprocess.CalledProcessError:
            print(Fore.RED + f"[ERROR] Failed to install {package}.")
    else:
        print(Fore.CYAN + f"[INFO] {package} is already installed.")

def install_packages():
    """Install required Python packages."""
    required_packages = [
        'flask', 'scapy', 'playsound', 'requests', 'numpy',
        'pychromecast', 'logging'
    ]
    for package in required_packages:
        install_package(package)

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
        "dalert_r.m4a": "https://github.com/YuB-W/yubx_protect/raw/main/dalert_r.m4a"
    }

    for filename, url in files.items():
        dest_path = os.path.join(base_dir, filename)
        download_file(url, dest_path)

    print(Fore.MAGENTA + "[INFO] Installing required packages...")
    install_packages()

    print(Fore.MAGENTA + "[INFO] Opening terminal windows with specified commands...")
    open_terminal_windows()

if __name__ == '__main__':
    main()
