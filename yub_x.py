import os
import subprocess
import sys
import time

# List of required packages
required_packages = [
    "python3-pyqt6",
    "python3-rpds-py",
    "python3-ruamel.yaml.clib",
    "python3-setproctitle",
    "python3-smbc",
    "python3-snappy",
    "python3-twisted",
    "python3-ubjson",
    "python3-ujson",
    "python3-uvloop",
    "python3-wrapt",
    "python3-yara",
    "python3-zstandard",
    "sqlmap",
    "sslyze"
]

def update_system():
    print("Updating the system...")
    try:
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)
        print("[SUCCESS] System updated successfully!")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] System update failed: {e}")
        sys.exit(1)

def install_packages(packages):
    print("Installing required packages...")
    for package in packages:
        try:
            subprocess.run(["sudo", "apt", "install", package, "-y"], check=True)
            print(f"[SUCCESS] Installed {package}")
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to install {package}. It may already be installed or not available.")

def check_installed_packages(packages):
    print("Checking installed packages...")
    for package in packages:
        try:
            subprocess.run(["dpkg", "-l", package], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"[INFO] {package} is already installed.")
        except subprocess.CalledProcessError:
            print(f"[INFO] {package} is not installed. Attempting to install...")
            install_packages([package])


import urllib.request
from urllib.error import HTTPError, URLError
import hashlib
import itertools
from threading import Thread
from colorama import Fore, init

# Initialize colorama for colorful terminal output
init(autoreset=True)

def animated_loading(message):
    """Display a loading animation with the provided message."""
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    while getattr(animated_loading, "running", True):
        sys.stdout.write(Fore.CYAN + f"\r{message} " + next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)

def stop_loading():
    """Stop the loading animation."""
    animated_loading.running = False

def print_banner():
    """Print a cool cyber-style YuB-X banner."""
    banner_lines = [
        "    ====================================",
        "          ██╗   ██╗██╗   ██╗██████╗ ",
        "          ██║   ██║██║   ██║██╔══██╗",
        "          ██║   ██║██║   ██║██████╔╝",
        "          ██║   ██║██║   ██║██╔═══╝ ",
        "          ╚██████╔╝╚██████╔╝██║     ",
        "           ╚═════╝  ╚═════╝ ╚═╝     ",
        "    ====================================",
        "               YuB-X Protect V1.5",
        "    ====================================",
    ]

    for line in banner_lines:
        print(Fore.GREEN + line)
        time.sleep(0.1)

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
    """Install a Python package using pip."""
    try:
        print(Fore.YELLOW + f"[INFO] Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print(Fore.GREEN + f"[SUCCESS] Installed {package}.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"[ERROR] Failed to install {package}.")

def install_required_packages():
    """Install required Python packages if not already installed."""
    required_packages = [
        'flask', 'scapy', 'playsound', 'requests', 'numpy',
        'pychromecast', 'colorama', 'hashlib', 'itertools'
    ]
    for package in required_packages:
        if not is_package_installed(package):
            install_package(package)

def check_and_update_system():
    print(Fore.YELLOW + "[INFO] Checking for system updates...")
    try:
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        print(Fore.GREEN + "[SUCCESS] System package lists updated.")
        
        # Prompt the user to upgrade if updates are available
        upgrade = input(Fore.YELLOW + "Do you want to upgrade packages? (y/n): ")
        if upgrade.lower() == 'y':
            subprocess.run(["sudo", "apt-get", "upgrade", "-y"], check=True)
            print(Fore.GREEN + "[SUCCESS] System packages upgraded.")
        else:
            print(Fore.YELLOW + "[INFO] Upgrade skipped.")
            
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[ERROR] An error occurred while checking for updates: {e}")

def open_terminal_window():
    """Open a single terminal window with split panes for commands."""
    commands = [
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/website.html',
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/index.html',
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/wifi_protect.py',
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/cast.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/sleep.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/cast.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/wifi_protect.py'
    ]

    # Start a new tmux session with a specific name
    subprocess.Popen(['tmux', 'new-session', '-d', '-s', 'yubx_protect'])

    # Create a new window and run commands in split panes
    for i, command in enumerate(commands):
        if i > 0:
            # Split the window vertically or horizontally based on the pane number
            if i % 2 == 0:
                subprocess.Popen(['tmux', 'split-window', '-h'])
            else:
                subprocess.Popen(['tmux', 'split-window', '-v'])
        
        # Send the command to the respective pane
        subprocess.Popen(['tmux', 'send-keys', '-t', f'yubx_protect:{i}', f'{command}', 'C-m'])

    # Attach to the tmux session
    subprocess.Popen(['tmux', 'attach-session', '-t', 'yubx_protect'])

def main():
    print_banner()

    base_dir = '/home/kali/Desktop/Python/yubx_protect'
    setup_complete_flag = '/home/kali/.yubx_setup_complete'

    # Check if the setup has already been completed
    if os.path.exists(setup_complete_flag):
        print(Fore.YELLOW + "[INFO] Setup has already been completed. Exiting.")
        sys.exit(0)

    create_dir_if_missing(base_dir)

    # Start loading animation
    loading_thread = Thread(target=animated_loading, args=("Downloading files...",))
    loading_thread.start()

    # Check for system updates
    check_and_update_system()

    # Install required packages
    install_required_packages()

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

    # Download required files
    for filename, url in files.items():
        dest_path = os.path.join(base_dir, filename)
        download_file(url, dest_path)

    # Stop loading animation
    stop_loading()
    loading_thread.join()

    # Create setup complete flag
    with open(setup_complete_flag, 'w') as f:
        f.write("Setup completed successfully.")

    # Final message and menu options
    print(Fore.GREEN + "[SUCCESS] Setup completed successfully! Opening terminal...")

    # Print menu options
    print(Fore.MAGENTA + """
        ====================================
            1. Start 
            2. Exit 
        ====================================
    """)

    # Get user choice
    choice = input(Fore.YELLOW + "Please enter your choice (1 or 2): ")

    if choice == "1":
        open_terminal_window()
    elif choice == "2":
        print(Fore.RED + "[INFO] Exiting the program.")
        sys.exit(0)
    else:
        print(Fore.RED + "[ERROR] Invalid choice. Please enter 1 or 2.")

if __name__ == '__main__':
    main()
