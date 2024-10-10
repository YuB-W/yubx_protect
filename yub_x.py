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


required_packages = [
    "python3-pyqt6", "python3-rpds-py", "python3-ruamel.yaml.clib",
    "python3-setproctitle", "python3-smbc", "python3-snappy",
    "python3-twisted", "python3-ubjson", "python3-ujson",
    "python3-uvloop", "python3-wrapt", "python3-yara",
    "python3-zstandard", "sqlmap", "sslyze"
]


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


def create_dir_if_missing(path):
    if not os.path.exists(path):
        os.makedirs(path)
        print(Fore.CYAN + f"[INFO] Created directory: {path}")


def calculate_checksum(filepath):
    hash_alg = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hash_alg.update(chunk)
    return hash_alg.hexdigest()


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
            else:
                os.rename(temp_file, dest)
                print(Fore.GREEN + f"[SUCCESS] Updated {dest}.")
                return True  # File was updated
        else:
            os.rename(temp_file, dest)
            print(Fore.GREEN + f"[SUCCESS] Downloaded {dest}.")
            return True  # File was downloaded
    except (HTTPError, URLError) as e:
        print(Fore.RED + f"[ERROR] Error downloading {url}: {e}")
        return False


def is_package_installed(package):
    try:
        subprocess.check_call([sys.executable, '-c', f'import {package}'])
        return True
    except subprocess.CalledProcessError:
        return False


def install_package(package):
    try:
        print(Fore.YELLOW + f"[INFO] Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print(Fore.GREEN + f"[SUCCESS] Installed {package}.")
    except subprocess.CalledProcessError:
        print(Fore.RED + f"[ERROR] Failed to install {package}.")


def install_required_packages():
    packages = ['flask', 'scapy', 'playsound', 'requests', 'numpy',
                'pychromecast', 'colorama', 'hashlib', 'itertools']
    for package in packages:
        if not is_package_installed(package):
            install_package(package)


def check_and_update_system():
    try:
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        print(Fore.GREEN + "[SUCCESS] System package lists updated.")
        
        upgrade = input(Fore.YELLOW + "Do you want to upgrade packages? (y/n): ").lower()
        if upgrade == 'y':
            subprocess.run(["sudo", "apt-get", "upgrade", "-y"], check=True)
            print(Fore.GREEN + "[SUCCESS] System packages upgraded.")
        else:
            print(Fore.YELLOW + "[INFO] Upgrade skipped.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[ERROR] An error occurred while updating: {e}")


def animated_loading(message):
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    while getattr(animated_loading, "running", True):
        sys.stdout.write(Fore.CYAN + f"\r{message} " + next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)


def stop_loading():
    animated_loading.running = False


def open_terminal_windows():
    commands = [
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/website.html',
        'sudo mousepad /home/kali/Desktop/Python/yubx_protect/index.html',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/sleep.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/cast.py',
        'sudo python3 /home/kali/Desktop/Python/yubx_protect/wifi_protect.py'
    ]
    for command in commands:
        print(Fore.YELLOW + f"[INFO] Opening terminal for: {command}")
        subprocess.Popen(['xterm', '-hold', '-e', f'sh -c "{command}"'])
        #time.sleep(0.5)


def update_files():
    base_dir = '/home/kali/Desktop/Python/yubx_protect'

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
        dest_path = os.path.join(base_dir, filename)
        updated = download_file(url, dest_path)
        if updated:
            updates_performed = True

    if updates_performed:
        print(Fore.GREEN + "[SUCCESS] Files updated successfully.")
    else:
        print(Fore.CYAN + "[INFO] All files are already up-to-date.")


def main():
    print_banner()

    base_dir = '/home/kali/Desktop/Python/yubx_protect'
    setup_complete_flag = '/home/kali/.yubx_setup_complete'

    if os.path.exists(setup_complete_flag):
        print(Fore.YELLOW + "[INFO] Setup has already been completed.")
        
        loading_thread = Thread(target=animated_loading, args=("Checking for file updates...",))
        loading_thread.start()

        check_and_update_system()
        install_required_packages()

        # Start file update check in a separate thread
        update_thread = Thread(target=update_files)
        update_thread.start()

        # Wait for the update threads to finish
        update_thread.join()

        stop_loading()
        loading_thread.join()

    else:
        create_dir_if_missing(base_dir)
        
        loading_thread = Thread(target=animated_loading, args=("Downloading files...",))
        loading_thread.start()

        check_and_update_system()
        install_required_packages()

        # Perform initial file downloads
        update_files()

        stop_loading()
        loading_thread.join()

        with open(setup_complete_flag, 'w') as f:
            f.write("Setup completed on: " + time.strftime("%Y-%m-%d %H:%M:%S"))

        print(Fore.GREEN + "[SUCCESS] Initial setup complete.")

    open_terminal_windows()


if __name__ == '__main__':
    main()
