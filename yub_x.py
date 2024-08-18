import os
import subprocess
import time
import urllib.request
from urllib.error import HTTPError, URLError
from colorama import Fore, Style, init

# Initialize colorama
init()

def print_banner():
    """Print a cool cyber-style YuB-X banner."""
    banner = """
    YuB-X Protect
    """
    print(Fore.GREEN + banner + Style.RESET_ALL)

def create_dir_if_missing(path):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)
        print(Fore.CYAN + f"[INFO] Created directory: {path}" + Style.RESET_ALL)

def download_file(url, dest):
    """Download a file if it doesn't exist locally."""
    if not os.path.exists(dest):
        try:
            print(Fore.YELLOW + f"[INFO] File {dest} is missing. Downloading from GitHub..." + Style.RESET_ALL)
            urllib.request.urlretrieve(url, dest)
            print(Fore.GREEN + f"[SUCCESS] Downloaded {dest}." + Style.RESET_ALL)
        except HTTPError as e:
            print(Fore.RED + f"[ERROR] HTTP Error: {e.code} when trying to download {url}" + Style.RESET_ALL)
        except URLError as e:
            print(Fore.RED + f"[ERROR] URL Error: {e.reason} when trying to download {url}" + Style.RESET_ALL)

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
    }

    for filename, url in files.items():
        dest_path = os.path.join(base_dir, filename)
        download_file(url, dest_path)

    print(Fore.MAGENTA + "[INFO] Opening terminal windows with specified commands..." + Style.RESET_ALL)
    open_terminal_windows()

if __name__ == '__main__':
    main()
