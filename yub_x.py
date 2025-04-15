import subprocess
import sys
import importlib


required_modules = [
    "flask", "playsound", "requests", "numpy", "termcolor", "netifaces", "scapy" "tkinter"
]


required_apt_packages = [
    "xterm", "python3-pip", "python3-venv", "ffmpeg", "build-essential", "python3-dev"
]

def install_apt_dependencies():
    log_console("Checking APT dependencies...")
    for pkg in required_apt_packages:
        result = subprocess.run(["dpkg", "-s", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            log_console(f"Installing missing APT package: {pkg}")
            try:
                subprocess.check_call(["sudo", "apt", "install", "-y", pkg])
            except subprocess.CalledProcessError:
                log_console(f"Failed to install APT package: {pkg}")

def install_python_modules():
    log_console("Checking Python modules...")
    for module in required_modules:
        try:
            importlib.import_module(module)
        except ImportError:
            log_console(f"Installing missing module: {module}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", module])
            except subprocess.CalledProcessError:
                log_console(f"Failed to install module: {module}")

install_apt_dependencies()
install_python_modules()


import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import threading
import time
from datetime import datetime
import hashlib
import psutil

# GitHub Configuration
BASE_URL = os.getenv("GITHUB_BASE_URL", "https://github.com/YuB-W/yubx_protect/raw/main/")
FILES = {
    "website.html": "website.html",
    "wifi_protect.py": "wifi_protect.py",
    "sleep.py": "sleep.py",
    "fix_wlan.py": "fix_wlan.py",
    "cast.py": "cast.py",
    "index.html": "index.html",
    "detect.m4a": "detect.m4a",
    "welcome.m4a": "welcome.m4a",
    "alert_r.m4a": "alert_r.m4a",
}

# Global Variables
is_running = True


# Functions
def calculate_checksum(file_path):
    """Calculate SHA-256 checksum of a file."""
    hash_alg = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_alg.update(chunk)
        return hash_alg.hexdigest()
    except FileNotFoundError:
        return None


def get_remote_checksum(url):
    """Fetch the remote file content and calculate its checksum."""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return hashlib.sha256(response.content).hexdigest()
    except requests.RequestException as e:
        log_console(f"Error fetching remote checksum: {str(e)}", "ERROR")
    return None


def monitor_github():
    """Monitor GitHub files and update only if changes are detected."""
    while is_running:
        try:
            updated_files = []
            for file_name, file_url in FILES.items():
                local_path = os.path.join(os.getcwd(), file_name)
                remote_url = BASE_URL + file_url

                # Get local and remote checksums
                local_checksum = calculate_checksum(local_path)
                remote_checksum = get_remote_checksum(remote_url)

                if remote_checksum and local_checksum != remote_checksum:
                    log_console(f"Updating {file_name}...", "INFO")
                    retry_attempts = 3
                    for attempt in range(retry_attempts):
                        try:
                            response = requests.get(remote_url, timeout=10)
                            response.raise_for_status()
                            with open(local_path, "wb") as f:
                                f.write(response.content)
                            updated_files.append(file_name)
                            break
                        except requests.RequestException as e:
                            log_console(f"Attempt {attempt + 1} failed: {str(e)}", "WARNING")
                            time.sleep(2 ** attempt)  # Exponential backoff

            if updated_files:
                log_console(f"Updated files: {', '.join(updated_files)}", "INFO")
                update_status("Updated", f"Last update: {datetime.now().strftime('%H:%M:%S')}")
            else:
                log_console("All files are up-to-date.", "INFO")

        except requests.RequestException as e:
            log_console(f"Network error during GitHub monitoring: {str(e)}", "ERROR")
        except Exception as e:
            log_console(f"Unexpected error during GitHub monitoring: {str(e)}", "ERROR")

        time.sleep(30)  # Check every 30 seconds


def start_program():
    log_console("Starting program...")
    commands = [
        'sudo python3 sleep.py',
        'sudo python3 cast.py',
        'sudo python3 wifi_protect.py',
    ]
    for command in commands:
        subprocess.Popen(['xterm', '-hold', '-e', f'sh -c "{command}"'])
    update_status("Running")
    log_console("Program started successfully!")


def close_all_xterm():
    log_console("Closing all xterm processes...")
    try:
        subprocess.run(['pkill', 'xterm'], check=True)
        log_console("All xterm processes closed successfully.", "INFO")
    except subprocess.CalledProcessError:
        log_console("No xterm processes found to close.", "WARNING")


def exit_app():
    global is_running
    is_running = False
    if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
        root.destroy()


def log_console(message, category="INFO"):
    """Update console log with messages."""
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    log_area.insert(tk.END, f"{timestamp} [{category}] {message}\n")
    log_area.see(tk.END)

    if category == "ERROR":
        log_area.tag_add("error", "end-2l", "end-1c")
        log_area.tag_config("error", foreground="red")
    elif category == "WARNING":
        log_area.tag_add("warning", "end-2l", "end-1c")
        log_area.tag_config("warning", foreground="orange")


def update_status(new_status, extra_info=None):
    """Update the status display."""
    status_var.set(new_status)
    if extra_info:
        extra_var.set(extra_info)
    status_label.config(fg="#32cd32" if new_status != "Error" else "red")


def check_health():
    """Monitor system health in real-time."""
    while is_running:
        cpu_usage = psutil.cpu_percent(interval=1)
        ram_usage = psutil.virtual_memory().percent
        update_status("Running", f"CPU: {cpu_usage}%, RAM: {ram_usage}%")
        time.sleep(1)


# GUI Setup
root = tk.Tk()
root.title("YuB-X Protect")
root.geometry("800x600")
root.configure(bg="#1f1f1f")

# Title Label
title_label = tk.Label(
    root,
    text="YuB-X Protect",
    font=("Arial", 24, "bold"),
    fg="#32cd32",
    bg="#1f1f1f"
)
title_label.pack(pady=10)

# Status Display
status_var = tk.StringVar(value="Idle")
extra_var = tk.StringVar(value="N/A")

status_frame = tk.Frame(root, bg="#1f1f1f")
status_frame.pack(pady=10)

status_label = tk.Label(
    status_frame,
    textvariable=status_var,
    font=("Arial", 16, "bold"),
    bg="#1f1f1f",
    fg="#32cd32"
)
status_label.pack()

extra_label = tk.Label(
    status_frame,
    textvariable=extra_var,
    font=("Arial", 12),
    bg="#1f1f1f",
    fg="#32cd32"
)
extra_label.pack()

# Button Frame
button_frame = tk.Frame(root, bg="#1f1f1f")
button_frame.pack(pady=10)

buttons = [
    ("Start Program", start_program),
    ("Close xterm", close_all_xterm),
    ("Exit", exit_app),
]

for idx, (text, command) in enumerate(buttons):
    btn = tk.Button(
        button_frame,
        text=text,
        font=("Arial", 12),
        bg="#333",
        fg="white",
        command=command,
        relief="flat",
        width=20
    )
    btn.grid(row=idx, column=0, padx=10, pady=5)
    btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#32cd32", fg="black"))
    btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#333", fg="white"))

# Console Log Area
log_frame = tk.Frame(root, bg="#1f1f1f")
log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

log_area = tk.Text(
    log_frame,
    bg="#0f0f0f",
    fg="lime",
    font=("Courier", 10),
    wrap=tk.WORD,
    state=tk.NORMAL
)
log_area.pack(fill=tk.BOTH, expand=True)

# Add scrollbar to log area
scrollbar = tk.Scrollbar(log_frame, command=log_area.yview)
log_area.config(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Background Threads
threading.Thread(target=monitor_github, daemon=True).start()
threading.Thread(target=check_health, daemon=True).start()

# Run the GUI
root.mainloop()
