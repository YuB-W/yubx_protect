import os
import time
import subprocess
import platform

# Function to prevent sleep using `xset` (graphical environments)
def prevent_sleep_xset():
    try:
        # Disable screen saver and power management
        subprocess.run(['xset', 's', 'off'], check=True)
        subprocess.run(['xset', '-dpms'], check=True)
        print("Screen saver and DPMS (Display Power Management Signaling) disabled.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute xset commands: {e}")

# Function to prevent sleep using `systemd-logind` configuration
def prevent_sleep_logind():
    try:
        with open('/etc/systemd/logind.conf', 'a') as f:
            f.write('\nHandleSuspendKey=ignore\n')
            f.write('HandleHibernateKey=ignore\n')
            f.write('HandleLidSwitch=ignore\n')
            f.write('HandleLidSwitchDocked=ignore\n')
        # Restart systemd-logind to apply changes
        subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-logind'], check=True)
        print("Systemd-logind configuration updated and service restarted.")
    except Exception as e:
        print(f"Failed to modify logind.conf or restart service: {e}")

# Function to prevent sleep on Windows using `powercfg`
def prevent_sleep_windows():
    try:
        subprocess.run(['powercfg', '/change', 'monitor-timeout-ac', '0'], check=True)
        subprocess.run(['powercfg', '/change', 'monitor-timeout-dc', '0'], check=True)
        print("Sleep prevention activated on Windows.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute powercfg commands: {e}")

# Function to prevent sleep on macOS using `caffeinate`
def prevent_sleep_macos():
    try:
        subprocess.Popen(['caffeinate'])
        print("Sleep prevention activated on macOS.")
    except Exception as e:
        print(f"Failed to execute caffeinate command: {e}")

# Function to run a dummy loop to keep the system awake
def prevent_sleep_loop():
    try:
        while True:
            time.sleep(60)  # Sleep for 60 seconds before looping again
    except KeyboardInterrupt:
        print("Script terminated by user.")

# Main function
def main():
    os_type = platform.system()
    if os_type == "Linux":
        prevent_sleep_xset()
        prevent_sleep_logind()
    elif os_type == "Windows":
        prevent_sleep_windows()
    elif os_type == "Darwin":  # macOS
        prevent_sleep_macos()
    else:
        print(f"Unsupported OS: {os_type}")

    print("System sleep prevention methods activated.")
    prevent_sleep_loop()

if __name__ == "__main__":
    main()