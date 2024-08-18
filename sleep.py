import os
import time
import subprocess

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

# Function to run a dummy loop to keep the system awake
def prevent_sleep_loop():
    try:
        while True:
            time.sleep(60)  # Sleep for 60 seconds before looping again
    except KeyboardInterrupt:
        print("Script terminated by user.")

# Main function
def main():
    prevent_sleep_xset()
    prevent_sleep_logind()
    print("System sleep prevention methods activated.")
    prevent_sleep_loop()

if __name__ == "__main__":
    main()
