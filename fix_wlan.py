import os
import subprocess
import time

def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip(), result.stderr.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return None, f"Error: {e.stderr.decode('utf-8').strip()}"

def check_wlan_interfaces():
    """Check available wlan interfaces."""
    stdout, stderr = run_command("iw dev | grep Interface")
    if stdout:
        interfaces = [line.split()[1] for line in stdout.splitlines()]
        return interfaces
    return []

def bring_interface_up(interface):
    """Bring the wlan interface up."""
    print(f"[*] Bringing up interface {interface}...")
    _, stderr = run_command(f"sudo ip link set {interface} up")
    if stderr:
        print(f"[!] Error bringing {interface} up: {stderr}")
    else:
        print(f"[+] {interface} is up.")

def bring_interface_down(interface):
    """Bring the wlan interface down."""
    print(f"[*] Bringing down interface {interface}...")
    _, stderr = run_command(f"sudo ip link set {interface} down")
    if stderr:
        print(f"[!] Error bringing {interface} down: {stderr}")
    else:
        print(f"[+] {interface} is down.")

def set_monitor_mode(interface):
    """Set wlan interface to monitor mode."""
    print(f"[*] Setting {interface} to monitor mode...")
    bring_interface_down(interface)
    stdout, stderr = run_command(f"sudo iw dev {interface} set type monitor")
    if stderr:
        print(f"[!] Error setting monitor mode for {interface}: {stderr}")
    else:
        print(f"[+] {interface} set to monitor mode.")
    bring_interface_up(interface)

def restart_network_manager():
    """Restart the Network Manager service."""
    print("[*] Restarting Network Manager...")
    _, stderr = run_command("sudo systemctl restart NetworkManager")
    if stderr:
        print(f"[!] Error restarting NetworkManager: {stderr}")
    else:
        print("[+] NetworkManager restarted successfully.")

def reload_wifi_driver():
    """Reload the Wi-Fi driver by removing and adding kernel modules."""
    print("[*] Reloading Wi-Fi driver...")
    _, stderr = run_command("sudo modprobe -r iwlwifi && sudo modprobe iwlwifi")
    if stderr:
        print(f"[!] Error reloading Wi-Fi driver: {stderr}")
    else:
        print("[+] Wi-Fi driver reloaded successfully.")

def renew_dhcp(interface):
    """Renew DHCP lease for the interface."""
    print(f"[*] Renewing DHCP lease for {interface}...")
    _, stderr = run_command(f"sudo dhclient -r {interface} && sudo dhclient {interface}")
    if stderr:
        print(f"[!] Error renewing DHCP lease for {interface}: {stderr}")
    else:
        print(f"[+] DHCP lease renewed for {interface}.")

def disable_airplane_mode():
    """Disable airplane mode if it's enabled."""
    print("[*] Checking for Airplane mode...")
    stdout, _ = run_command("rfkill list all | grep -i 'Airplane Mode: on'")
    if stdout:
        print("[*] Disabling Airplane mode...")
        run_command("rfkill unblock all")
        print("[+] Airplane mode disabled.")

def wait_for_wlan(timeout=5, interval=5):
    """Wait for a wlan interface to be detected, with a timeout."""
    print(f"[*] Waiting for wlan interfaces to be detected (timeout: {timeout} seconds)...")
    elapsed_time = 0
    while elapsed_time < timeout:
        interfaces = check_wlan_interfaces()
        if interfaces:
            print(f"[+] Detected wlan interface(s): {', '.join(interfaces)}")
            return interfaces
        time.sleep(interval)
        elapsed_time += interval
        print(f"[*] Retrying... {elapsed_time}/{timeout} seconds")
    
    print("[!] No wlan interfaces detected after waiting. Exiting.")
    return None

def fix_wlan_issues():
    """Fix all wlan issues by resetting interfaces, drivers, and services."""
    print("[*] Fixing wlan issues...")

    # Step 1: Disable Airplane mode if enabled
    disable_airplane_mode()

    # Step 2: Check available wlan interfaces
    interfaces = check_wlan_interfaces()
    if not interfaces:
        print("[!] No wlan interfaces found. Reloading Wi-Fi driver...")
        reload_wifi_driver()
        interfaces = wait_for_wlan()  # Wait for wlan to appear

    if not interfaces:
        print("[!] No wlan interfaces detected after driver reload. Exiting.")
        return

    # Step 3: Bring interfaces up and set monitor mode
    for interface in interfaces:
        print(f"[*] Working on interface {interface}...")

        bring_interface_down(interface)
        bring_interface_up(interface)

        # Set monitor mode for wifite compatibility
        set_monitor_mode(interface)

        # Renew DHCP lease if needed
        renew_dhcp(interface)

    # Step 4: Restart Network Manager
    restart_network_manager()

    print("[+] All wlan interfaces have been fixed and set to monitor mode for wifite.")

if __name__ == "__main__":
    fix_wlan_issues()
