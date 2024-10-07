import os
import subprocess
import time
import logging

LOG_FILE = "wlan_fix.log"
logging.basicConfig(
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

def log_and_print(message, level="info"):
    """Log the message and print it to the console."""
    print(message)
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)

def run_command(command):
    """Runs a shell command and returns the output, logging any errors."""
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()
        return result
    except subprocess.CalledProcessError as e:
        log_and_print(f"[!] Command failed: {command} \nError: {e.output.decode()}", "error")
        return None

def check_rf_kill():
    """Check the RF-kill status and unblock the wireless LAN if necessary."""
    log_and_print("[*] Checking RF-kill status...")
    rf_kill_output = run_command("rfkill list all")
    if not rf_kill_output:
        log_and_print("[!] Unable to retrieve RF-kill status.", "error")
        return False

    log_and_print(rf_kill_output)

    if "Soft blocked: yes" in rf_kill_output:
        log_and_print("[!] Wireless LAN is blocked by RF-kill. Unblocking...")
        run_command("sudo rfkill unblock wifi")
        time.sleep(1)  # Wait for the unblock command to take effect
        log_and_print("[+] Wireless LAN unblocked.")
        
        # Check RF-kill status again
        rf_kill_output = run_command("rfkill list all")
        if "Soft blocked: yes" in rf_kill_output:
            log_and_print("[!] Failed to unblock Wireless LAN. Exiting...", "error")
            return False
    else:
        log_and_print("[+] Wireless LAN is not blocked.")
    
    return True

def check_airplane_mode():
    """Check if the system is in airplane mode and disable it if necessary."""
    log_and_print("[*] Checking Airplane mode status...")
    airplane_mode_status = run_command("nmcli radio")
    if not airplane_mode_status:
        log_and_print("[!] Unable to retrieve Airplane mode status.", "error")
        return False

    if "enabled" in airplane_mode_status:
        log_and_print("[!] Airplane mode is enabled. Disabling...")
        run_command("nmcli radio all off")
        log_and_print("[+] Airplane mode disabled.")
    else:
        log_and_print("[+] Airplane mode is not enabled.")
    
    return True

def bring_interface_down(interface):
    """Bring down the specified interface."""
    log_and_print(f"[*] Bringing down interface {interface}...")
    result = run_command(f"sudo ip link set {interface} down")
    if result is None:
        log_and_print(f"[!] Error bringing {interface} down.", "error")
        return False
    log_and_print(f"[+] {interface} is down.")
    return True

def bring_interface_up(interface):
    """Bring up the specified interface."""
    log_and_print(f"[*] Bringing up interface {interface}...")
    result = run_command(f"sudo ip link set {interface} up")
    if result is None:
        log_and_print(f"[!] Error bringing {interface} up.", "error")
        return False
    log_and_print(f"[+] {interface} is up.")
    return True

def set_monitor_mode(interface):
    """Set the WLAN interface to monitor mode."""
    log_and_print(f"[*] Setting {interface} to monitor mode...")
    run_command(f"sudo iw dev {interface} set type monitor")
    log_and_print(f"[+] {interface} set to monitor mode.")
    return bring_interface_up(interface)

def renew_dhcp_lease(interface):
    """Renew the DHCP lease for the specified interface."""
    log_and_print(f"[*] Renewing DHCP lease for {interface}...")
    dhcp_output = run_command(f"sudo dhclient {interface}")
    if dhcp_output is None:
        log_and_print(f"[!] Error renewing DHCP lease for {interface}.", "error")
        return False
    log_and_print(f"[+] DHCP lease renewed for {interface}.")
    return True

def restart_network_manager():
    """Restart the Network Manager service."""
    log_and_print("[*] Restarting Network Manager...")
    result = run_command("sudo systemctl restart NetworkManager")
    if result is None:
        log_and_print("[!] Error restarting Network Manager.", "error")
        return False
    log_and_print("[+] Network Manager restarted successfully.")
    return True

def fix_wlan(interface="wlan0"):
    """Fix WLAN issues by handling RF-kill, airplane mode, and interface settings."""
    log_and_print(f"[*] Starting WLAN fix for {interface}...")
    
    if not check_rf_kill():
        return
    if not check_airplane_mode():
        return
    if not bring_interface_down(interface):
        return
    if not bring_interface_up(interface):
        return
    if not set_monitor_mode(interface):
        return
    if not renew_dhcp_lease(interface):
        log_and_print(f"[!] Continuing despite DHCP lease failure.")
    
    if not restart_network_manager():
        return
    
    log_and_print(f"[+] WLAN interface {interface} has been fixed and set to monitor mode.")

if __name__ == "__main__":
    fix_wlan("wlan0")
