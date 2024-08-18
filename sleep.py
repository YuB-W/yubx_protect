import subprocess
import time

def open_terminal_windows():
    """Open four terminal windows with different commands."""
    commands = [
        '/usr/bin/mousepad /home/kali/Desktop/Python/website.html',  # Open website.html in Mousepad
        '/usr/bin/wifite',  # Run wifite
        'ls',  # List directory contents
        'sudo python3 /home/kali/Desktop/Python/fix_wlan.py'  # Run the Python script
    ]
    
    for command in commands:
        subprocess.Popen(['xterm', '-e', command])
        time.sleep(1)  # Delay to ensure each terminal opens correctly

if __name__ == '__main__':
    open_terminal_windows()
