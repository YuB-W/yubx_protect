import os
import subprocess
import sys
import logging
from datetime import datetime

required_modules = ["pychromecast", "termcolor"]

def install_module(module_name):
    """Install the module via pip if it's not already installed."""
    try:
        print(f"[*] Checking if {module_name} is installed...")
        __import__(module_name)
        print(f"[+] {module_name} is already installed.")
    except ImportError:
        print(f"[!] {module_name} not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
        print(f"[+] {module_name} installed successfully.")

def check_and_install_modules():
    """Check if all required modules are installed, install them if missing."""
    for module in required_modules:
        install_module(module)

check_and_install_modules()

import pychromecast
import time
import threading
import urllib.parse
from termcolor import colored

logging.basicConfig(filename='casting.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def print_colored_message(message, color):
    """Print a colored message to the console."""
    print(colored(message, color))

def discover_chromecast_devices(timeout=5):
    """Discover Chromecast devices with a specified timeout."""
    logging.info("Discovering Chromecast devices...")
    try:
        chromecasts, _ = pychromecast.get_chromecasts(timeout=timeout)
        return chromecasts
    except Exception as e:
        logging.error(f"An error occurred while discovering devices: {e}")
        print_colored_message("Failed to discover devices. Check the log for details.", 'red')
        return []

def print_available_devices(chromecasts):
    """Print the list of discovered Chromecast devices."""
    print_colored_message("Available Chromecast devices:", 'cyan')
    for i, cast in enumerate(chromecasts):
        print_colored_message(f"Device {i + 1}: {cast.name}", 'green')

def cast_text_to_device(device, text_message, animation=False):
    """Cast a text message to the selected Chromecast device with optional animation."""
    try:
        logging.info(f"Displaying message on {device.name}...")

        device.wait()
        mc = device.media_controller

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
        <style>
        body {{
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: black;
            color: white;
            font-family: Arial, sans-serif;
        }}
        h1 {{
            font-size: 3em;
            {'animation: fadeInOut 2s infinite;' if animation else ''}
        }}
        @keyframes fadeInOut {{
            0% {{ opacity: 0; }}
            50% {{ opacity: 1; }}
            100% {{ opacity: 0; }}
        }}
        </style>
        </head>
        <body>
        <h1>{text_message}</h1>
        </body>
        </html>
        """
        
        html_url = f"data:text/html,{urllib.parse.quote(html_content)}"
        mc.play_media(html_url, 'text/html')
        mc.block_until_active()
        logging.info(f"Message displayed on {device.name}.")
        print_colored_message(f"Message sent to {device.name}.", 'green')
    except Exception as e:
        logging.error(f"An error occurred while displaying the message on {device.name}: {e}")
        print_colored_message(f"Failed to display message on {device.name}.", 'red')

def cast_media_to_device(device, media_url, media_type, duration=None):
    """Cast a media URL to the selected Chromecast device with optional duration."""
    try:
        logging.info(f"Casting media {media_url} to {device.name}...")

        device.wait()
        mc = device.media_controller

        if not device.is_idle:
            logging.warning(f"{device.name} is not idle. Skipping casting.")
            print_colored_message(f"{device.name} is not idle. Skipping casting.", 'yellow')
            return

        mc.play_media(media_url, media_type)
        mc.block_until_active()

        if duration:
            logging.info(f"Waiting for {duration} seconds...")
            time.sleep(duration)
            mc.stop()
        
        logging.info(f"Media casting started on {device.name}.")
        print_colored_message(f"Media casting started on {device.name}.", 'green')
    except Exception as e:
        logging.error(f"An error occurred while casting: {e}")
        print_colored_message("Failed to cast media. Check the log for details.", 'red')

def shutdown_device(device):
    """Shutdown the selected Chromecast device."""
    try:
        logging.info(f"Shutting down {device.name}...")

        device.wait()
        device.quit_app()
        logging.info(f"Shutdown command sent to {device.name}.")
        print_colored_message(f"Shutdown command sent to {device.name}.", 'green')
    except Exception as e:
        logging.error(f"An error occurred while shutting down {device.name}: {e}")
        print_colored_message(f"Failed to shut down {device.name}.", 'red')

def turn_on_device(device):
    """Turn on the selected Chromecast device by playing a default media."""
    try:
        logging.info(f"Turning on {device.name}...")

        device.wait()
        mc = device.media_controller

        # Play a default media URL to wake up the device
        default_media_url = "http://www.hdwallpapers.in/walls/black_hd-wide.jpg"
        default_media_type = "image/jpeg"
        mc.play_media(default_media_url, default_media_type)
        mc.block_until_active()
        logging.info(f"Turned on {device.name} by playing default media.")
        print_colored_message(f"Turned on {device.name} by playing default media.", 'green')
    except Exception as e:
        logging.error(f"An error occurred while turning on {device.name}: {e}")
        print_colored_message(f"Failed to turn on {device.name}.", 'red')

def set_volume(device, volume_level):
    """Set the volume of the selected Chromecast device."""
    try:
        logging.info(f"Setting volume of {device.name} to {volume_level}...")

        device.wait()
        device.set_volume(volume_level)
        logging.info(f"Volume set to {volume_level} for {device.name}.")
        print_colored_message(f"Volume set to {volume_level} for {device.name}.", 'green')
    except Exception as e:
        logging.error(f"An error occurred while setting the volume for {device.name}: {e}")
        print_colored_message(f"Failed to set volume for {device.name}.", 'red')

def mute_device(device):
    """Mute the selected Chromecast device."""
    try:
        logging.info(f"Muting {device.name}...")

        device.wait()
        device.set_volume_muted(True)
        logging.info(f"{device.name} is now muted.")
        print_colored_message(f"{device.name} is now muted.", 'green')
    except Exception as e:
        logging.error(f"An error occurred while muting {device.name}: {e}")
        print_colored_message(f"Failed to mute {device.name}.", 'red')

def unmute_device(device):
    """Unmute the selected Chromecast device."""
    try:
        logging.info(f"Unmuting {device.name}...")

        device.wait()
        device.set_volume_muted(False)
        logging.info(f"{device.name} is now unmuted.")
        print_colored_message(f"{device.name} is now unmuted.", 'green')
    except Exception as e:
        logging.error(f"An error occurred while unmuting {device.name}: {e}")
        print_colored_message(f"Failed to unmute {device.name}.", 'red')

def format_media_status(status):
    """Format the media status into a human-readable string."""
    try:
        # Extract and format relevant information from the MediaStatus
        return (
            f"Title: {status.title if status.title else 'No Title'}\n"
            f"Series Title: {status.series_title if status.series_title else 'No Series Title'}\n"
            f"Season: {status.season if status.season else 'No Season'}\n"
            f"Episode: {status.episode if status.episode else 'No Episode'}\n"
            f"Artist: {status.artist if status.artist else 'No Artist'}\n"
            f"Album Name: {status.album_name if status.album_name else 'No Album Name'}\n"
            f"Album Artist: {status.album_artist if status.album_artist else 'No Album Artist'}\n"
            f"Track: {status.track if status.track else 'No Track'}\n"
            f"Current Time: {status.current_time if status.current_time is not None else 'Unknown'}\n"
            f"Duration: {status.duration if status.duration is not None else 'Unknown'}\n"
            f"Volume Level: {status.volume_level if status.volume_level is not None else 'Unknown'}\n"
            f"Volume Muted: {status.volume_muted}\n"
            f"Playback Rate: {status.playback_rate if status.playback_rate is not None else 'Unknown'}\n"
            f"Player State: {status.player_state if status.player_state else 'Unknown'}\n"
            f"Stream Type: {status.stream_type if status.stream_type else 'Unknown'}\n"
            f"Supports Pause: {status.supports_pause}\n"
            f"Supports Seek: {status.supports_seek}\n"
            f"Supports Volume: {status.supports_stream_volume}\n"
            f"Supports Mute: {status.supports_stream_mute}\n"
            f"Supports Skip Forward: {status.supports_skip_forward}\n"
            f"Supports Skip Backward: {status.supports_skip_backward}\n"
        )
    except Exception as e:
        logging.error(f"Error formatting media status: {e}")
        return "Error formatting media status."

def check_playback_status(device):
    """Check the playback status of the selected Chromecast device."""
    try:
        logging.info(f"Checking playback status of {device.name}...")

        device.wait()
        mc = device.media_controller
        status = mc.status

        formatted_status = format_media_status(status)

        logging.info(f"{device.name} playback status:\n{formatted_status}")
        print_colored_message(f"{device.name} playback status:\n{formatted_status}", 'cyan')

        return status
    except Exception as e:
        logging.error(f"An error occurred while checking playback status for {device.name}: {e}")
        print_colored_message(f"Failed to check playback status for {device.name}.", 'red')
        return None
        
        
def cast_to_all_devices(chromecasts, text_message, media_url, media_type, duration=None):
    """Cast a text message and media URL to all Chromecast devices simultaneously."""
    threads = []

    for device in chromecasts:
        if text_message:
            thread = threading.Thread(target=cast_text_to_device, args=(device, text_message, True))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    print_colored_message("Text message cast to all devices. Now casting media.", 'cyan')

    threads = []
    for device in chromecasts:
        if media_url:
            thread = threading.Thread(target=cast_media_to_device, args=(device, media_url, media_type, duration))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

def schedule_cast(text_message=None, media_url=None, media_type=None, schedule_time=None):
    """Schedule casting at a specific time."""
    if schedule_time:
        while datetime.now() < schedule_time:
            time.sleep(1)
    cast_to_all_devices(discover_chromecast_devices(), text_message, media_url, media_type)

def shutdown_all_devices(chromecasts):
    """Shutdown all Chromecast devices."""
    threads = []
    for device in chromecasts:
        if input(f"Are you sure you want to shutdown {device.name}? (y/n): ").strip().lower() == 'y':
            thread = threading.Thread(target=shutdown_device, args=(device,))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()

def main():
    """Main function to interact with Chromecast devices."""
    devices = discover_chromecast_devices()
    print_available_devices(devices)
    while True:
        print_colored_message("Chromecast Device Control", 'blue')
        print_colored_message("1. Discover Devices", 'yellow')
        print_colored_message("2. Cast Text to Devices", 'yellow')
        print_colored_message("3. Cast Media to Devices", 'yellow')
        print_colored_message("4. Set Volume", 'yellow')
        print_colored_message("5. Mute Device", 'yellow')
        print_colored_message("6. Unmute Device", 'yellow')
        print_colored_message("7. Check Playback Status", 'yellow')
        print_colored_message("8. Shutdown All Devices", 'yellow')
        print_colored_message("9. Schedule Cast", 'yellow')
        print_colored_message("0. Exit", 'yellow')

        choice = input("Enter your choice: ").strip()

        if choice == '0':
            print_colored_message("Exiting...", 'red')
            break
        elif choice == '1':
            devices = discover_chromecast_devices()
            print_available_devices(devices)
        elif choice == '2':
            text_message = input("Enter the text message: ").strip()
            cast_to_all_devices(devices, text_message, None, None)
        elif choice == '3':
            media_url = input("Enter the media URL: ").strip()
            media_type = input("Enter the media type (e.g., video/mp4): ").strip()
            duration = input("Enter duration in seconds (leave blank for no duration): ").strip()
            duration = int(duration) if duration else None
            cast_to_all_devices(devices, None, media_url, media_type, duration)
        elif choice == '4':
            volume_level = float(input("Enter volume level (0.0 to 1.0): ").strip())
            for device in devices:
                set_volume(device, volume_level)
        elif choice == '5':
            for device in devices:
                mute_device(device)
        elif choice == '6':
            for device in devices:
                unmute_device(device)
        elif choice == '7':
            for device in devices:
                check_playback_status(device)
        elif choice == '8':
            shutdown_all_devices(devices)
        elif choice == '9':
            text_message = input("Enter the text message (leave blank for none): ").strip()
            media_url = input("Enter the media URL (leave blank for none): ").strip()
            media_type = input("Enter the media type (e.g., video/mp4, image/jpeg) (leave blank for none): ").strip()
            schedule_time_str = input("Enter schedule time (YYYY-MM-DD HH:MM:SS, leave blank for immediate): ").strip()
            schedule_time = datetime.strptime(schedule_time_str, '%Y-%m-%d %H:%M:%S') if schedule_time_str else None
            schedule_cast(text_message, media_url, media_type, schedule_time)
        else:
            print_colored_message("Invalid choice. Please try again.", 'red')

if __name__ == "__main__":
    main()
