from flask import Flask, render_template_string, request, jsonify
import pychromecast
import logging
import json
import os

# Configure logging
logging.basicConfig(filename='casting.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration File
CONFIG_FILE = 'config.json'

def load_config():
    """Load configuration from a JSON file."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            return json.load(file)
    return {"default_volume": 0.5}

def save_config(config):
    """Save configuration to a JSON file."""
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file, indent=4)

app = Flask(__name__)

# Read HTML content from file
with open('/home/kali/Desktop/Python/yubx_protect/index.html', 'r') as file:
    MAP_HTML = file.read()

def discover_chromecast_devices(timeout=5):
    """Discover Chromecast devices with a specified timeout."""
    logging.info("Discovering Chromecast devices...")
    try:
        chromecasts, _ = pychromecast.get_chromecasts(timeout=timeout)
        return chromecasts
    except Exception as e:
        logging.error(f"An error occurred while discovering devices: {e}")
        return []

@app.route('/')
def index():
    """Render the main page with HTML content."""
    return render_template_string(MAP_HTML)

@app.route('/cast_media', methods=['POST'])
def cast_media():
    """Cast media to selected devices."""
    data = request.json
    device_ids = data.get('device_ids', [])
    media_url = data.get('media_url', '')
    media_type = data.get('media_type', '')
    duration = data.get('duration', None)
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Casting media {media_url} to {device.name}...")
            device.wait()
            mc = device.media_controller

            if not device.is_idle:
                logging.warning(f"{device.name} is not idle. Skipping casting.")
                continue

            mc.play_media(media_url, media_type)
            mc.block_until_active()

            if duration:
                logging.info(f"Waiting for {duration} seconds...")
                time.sleep(duration)
                mc.stop()

            logging.info(f"Media casting started on {device.name}.")
        except Exception as e:
            logging.error(f"An error occurred while casting: {e}")

    return jsonify({'status': 'success'}), 200

@app.route('/shutdown', methods=['POST'])
def shutdown():
    """Shutdown the selected devices."""
    data = request.json
    device_ids = data.get('device_ids', [])
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Shutting down {device.name}...")
            device.quit_app()
            logging.info(f"{device.name} has been shut down.")
        except Exception as e:
            logging.error(f"Error shutting down {device.name}: {e}")

    return jsonify({'status': 'success'}), 200

@app.route('/turn_on', methods=['POST'])
def turn_on():
    """Turn on the selected devices by playing default media."""
    data = request.json
    device_ids = data.get('device_ids', [])
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Turning on {device.name}...")
            device.wait()
            mc = device.media_controller
            mc.play_media('http://192.168.2.41:5000/', 'video/mp4')
            mc.block_until_active()
            logging.info(f"{device.name} turned on and playing default media.")
        except Exception as e:
            logging.error(f"Error turning on {device.name}: {e}")

    return jsonify({'status': 'success'}), 200

@app.route('/set_volume', methods=['POST'])
def set_volume():
    """Set volume for the selected devices."""
    data = request.json
    device_ids = data.get('device_ids', [])
    volume_level = data.get('volume_level', 0.5)
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Setting volume to {volume_level} on {device.name}...")
            device.wait()
            mc = device.media_controller
            mc.set_volume(volume_level)
            logging.info(f"Volume set on {device.name}.")
        except Exception as e:
            logging.error(f"Error setting volume on {device.name}: {e}")

    return jsonify({'status': 'success'}), 200

@app.route('/mute', methods=['POST'])
def mute():
    """Mute the selected devices."""
    data = request.json
    device_ids = data.get('device_ids', [])
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Muting {device.name}...")
            device.wait()
            mc = device.media_controller
            mc.set_volume(0)
            logging.info(f"{device.name} is muted.")
        except Exception as e:
            logging.error(f"Error muting {device.name}: {e}")

    return jsonify({'status': 'success'}), 200

@app.route('/unmute', methods=['POST'])
def unmute():
    """Unmute the selected devices."""
    data = request.json
    device_ids = data.get('device_ids', [])
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Unmuting {device.name}...")
            device.wait()
            mc = device.media_controller
            default_volume = load_config().get('default_volume', 0.5)
            mc.set_volume(default_volume)
            logging.info(f"{device.name} is unmuted.")
        except Exception as e:
            logging.error(f"Error unmuting {device.name}: {e}")

    return jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
