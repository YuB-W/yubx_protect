from flask import Flask, render_template_string, request, jsonify
import pychromecast
from semantic_search import SemanticSearch
import logging
import json
import os
import time
import socket

# Configure logging
logging.basicConfig(filename='casting.log', level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

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
semantic_search = SemanticSearch()

def load_html_content():
    """Load HTML content from a file."""
    html_file_path = os.getenv('HTML_FILE_PATH', 'index.html')
    if os.path.exists(html_file_path):
        with open(html_file_path, 'r') as file:
            return file.read()
    return "<h1>HTML file not found</h1>"

HTML_CONTENT = load_html_content()

def discover_chromecast_devices(timeout=5):
    """Discover Chromecast devices with a specified timeout."""
    logging.info("Discovering Chromecast devices...")
    attempts = 3
    for attempt in range(attempts):
        try:
            chromecasts, _ = pychromecast.get_chromecasts(timeout=timeout)
            if chromecasts:
                logging.info(f"Discovered {len(chromecasts)} Chromecast devices.")
                return chromecasts
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff
    logging.error("Failed to discover devices after multiple attempts.")
    return []

def get_ip_address(interface):
    """Get the IP address of a specified network interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(('8.8.8.8', 80))  # Connect to an external address
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        logging.error(f"Unable to get IP address for interface {interface}: {e}")
        return "0.0.0.0"

@app.route('/')
def index():
    """Render the main page with HTML content."""
    chromecasts = discover_chromecast_devices()
    return render_template_string(HTML_CONTENT, chromecasts=chromecasts)

@app.route('/semantic_search', methods=['POST'])
def semantic_search_route():
    """Perform a semantic search on provided documents."""
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
    query = data.get('query')
    documents = data.get('documents')
    if not query or not documents:
        return jsonify({'status': 'error', 'message': 'Query and documents are required'}), 400
    results = semantic_search.search(query, documents)
    return jsonify({'status': 'success', 'results': results}), 200

@app.route('/cast_media', methods=['POST'])
def cast_media():
    """Cast media to selected devices."""
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
    device_ids = data.get('device_ids')
    media_url = data.get('media_url')
    media_type = data.get('media_type')
    duration = data.get('duration')
    if not device_ids or not media_url:
        return jsonify({'status': 'error', 'message': 'Device IDs and media URL are required'}), 400
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        try:
            device = chromecasts[int(device_id)]
        except (IndexError, ValueError):
            logging.error(f"Invalid device ID: {device_id}")
            continue
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

@app.route('/pause', methods=['POST'])
def pause():
    """Pause media on selected devices."""
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
    device_ids = data.get('device_ids')
    if not device_ids:
        return jsonify({'status': 'error', 'message': 'Device IDs are required'}), 400
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Pausing media on {device.name}...")
            device.media_controller.pause()
            logging.info(f"Media paused on {device.name}.")
        except Exception as e:
            logging.error(f"Error pausing media on {device.name}: {e}")

    return jsonify({'status': 'success'}), 200

@app.route('/resume', methods=['POST'])
def resume():
    """Resume media on selected devices."""
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
    device_ids = data.get('device_ids')
    if not device_ids:
        return jsonify({'status': 'error', 'message': 'Device IDs are required'}), 400
    chromecasts = discover_chromecast_devices()

    for device_id in device_ids:
        device = chromecasts[int(device_id)]
        try:
            logging.info(f"Resuming media on {device.name}...")
            device.media_controller.play()
            logging.info(f"Media resumed on {device.name}.")
        except Exception as e:
            logging.error(f"Error resuming media on {device.name}: {e}")

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
    ip_address = get_ip_address('eth0')
    print(f"\nWebsite: http://{ip_address}:5001\n")
    app.run(debug=True, host='0.0.0.0', port=5001)