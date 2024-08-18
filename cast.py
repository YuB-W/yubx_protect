from flask import Flask, request, jsonify, send_file
import pychromecast
import logging
import threading
from datetime import datetime
from termcolor import colored

# Configure logging
logging.basicConfig(filename='casting.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Function to discover Chromecast devices
def discover_chromecast_devices(timeout=5):
    """Discover Chromecast devices with a specified timeout."""
    logging.info("Discovering Chromecast devices...")
    try:
        chromecasts, _ = pychromecast.get_chromecasts(timeout=timeout)
        return chromecasts
    except Exception as e:
        logging.error(f"An error occurred while discovering devices: {e}")
        return []

def get_device(name):
    """Get a Chromecast device by its name."""
    devices = discover_chromecast_devices()
    for device in devices:
        if device.name == name:
            return device
    return None

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/discover_devices')
def discover_devices():
    devices = discover_chromecast_devices()
    device_list = [{"name": cast.name} for cast in devices]
    return jsonify(device_list)

@app.route('/cast_text', methods=['POST'])
def cast_text():
    data = request.json
    text_message = data.get('text_message')
    device_name = data.get('device_name')
    animation = data.get('animation')

    device = get_device(device_name)
    if device:
        try:
            logging.info(f"Casting text '{text_message}' to {device_name} with animation={animation}")
            # Implement text casting functionality here
            return jsonify({"status": "success", "message": f"Text '{text_message}' cast to '{device_name}' with animation={animation}"})
        except Exception as e:
            logging.error(f"An error occurred while casting text: {e}")
            return jsonify({"status": "error", "message": "Failed to cast text."}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found."}), 404

@app.route('/cast_media', methods=['POST'])
def cast_media():
    data = request.json
    media_url = data.get('media_url')
    media_type = data.get('media_type')
    duration = data.get('duration')
    device_name = data.get('device_name')

    device = get_device(device_name)
    if device:
        try:
            logging.info(f"Casting media '{media_url}' to {device_name} for duration={duration}")
            mc = device.media_controller
            mc.play_media(media_url, media_type)
            mc.block_until_active()
            return jsonify({"status": "success", "message": f"Media '{media_url}' cast to '{device_name}' for duration={duration}"})
        except Exception as e:
            logging.error(f"An error occurred while casting media: {e}")
            return jsonify({"status": "error", "message": "Failed to cast media."}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found."}), 404

@app.route('/shutdown_device', methods=['POST'])
def shutdown_device():
    data = request.json
    device_name = data.get('device_name')

    device = get_device(device_name)
    if device:
        try:
            logging.info(f"Shutting down {device_name}...")
            device.wait()
            device.quit_app()
            return jsonify({"status": "success", "message": f"Shutdown command sent to {device_name}."})
        except Exception as e:
            logging.error(f"An error occurred while shutting down {device_name}: {e}")
            return jsonify({"status": "error", "message": "Failed to shut down device."}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found."}), 404

@app.route('/turn_on_device', methods=['POST'])
def turn_on_device():
    data = request.json
    device_name = data.get('device_name')

    device = get_device(device_name)
    if device:
        try:
            logging.info(f"Turning on {device_name}...")
            device.wait()
            mc = device.media_controller
            default_media_url = "http://www.hdwallpapers.in/walls/black_hd-wide.jpg"
            default_media_type = "image/jpeg"
            mc.play_media(default_media_url, default_media_type)
            mc.block_until_active()
            return jsonify({"status": "success", "message": f"Turned on {device_name} by playing default media."})
        except Exception as e:
            logging.error(f"An error occurred while turning on {device_name}: {e}")
            return jsonify({"status": "error", "message": "Failed to turn on device."}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found."}), 404

@app.route('/set_volume', methods=['POST'])
def set_volume():
    data = request.json
    volume_level = data.get('volume_level')
    device_name = data.get('device_name')

    device = get_device(device_name)
    if device:
        try:
            logging.info(f"Setting volume of {device_name} to {volume_level}...")
            device.wait()
            device.set_volume(volume_level)
            return jsonify({"status": "success", "message": f"Volume set to {volume_level} for {device_name}."})
        except Exception as e:
            logging.error(f"An error occurred while setting volume for {device_name}: {e}")
            return jsonify({"status": "error", "message": "Failed to set volume."}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found."}), 404

@app.route('/mute_device', methods=['POST'])
def mute_device():
    data = request.json
    device_name = data.get('device_name')

    device = get_device(device_name)
    if device:
        try:
            logging.info(f"Muting {device_name}...")
            device.wait()
            device.set_volume_muted(True)
            return jsonify({"status": "success", "message": f"{device_name} is now muted."})
        except Exception as e:
            logging.error(f"An error occurred while muting {device_name}: {e}")
            return jsonify({"status": "error", "message": "Failed to mute device."}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found."}), 404

@app.route('/unmute_device', methods=['POST'])
def unmute_device():
    data = request.json
    device_name = data.get('device_name')

    device = get_device(device_name)
    if device:
        try:
            logging.info(f"Unmuting {device_name}...")
            device.wait()
            device.set_volume_muted(False)
            return jsonify({"status": "success", "message": f"{device_name} is now unmuted."})
        except Exception as e:
            logging.error(f"An error occurred while unmuting {device_name}: {e}")
            return jsonify({"status": "error", "message": "Failed to unmute device."}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found."}), 404

@app.route('/shutdown_all_devices', methods=['POST'])
def shutdown_all_devices():
    data = request.json
    device_names = data.get('device_names')

    devices = [get_device(name) for name in device_names]
    threads = []
    for device in devices:
        if device:
            thread = threading.Thread(target=shutdown_device, args=(device,))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()
    return jsonify({"status": "success", "message": "Shutdown commands sent to all devices."})

if __name__ == '__main__':
    ip_address = socket.gethostbyname(socket.gethostname())
    print(f"Website: http://{ip_address}:5001\n")
    app.run(debug=True, host='0.0.0.0', port=5001)
