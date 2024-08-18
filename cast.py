from flask import Flask, render_template, request, jsonify
import logging
from pychromecast import Chromecast, discover_chromecasts
import socket

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def discover_chromecast_devices():
    devices = discover_chromecasts()
    return [device for device in devices if isinstance(device, Chromecast)]

def get_ip_address(interface):
    """ Get the IP address of the specified network interface. """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((interface, 0))
        ip_address = s.getsockname()[0]
    except Exception as e:
        logging.error(f"An error occurred while getting IP address: {e}")
        ip_address = '127.0.0.1'  # Default to localhost if there is an error
    finally:
        s.close()
    return ip_address

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/discover_devices', methods=['GET'])
def discover_devices():
    try:
        devices = discover_chromecast_devices()
        device_info = [{'name': device.name, 'ip': device.host} for device in devices]
        return jsonify(device_info)
    except Exception as e:
        logging.error(f"An error occurred while discovering devices: {e}")
        return jsonify({'status': 'error'})

@app.route('/cast_text', methods=['POST'])
def cast_text():
    data = request.json
    text_message = data.get('text_message')
    device_name = data.get('device_name')
    animation = data.get('animation', False)
    try:
        devices = discover_chromecast_devices()
        for device in devices:
            if device.name == device_name:
                device.wait()
                mc = device.media_controller
                mc.play_media(text_message, 'text/plain')
                if animation:
                    # You may need to handle animation if applicable
                    pass
                return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Device not found'})
    except Exception as e:
        logging.error(f"An error occurred while casting text: {e}")
        return jsonify({'status': 'error'})

@app.route('/cast_media', methods=['POST'])
def cast_media():
    data = request.json
    media_url = data.get('media_url')
    media_type = data.get('media_type')
    duration = data.get('duration')
    device_name = data.get('device_name')
    try:
        devices = discover_chromecast_devices()
        for device in devices:
            if device.name == device_name:
                device.wait()
                mc = device.media_controller
                mc.play_media(media_url, media_type)
                if duration:
                    mc.pause()
                return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Device not found'})
    except Exception as e:
        logging.error(f"An error occurred while casting media: {e}")
        return jsonify({'status': 'error'})

@app.route('/shutdown_devices', methods=['POST'])
def shutdown_devices():
    try:
        devices = discover_chromecast_devices()
        for device in devices:
            device.wait()
            device.turn_off()
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"An error occurred while shutting down devices: {e}")
        return jsonify({'status': 'error'})

@app.route('/turn_on_devices', methods=['POST'])
def turn_on_devices():
    try:
        devices = discover_chromecast_devices()
        for device in devices:
            device.wait()
            device.turn_on()
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"An error occurred while turning on devices: {e}")
        return jsonify({'status': 'error'})

@app.route('/set_volume', methods=['POST'])
def set_volume():
    data = request.json
    volume = data.get('volume')
    try:
        devices = discover_chromecast_devices()
        for device in devices:
            device.wait()
            mc = device.media_controller
            mc.set_volume(float(volume) / 100)
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"An error occurred while setting volume: {e}")
        return jsonify({'status': 'error'})

@app.route('/mute_devices', methods=['POST'])
def mute_devices():
    try:
        devices = discover_chromecast_devices()
        for device in devices:
            device.wait()
            mc = device.media_controller
            mc.set_volume(0)
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"An error occurred while muting devices: {e}")
        return jsonify({'status': 'error'})

@app.route('/unmute_devices', methods=['POST'])
def unmute_devices():
    try:
        devices = discover_chromecast_devices()
        for device in devices:
            device.wait()
            mc = device.media_controller
            mc.set_volume(0.5)  # Set to 50% volume
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"An error occurred while unmuting devices: {e}")
        return jsonify({'status': 'error'})

if __name__ == '__main__':
    ip_address = get_ip_address('eth0')
    print(f"\nWebsite: http://{ip_address}:5001\n")
    app.run(debug=True, host='0.0.0.0', port=5001)
