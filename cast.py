from flask import Flask, jsonify, render_template, request
import pychromecast
import logging

app = Flask(__name__)

# Initialize logging
logging.basicConfig(filename='casting.log', level=logging.DEBUG)

# Discover Chromecast devices
chromecasts, browser = pychromecast.get_chromecasts()
devices = {cc.device.friendly_name: cc for cc in chromecasts}

@app.route('/')
def index():
    return render_template('index.html', devices=list(devices.keys()))

@app.route('/discover_devices', methods=['GET'])
def discover_devices():
    try:
        global chromecasts, browser, devices
        chromecasts, browser = pychromecast.get_chromecasts()
        devices = {cc.device.friendly_name: cc for cc in chromecasts}

        # Return devices as JSON
        return jsonify(devices), 200

    except Exception as e:
        logging.error(f"Error discovering devices: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cast_text', methods=['POST'])
def cast_text():
    try:
        device_name = request.json.get('device_name')
        text = request.json.get('text')
        cc = devices.get(device_name)
        if not cc:
            return jsonify({'error': 'Device not found'}), 404

        # Cast text to the device
        mc = cc.media_controller
        mc.play_media(f"http://translate.google.com/translate_tts?tl=en&q={text}", 'audio/mpeg')
        mc.block_until_active()
        return jsonify({'status': 'Text casted successfully'}), 200

    except Exception as e:
        logging.error(f"Error casting text: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cast_media', methods=['POST'])
def cast_media():
    try:
        device_name = request.json.get('device_name')
        media_url = request.json.get('media_url')
        media_type = request.json.get('media_type')
        duration = request.json.get('duration', 0)
        cc = devices.get(device_name)
        if not cc:
            return jsonify({'error': 'Device not found'}), 404

        # Cast media to the device
        mc = cc.media_controller
        mc.play_media(media_url, media_type)
        mc.block_until_active()
        mc.play()
        if duration > 0:
            mc.pause()
        return jsonify({'status': 'Media casted successfully'}), 200

    except Exception as e:
        logging.error(f"Error casting media: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/control_device', methods=['POST'])
def control_device():
    try:
        action = request.json.get('action')
        device_name = request.json.get('device_name')
        cc = devices.get(device_name)
        if not cc:
            return jsonify({'error': 'Device not found'}), 404

        # Perform the action on the device
        if action == 'shutdown':
            cc.quit_app()
        elif action == 'turn_on':
            # Chromecast does not have a turn-on command; you can send a command to wake it up
            cc.media_controller.block_until_active()
        elif action == 'mute':
            cc.set_volume_muted(True)
        elif action == 'unmute':
            cc.set_volume_muted(False)
        elif action == 'set_volume':
            volume = float(request.json.get('volume', 1.0))
            cc.set_volume(volume)
        else:
            return jsonify({'error': 'Invalid action'}), 400

        return jsonify({'status': f'{action.capitalize()} performed successfully'}), 200

    except Exception as e:
        logging.error(f"Error controlling device: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
