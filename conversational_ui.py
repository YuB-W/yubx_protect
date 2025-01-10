from flask import Blueprint, request, jsonify, session
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a Blueprint for the conversational UI
conversational_ui_bp = Blueprint('conversational_ui', __name__)

# In-memory store for conversation states
conversation_states = {}

class ConversationManager:
    """Manage conversation states and responses."""
    
    def __init__(self, user_id):
        self.user_id = user_id
        self.state = conversation_states.get(user_id, {})
    
    def update_state(self, new_state):
        """Update the conversation state."""
        self.state.update(new_state)
        conversation_states[self.user_id] = self.state
    
    def get_response(self, user_input):
        """Generate a response based on user input and current state."""
        # Example logic for generating a response
        if 'hello' in user_input.lower():
            return "Hi there! How can I assist you today?"
        elif 'bye' in user_input.lower():
            return "Goodbye! Have a great day!"
        else:
            return "I'm sorry, I didn't understand that. Can you please rephrase?"

@conversational_ui_bp.route('/process_input', methods=['POST'])
def process_input():
    """Process user input and return a response."""
    data = request.get_json()
    user_id = data.get('user_id')
    user_input = data.get('input')
    
    if not user_id or not user_input:
        logger.error("Invalid input data")
        return jsonify({'error': 'Invalid input data'}), 400
    
    # Manage conversation state
    manager = ConversationManager(user_id)
    response = manager.get_response(user_input)
    
    logger.info(f"User {user_id} input: {user_input}")
    logger.info(f"Response: {response}")
    
    return jsonify({'response': response})

# Example of integrating the Blueprint with a Flask app
# from flask import Flask
# app = Flask(__name__)
# app.register_blueprint(conversational_ui_bp, url_prefix='/conversational_ui')
