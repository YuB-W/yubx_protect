// conversational_ui.js

document.addEventListener('DOMContentLoaded', function () {
    const chatInput = document.getElementById('chat-input');
    const sendButton = document.getElementById('send-button');
    const chatHistory = document.getElementById('chat-history');

    // Function to append a message to the chat history
    function appendMessage(message, isUser = false) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('chat-message');
        if (isUser) {
            messageElement.classList.add('user');
        }
        messageElement.textContent = message;
        chatHistory.appendChild(messageElement);
        chatHistory.scrollTop = chatHistory.scrollHeight; // Scroll to the bottom
    }

    // Function to send user input to the server
    function sendMessage() {
        const userInput = chatInput.value.trim();
        if (!userInput) return;

        // Append user message to chat history
        appendMessage(userInput, true);

        // Clear the input field
        chatInput.value = '';

        // Send AJAX request to the server
        fetch('/conversational_ui/process_input', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_id: 'default_user', // Example user ID, replace with actual user management logic
                input: userInput
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.response) {
                // Append server response to chat history
                appendMessage(data.response);
            } else {
                appendMessage("Error: No response from server.");
            }
        })
        .catch(error => {
            console.error('Error:', error);
            appendMessage("Error: Unable to send message.");
        });
    }

    // Event listener for the send button
    sendButton.addEventListener('click', sendMessage);

    // Event listener for the Enter key
    chatInput.addEventListener('keypress', function (event) {
        if (event.key === 'Enter') {
            sendMessage();
        }
    });
});
