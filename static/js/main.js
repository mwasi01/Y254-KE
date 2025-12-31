// Socket.IO connection
const socket = io();

// Chat functionality
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const chatMessages = document.getElementById('chat-messages');
const fileInput = document.getElementById('file-input');
const attachBtn = document.getElementById('attach-btn');

if (messageForm) {
    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            socket.emit('send_message', {
                content: message,
                receiver_id: contactId
            });
            messageInput.value = '';
        }
    });
}

if (attachBtn) {
    attachBtn.addEventListener('click', () => {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) {
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (data.success) {
                    socket.emit('send_message', {
                        content: `Shared a file: ${file.name}`,
                        receiver_id: contactId,
                        file_path: data.file_path,
                        file_type: file.type
                    });
                }
            } catch (error) {
                console.error('Upload error:', error);
            }
        }
    });
}

// Socket event listeners
socket.on('receive_message', (data) => {
    if (chatMessages) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${data.sender_id === currentUserId ? 'sent' : 'received'}`;
        
        let content = '';
        if (data.file_path) {
            if (data.file_type && data.file_type.startsWith('image/')) {
                content = `<img src="/static/uploads/${data.file_path}" class="file-preview">`;
            } else {
                content = `
                    <div class="file-message">
                        <i class="fas fa-file"></i>
                        <a href="/static/uploads/${data.file_path}" download>
                            Download File
                        </a>
                    </div>
                `;
            }
        }
        content += `<p>${data.content}</p><small>${new Date(data.timestamp).toLocaleTimeString()}</small>`;
        
        messageDiv.innerHTML = content;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
});

socket.on('user_status', (data) => {
    updateUserStatus(data);
});

// Update online users list
function updateUserStatus(data) {
    const userElement = document.querySelector(`.user-${data.user_id}`);
    if (userElement) {
        const statusElement = userElement.querySelector('.online-status');
        if (statusElement) {
            statusElement.className = `online-status ${data.status}`;
        }
    }
}

// Load recent chats
async function loadRecentChats() {
    try {
        const response = await fetch('/api/recent_chats');
        const chats = await response.json();
        
        const chatsList = document.getElementById('recent-chats-list');
        if (chatsList) {
            chatsList.innerHTML = chats.map(chat => `
                <div class="recent-chat-item">
                    <img src="/static/profile_pics/${chat.profile_pic}" class="profile-pic-small">
                    <div>
                        <h6>${chat.username}</h6>
                        <small>${chat.last_message}</small>
                    </div>
                    <small class="text-muted">${chat.time}</small>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading chats:', error);
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadRecentChats();
    
    // Auto-scroll to bottom of chat
    if (chatMessages) {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
});
