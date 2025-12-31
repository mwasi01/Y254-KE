// Initialize Socket.IO
const socket = io();

// Chat functionality
let currentChatId = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeChat();
    initializeContacts();
    loadOnlineUsers();
    initializeFileUpload();
});

// Initialize chat functionality
function initializeChat() {
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-input');
    const chatMessages = document.getElementById('chat-messages');
    const fileInput = document.getElementById('file-input');
    const attachBtn = document.getElementById('attach-btn');

    if (messageForm) {
        messageForm.addEventListener('submit', function(e) {
            e.preventDefault();
            sendMessage();
        });
    }

    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    if (attachBtn && fileInput) {
        attachBtn.addEventListener('click', () => fileInput.click());
        
        fileInput.addEventListener('change', async function(e) {
            await handleFileUpload(e.target.files[0]);
            fileInput.value = '';
        });
    }
}

// Send message function
function sendMessage() {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value.trim();
    
    if (message && currentChatId) {
        socket.emit('send_message', {
            content: message,
            receiver_id: currentChatId,
            timestamp: new Date().toISOString()
        });
        
        // Add message to UI immediately
        addMessageToUI({
            content: message,
            sender_id: window.currentUserId,
            receiver_id: currentChatId,
            timestamp: new Date().toISOString(),
            file_path: null,
            file_type: null
        });
        
        messageInput.value = '';
        messageInput.focus();
    }
}

// Handle file upload
async function handleFileUpload(file) {
    if (!file || !currentChatId) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const data = await response.json();
            
            socket.emit('send_message', {
                content: `Shared file: ${file.name}`,
                receiver_id: currentChatId,
                file_path: data.filename,
                file_type: file.type
            });
            
            // Add file message to UI immediately
            addMessageToUI({
                content: `Shared file: ${file.name}`,
                sender_id: window.currentUserId,
                receiver_id: currentChatId,
                timestamp: new Date().toISOString(),
                file_path: data.filename,
                file_type: file.type
            });
        }
    } catch (error) {
        console.error('Upload error:', error);
        alert('Failed to upload file');
    }
}

// Add message to UI
function addMessageToUI(message) {
    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) return;
    
    const isSent = message.sender_id == window.currentUserId;
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    
    let contentHTML = '';
    
    if (message.file_path) {
        if (message.file_type && message.file_type.startsWith('image/')) {
            contentHTML = `
                <img src="/static/uploads/${message.file_path}" 
                     class="file-preview" 
                     onclick="openImageModal('/static/uploads/${message.file_path}')">
            `;
        } else {
            contentHTML = `
                <div class="file-message d-flex align-items-center">
                    <i class="fas fa-file"></i>
                    <div>
                        <a href="/static/uploads/${message.file_path}" 
                           download="${message.file_path.split('_').pop()}">
                            Download ${message.file_path.split('_').pop()}
                        </a>
                        <br>
                        <small>${formatFileSize(message.file_size)}</small>
                    </div>
                </div>
            `;
        }
    }
    
    contentHTML += `
        <p>${message.content}</p>
        <small>${formatTime(message.timestamp)}</small>
    `;
    
    messageDiv.innerHTML = contentHTML;
    chatMessages.appendChild(messageDiv);
    
    // Auto-scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Format file size
function formatFileSize(bytes) {
    if (!bytes) return '';
    if (bytes < 1024) return bytes + ' bytes';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// Format time
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Initialize contacts functionality
function initializeContacts() {
    // Add contact buttons
    document.querySelectorAll('.add-contact').forEach(button => {
        button.addEventListener('click', async function() {
            const userId = this.dataset.userId;
            await addContact(userId);
        });
    });
    
    // Remove contact buttons
    document.querySelectorAll('.remove-contact').forEach(button => {
        button.addEventListener('click', async function() {
            const userId = this.dataset.userId;
            if (confirm('Remove this contact?')) {
                await removeContact(userId);
            }
        });
    });
    
    // Search functionality
    const searchInput = document.getElementById('searchUsers');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(searchUsers, 300));
    }
}

// Add contact
async function addContact(userId) {
    try {
        const response = await fetch(`/api/add_contact/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        if (data.success) {
            location.reload();
        } else {
            alert(data.message || 'Failed to add contact');
        }
    } catch (error) {
        console.error('Error adding contact:', error);
        alert('Failed to add contact');
    }
}

// Remove contact
async function removeContact(userId) {
    try {
        const response = await fetch(`/api/remove_contact/${userId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        if (data.success) {
            location.reload();
        }
    } catch (error) {
        console.error('Error removing contact:', error);
    }
}

// Search users
async function searchUsers(query) {
    try {
        const response = await fetch(`/api/search_users?q=${encodeURIComponent(query)}`);
        const users = await response.json();
        updateUserSearchResults(users);
    } catch (error) {
        console.error('Search error:', error);
    }
}

// Load online users
async function loadOnlineUsers() {
    try {
        const response = await fetch('/api/online_users');
        const users = await response.json();
        updateOnlineUsersList(users);
    } catch (error) {
        console.error('Error loading online users:', error);
    }
}

// Update online users list
function updateOnlineUsersList(users) {
    const container = document.getElementById('online-users-list');
    if (!container) return;
    
    container.innerHTML = users.map(user => `
        <div class="d-flex align-items-center mb-2 p-2 rounded hover-bg" 
             onclick="openChat(${user.id})" style="cursor: pointer;">
            <span class="online-status ${user.status}"></span>
            <img src="/static/profile_pics/${user.profile_pic}" 
                 class="rounded-circle me-2" width="30" height="30">
            <span class="flex-grow-1">${user.username}</span>
        </div>
    `).join('');
}

// Open chat with user
function openChat(userId) {
    window.location.href = `/chat/${userId}`;
}

// Debounce function for search
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Socket.IO event handlers
socket.on('connect', () => {
    console.log('Connected to server');
});

socket.on('receive_message', (data) => {
    // Check if we're in the chat with this sender
    if (currentChatId === data.sender_id || currentChatId === null) {
        addMessageToUI(data);
    } else {
        // Show notification
        showNotification(data.sender_name, data.content);
    }
});

socket.on('user_status', (data) => {
    updateUserStatus(data);
});

socket.on('user_typing', (data) => {
    if (data.user_id === currentChatId) {
        showTypingIndicator(data.user_id);
    }
});

// Update user status
function updateUserStatus(data) {
    const statusElement = document.querySelector(`.user-status-${data.user_id}`);
    if (statusElement) {
        statusElement.className = `online-status ${data.status}`;
        statusElement.nextElementSibling.textContent = data.status;
    }
}

// Show typing indicator
function showTypingIndicator(userId) {
    const indicator = document.getElementById('typing-indicator');
    if (indicator) {
        indicator.style.display = 'block';
        clearTimeout(indicator.timeout);
        indicator.timeout = setTimeout(() => {
            indicator.style.display = 'none';
        }, 1000);
    }
}

// Show notification
function showNotification(title, message) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(`${title}: ${message}`);
    }
}

// Initialize file upload
function initializeFileUpload() {
    // Drag and drop functionality
    const chatContainer = document.querySelector('.chat-messages');
    if (chatContainer) {
        chatContainer.addEventListener('dragover', (e) => {
            e.preventDefault();
            chatContainer.classList.add('dragover');
        });
        
        chatContainer.addEventListener('dragleave', () => {
            chatContainer.classList.remove('dragover');
        });
        
        chatContainer.addEventListener('drop', async (e) => {
            e.preventDefault();
            chatContainer.classList.remove('dragover');
            
            if (e.dataTransfer.files.length > 0) {
                await handleFileUpload(e.dataTransfer.files[0]);
            }
        });
    }
}

// Open image in modal
function openImageModal(src) {
    const modal = document.createElement('div');
    modal.className = 'image-modal';
    modal.innerHTML = `
        <div class="modal-backdrop" onclick="closeImageModal()"></div>
        <div class="modal-content">
            <img src="${src}" alt="Preview">
            <button class="close-btn" onclick="closeImageModal()">&times;</button>
            <a href="${src}" download class="download-btn">
                <i class="fas fa-download"></i>
            </a>
        </div>
    `;
    document.body.appendChild(modal);
    
    // Add CSS for modal
    if (!document.querySelector('#modal-styles')) {
        const styles = document.createElement('style');
        styles.id = 'modal-styles';
        styles.textContent = `
            .image-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: 9999;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .modal-backdrop {
                position: absolute;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.9);
            }
            .modal-content {
                position: relative;
                z-index: 10000;
                max-width: 90%;
                max-height: 90%;
            }
            .modal-content img {
                max-width: 100%;
                max-height: 90vh;
                border-radius: 10px;
            }
            .close-btn, .download-btn {
                position: absolute;
                background: white;
                border: none;
                border-radius: 50%;
                width: 50px;
                height: 50px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 24px;
                cursor: pointer;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            }
            .close-btn {
                top: -25px;
                right: -25px;
            }
            .download-btn {
                bottom: -25px;
                right: -25px;
                text-decoration: none;
                color: #333;
            }
        `;
        document.head.appendChild(styles);
    }
}

// Close image modal
function closeImageModal() {
    const modal = document.querySelector('.image-modal');
    if (modal) {
        modal.remove();
    }
}

// Request notification permission
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}

// Export for use in HTML
window.sendMessage = sendMessage;
window.openChat = openChat;
window.openImageModal = openImageModal;
window.closeImageModal = closeImageModal;
