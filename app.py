"""
Y254-KE - Enhanced Social Messaging Platform
Main Application File
"""

import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    if os.environ.get('DATABASE_URL'):
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
    else:
        SQLALCHEMY_DATABASE_URI = 'sqlite:///instance/database.db'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }
    
    # File upload configuration
    UPLOAD_FOLDER = 'static/uploads'
    PROFILE_PICS_FOLDER = 'static/profile_pics'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'image': {'png', 'jpg', 'jpeg', 'gif', 'webp'},
        'document': {'pdf', 'doc', 'docx', 'txt', 'rtf'},
        'audio': {'mp3', 'wav', 'ogg'},
        'video': {'mp4', 'avi', 'mov', 'mkv'}
    }
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # SocketIO configuration
    SOCKETIO_ASYNC_MODE = 'eventlet'
    
    # Application settings
    APP_NAME = "Y254-KE"
    APP_VERSION = "1.0.0"

app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=app.config['SOCKETIO_ASYNC_MODE'])
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page.'
login_manager.login_message_category = 'info'

# Configure logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/y254ke.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Y254-KE startup')

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
os.makedirs('instance', exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), default='default.png')
    status = db.Column(db.String(200), default='Available')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    
    # Relationships
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', 
                                   backref='sender', lazy='dynamic', cascade='all, delete-orphan')
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', 
                                       backref='receiver', lazy='dynamic', cascade='all, delete-orphan')
    contacts_added = db.relationship('Contact', foreign_keys='Contact.user_id', 
                                    backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'profile_pic': self.profile_pic,
            'status': self.status,
            'is_online': self.is_online,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, default=False)
    file_path = db.Column(db.String(500))
    file_type = db.Column(db.String(50))
    file_name = db.Column(db.String(200))
    file_size = db.Column(db.Integer)  # in bytes
    
    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} to {self.receiver_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'timestamp': self.timestamp.isoformat(),
            'is_read': self.is_read,
            'file_path': self.file_path,
            'file_type': self.file_type,
            'file_name': self.file_name,
            'file_size': self.file_size
        }

class Contact(db.Model):
    __tablename__ = 'contacts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    contact_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_blocked = db.Column(db.Boolean, default=False)
    
    # Unique constraint to prevent duplicate contacts
    __table_args__ = (db.UniqueConstraint('user_id', 'contact_id', name='_user_contact_uc'),)
    
    def __repr__(self):
        return f'<Contact {self.user_id} -> {self.contact_id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def allowed_file(filename, file_type='all'):
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if file_type == 'all':
        for category in app.config['ALLOWED_EXTENSIONS'].values():
            if ext in category:
                return True
        return False
    elif file_type in app.config['ALLOWED_EXTENSIONS']:
        return ext in app.config['ALLOWED_EXTENSIONS'][file_type]
    
    return False

def get_file_category(filename):
    if '.' not in filename:
        return None
    
    ext = filename.rsplit('.', 1)[1].lower()
    for category, extensions in app.config['ALLOWED_EXTENSIONS'].items():
        if ext in extensions:
            return category
    return None

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Validation
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            created_at=datetime.utcnow()
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Auto-login after registration
            login_user(user, remember=True)
            flash('Registration successful! Welcome to Y254-KE!', 'success')
            
            # Log the registration
            app.logger.info(f'New user registered: {username} ({email})')
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            # Log the login
            app.logger.info(f'User logged in: {username}')
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            app.logger.warning(f'Failed login attempt for username: {username}')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash('You have been logged out successfully.', 'info')
    app.logger.info(f'User logged out: {username}')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent chats
    recent_chats = []
    
    # Get contacts with their last message
    contacts = Contact.query.filter_by(user_id=current_user.id, is_blocked=False).all()
    
    for contact in contacts:
        contact_user = User.query.get(contact.contact_id)
        if contact_user:
            last_message = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_user.id)) |
                ((Message.sender_id == contact_user.id) & (Message.receiver_id == current_user.id))
            ).order_by(Message.timestamp.desc()).first()
            
            unread_count = Message.query.filter_by(
                sender_id=contact_user.id,
                receiver_id=current_user.id,
                is_read=False
            ).count()
            
            recent_chats.append({
                'user': contact_user,
                'last_message': last_message,
                'unread_count': unread_count
            })
    
    return render_template('dashboard.html', 
                          user=current_user, 
                          recent_chats=recent_chats)

@app.route('/chat/<int:contact_id>')
@login_required
def chat(contact_id):
    # Verify contact exists and is not blocked
    contact_user = User.query.get_or_404(contact_id)
    
    contact = Contact.query.filter_by(
        user_id=current_user.id,
        contact_id=contact_id,
        is_blocked=False
    ).first()
    
    if not contact:
        flash('User is not in your contacts or is blocked', 'warning')
        return redirect(url_for('dashboard'))
    
    # Get messages between current user and contact
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    # Mark messages as read
    unread_messages = Message.query.filter_by(
        sender_id=contact_id,
        receiver_id=current_user.id,
        is_read=False
    ).all()
    
    for msg in unread_messages:
        msg.is_read = True
    
    if unread_messages:
        db.session.commit()
    
    return render_template('chat.html', 
                          contact=contact_user, 
                          messages=messages,
                          current_user=current_user)

@app.route('/contacts')
@login_required
def contacts():
    # Get all contacts
    user_contacts = Contact.query.filter_by(
        user_id=current_user.id,
        is_blocked=False
    ).all()
    
    # Get contact users
    contacts = []
    for uc in user_contacts:
        contact_user = User.query.get(uc.contact_id)
        if contact_user:
            contacts.append(contact_user)
    
    # Get all other users for "discover" section
    all_users = User.query.filter(
        User.id != current_user.id,
        ~User.id.in_([c.id for c in contacts])
    ).all()
    
    return render_template('contacts.html', 
                          contacts=contacts,
                          all_users=all_users,
                          user=current_user)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update status
        new_status = request.form.get('status', '').strip()
        if new_status:
            current_user.status = new_status
        
        # Update profile picture
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '' and allowed_file(file.filename, 'image'):
                # Delete old profile picture if not default
                if current_user.profile_pic != 'default.png':
                    old_pic_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], current_user.profile_pic)
                    if os.path.exists(old_pic_path):
                        os.remove(old_pic_path)
                
                # Save new picture
                filename = secure_filename(f"{current_user.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file.save(os.path.join(app.config['PROFILE_PICS_FOLDER'], filename))
                current_user.profile_pic = filename
        
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            app.logger.info(f'Profile updated for user: {current_user.username}')
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'danger')
            app.logger.error(f'Profile update error: {str(e)}')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user)

# API Routes
@app.route('/api/users')
@login_required
def get_users():
    users = User.query.filter(User.id != current_user.id).all()
    return jsonify([user.to_dict() for user in users])

@app.route('/api/messages/<int:contact_id>')
@login_required
def get_messages(contact_id):
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    return jsonify([msg.to_dict() for msg in messages])

@app.route('/api/contacts')
@login_required
def get_contacts():
    contacts = Contact.query.filter_by(user_id=current_user.id, is_blocked=False).all()
    contact_list = []
    
    for contact in contacts:
        user = User.query.get(contact.contact_id)
        if user:
            # Get last message and unread count
            last_message = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == user.id)) |
                ((Message.sender_id == user.id) & (Message.receiver_id == current_user.id))
            ).order_by(Message.timestamp.desc()).first()
            
            unread_count = Message.query.filter_by(
                sender_id=user.id,
                receiver_id=current_user.id,
                is_read=False
            ).count()
            
            contact_list.append({
                **user.to_dict(),
                'last_message': last_message.to_dict() if last_message else None,
                'unread_count': unread_count,
                'contact_since': contact.created_at.isoformat()
            })
    
    return jsonify(contact_list)

@app.route('/api/add_contact/<int:contact_id>', methods=['POST'])
@login_required
def add_contact(contact_id):
    if contact_id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot add yourself as contact'}), 400
    
    # Check if contact exists
    contact_user = User.query.get(contact_id)
    if not contact_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Check if already a contact
    existing = Contact.query.filter_by(
        user_id=current_user.id,
        contact_id=contact_id
    ).first()
    
    if existing:
        if existing.is_blocked:
            existing.is_blocked = False
            db.session.commit()
            return jsonify({'success': True, 'message': 'Contact unblocked and added'})
        return jsonify({'success': False, 'message': 'Contact already exists'}), 400
    
    # Create contact
    contact = Contact(
        user_id=current_user.id,
        contact_id=contact_id,
        created_at=datetime.utcnow()
    )
    
    try:
        db.session.add(contact)
        db.session.commit()
        app.logger.info(f'Contact added: {current_user.username} -> {contact_user.username}')
        return jsonify({'success': True, 'message': 'Contact added successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error adding contact: {str(e)}')
        return jsonify({'success': False, 'message': 'Error adding contact'}), 500

@app.route('/api/remove_contact/<int:contact_id>', methods=['DELETE'])
@login_required
def remove_contact(contact_id):
    contact = Contact.query.filter_by(
        user_id=current_user.id,
        contact_id=contact_id
    ).first()
    
    if not contact:
        return jsonify({'success': False, 'message': 'Contact not found'}), 404
    
    try:
        db.session.delete(contact)
        db.session.commit()
        app.logger.info(f'Contact removed: {current_user.username} -> {contact_id}')
        return jsonify({'success': True, 'message': 'Contact removed successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error removing contact: {str(e)}')
        return jsonify({'success': False, 'message': 'Error removing contact'}), 500

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'File type not allowed'}), 400
    
    # Generate secure filename
    filename = secure_filename(f"{current_user.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        file_category = get_file_category(filename)
        
        app.logger.info(f'File uploaded: {filename} ({file_size} bytes) by {current_user.username}')
        
        return jsonify({
            'success': True,
            'filename': filename,
            'file_size': file_size,
            'file_category': file_category,
            'file_type': file.content_type,
            'original_name': file.filename
        })
    except Exception as e:
        app.logger.error(f'File upload error: {str(e)}')
        return jsonify({'success': False, 'message': 'Error uploading file'}), 500

@app.route('/api/search_users')
@login_required
def search_users():
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return jsonify([])
    
    users = User.query.filter(
        User.id != current_user.id,
        (User.username.ilike(f'%{query}%') | User.email.ilike(f'%{query}%'))
    ).limit(20).all()
    
    return jsonify([user.to_dict() for user in users])

@app.route('/api/update_status', methods=['POST'])
@login_required
def update_status():
    status = request.json.get('status', '').strip()
    
    if status:
        current_user.status = status
        current_user.last_seen = datetime.utcnow()
        
        try:
            db.session.commit()
            
            # Broadcast status update
            socketio.emit('user_status_update', {
                'user_id': current_user.id,
                'status': status,
                'is_online': current_user.is_online
            }, broadcast=True)
            
            return jsonify({'success': True, 'message': 'Status updated'})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Status update error: {str(e)}')
            return jsonify({'success': False, 'message': 'Error updating status'}), 500
    
    return jsonify({'success': False, 'message': 'Invalid status'}), 400

# Static file serving
@app.route('/static/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/static/profile_pics/<filename>')
def profile_pic(filename):
    return send_from_directory(app.config['PROFILE_PICS_FOLDER'], filename)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'success': False, 'message': 'File too large (max 16MB)'}), 413

# SocketIO Events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        # Update user online status
        current_user.is_online = True
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        
        # Join user's personal room
        join_room(f'user_{current_user.id}')
        
        # Broadcast online status
        emit('user_status', {
            'user_id': current_user.id,
            'status': current_user.status,
            'is_online': True,
            'last_seen': current_user.last_seen.isoformat()
        }, broadcast=True)
        
        app.logger.info(f'User connected via WebSocket: {current_user.username}')

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        # Update user offline status
        current_user.is_online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        
        # Broadcast offline status
        emit('user_status', {
            'user_id': current_user.id,
            'status': current_user.status,
            'is_online': False,
            'last_seen': current_user.last_seen.isoformat()
        }, broadcast=True)
        
        app.logger.info(f'User disconnected from WebSocket: {current_user.username}')

@socketio.on('join_chat')
def handle_join_chat(data):
    contact_id = data.get('contact_id')
    if current_user.is_authenticated and contact_id:
        room = f'chat_{min(current_user.id, contact_id)}_{max(current_user.id, contact_id)}'
        join_room(room)
        
        app.logger.debug(f'User {current_user.username} joined chat room: {room}')

@socketio.on('leave_chat')
def handle_leave_chat(data):
    contact_id = data.get('contact_id')
    if current_user.is_authenticated and contact_id:
        room = f'chat_{min(current_user.id, contact_id)}_{max(current_user.id, contact_id)}'
        leave_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return
    
    content = data.get('content', '').strip()
    receiver_id = data.get('receiver_id')
    file_info = data.get('file_info', {})
    
    if not content and not file_info:
        return
    
    # Create message
    message = Message(
        content=content,
        sender_id=current_user.id,
        receiver_id=receiver_id,
        timestamp=datetime.utcnow(),
        file_path=file_info.get('filename'),
        file_type=file_info.get('file_type'),
        file_name=file_info.get('original_name'),
        file_size=file_info.get('file_size')
    )
    
    try:
        db.session.add(message)
        db.session.commit()
        
        # Prepare message data for broadcasting
        message_data = {
            'id': message.id,
            'content': message.content,
            'sender_id': message.sender_id,
            'sender_name': current_user.username,
            'sender_profile_pic': current_user.profile_pic,
            'receiver_id': message.receiver_id,
            'timestamp': message.timestamp.isoformat(),
            'file_info': {
                'path': message.file_path,
                'type': message.file_type,
                'name': message.file_name,
                'size': message.file_size
            } if message.file_path else None
        }
        
        # Room for this chat
        room = f'chat_{min(current_user.id, receiver_id)}_{max(current_user.id, receiver_id)}'
        
        # Broadcast to the chat room
        emit('receive_message', message_data, room=room)
        
        # Also send to receiver's personal room for notifications
        emit('new_message_notification', {
            'message': message_data,
            'sender': current_user.username
        }, room=f'user_{receiver_id}')
        
        app.logger.info(f'Message sent: {current_user.username} -> {receiver_id}')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error sending message: {str(e)}')
        emit('message_error', {'error': 'Failed to send message'})

@socketio.on('typing')
def handle_typing(data):
    if current_user.is_authenticated:
        receiver_id = data.get('receiver_id')
        room = f'chat_{min(current_user.id, receiver_id)}_{max(current_user.id, receiver_id)}'
        
        emit('user_typing', {
            'user_id': current_user.id,
            'username': current_user.username
        }, room=room, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    if current_user.is_authenticated:
        receiver_id = data.get('receiver_id')
        room = f'chat_{min(current_user.id, receiver_id)}_{max(current_user.id, receiver_id)}'
        
        emit('user_stop_typing', {
            'user_id': current_user.id
        }, room=room, include_self=False)

@socketio.on('message_read')
def handle_message_read(data):
    if current_user.is_authenticated:
        message_id = data.get('message_id')
        sender_id = data.get('sender_id')
        
        message = Message.query.get(message_id)
        if message and message.receiver_id == current_user.id:
            message.is_read = True
            db.session.commit()
            
            # Notify sender that message was read
            emit('message_read_notification', {
                'message_id': message_id,
                'reader_id': current_user.id,
                'reader_name': current_user.username
            }, room=f'user_{sender_id}')

# Health check endpoint for Render
@app.route('/health')
def health_check():
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'service': 'Y254-KE',
            'version': app.config['APP_VERSION'],
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'service': 'Y254-KE',
            'error': str(e)
        }), 500

# Application initialization
def init_app():
    """Initialize the application"""
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@y254ke.com',
                password_hash=generate_password_hash('admin123'),
                status='Administrator',
                created_at=datetime.utcnow()
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.info('Default admin user created')
        
        # Create some test users in development
        if app.debug and not User.query.filter_by(username='alice').first():
            test_users = [
                ('alice', 'alice@y254ke.com', 'password123'),
                ('bob', 'bob@y254ke.com', 'password123'),
                ('charlie', 'charlie@y254ke.com', 'password123'),
            ]
            
            for username, email, password in test_users:
                user = User(
                    username=username,
                    email=email,
                    password_hash=generate_password_hash(password),
                    status='Available',
                    created_at=datetime.utcnow()
                )
                db.session.add(user)
            
            db.session.commit()
            app.logger.info('Test users created')
        
        app.logger.info('Application initialized successfully')

# Production WSGI application for gunicorn
application = socketio

if __name__ == '__main__':
    # Initialize the application
    init_app()
    
    # Get port from environment variable (Render provides this)
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true',
        log_output=True,
        allow_unsafe_werkzeug=True
    )
