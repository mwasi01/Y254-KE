import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import json
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), default='default.png')
    status = db.Column(db.String(200), default='Available')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    file_path = db.Column(db.String(500))
    file_type = db.Column(db.String(50))

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/chat/<int:contact_id>')
@login_required
def chat(contact_id):
    contact = User.query.get_or_404(contact_id)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    return render_template('chat.html', contact=contact, messages=messages)

@app.route('/contacts')
@login_required
def contacts():
    all_users = User.query.filter(User.id != current_user.id).all()
    user_contacts = Contact.query.filter_by(user_id=current_user.id).all()
    contact_ids = [c.contact_id for c in user_contacts]
    
    return render_template('contacts.html', 
                         users=all_users, 
                         contacts=contact_ids)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        status = request.form.get('status')
        current_user.status = status
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '':
                filename = secure_filename(f"{current_user.id}_{file.filename}")
                file.save(os.path.join(app.config['PROFILE_PICS_FOLDER'], filename))
                current_user.profile_pic = filename
        
        db.session.commit()
        flash('Profile updated successfully')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user)

# API Routes
@app.route('/api/users')
@login_required
def get_users():
    users = User.query.filter(User.id != current_user.id).all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'profile_pic': user.profile_pic,
        'status': user.status
    } for user in users])

@app.route('/api/messages/<int:contact_id>')
@login_required
def get_messages(contact_id):
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    return jsonify([{
        'id': msg.id,
        'content': msg.content,
        'sender_id': msg.sender_id,
        'receiver_id': msg.receiver_id,
        'timestamp': msg.timestamp.isoformat(),
        'file_path': msg.file_path,
        'file_type': msg.file_type
    } for msg in messages])

@app.route('/api/add_contact/<int:contact_id>', methods=['POST'])
@login_required
def add_contact(contact_id):
    if not Contact.query.filter_by(user_id=current_user.id, contact_id=contact_id).first():
        contact = Contact(user_id=current_user.id, contact_id=contact_id)
        db.session.add(contact)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False})

# SocketIO Events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(str(current_user.id))
        emit('user_status', {
            'user_id': current_user.id,
            'status': 'online'
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(str(current_user.id))
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('user_status', {
            'user_id': current_user.id,
            'status': 'offline',
            'last_seen': current_user.last_seen.isoformat()
        }, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    message = Message(
        content=data['content'],
        sender_id=current_user.id,
        receiver_id=data['receiver_id'],
        file_path=data.get('file_path'),
        file_type=data.get('file_type')
    )
    db.session.add(message)
    db.session.commit()
    
    emit('receive_message', {
        'id': message.id,
        'content': message.content,
        'sender_id': message.sender_id,
        'receiver_id': message.receiver_id,
        'timestamp': message.timestamp.isoformat(),
        'file_path': message.file_path,
        'file_type': message.file_type,
        'sender_name': current_user.username
    }, room=str(data['receiver_id']))
    
    emit('message_sent', {
        'id': message.id,
        'timestamp': message.timestamp.isoformat()
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
