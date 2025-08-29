from flask import Flask, request, jsonify, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from datetime import datetime, timezone
import uuid
import requests
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dietex_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# API Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "your-api-key-here")
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "deepseek/deepseek-chat-v3-0324:free"
AI_AGENT_NAME = os.getenv("AI_AGENT_NAME")

# System Prompt for the AI
SYSTEM_PROMPT = """You are {AI_AGENT_NAME}, a Nigerian professional diet recommendation assistant for Nigerians. Your role is to:
1. Ask clarifying questions ONE at a time to understand the user's dietary needs
2. Only provide food and diet-related recommendations
3. Be concise and professional
4. Format responses in html with proper spacing and lists when appropriate
5. Start by asking a question
6. Ask one question at a time
7. Never discuss non-food related topics - redirect to food/diet if needed"""

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    histories = db.relationship('ChatHistory', backref='user', lazy=True)

class ChatHistory(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), default='New Chat')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('ChatMessage', backref='history', lazy=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # Updated
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), 
                          onupdate=lambda: datetime.now(timezone.utc))  # Updated

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.String(36), db.ForeignKey('chat_history.id'), nullable=False)
    sender = db.Column(db.String(10))  # 'user' or 'system'
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Authentication
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Chat Routes
@app.route('/chat')
@login_required
def chat():
    histories = ChatHistory.query.filter_by(user_id=current_user.id).order_by(ChatHistory.updated_at.desc()).all()
    return render_template('chat.html', histories=histories)

@app.route('/chat/new', methods=['POST'])
@login_required
def new_chat():
    history = ChatHistory(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        title="New Chat " + datetime.utcnow().strftime("%b %d")
    )
    db.session.add(history)
    
    # Add welcome message
    welcome_msg = ChatMessage(
        history_id=history.id,
        sender='system',
        message="Hi! I'm {AI_AGENT_NAME}, your diet recommendation assistant. I'll ask you some questions first to understand your needs before making recommendations. What's your primary diet goal?"
    )
    db.session.add(welcome_msg)
    db.session.commit()
    
    return jsonify({
        'history_id': history.id,
        'title': history.title,
        'welcome_message': welcome_msg.message
    })

@app.route('/chat/send', methods=['POST'])
@login_required
def send_message():
    data = request.json
    message = data.get('message')
    history_id = data.get('history_id', None)

    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    is_new_chat = False
    # Fetch or create chat history
    if not history_id or history_id == 'new':
        history_id = str(uuid.uuid4())
        history = ChatHistory(
            id=history_id,
            user_id=current_user.id,
            title=message[:50]
        )
        db.session.add(history)
        is_new_chat = True
    else:
        history = ChatHistory.query.get(history_id)
        if not history or history.user_id != current_user.id:
            return jsonify({'error': 'Invalid history ID'}), 400

    # Save user message
    user_message = ChatMessage(
        history_id=history.id,
        sender='user',
        message=message
    )
    db.session.add(user_message)
    db.session.flush()

    # Prepare messages for API
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    # Get previous messages if this isn't a new chat
    if not is_new_chat:
        previous_messages = ChatMessage.query.filter_by(
            history_id=history.id
        ).order_by(ChatMessage.timestamp.asc()).all()
        
        for msg in previous_messages:
            messages.append({
                "role": "user" if msg.sender == "user" else "assistant",
                "content": msg.message
            })
    
    # Add current message
    messages.append({"role": "user", "content": message})

    try:
        # Call OpenRouter API
        response = requests.post(
            OPENROUTER_ENDPOINT,
            headers={
                'Authorization': f'Bearer {OPENROUTER_API_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                "model": DEFAULT_MODEL,
                "messages": messages
            },
            timeout=30  # 30 second timeout
        )
        response.raise_for_status()
        response_json = response.json()
        
        response_text = response_json['choices'][0]['message']['content']
        
        # Save system response
        system_message = ChatMessage(
            history_id=history.id,
            sender='system',
            message=response_text
        )
        db.session.add(system_message)
        
        # Update chat title if it's the first exchange
        if len(history.messages) <= 2:  # user + system messages
            history.title = "Diet Chat: " + datetime.now(timezone.utc).strftime("%b %d")
        
        db.session.commit()
        
        return jsonify({
            'reply': (response_text),
            'history_id': history.id,
            'title': history.title,
            'is_new': is_new_chat
        })
        
    except requests.exceptions.RequestException as e:
        print(f"API Error: {str(e)}")
        error_message = "Sorry, I'm having trouble connecting to the service. Please try again later."
    except Exception as e:
        print(f"Unexpected Error: {str(e)}")
        error_message = "Sorry, something went wrong. Please try again."
    
    db.session.rollback()
    return jsonify({'reply': error_message}), 500

# History Management
@app.route('/histories', methods=['GET'])
@login_required
def get_histories():
    histories = ChatHistory.query.filter_by(user_id=current_user.id).order_by(ChatHistory.updated_at.desc()).all()
    return jsonify([{
        'id': h.id,
        'title': h.title,
        'created_at': h.created_at,
        'updated_at': h.updated_at
    } for h in histories])

@app.route('/history/<string:history_id>', methods=['GET'])
@login_required
def get_history(history_id):
    history = ChatHistory.query.filter_by(id=history_id, user_id=current_user.id).first()
    if not history:
        return jsonify({'message': 'Not found'}), 404
        
    messages = ChatMessage.query.filter_by(history_id=history.id).order_by(ChatMessage.timestamp.asc()).all()
    
    history.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    formatted_messages = []
    for msg in messages:
        formatted_messages.append({
            'sender': msg.sender,
            'message': msg.message if msg.sender == 'system' else msg.message,
            'timestamp': msg.timestamp.isoformat()
        })
    
    return jsonify({
        'id': history.id,
        'title': history.title,
        'messages': formatted_messages
    })

@app.route('/history/rename/<history_id>', methods=['POST'])
@login_required
def rename_history(history_id):
    new_title = request.json.get('title')
    if not new_title or len(new_title) > 150:
        return jsonify({'error': 'Invalid title'}), 400

    history = ChatHistory.query.filter_by(id=history_id, user_id=current_user.id).first()
    if not history:
        return jsonify({'error': 'Not found'}), 404
    
    history.title = new_title
    db.session.commit()
    return jsonify({'success': True, 'new_title': new_title})

@app.route('/history/delete/<history_id>', methods=['POST'])
@login_required
def delete_history(history_id):
    history = ChatHistory.query.filter_by(id=history_id, user_id=current_user.id).first()
    if not history:
        return jsonify({'error': 'Not found'}), 404
    
    # Delete all messages first
    ChatMessage.query.filter_by(history_id=history.id).delete()
    db.session.delete(history)
    db.session.commit()
    return jsonify({'success': True})

# Initialize database
def initialize_database():
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123')
            )
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True, port=5002)