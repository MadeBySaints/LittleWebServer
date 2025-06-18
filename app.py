#!/usr/bin/env python3
"""
Flask Web Application with User Authentication and File Management
Production-ready with Waitress WSGI server
"""

import os
import hashlib
import secrets
import time

from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, send_file, abort, make_response, jsonify
from waitress import serve # type: ignore

active_sessions = {}

# ============================================================================
# CONFIGURATION
# ============================================================================

# Security Configuration
SECRET_KEY = "b6f6380c02b54d2cb561305ae2f1e9ca0281ce1a77bbde680000aad8b853ccea"
PEPPER = "dec5a2630515519ec51afc9e258748d81e99a54157002b694027ea54e6725c04"
HASH_PASSWORDS = True  # Set to False to disable password hashing

# Server Configuration
HOST = "0.0.0.0"
PORT = 8440
DEBUG = False

# File Upload Configuration
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip', 'csv', 'stl', '3mf'}

# Website Content - Easy to customize
SITE_CONFIG = {
    'site_name': 'SecureFileHub',
    'tagline': 'Your Personal File Storage Solution',
    'company_name': 'Dot.Pixel(Studio)',
    'primary_color': '#2563eb',
    'secondary_color': '#1e40af',
    'background_gradient': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    'about_content': {
        'title': 'About SecureFileHub',
        'description': 'Reliable file storage solutions for individuals and teams.',
        'features': [
            'Secure user authentication',
            'Personal file storage',
            'Easy file upload and download',
            'User-friendly interface',
            'Production-grade security'
        ],
        'team_info': 'Just a guy with a keyboard.'
    }
}

# ============================================================================
# APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create necessary directories
os.makedirs('data/userdata', exist_ok=True)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hash_password(password):
    """Hash password with pepper if hashing is enabled"""
    if not HASH_PASSWORDS:
        return password
    peppered = password + PEPPER
    return hashlib.sha256(peppered.encode()).hexdigest()

def verify_password(password, hashed):
    """Verify password against hash"""
    if not HASH_PASSWORDS:
        return password == hashed
    return hash_password(password) == hashed

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_folder(username):
    """Get user's file storage folder"""
    user_id = hashlib.md5(username.encode()).hexdigest()[:8]
    folder = f'data/userdata/user{user_id}'
    os.makedirs(folder, exist_ok=True)
    return folder

def load_users():
    """Load users from file"""
    users = {}
    users_file = 'data/userdata/users.txt'
    if os.path.exists(users_file):
        with open(users_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    username, password_hash = line.split(':', 1)
                    users[username] = password_hash
    return users

def save_user(username, password):
    """Save new user to file"""
    users_file = 'data/userdata/users.txt'
    password_hash = hash_password(password)
    with open(users_file, 'a') as f:
        f.write(f"{username}:{password_hash}\n")

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# HTML TEMPLATES
# ============================================================================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}{{ config.site_name }}{% endblock %}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: {{ config.background_gradient }};
            min-height: 100vh;
            color: #333;
        }
        
        .navbar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1rem 0;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 2rem;
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: {{ config.primary_color }};
            text-decoration: none;
        }
        
        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }
        
        .nav-links a {
            text-decoration: none;
            color: #333;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .nav-links a:hover {
            color: {{ config.primary_color }};
        }
        
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        
        .btn {
            background: {{ config.primary_color }};
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        .btn:hover {
            background: {{ config.secondary_color }};
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: #6b7280;
        }
        
        .btn-secondary:hover {
            background: #4b5563;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: {{ config.primary_color }};
        }
        
        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        
        .alert-success {
            background: #d1fae5;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }
        
        .alert-error {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fca5a5;
        }
        
        .file-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .file-item {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        
        .file-item:hover {
            transform: translateY(-2px);
        }
        
        .upload-area {
            border: 2px dashed {{ config.primary_color }};
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
            transition: all 0.3s;
        }
        
        .upload-area:hover {
            background: rgba(37, 99, 235, 0.05);
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <a href="{{ url_for('home') }}" class="logo">{{ config.site_name }}</a>
            <ul class="nav-links">
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('about') }}">About</a></li>
                {% if session.username %}
                    <li><a href="{{ url_for('files') }}">My Files</a></li>
                    <li><a href="{{ url_for('logout') }}">Logout ({{ session.username }})</a></li>
                {% else %}
                    <li><a href="{{ url_for('login') }}">Login</a></li>
                {% endif %}
            </ul>
        </div>
    </nav>
    
    <div class="container">
        {% if get_flashed_messages() %}
            {% for message in get_flashed_messages() %}
                <div class="alert alert-success">{{ message }}</div>
            {% endfor %}
        {% endif %}
        
        {% block content %}{% endblock %}
    </div>
</body>
</html>

<script>
// Send periodic pings to server
const pingInterval = setInterval(() => {
    fetch('/ping', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'same-origin'
    }).catch(() => clearInterval(pingInterval));
}, 10000); // Ping every 10 seconds

// Detect page unload (tab close or refresh)
window.addEventListener('beforeunload', () => {
    // Send immediate logout request
    navigator.sendBeacon('/logout');
});

// Check activity status periodically
setInterval(() => {
    fetch('/check_activity')
        .then(response => response.json())
        .then(data => {
            if (!data.active) {
                window.location.href = '/?timeout=1';
            }
        });
}, 30000); // Check every 30 seconds
</script>
"""

HOME_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
<div class="card">
    <h1 style="font-size: 3rem; margin-bottom: 1rem; background: linear-gradient(135deg, {{ config.primary_color }}, {{ config.secondary_color }}); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
        {{ config.site_name }}
    </h1>
    <p style="font-size: 1.25rem; color: #6b7280; margin-bottom: 2rem;">
        {{ config.tagline }}
    </p>
    
    {% if session.username %}
        <h2>Welcome back, {{ session.username }}!</h2>
        <p style="margin: 1rem 0;">Ready to manage your files?</p>
        <a href="{{ url_for('files') }}" class="btn">Go to My Files</a>
    {% else %}
        <p style="margin-bottom: 2rem; font-size: 1.1rem;">
            Get started with secure file storage today. Upload, organize, and access your files from anywhere.
        </p>
        <div style="display: flex; gap: 1rem;">
            <a href="{{ url_for('login') }}" class="btn">Get Started</a>
            <a href="{{ url_for('about') }}" class="btn btn-secondary">Learn More</a>
        </div>
    {% endif %}
</div>

<div class="card">
    <h2 style="margin-bottom: 1rem;">Why Choose {{ config.site_name }}?</h2>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem;">
        <div>
            <h3 style="color: {{ config.primary_color }}; margin-bottom: 0.5rem;">🔒 Secure</h3>
            <p>Your files are protected with industry-standard security measures.</p>
        </div>
        <div>
            <h3 style="color: {{ config.primary_color }}; margin-bottom: 0.5rem;">⚡ Fast</h3>
            <p>Quick uploads and downloads with optimized performance.</p>
        </div>
        <div>
            <h3 style="color: {{ config.primary_color }}; margin-bottom: 0.5rem;">📱 Accessible</h3>
            <p>Access your files from any device, anywhere, anytime.</p>
        </div>
    </div>
</div>
{% endblock %}
"""

ABOUT_TEMPLATE = """
{% extends "base.html" %}
{% block title %}About - {{ config.site_name }}{% endblock %}
{% block content %}
<div class="card">
    <h1>{{ config.about_content.title }}</h1>
    <p style="font-size: 1.1rem; margin: 1.5rem 0;">
        {{ config.about_content.description }}
    </p>
    
    <h2 style="margin: 2rem 0 1rem 0;">Our Features</h2>
    <ul style="list-style: none; padding: 0;">
        {% for feature in config.about_content.features %}
            <li style="padding: 0.5rem 0; border-bottom: 1px solid #e5e7eb;">
                ✓ {{ feature }}
            </li>
        {% endfor %}
    </ul>
    
    <h2 style="margin: 2rem 0 1rem 0;">Our Team</h2>
    <p>{{ config.about_content.team_info }}</p>
    
    <div style="margin-top: 2rem;">
        <a href="{{ url_for('home') }}" class="btn btn-secondary">Back to Home</a>
        {% if not session.username %}
            <a href="{{ url_for('login') }}" class="btn">Get Started</a>
        {% endif %}
    </div>
</div>
{% endblock %}
"""

LOGIN_TEMPLATE = """
{% extends "base.html" %}
{% block title %}Login - {{ config.site_name }}{% endblock %}
{% block content %}
<div class="card" style="max-width: 500px; margin: 0 auto;">
    <h1>Login to {{ config.site_name }}</h1>
    
    {% if error %}
        <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    
    <form method="POST" action="{{ url_for('login') }}">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        
        <button type="submit" class="btn">Login</button>
    </form>
    
    <hr style="margin: 2rem 0;">
    
    <h2>Register New Account</h2>
    <form method="POST" action="{{ url_for('register') }}">
        <div class="form-group">
            <label for="new_username">Username:</label>
            <input type="text" id="new_username" name="username" required>
        </div>
        
        <div class="form-group">
            <label for="new_password">Password:</label>
            <input type="password" id="new_password" name="password" required>
        </div>
        
        <div class="form-group">
            <label for="confirm_password">Confirm Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>
        
        <button type="submit" class="btn btn-secondary">Register</button>
    </form>
</div>
{% endblock %}
"""

FILES_TEMPLATE = """
{% extends "base.html" %}
{% block title %}My Files - {{ config.site_name }}{% endblock %}
{% block content %}
<div class="card">
    <h1>My Files</h1>
    <p>Welcome, {{ session.username }}! Manage your files below.</p>
    
    <div class="upload-area">
        <h3>Upload New File</h3>
        <form method="POST" enctype="multipart/form-data" action="{{ url_for('upload') }}">
            <input type="file" name="file" required style="margin: 1rem 0;">
            <br>
            <button type="submit" class="btn">Upload File</button>
        </form>
        <p style="margin-top: 1rem; color: #6b7280; font-size: 0.9rem;">
            Allowed formats: {{ allowed_extensions | join(', ') }}<br>
            Maximum file size: {{ max_size_mb }}MB
        </p>
    </div>
    
    {% if files %}
        <h2>Your Files ({{ files|length }} files)</h2>
        <div class="file-grid">
            {% for file in files %}
                <div class="file-item">
                    <h4 title="{{ file.name }}">
                        {% set max_length = 20 %}
                        {% if file.name|length > max_length %}
                            {{ file.name[:max_length//2] }}...{{ file.name[-(max_length//2):] }}
                        {% else %}
                            {{ file.name }}
                        {% endif %}
                    </h4>
                    <p style="color: #6b7280; font-size: 0.9rem;">
                        Size: {{ file.size }}<br>
                        Modified: {{ file.modified }}
                    </p>
                    <div style="margin-top: 1rem;">
                        <a href="{{ url_for('download', filename=file.name) }}" class="btn" style="font-size: 0.9rem; padding: 0.5rem 1rem;">Download</a>
                        <a href="{{ url_for('delete', filename=file.name) }}" class="btn btn-secondary" style="font-size: 0.9rem; padding: 0.5rem 1rem;" onclick="return confirm('Are you sure you want to delete this file?')">Delete</a>
                    </div>
                </div>
            {% endfor %}
        </div>
    {% else %}
        <div class="card">
            <h3>No files uploaded yet</h3>
            <p>Upload your first file using the form above!</p>
        </div>
    {% endif %}
</div>
{% endblock %}
"""

# ============================================================================
# ROUTES
# ============================================================================
@app.before_request
def check_valid_user():
    if 'username' in session:
        users = load_users()
        if session['username'] not in users:
            # User was deleted but still has active session
            session.clear()
            active_sessions.pop(session.get('username'), None)
            flash('Your account has been removed')
            return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template_string(HOME_TEMPLATE, config=SITE_CONFIG)

@app.route('/about')
def about():
    return render_template_string(ABOUT_TEMPLATE, config=SITE_CONFIG)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        if username in users and verify_password(password, users[username]):
            session['username'] = username
            flash(f'Welcome back, {username}!')
            return redirect(url_for('files'))
        else:
            return render_template_string(LOGIN_TEMPLATE, config=SITE_CONFIG, error='Invalid username or password')
    
    return render_template_string(LOGIN_TEMPLATE, config=SITE_CONFIG)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    
    if password != confirm_password:
        return render_template_string(LOGIN_TEMPLATE, config=SITE_CONFIG, error='Passwords do not match')
    
    users = load_users()
    if username in users:
        return render_template_string(LOGIN_TEMPLATE, config=SITE_CONFIG, error='Username already exists')
    
    save_user(username, password)
    session['username'] = username
    flash(f'Account created successfully! Welcome, {username}!')
    return redirect(url_for('files'))

@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        active_sessions.pop(username, None)  # Remove from active sessions
        session.clear()  # Clear all session data
    
    # Clear the session cookie
    response = make_response(redirect(url_for('home')))
    response.set_cookie('session', '', expires=0)
    
    # Add security headers
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    
    return response

@app.route('/files')
@login_required

def files():
    user_folder = get_user_folder(session['username'])
    files = []
    
    for filename in os.listdir(user_folder):
        filepath = os.path.join(user_folder, filename)
        if os.path.isfile(filepath):
            stat = os.stat(filepath)
            files.append({
                'name': filename,
                'size': f"{stat.st_size / 1024:.1f} KB" if stat.st_size < 1024*1024 else f"{stat.st_size / (1024*1024):.1f} MB",
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            })
    
    files.sort(key=lambda x: x['name'])
    
    return render_template_string(FILES_TEMPLATE, 
                                config=SITE_CONFIG, 
                                files=files,
                                allowed_extensions=ALLOWED_EXTENSIONS,
                                max_size_mb=MAX_FILE_SIZE // (1024*1024))


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('files'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('files'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_folder = get_user_folder(session['username'])
        filepath = os.path.join(user_folder, filename)
        
        # Check if file already exists
        counter = 1
        name, ext = os.path.splitext(filename)
        while os.path.exists(filepath):
            filename = f"{name}_{counter}{ext}"
            filepath = os.path.join(user_folder, filename)
            counter += 1
        
        file.save(filepath)
        flash(f'File "{filename}" uploaded successfully!')
    else:
        flash('File type not allowed')
    
    return redirect(url_for('files'))

@app.route('/download/<filename>')
@login_required
def download(filename):
    user_folder = get_user_folder(session['username'])
    filepath = os.path.join(user_folder, filename)
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        abort(404)

@app.route('/delete/<filename>')
@login_required
def delete(filename):
    user_folder = get_user_folder(session['username'])
    filepath = os.path.join(user_folder, filename)
    
    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f'File "{filename}" deleted successfully!')
    else:
        flash('File not found')
    
    return redirect(url_for('files'))

@app.route('/ping', methods=['POST'])
def ping():
    """Endpoint for the client to ping periodically"""
    if 'username' in session:
        active_sessions[session['username']] = time.time()
        return jsonify({'status': 'active'})
    return jsonify({'status': 'inactive'}), 401

@app.route('/check_activity')
def check_activity():
    """Endpoint to check if user is still active"""
    if 'username' not in session:
        return jsonify({'active': False})
    
    username = session['username']
    last_seen = active_sessions.get(username, 0)
    
    # Consider inactive if no ping in last 30 seconds
    if time.time() - last_seen > 30:
        session.clear()
        active_sessions.pop(username, None)
        return jsonify({'active': False})
    
    return jsonify({'active': True})
# ============================================================================
# TEMPLATE LOADER
# ============================================================================

@app.context_processor
def inject_template_vars():
    return {
        'BASE_TEMPLATE': BASE_TEMPLATE
    }

# Make base template available
app.jinja_env.globals['BASE_TEMPLATE'] = BASE_TEMPLATE

# Custom template loader to handle template inheritance
class StringTemplateLoader:
    def __init__(self):
        self.templates = {
            'base.html': BASE_TEMPLATE
        }
    
    def get_source(self, environment, template):
        if template in self.templates:
            source = self.templates[template]
            return source, None, lambda: True
        raise FileNotFoundError(f"Template {template} not found")

# Set up custom template loader
from jinja2 import BaseLoader
class StringLoader(BaseLoader):
    def get_source(self, environment, template):
        if template == 'base.html':
            return BASE_TEMPLATE, None, lambda: True
        raise FileNotFoundError(f"Template {template} not found")

app.jinja_loader = StringLoader()

# ============================================================================
# MAIN APPLICATION
# ============================================================================

if __name__ == '__main__':
    print(f"\n{'='*60}")
    print(f"🚀 Starting {SITE_CONFIG['site_name']} Server")
    print(f"{'='*60}")
    print(f"📊 Server URL: http://{HOST}:{PORT}")
    print(f"🔐 Password hashing: {'✅ Enabled' if HASH_PASSWORDS else '❌ Disabled'}")
    print(f"📁 Max file size: {MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"📂 Allowed extensions: {', '.join(list(ALLOWED_EXTENSIONS)[:5])}...")
    print(f"{'='*60}")
    print(f"💡 Press Ctrl+C to stop the server")
    print(f"{'='*60}\n")
# Use Waitress for production serving
    serve(app, host=HOST, port=PORT, threads=4)