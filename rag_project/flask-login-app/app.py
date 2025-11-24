from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import random
import requests

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

class MongoDB:
    def __init__(self):
        self.client = MongoClient(os.getenv('MONGO_URI'))
        self.db = self.client['auth_system']
        self.users = self.db['users']
        self.auth_events = self.db['auth_events']
    
    def create_user(self, username, email, password):
        """Create a new user with hashed password"""
        if self.users.find_one({'$or': [{'username': username}, {'email': email}]}):
            return None
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow(),
            'last_login': None
        }
        
        result = self.users.insert_one(user)
        return str(result.inserted_id)
    
    def verify_user(self, username, password):
        """Verify user credentials"""
        user = self.users.find_one({'username': username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return user
        return None
    
    def log_auth_event(self, user_id, ip, device_info, event_type, outcome, extra_features):
        """Log authentication events for RAG model training"""
        event = {
            'user_id': user_id,
            'timestamp': datetime.utcnow(),
            'ip': ip,
            'device_info': device_info,
            'event_type': event_type,
            'outcome': outcome,
            'extra_features': extra_features
        }
        
        return self.auth_events.insert_one(event)
    
    def update_last_login(self, user_id):
        """Update user's last login timestamp"""
        self.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'last_login': datetime.utcnow()}}
        )

db = MongoDB()

# Global variables to track login attempts for demo purposes
login_attempts = {}

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

def get_device_info():
    """Extract device information from user agent"""
    user_agent = request.headers.get('User-Agent', '')
    if 'Mobile' in user_agent:
        if 'Android' in user_agent:
            return "Android - Mobile Browser"
        elif 'iPhone' in user_agent:
            return "iOS - Mobile Browser"
    elif 'Windows' in user_agent:
        return "Windows - Desktop Browser"
    elif 'Mac' in user_agent:
        return "Mac - Desktop Browser"
    return "Unknown Device"

def send_to_n8n_webhook(user_id, event_type, outcome, ip, extra_features):
    """Send login event to N8N webhook for analysis"""
    n8n_webhook_url = "http://localhost:5678/webhook-test/dee866a3-70c8-4a5f-8891-43e3212ca141"
    payload = {
        "user_id": user_id,
        "event_type": event_type,
        "outcome": outcome,
        "ip": ip,
        "extra_features": extra_features,
        "timestamp": datetime.utcnow().isoformat(),
        "device_info": get_device_info()
    }
    
    try:
        response = requests.post(n8n_webhook_url, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"✅ Sent to N8N: {event_type} - {outcome}")
        else:
            print(f"⚠️ N8N response: {response.status_code}")
    except Exception as e:
        print(f"❌ N8N webhook failed: {e}")

def calculate_extra_features(user_id, event_type, outcome, username=None):
    """Calculate REAL extra features for RAG model training"""
    
    # Count actual failures in last 5 minutes for this user
    five_min_ago = datetime.utcnow() - timedelta(minutes=5)
    
    # Count previous failures in the last 5 minutes
    previous_fail_count = db.auth_events.count_documents({
        'user_id': user_id,
        'event_type': 'login',
        'outcome': 'failed',
        'timestamp': {'$gte': five_min_ago}
    })
    
    # If this is a failed login, add 1 to include the current attempt
    if event_type == 'login' and outcome == 'failed':
        fail_count = previous_fail_count + 1
    else:
        fail_count = previous_fail_count
    
    # Count distinct IPs for this user in last hour
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    distinct_ips = len(db.auth_events.distinct('ip', {
        'user_id': user_id,
        'timestamp': {'$gte': one_hour_ago}
    }))
    
    # Calculate attempts per minute based on recent activity
    recent_attempts = list(db.auth_events.find({
        'user_id': user_id,
        'timestamp': {'$gte': five_min_ago}
    }).sort('timestamp', 1))
    
    attempts_per_minute = 0
    if len(recent_attempts) > 1:
        time_span = (recent_attempts[-1]['timestamp'] - recent_attempts[0]['timestamp']).total_seconds() / 60
        if time_span > 0:
            attempts_per_minute = len(recent_attempts) / time_span
    
    # Determine geo_velocity based on IP diversity and timing
    if distinct_ips >= 3 and attempts_per_minute > 10:
        geo_velocity = "high"
    elif distinct_ips >= 2:
        geo_velocity = "medium"
    else:
        geo_velocity = "low"
    
    # Determine suspicious patterns
    suspicious_patterns = []
    
    if fail_count >= 5:
        suspicious_patterns.extend(["high_failure_rate", "possible_brute_force"])
    elif fail_count >= 2:
        suspicious_patterns.append("multiple_failures")
    
    if distinct_ips >= 3:
        suspicious_patterns.extend(["multiple_ips", "possible_credential_stuffing"])
    elif distinct_ips >= 2:
        suspicious_patterns.append("ip_diversity")
    
    if attempts_per_minute > 20:
        suspicious_patterns.extend(["rapid_attempts", "automated_behavior"])
    elif attempts_per_minute > 10:
        suspicious_patterns.append("elevated_frequency")
    
    if geo_velocity == "high":
        suspicious_patterns.extend(["high_geo_velocity", "suspicious_travel"])
    
    if not suspicious_patterns:
        suspicious_patterns = ["normal_behavior"]
    
    # Determine label based on patterns
    if any(pattern in suspicious_patterns for pattern in ["brute_force", "credential_stuffing", "high_geo_velocity"]):
        label = "suspicious"
    elif any(pattern in suspicious_patterns for pattern in ["multiple_failures", "ip_diversity"]):
        label = "suspicious_low"
    else:
        label = "normal"
    
    print(f"🔢 DEBUG: user_id={user_id}, fail_count={fail_count}, distinct_ips={distinct_ips}, attempts_per_min={attempts_per_minute:.1f}, geo_velocity={geo_velocity}")
    
    return {
        "fail_count_5min": fail_count,
        "distinct_ips": distinct_ips,
        "geo_velocity": geo_velocity,
        "attempts_per_minute": round(attempts_per_minute, 1),
        "suspicious_patterns": suspicious_patterns,
        "label": label
    }

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')
        
        user_id = db.create_user(username, email, password)
        if user_id:
            # Log registration event
            extra_features = calculate_extra_features(user_id, 'registration', 'success', username)
            db.log_auth_event(
                user_id=user_id,
                ip=get_client_ip(),
                device_info=get_device_info(),
                event_type='registration',
                outcome='success',
                extra_features=extra_features
            )
            
            # Send to N8N for monitoring
            send_to_n8n_webhook(
                user_id=user_id,
                event_type='registration',
                outcome='success',
                ip=get_client_ip(),
                extra_features=extra_features
            )
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username or email already exists!', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = db.verify_user(username, password)
        if user:
            # Calculate features BEFORE logging
            extra_features = calculate_extra_features(str(user['_id']), 'login', 'success', username)
            
            # Log successful login
            db.log_auth_event(
                user_id=str(user['_id']),
                ip=get_client_ip(),
                device_info=get_device_info(),
                event_type='login',
                outcome='success',
                extra_features=extra_features
            )
            
            # Send to N8N
            send_to_n8n_webhook(
                user_id=str(user['_id']),
                event_type='login',
                outcome='success',
                ip=get_client_ip(),
                extra_features=extra_features
            )
            
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            db.update_last_login(str(user['_id']))
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Find the user to get user_id even for failed attempts
            user_doc = db.users.find_one({'username': username})
            user_id = str(user_doc['_id']) if user_doc else 'unknown'
            
            # Calculate features BEFORE logging
            extra_features = calculate_extra_features(user_id, 'login', 'failed', username)
            
            # Log failed login attempt
            db.log_auth_event(
                user_id=user_id,
                ip=get_client_ip(),
                device_info=get_device_info(),
                event_type='login',
                outcome='failed',
                extra_features=extra_features
            )
            
            # Send to N8N
            send_to_n8n_webhook(
                user_id=user_id,
                event_type='login', 
                outcome='failed',
                ip=get_client_ip(),
                extra_features=extra_features
            )
            
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user's recent events
    user_events = list(db.auth_events.find(
        {'user_id': session['user_id']}
    ).sort('timestamp', -1).limit(10))
    
    # Convert for display
    for event in user_events:
        event['_id'] = str(event['_id'])
        event['timestamp'] = event['timestamp'].isoformat()
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         events=user_events)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Log logout event
        extra_features = calculate_extra_features(session['user_id'], 'logout', 'success')
        db.log_auth_event(
            user_id=session['user_id'],
            ip=get_client_ip(),
            device_info=get_device_info(),
            event_type='logout',
            outcome='success',
            extra_features=extra_features
        )
        
        # Send to N8N
        send_to_n8n_webhook(
            user_id=session['user_id'],
            event_type='logout',
            outcome='success',
            ip=get_client_ip(),
            extra_features=extra_features
        )
    
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

@app.route('/api/auth-events')
def get_auth_events():
    """API endpoint to get authentication events"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    events = list(db.auth_events.find({'user_id': session['user_id']}).sort('timestamp', -1).limit(10))
    
    # Convert ObjectId to string for JSON serialization
    for event in events:
        event['_id'] = str(event['_id'])
        event['timestamp'] = event['timestamp'].isoformat()
    
    return jsonify(events)

# TEST ROUTES FOR GENERATING ATTACK PATTERNS
@app.route('/test/brute-force')
def test_brute_force():
    """Simulate brute force attack - multiple rapid failures from same IP"""
    user_doc = db.users.find_one({})
    if not user_doc:
        return "No users found. Please register first."
    
    user_id = str(user_doc['_id'])
    username = user_doc['username']
    
    for i in range(8):
        extra_features = calculate_extra_features(user_id, 'login', 'failed', username)
        db.log_auth_event(
            user_id=user_id,
            ip='192.168.1.100',  # Same IP
            device_info=get_device_info(),
            event_type='login',
            outcome='failed',
            extra_features=extra_features
        )
        
        # Send each failed attempt to N8N
        send_to_n8n_webhook(
            user_id=user_id,
            event_type='login',
            outcome='failed',
            ip='192.168.1.100',
            extra_features=extra_features
        )
    
    return "Brute force test data generated! Check MongoDB."

@app.route('/test/credential-stuffing')
def test_credential_stuffing():
    """Simulate credential stuffing - failures from multiple IPs"""
    user_doc = db.users.find_one({})
    if not user_doc:
        return "No users found. Please register first."
    
    user_id = str(user_doc['_id'])
    username = user_doc['username']
    
    ips = ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4', '203.0.113.5']
    
    for ip in ips:
        extra_features = calculate_extra_features(user_id, 'login', 'failed', username)
        db.log_auth_event(
            user_id=user_id,
            ip=ip,  # Different IPs
            device_info=get_device_info(),
            event_type='login',
            outcome='failed',
            extra_features=extra_features
        )
        
        # Send to N8N
        send_to_n8n_webhook(
            user_id=user_id,
            event_type='login',
            outcome='failed',
            ip=ip,
            extra_features=extra_features
        )
    
    return "Credential stuffing test data generated! Check MongoDB."

@app.route('/test/multi-geo')
def test_multi_geo():
    """Simulate multi-geo anomalies"""
    user_doc = db.users.find_one({})
    if not user_doc:
        return "No users found. Please register first."
    
    user_id = str(user_doc['_id'])
    username = user_doc['username']
    
    # Logins from different countries in short time
    locations = [
        {'ip': '8.8.8.8', 'country': 'US'},
        {'ip': '1.1.1.1', 'country': 'AU'}, 
        {'ip': '9.9.9.9', 'country': 'DE'},
        {'ip': '5.5.5.5', 'country': 'FR'}
    ]
    
    for loc in locations:
        extra_features = calculate_extra_features(user_id, 'login', 'failed', username)
        db.log_auth_event(
            user_id=user_id,
            ip=loc['ip'],
            device_info=get_device_info(),
            event_type='login',
            outcome='failed',
            extra_features=extra_features
        )
        
        # Send to N8N
        send_to_n8n_webhook(
            user_id=user_id,
            event_type='login',
            outcome='failed',
            ip=loc['ip'],
            extra_features=extra_features
        )
    
    return "Multi-geo anomalies test data generated! Check MongoDB."


if __name__ == '__main__':
    app.run(debug=True, port=5000)