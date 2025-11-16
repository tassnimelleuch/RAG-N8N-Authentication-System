from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from models import db
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import random
import requests

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Global variables to track login attempts for demo purposes
login_attempts = {}
user_sessions = {}

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
    n8n_webhook_url = "https://tasnimelleuch.app.n8n.cloud/webhook-test/5321effb-5a87-4470-8574-b78e8881f8f4"
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
        
        # Track in global dictionary for demo
        if username:
            if username not in login_attempts:
                login_attempts[username] = []
            login_attempts[username].append(datetime.utcnow())
            # Clean old attempts (older than 5 minutes)
            login_attempts[username] = [t for t in login_attempts[username] if datetime.utcnow() - t < timedelta(minutes=5)]
    else:
        fail_count = previous_fail_count
    
    # Count distinct IPs for this user in last hour
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    distinct_ips = len(db.auth_events.distinct('ip', {
        'user_id': user_id,
        'timestamp': {'$gte': one_hour_ago}
    }))
    
    # Simulate different scenarios for demo
    scenarios = [
        {"geo_velocity": "low", "distinct_ips": max(1, distinct_ips), "fail_count": fail_count},
        {"geo_velocity": "high", "distinct_ips": max(3, distinct_ips), "fail_count": fail_count},
        {"geo_velocity": "high", "distinct_ips": max(1, distinct_ips), "fail_count": max(5, fail_count)},
        {"geo_velocity": "low", "distinct_ips": max(5, distinct_ips), "fail_count": max(1, fail_count)}
    ]
    
    # Pick a random scenario to generate different attack patterns
    scenario = random.choice(scenarios)
    
    # Add suspicious patterns based on behavior
    suspicious_patterns = ["none"]
    if fail_count >= 3:
        suspicious_patterns = ["rapid_failures", "possible_brute_force"]
    if scenario['distinct_ips'] >= 3:
        suspicious_patterns = ["multiple_ips", "possible_credential_stuffing"]
    if scenario['geo_velocity'] == "high":
        suspicious_patterns = ["high_geo_velocity", "impossible_travel"]
    
    print(f"🔢 DEBUG: user_id={user_id}, event_type={event_type}, outcome={outcome}, fail_count={fail_count}, distinct_ips={scenario['distinct_ips']}, geo_velocity={scenario['geo_velocity']}")
    
    return {
        "fail_count_5min": fail_count,
        "distinct_ips": scenario['distinct_ips'],
        "geo_velocity": scenario['geo_velocity'],
        "suspicious_patterns": suspicious_patterns,
        "label": "suspicious" if any(p != "none" for p in suspicious_patterns) else "normal"
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
            
            # TRIGGER N8N for successful login
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
            
            # Calculate features BEFORE logging (this is crucial!)
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
            
            # TRIGGER N8N for failed login
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
    
    return render_template('dashboard.html', username=session['username'])

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
    """API endpoint to get authentication events (for future RAG integration)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    events = list(db.auth_events.find({'user_id': session['user_id']}).sort('timestamp', -1).limit(10))
    
    # Convert ObjectId to string for JSON serialization
    for event in events:
        event['_id'] = str(event['_id'])
        event['timestamp'] = event['timestamp'].isoformat()
    
    return jsonify(events)

# NEW ROUTES FOR TESTING DIFFERENT ATTACK SCENARIOS
@app.route('/test/brute-force')
def test_brute_force():
    """Simulate brute force attack - multiple rapid failures from same IP"""
    user_doc = db.users.find_one({})
    if not user_doc:
        return "No users found. Please register first."
    
    user_id = str(user_doc['_id'])
    username = user_doc['username']
    
    for i in range(5):
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
    
    return "Brute force test data generated! Check MongoDB and N8N."

@app.route('/test/credential-stuffing')
def test_credential_stuffing():
    """Simulate credential stuffing - single failures from multiple IPs"""
    user_doc = db.users.find_one({})
    if not user_doc:
        return "No users found. Please register first."
    
    user_id = str(user_doc['_id'])
    username = user_doc['username']
    
    ips = ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4']
    
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
    
    return "Credential stuffing test data generated! Check MongoDB and N8N."

@app.route('/test/account-takeover')
def test_account_takeover():
    """Simulate account takeover - successful login with high geo velocity"""
    user_doc = db.users.find_one({})
    if not user_doc:
        return "No users found. Please register first."
    
    user_id = str(user_doc['_id'])
    
    extra_features = {
        "fail_count_5min": 0,
        "distinct_ips": 1,
        "geo_velocity": "high",  # High geo velocity
        "suspicious_patterns": ["impossible_travel", "account_takeover"],
        "label": "suspicious"
    }
    
    db.log_auth_event(
        user_id=user_id,
        ip='93.184.216.34',  # Different country
        device_info=get_device_info(),
        event_type='login',
        outcome='success',  # Successful but suspicious
        extra_features=extra_features
    )
    
    # Send to N8N
    send_to_n8n_webhook(
        user_id=user_id,
        event_type='login',
        outcome='success',
        ip='93.184.216.34',
        extra_features=extra_features
    )
    
    return "Account takeover test data generated! Check MongoDB and N8N."

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
        {'ip': '8.8.8.8', 'geo': 'US'},
        {'ip': '1.1.1.1', 'geo': 'AU'},
        {'ip': '9.9.9.9', 'geo': 'DE'}
    ]
    
    for loc in locations:
        extra_features = {
            "fail_count_5min": 1,
            "distinct_ips": 3,
            "geo_velocity": "high",
            "suspicious_patterns": ["multi_geo", "impossible_travel"],
            "label": "suspicious"
        }
        
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
    
    return "Multi-geo anomalies test data generated! Check MongoDB and N8N."

@app.route('/n8n-status')
def n8n_status():
    """Check if N8N is running"""
    try:
        response = requests.get('http://localhost:5678/healthz', timeout=5)
        return f"✅ N8N is running - Status: {response.status_code}"
    except Exception as e:
        return f"❌ N8N is not running - Error: {e}"

if __name__ == '__main__':
    app.run(debug=True, port=5000)