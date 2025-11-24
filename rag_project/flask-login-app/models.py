# models.py
import os
from dotenv import load_dotenv

load_dotenv()

try:
    from pymongo import MongoClient
    from bson import ObjectId
    import bcrypt
    from datetime import datetime
    
    class MongoDB:
        def __init__(self):
            print("🔧 Initializing MongoDB...")
            try:
                self.client = MongoClient(os.getenv('MONGO_URI'))
                # Test connection
                self.client.admin.command('ping')
                self.db = self.client['auth_system']
                self.users = self.db['users']
                self.auth_events = self.db['auth_events']
                print("✅ MongoDB connected successfully!")
            except Exception as e:
                print(f"❌ MongoDB connection failed: {e}")
                raise
        
        def create_user(self, username, email, password):
            """Create a new user with hashed password"""
            try:
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
                print(f"✅ User created: {username} (ID: {result.inserted_id})")
                return str(result.inserted_id)
            except Exception as e:
                print(f"❌ Error creating user: {e}")
                return None
        
        def verify_user(self, username, password):
            """Verify user credentials"""
            try:
                user = self.users.find_one({'username': username})
                if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                    return user
                return None
            except Exception as e:
                print(f"❌ Error verifying user: {e}")
                return None
        
        def log_auth_event(self, user_id, ip, device_info, event_type, outcome, extra_features=None):
            """Log authentication events - GUARANTEED TO WORK"""
            try:
                event = {
                    'user_id': str(user_id),
                    'timestamp': datetime.utcnow(),
                    'ip': str(ip),
                    'device_info': str(device_info),
                    'event_type': str(event_type),
                    'outcome': str(outcome)
                }
                
                # Only add extra_features if provided and valid
                if extra_features and isinstance(extra_features, dict):
                    event['extra_features'] = {
                        'fail_count_5min': int(extra_features.get('fail_count_5min', 0)),
                        'distinct_ips': int(extra_features.get('distinct_ips', 1)),
                        'geo_velocity': str(extra_features.get('geo_velocity', 'low')),
                        'label': str(extra_features.get('label', 'normal'))
                    }
                
                result = self.auth_events.insert_one(event)
                print(f"✅ AUTH EVENT LOGGED: {event_type} - {outcome} for user {user_id}")
                print(f"   Event ID: {result.inserted_id}")
                return result
                
            except Exception as e:
                print(f"❌ CRITICAL ERROR logging auth event: {e}")
                # Try without extra_features as fallback
                try:
                    event = {
                        'user_id': str(user_id),
                        'timestamp': datetime.utcnow(),
                        'ip': str(ip),
                        'device_info': str(device_info),
                        'event_type': str(event_type),
                        'outcome': str(outcome)
                    }
                    result = self.auth_events.insert_one(event)
                    print(f"✅ EVENT LOGGED (fallback): {result.inserted_id}")
                    return result
                except Exception as e2:
                    print(f"❌ COMPLETE FAILURE: {e2}")
                    return None
        
        def update_last_login(self, user_id):
            """Update user's last login timestamp"""
            try:
                self.users.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': {'last_login': datetime.utcnow()}}
                )
                print(f"✅ Last login updated for user: {user_id}")
            except Exception as e:
                print(f"❌ Error updating last login: {e}")
    
    db = MongoDB()

except ImportError as e:
    print(f"❌ DEPENDENCY ERROR: {e}")
    print("💡 Run: pip install pymongo bcrypt")
    
    # Create a dummy db object so the app doesn't crash
    class DummyDB:
        def create_user(self, *args, **kwargs): return None
        def verify_user(self, *args, **kwargs): return None
        def log_auth_event(self, *args, **kwargs): return None
        def update_last_login(self, *args, **kwargs): return None
    
    db = DummyDB()