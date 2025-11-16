from pymongo import MongoClient
from bson import ObjectId
import bcrypt
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

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