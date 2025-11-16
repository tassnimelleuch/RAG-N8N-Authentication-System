from pymongo import MongoClient
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

client = MongoClient('mongodb://localhost:27017/')
db = client['security_db']
login_events = db['login_events']

def analyze_user_behavior(username):
    last_hour = datetime.now() - timedelta(hours=1)
    
    user_logins = list(login_events.find({
        "username": username,
        "timestamp": {"$gte": last_hour}
    }))
    
    total_logins = len(user_logins)
    distinct_ips = len(set(login['ip'] for login in user_logins))
    
    logger.info(f"🔍 RAG Analysis: {username} - {total_logins} logins, {distinct_ips} IPs")
    
    return {
        "username": username,
        "total_logins": total_logins,
        "distinct_ips": distinct_ips,
        "analysis_timestamp": datetime.now()
    }