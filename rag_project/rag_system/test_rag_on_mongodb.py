from pymongo import MongoClient
from rag_pipeline import detect_attack_type_improved
import json
import time

def test_rag_on_mongodb():
    client = MongoClient("mongodb://localhost:27017/auth_system")
    db = client['auth_system']
    auth_events = db['auth_events']
     
    print("🔍 Testing RAG Pipeline on MongoDB Data...")
    print("=" * 70)
    
    # Get recent authentication events
    recent_events = list(auth_events.find().sort('timestamp', -1).limit(10))
    
    if not recent_events:
        print("❌ No events found in MongoDB. Please run the Flask app and generate some login data first.")
        return
    
    print(f"📊 Found {len(recent_events)} events in MongoDB")
    print("=" * 70)
    
    for i, event in enumerate(recent_events, 1):
        print(f"\n🎯 Event {i}/{len(recent_events)}")
        print("-" * 50)
        
        # Convert MongoDB event to the format expected by your RAG pipeline
        event_data = {
            'event_type': event.get('event_type', 'login'),
            'outcome': event.get('outcome', 'unknown'),
            'ip': event.get('ip', ''),
            'extra_features': event.get('extra_features', {})
        }
        
        print(f"👤 User ID: {event.get('user_id', 'N/A')}")
        print(f"📅 Timestamp: {event.get('timestamp', 'N/A')}")
        print(f"🌐 IP: {event_data['ip']}")
        print(f"📱 Event Type: {event_data['event_type']}")
        print(f"✅ Outcome: {event_data['outcome']}")
        print(f"🔢 Fail Count: {event_data['extra_features'].get('fail_count_5min', 0)}")
        print(f"📍 Distinct IPs: {event_data['extra_features'].get('distinct_ips', 1)}")
        print(f"🚀 Geo Velocity: {event_data['extra_features'].get('geo_velocity', 'unknown')}")
        
        try:
            # Run your RAG pipeline
            print("🔄 Running RAG detection...")
            attack_result, relevant_patterns = detect_attack_type_improved(event_data)
            
            print("🔍 RAG DETECTION RESULTS:")
            print(f"📍 {attack_result}")
            
            # Extract attack type for clarity
            if "ATTACK_TYPE:" in attack_result:
                for line in attack_result.split('\n'):
                    if "ATTACK_TYPE:" in line:
                        print(f"🚨 IDENTIFIED: {line.strip()}")
                        break
            
            if relevant_patterns:
                print(f"📚 Relevant Patterns Found: {len(relevant_patterns)}")
                
        except Exception as e:
            print(f"❌ Error in RAG pipeline: {e}")
        
        # Add delay to avoid rate limits
        if i < len(recent_events):
            print("⏳ Waiting 2 seconds to avoid rate limits...")
            time.sleep(2)
        
        print("-" * 50)

def analyze_detection_accuracy():
    """Analyze how well RAG is detecting different attack patterns"""
    client = MongoClient("mongodb://localhost:27017/auth_system")
    db = client['auth_system']
    auth_events = db['auth_events']
    
    print("\n📊 RAG DETECTION ACCURACY ANALYSIS")
    print("=" * 50)
    
    # Get events that should be detected as attacks
    suspicious_events = list(auth_events.find({
        '$or': [
            {'extra_features.fail_count_5min': {'$gte': 3}},
            {'extra_features.distinct_ips': {'$gte': 3}},
            {'extra_features.geo_velocity': 'high'},
            {'outcome': 'failed'}
        ]
    }).limit(15))
    
    print(f"Analyzing {len(suspicious_events)} potentially suspicious events...")
    
    for event in suspicious_events:
        event_data = {
            'event_type': event.get('event_type', 'login'),
            'outcome': event.get('outcome', 'unknown'),
            'ip': event.get('ip', ''),
            'extra_features': event.get('extra_features', {})
        }
        
        extra = event_data['extra_features']
        expected_attack = "NORMAL"
        
        # What we expect based on rules
        if extra.get('distinct_ips', 1) > 2 and extra.get('fail_count_5min', 0) == 1:
            expected_attack = "CREDENTIAL_STUFFING"
        elif extra.get('fail_count_5min', 0) > 3 and extra.get('distinct_ips', 1) == 1:
            expected_attack = "BRUTE_FORCE"
        elif extra.get('fail_count_5min', 0) == 1 and extra.get('distinct_ips', 1) == 1:
            expected_attack = "PASSWORD_SPRAYING"
        elif extra.get('geo_velocity') == "high":
            expected_attack = "MULTI_GEO_ANOMALIES"
        elif event_data['outcome'] == "success" and extra.get('geo_velocity') == "high":
            expected_attack = "ACCOUNT_TAKEOVER"
        
        print(f"Event: {event_data['event_type']} | Expected: {expected_attack} | Failures: {extra.get('fail_count_5min', 0)} | IPs: {extra.get('distinct_ips', 1)}")

if __name__ == "__main__":
    test_rag_on_mongodb()
    analyze_detection_accuracy()