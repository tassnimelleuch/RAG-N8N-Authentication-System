# rag_integration.py
from rag_pipeline import SecurityRAG
from pymongo import MongoClient
import os
from datetime import datetime, timedelta

class RAGSecurityAnalyzer:
    def __init__(self):
        self.rag = SecurityRAG()
        self.client = MongoClient(os.getenv('MONGO_URI'))
        self.db = self.client['auth_system']
        self.auth_events = self.db['auth_events']
    
    def analyze_recent_events(self, hours=24):
        """Analyze recent authentication events with RAG"""
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        events = self.auth_events.find({
            'timestamp': {'$gte': time_threshold}
        }).sort('timestamp', -1)
        
        results = []
        for event in events:
            print(f"\n🔍 Analyzing event: {event['_id']}")
            
            # Convert MongoDB event to RAG format
            rag_event = self.convert_to_rag_format(event)
            
            # Analyze with RAG
            try:
                rag_result = self.rag.classify_security_event(rag_event)
                results.append({
                    'event_id': str(event['_id']),
                    'timestamp': event['timestamp'],
                    'user_id': event['user_id'],
                    'event_type': event['event_type'],
                    'outcome': event['outcome'],
                    'rag_classification': rag_result,
                    'ip': event.get('ip'),
                    'original_event': event
                })
                
                # Update MongoDB with RAG results
                self.auth_events.update_one(
                    {'_id': event['_id']},
                    {'$set': {'rag_analysis': rag_result}}
                )
                
            except Exception as e:
                print(f"❌ RAG analysis failed for event {event['_id']}: {e}")
        
        return results
    
    def convert_to_rag_format(self, mongodb_event):
        """Convert MongoDB auth event to RAG input format"""
        extra_features = mongodb_event.get('extra_features', {})
        
        return {
            "id": str(mongodb_event['_id']),
            "user_id": mongodb_event['user_id'],
            "features": {
                "fail_count_5min": extra_features.get('fail_count_5min', 0),
                "distinct_ips": extra_features.get('distinct_ips', 1),
                "geo_velocity": 8500 if extra_features.get('geo_velocity') == 'high' else 0,
                "device_change": 'new_device' in extra_features.get('suspicious_patterns', []),
                "success_count": 1 if mongodb_event['outcome'] == 'success' else 0,
                "attempts_per_minute": extra_features.get('fail_count_5min', 0) / 5  # Estimate
            },
            "recent_events": [{
                "timestamp": mongodb_event['timestamp'].isoformat(),
                "outcome": mongodb_event['outcome'],
                "ip": mongodb_event.get('ip'),
                "device": mongodb_event.get('device_info')
            }],
            "label": "unknown"
        }
    
    def real_time_analysis(self, new_event):
        """Analyze a single new event in real-time"""
        print(f"🚨 REAL-TIME ANALYSIS for new event: {new_event['_id']}")
        
        rag_event = self.convert_to_rag_format(new_event)
        rag_result = self.rag.classify_security_event(rag_event)
        
        # Store results
        self.auth_events.update_one(
            {'_id': new_event['_id']},
            {'$set': {'rag_analysis': rag_result}}
        )
        
        return rag_result
    
    def generate_security_report(self, hours=24):
        """Generate a comprehensive security report"""
        results = self.analyze_recent_events(hours)
        
        attack_counts = {}
        for result in results:
            label = self.extract_label(result['rag_classification']['llm_response'])
            attack_counts[label] = attack_counts.get(label, 0) + 1
        
        print("\n📊 SECURITY REPORT:")
        print("=" * 50)
        for attack_type, count in attack_counts.items():
            print(f"🔍 {attack_type.upper()}: {count} events")
        
        return attack_counts
    
    def extract_label(self, llm_response):
        """Extract classification label from LLM response"""
        import re
        label_match = re.search(r'"label":\s*"([^"]+)"', llm_response)
        return label_match.group(1) if label_match else "unknown"

# Test the integration
if __name__ == "__main__":
    analyzer = RAGSecurityAnalyzer()
    
    print("🔄 Analyzing recent authentication events...")
    results = analyzer.analyze_recent_events(hours=1)  # Last hour
    
    print(f"\n✅ Analyzed {len(results)} events")
    analyzer.generate_security_report(hours=1)