"""
Improved RAG Pipeline Testing on MongoDB Data
Tests attack detection on real authentication events using SecurityRAG
"""

from pymongo import MongoClient
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import time
import json

# Import your RAG pipeline
try:
    from rag_pipeline import SecurityRAG
    RAG_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Warning: Could not import rag_pipeline: {e}")
    RAG_AVAILABLE = False

load_dotenv()

class RAGMongoDBTester:
    def __init__(self):
        """Initialize MongoDB connection and RAG system"""
        try:
            # MongoDB connection
            mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
            self.client = MongoClient(mongo_uri)
            self.db = self.client['auth_system']
            self.auth_events = self.db['auth_events']
            
            # Test connection
            self.client.admin.command('ping')
            print("✅ Connected to MongoDB")
            
            # Initialize RAG system
            if RAG_AVAILABLE:
                print("🚀 Initializing SecurityRAG system...")
                self.rag = SecurityRAG()
                print("✅ SecurityRAG initialized")
            else:
                self.rag = None
                print("⚠️  RAG system not available - skipping RAG detection")
                
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            raise
    
    def convert_event_to_rag_format(self, event):
        """Convert MongoDB event to SecurityRAG expected format"""
        extra = event.get('extra_features', {})
        
        # Build features dict for RAG
        features = {
            'fail_count_5min': extra.get('fail_count_5min', 0),
            'distinct_ips': extra.get('distinct_ips', 1),
            'geo_velocity': extra.get('geo_velocity', 'low'),
            'attempts_per_minute': extra.get('attempts_per_minute', 0),
            'device_change': False,  # You can enhance this from device_info comparison
            'success_count': 1 if event.get('outcome') == 'success' else 0,
            'common_passwords_detected': False,  # Add if you track this
        }
        
        # Convert geo_velocity to numeric if it's a string
        if isinstance(features['geo_velocity'], str):
            geo_map = {'low': 0, 'medium': 500, 'high': 2000}
            features['geo_velocity'] = geo_map.get(features['geo_velocity'], 0)
        
        return {
            'event_id': str(event.get('_id')),
            'user_id': event.get('user_id'),
            'timestamp': event.get('timestamp'),
            'ip': event.get('ip'),
            'device_info': event.get('device_info'),
            'event_type': event.get('event_type'),
            'outcome': event.get('outcome'),
            'features': features,
            'suspicious_patterns': extra.get('suspicious_patterns', []),
            'pre_label': extra.get('label', 'unknown')
        }
    
    def get_events_by_time_range(self, hours=24, limit=None):
        """Get events from the last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        query = {'timestamp': {'$gte': cutoff_time}}
        cursor = self.auth_events.find(query).sort('timestamp', -1)
        if limit:
            cursor = cursor.limit(limit)
        return list(cursor)
    
    def get_suspicious_events(self, limit=20):
        """Get events that are likely suspicious based on features"""
        query = {
            '$or': [
                {'extra_features.fail_count_5min': {'$gte': 3}},
                {'extra_features.distinct_ips': {'$gte': 2}},
                {'extra_features.geo_velocity': 'high'},
                {'extra_features.label': {'$in': ['suspicious', 'suspicious_low']}},
                {'outcome': 'failed'}
            ]
        }
        return list(self.auth_events.find(query).sort('timestamp', -1).limit(limit))
    
    def test_rag_detection(self, events, rate_limit_delay=3):
        """Test RAG pipeline on a list of events"""
        
        if not self.rag:
            print("❌ RAG system not available")
            return []
        
        print(f"\n🔍 Testing SecurityRAG on {len(events)} Events")
        print("=" * 80)
        
        results = []
        
        for i, event in enumerate(events, 1):
            print(f"\n{'='*80}")
            print(f"🎯 Event {i}/{len(events)}")
            print(f"{'='*80}")
            
            # Convert to RAG format
            event_data = self.convert_event_to_rag_format(event)
            features = event_data['features']
            
            # Display event details
            print(f"👤 User ID: {event_data['user_id']}")
            print(f"📅 Timestamp: {event_data['timestamp']}")
            print(f"🌐 IP: {event_data['ip']}")
            print(f"📱 Device: {event_data['device_info']}")
            print(f"📍 Event: {event_data['event_type']} - {event_data['outcome']}")
            
            print(f"\n📊 Features for RAG:")
            print(f"   ❌ Failed Attempts (5min): {features['fail_count_5min']}")
            print(f"   🌍 Distinct IPs: {features['distinct_ips']}")
            print(f"   🚀 Geo Velocity: {features['geo_velocity']} km/h")
            print(f"   ⏱️  Attempts/min: {features['attempts_per_minute']}")
            print(f"   ✅ Success Count: {features['success_count']}")
            print(f"   🏷️  Pre-Label: {event_data['pre_label']}")
            
            if event_data['suspicious_patterns']:
                print(f"   🔍 Patterns: {', '.join(event_data['suspicious_patterns'])}")
            
            # Run RAG detection
            try:
                print(f"\n🤖 Running SecurityRAG Classification...")
                start_time = time.time()
                
                # Use the SecurityRAG classify method
                result = self.rag.classify_security_event(event_data)
                
                detection_time = time.time() - start_time
                
                print(f"\n✅ RAG Classification Complete ({detection_time:.2f}s)")
                print(f"{'─'*80}")
                print(f"🚨 RAG DETECTION RESULT:")
                print(f"{'─'*80}")
                print(result['llm_response'])
                
                # Try to parse JSON response
                try:
                    response_json = json.loads(result['llm_response'])
                    print(f"\n📊 Parsed Classification:")
                    print(f"   🎯 Label: {response_json.get('label', 'unknown')}")
                    print(f"   📈 Confidence: {response_json.get('confidence', 0):.2%}")
                    print(f"   💡 Reasoning: {response_json.get('reasoning', 'N/A')}")
                    if 'key_indicators' in response_json:
                        print(f"   🔑 Key Indicators: {', '.join(response_json['key_indicators'])}")
                except:
                    # Response wasn't JSON, that's okay
                    pass
                
                print(f"\n📚 Retrieved Patterns ({len(result['retrieved_passages'])}):")
                for idx, passage in enumerate(result['retrieved_passages'][:3], 1):
                    print(f"   {idx}. {passage['passage_id']} - {passage['tags']} (score: {passage['score']:.3f})")
                
                # Store result
                results.append({
                    'event': event_data,
                    'rag_result': result,
                    'time': detection_time
                })
                
            except Exception as e:
                print(f"❌ RAG Detection Error: {e}")
                import traceback
                traceback.print_exc()
                results.append({
                    'event': event_data,
                    'rag_result': {'error': str(e)},
                    'time': 0
                })
            
            # Rate limiting
            if i < len(events) and rate_limit_delay > 0:
                print(f"\n⏳ Rate limit delay: {rate_limit_delay}s...")
                time.sleep(rate_limit_delay)
        
        return results
    
    def analyze_results(self, results):
        """Analyze detection results and show statistics"""
        
        print(f"\n{'='*80}")
        print(f"📊 DETECTION ANALYSIS SUMMARY")
        print(f"{'='*80}")
        
        total = len(results)
        if total == 0:
            print("No results to analyze")
            return
        
        attack_types = {}
        avg_time = sum(r['time'] for r in results) / total if total > 0 else 0
        
        # Extract attack types from RAG results
        for result in results:
            if 'error' in result['rag_result']:
                attack_type = "ERROR"
            else:
                llm_response = result['rag_result'].get('llm_response', '')
                
                # Try to parse JSON
                try:
                    response_json = json.loads(llm_response)
                    attack_type = response_json.get('label', 'unknown').upper()
                except:
                    # Extract from text
                    attack_type = "UNKNOWN"
                    if 'brute_force' in llm_response.lower():
                        attack_type = "BRUTE_FORCE"
                    elif 'credential_stuffing' in llm_response.lower():
                        attack_type = "CREDENTIAL_STUFFING"
                    elif 'password_spraying' in llm_response.lower():
                        attack_type = "PASSWORD_SPRAYING"
                    elif 'session_hijack' in llm_response.lower():
                        attack_type = "SESSION_HIJACK"
                    elif 'account_takeover' in llm_response.lower():
                        attack_type = "ACCOUNT_TAKEOVER"
                    elif 'phishing' in llm_response.lower():
                        attack_type = "PHISHING"
                    elif 'normal' in llm_response.lower():
                        attack_type = "NORMAL"
            
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        print(f"\n📈 Detection Statistics:")
        print(f"   Total Events Analyzed: {total}")
        print(f"   Average Detection Time: {avg_time:.2f}s")
        
        print(f"\n🎯 Attack Types Detected:")
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            print(f"   {attack_type}: {count} ({percentage:.1f}%)")
        
        # Compare with pre-labels
        print(f"\n🏷️  Pre-Label vs RAG Detection Comparison:")
        matches = 0
        mismatches = 0
        comparisons = []
        
        for result in results:
            pre_label = result['event']['pre_label']
            
            if 'error' in result['rag_result']:
                continue
            
            llm_response = result['rag_result'].get('llm_response', '').lower()
            
            # Simple comparison
            is_normal_pre = pre_label == 'normal'
            is_normal_rag = 'normal' in llm_response and 'attack' not in llm_response
            
            if is_normal_pre == is_normal_rag:
                matches += 1
            else:
                mismatches += 1
                comparisons.append({
                    'pre': pre_label,
                    'rag': llm_response[:100]
                })
        
        if total > 0:
            agreement = (matches / total * 100) if total > 0 else 0
            print(f"   Agreement: {matches}/{total} ({agreement:.1f}%)")
            print(f"   Disagreement: {mismatches}/{total}")
        
        # Show some disagreements
        if comparisons and len(comparisons) <= 3:
            print(f"\n⚠️  Example Disagreements:")
            for comp in comparisons[:3]:
                print(f"   Pre-label: {comp['pre']} | RAG: {comp['rag'][:80]}...")

def main():
    """Main testing function"""
    
    print("🚀 SecurityRAG MongoDB Testing Suite")
    print("=" * 80)
    
    if not RAG_AVAILABLE:
        print("❌ SecurityRAG not available. Make sure rag_pipeline.py is in the same directory.")
        return
    
    tester = RAGMongoDBTester()
    
    # Test 1: Recent events
    print("\n📋 TEST 1: Recent Events (Last 24 Hours)")
    recent_events = tester.get_events_by_time_range(hours=24, limit=5)
    
    if not recent_events:
        print("❌ No recent events found. Run your Flask app and generate login data first.")
        print("\n💡 Try these URLs to generate test data:")
        print("   - http://localhost:5000/test/brute-force")
        print("   - http://localhost:5000/test/credential-stuffing")
        print("   - http://localhost:5000/test/multi-geo")
        return
    
    recent_results = tester.test_rag_detection(recent_events, rate_limit_delay=3)
    tester.analyze_results(recent_results)
    
    # Test 2: Suspicious events only
    print("\n\n📋 TEST 2: Suspicious Events Only")
    suspicious_events = tester.get_suspicious_events(limit=5)
    
    if suspicious_events:
        suspicious_results = tester.test_rag_detection(suspicious_events, rate_limit_delay=3)
        tester.analyze_results(suspicious_results)
    else:
        print("No suspicious events found.")
    
    print("\n✅ Testing Complete!")

if __name__ == "__main__":
    main()