# test_all_attacks.py
from rag_pipeline import test_security_event
import json
import os
import glob

def test_all_json_files():
    """Test ALL JSON files in the current directory"""
    print("🎯 UNIVERSAL SECURITY ATTACK TESTER")
    print("=" * 50)
    
    # Find all JSON files
    json_files = glob.glob("*.json")
    
    if not json_files:
        print("❌ No JSON files found in current directory!")
        return
    
    print(f"📁 Found {len(json_files)} JSON files to test:")
    for file in json_files:
        print(f"   • {file}")
    
    print("\n" + "=" * 50)
    
    for json_file in json_files:
        print(f"\n🔍 TESTING FILE: {json_file}")
        print("-" * 40)
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Handle both single event and multiple events
            if isinstance(data, dict):
                # Single event
                if 'features' in data:
                    # Direct event
                    test_single_event(data, json_file)
                else:
                    # Multiple events in one file (like our multi_geo_attacks.json)
                    test_multiple_events(data, json_file)
            elif isinstance(data, list):
                # List of events
                for i, event in enumerate(data):
                    print(f"\n📊 Event {i+1} from {json_file}:")
                    test_single_event(event, f"{json_file}_event_{i+1}")
            
        except Exception as e:
            print(f"❌ Error processing {json_file}: {e}")

def test_multiple_events(events_dict, filename):
    """Test multiple events from a dictionary"""
    for attack_type, event_data in events_dict.items():
        print(f"\n💥 Testing: {attack_type.upper()}")
        print("-" * 30)
        test_single_event(event_data, f"{filename}_{attack_type}")

def test_single_event(event_data, source):
    """Test a single security event"""
    try:
        # Extract key features for display
        features = event_data.get('features', {})
        
        print(f"📊 Event Analysis:")
        print(f"   • Failures/5min: {features.get('fail_count_5min', 0)}")
        print(f"   • Distinct IPs: {features.get('distinct_ips', 1)}")
        print(f"   • Geo Velocity: {features.get('geo_velocity', 0)} km/h")
        print(f"   • Device Change: {features.get('device_change', False)}")
        print(f"   • Success Count: {features.get('success_count', 0)}")
        
        # Run RAG detection
        result = test_security_event(event_data)
        
        print("✅ Test completed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

def test_specific_attack_types():
    """Test specific attack types from our multi_geo_attacks.json"""
    print("\n🎯 TARGETED ATTACK TYPE TESTING")
    print("=" * 50)
    
    try:
        with open('multi_geo_attacks.json', 'r') as f:
            attacks = json.load(f)
        
        attack_descriptions = {
            "session_hijack": "🌍 IMPOSSIBLE TRAVEL: Paris → Tokyo in 10 minutes",
            "credential_stuffing": "🌐 DISTRIBUTED GLOBAL: Multiple countries, moderate failures",
            "account_takeover": "🎭 GEO ANOMALIES: Normal login + suspicious activity",
            "brute_force": "💥 CONCENTRATED ATTACK: High failures, single IP",
            "password_spraying": "☔ WIDESPREAD: Common passwords across accounts"
        }
        
        for attack_type, event_data in attacks.items():
            description = attack_descriptions.get(attack_type, attack_type.upper())
            print(f"\n{description}")
            print("-" * 50)
            test_single_event(event_data, attack_type)
            
    except FileNotFoundError:
        print("❌ multi_geo_attacks.json not found!")

if __name__ == "__main__":
    print("🛡️ UNIVERSAL SECURITY ATTACK DETECTION TESTER")
    print("This will test ALL JSON files and ALL attack types!")
    
    # Test all JSON files in directory
    test_all_json_files()
    
    # Test specific attack types from our multi file
    test_specific_attack_types()
    
    print("\n🎉 ALL TESTS COMPLETED! 🎉")