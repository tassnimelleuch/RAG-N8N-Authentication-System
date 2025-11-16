# test_real_scenarios.py
import json
from rag_pipeline import detect_attack_type

def test_real_scenarios():
    # Charger les scénarios
    with open('test_multi.json', 'r') as f:
        scenarios = json.load(f)
    
    print("🔍 Testing Real Security Scenarios...")
    print("=" * 70)
    
    for i, event in enumerate(scenarios):
        print(f"\n🎯 Scenario {i+1} - User: {event['user_email']}")
        print(f"   IP: {event['ip']} | Outcome: {event['outcome']}")
        print(f"   Features: fails={event['extra_features']['fail_count_5min']}, "
              f"IPs={event['extra_features']['distinct_ips']}, "
              f"geo={event['extra_features']['geo_velocity']}")
        
        # Analyser avec votre pipeline RAG
        result, patterns = detect_attack_type(event)
        
        print(f"   🔍 Patterns: {len(patterns)}")
        print(f"   🎯 Result: {result}")
        print("-" * 70)

if __name__ == "__main__":
    test_real_scenarios()