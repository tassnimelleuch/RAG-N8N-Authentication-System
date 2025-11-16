# test_brute_force.py
import json

def test_all_brute_force():
    # Vos logs de test
    logs = [
        {
            "id": 1, "user_id": 101, "timestamp": "2025-10-14T10:00:00Z",
            "ip": "192.168.1.100", "event_type": "login", "outcome": "success"
        },
        {
            "id": 2, "user_id": 101, "timestamp": "2025-10-14T10:01:15Z", 
            "ip": "192.168.1.100", "event_type": "login", "outcome": "failed"
        },
        {
            "id": 3, "user_id": 101, "timestamp": "2025-10-14T10:01:20Z",
            "ip": "192.168.1.100", "event_type": "login", "outcome": "failed"
        }
    ]
    
    # Import après avoir défini les logs
    from rag_pipeline import detect_attack_type
    
    for i, log in enumerate(logs):
        print(f"\n--- Testing Log {i+1} ---")
        result, patterns = detect_attack_type(log)
        print(f"Result: {result}")

if __name__ == "__main__":
    test_all_brute_force()