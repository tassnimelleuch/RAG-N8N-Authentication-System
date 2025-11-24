# generate_complete_corpus.py
import json
from pathlib import Path

def generate_complete_corpus():
    print("🎯 GENERATING COMPLETE CORPUS FOR ALL 8 ATTACK TYPES...")
    
    data_dir = Path("data")
    prompts_dir = Path("prepared/prompts")
    prompts_dir.mkdir(parents=True, exist_ok=True)
    
    # Map your files to attack types
    attack_type_mapping = {
        "account_takeover_examples.json": "account_takeover",
        "auth_logs_multi-geo_anomaly.json": "session_hijack", 
        "auth_logs_phishing_dataset.json": "phishing_attempt",
        "automated_login_flood_100.json": "credential_stuffing",
        "brute_force_100_scenarios.json": "brute_force",
        "credential_stuffing_examples.json": "credential_stuffing",
        "normal_800_scenarios.json": "normal",
        "password_spraying_100_scenarios.json": "password_spraying"
    }
    
    corpus = []
    
    for file_path in data_dir.glob("*.json"):
        attack_type = attack_type_mapping.get(file_path.name, "unknown")
        print(f"📖 Processing {file_path.name} → {attack_type.upper()}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            items = data if isinstance(data, list) else [data]
            
            for i, item in enumerate(items[:25]):  # Process 25 items per file
                features = item.get('extra_features', {})
                
                # Create attack-specific descriptions
                content = create_attack_description(attack_type, features, item)
                
                passage = {
                    "passage_id": f"{attack_type}_p{i+1:03d}",
                    "doc_id": f"{attack_type}_doc",
                    "content": content,
                    "tags": [attack_type],
                    "source_file": file_path.name,
                    "attack_type": attack_type
                }
                corpus.append(passage)
                
        except Exception as e:
            print(f"   ⚠️  Error: {e}")
    
    # Save corpus
    corpus_path = prompts_dir / "corpus_passages.json"
    with open(corpus_path, 'w', encoding='utf-8') as f:
        json.dump(corpus, f, indent=2, ensure_ascii=False)
    
    print(f"✅ COMPLETE CORPUS: {len(corpus)} passages for 8 attack types!")
    print(f"✅ Saved to: {corpus_path}")
    
    # Create proper event summaries
    create_attack_summaries(prompts_dir)
    
    return len(corpus)

def create_attack_description(attack_type, features, original_item):
    """Create precise descriptions for each attack type"""
    
    descriptions = {
        "account_takeover": """
ACCOUNT TAKEOVER: Attacker gains unauthorized access to a legitimate user's account using stolen credentials.
COMPROMISE METHOD: Credentials obtained through data breaches, phishing, or malware.
POST-COMPROMISE: Attacker changes security settings, accesses sensitive data, or performs unauthorized actions.
DETECTION: Unusual login locations, password/email changes, unfamiliar devices, abnormal activity patterns.
        """,
        
        "session_hijack": """
SESSION HIJACKING: Attacker steals active user session tokens to impersonate legitimate users.
METHODS: Cross-site scripting, man-in-the-middle attacks, session sidejacking, or malware.
EVIDENCE: Concurrent sessions, impossible travel between geographic locations, session token reuse.
IMPACT: Unauthorized access without needing login credentials, bypassing authentication.
        """,
        
        "phishing_attempt": """
PHISHING ATTEMPT: Login attempts following user exposure to phishing campaigns.
ORIGIN: Known malicious IP ranges, suspicious domains, infrastructure linked to phishing operations.
PATTERN: Successful logins shortly after phishing email delivery to target users.
INDICATORS: New device usage, password reset requests, access from blacklisted IP ranges.
        """,
        
        "credential_stuffing": """
CREDENTIAL STUFFING: Automated testing of username/password pairs from previous data breaches.
SCALE: Testing thousands of known compromised credentials across multiple services.
PATTERN: Distributed login attempts from multiple IP addresses with moderate failure rates.
DEFENSE: Multi-factor authentication, breached password detection, rate limiting.
        """,
        
        "brute_force": """
BRUTE FORCE ATTACK: Systematic password guessing against specific target accounts.
INTENSITY: High-frequency attempts using password dictionaries, common patterns, and incremental changes.
FOCUS: Concentrated attacks on individual accounts or high-value targets.
PREVENTION: Account lockouts, CAPTCHA challenges, progressive delays, suspicious login detection.
        """,
        
        "password_spraying": """
PASSWORD SPRAYING: Attackers try a few common passwords across many user accounts.
STRATEGY: Using passwords like 'Winter2024!', 'Company123!', 'Password123' organization-wide.
STEALTH: Low failure rate per account to avoid detection, but widespread across user base.
RISK: High success probability if any user employs weak or common passwords.
        """,
        
        "normal": """
NORMAL BEHAVIOR: Standard authentication patterns consistent with established user profiles.
CHARACTERISTICS: Familiar devices, expected geographic locations, typical access times.
BASELINE: Consistent login success/failure rates matching historical user behavior.
SECURITY: No anomalies detected - aligns with regular access patterns and organizational policies.
        """
    }
    
    base_desc = descriptions.get(attack_type, "Security event requiring analysis based on observed authentication patterns.")
    feature_analysis = analyze_attack_features(attack_type, features)
    
    return f"ATTACK TYPE: {attack_type.upper()}\n\n{base_desc}\n\nDETECTION SIGNALS: {feature_analysis}"

def analyze_attack_features(attack_type, features):
    """Generate specific feature analysis for each attack type"""
    
    analysis = {
        "account_takeover": [
            f"Distinct IPs: {features.get('distinct_ips', 0)}",
            f"Geo velocity: {features.get('geo_velocity_kmh', 0)} km/h",
            f"Device changes: {features.get('unusual_device', 0)}",
            "Multiple security setting modifications",
            "Unusual resource access patterns"
        ],
        
        "session_hijack": [
            f"Geo velocity: {features.get('geo_velocity_kmh', 0)} km/h",
            f"Distinct IPs: {features.get('distinct_ips', 0)}", 
            "Concurrent active sessions",
            "Session token anomalies",
            "Impossible travel timelines"
        ],
        
        "phishing_attempt": [
            f"Fail count: {features.get('fail_count_5min', 0)}",
            "Known malicious IP ranges",
            "New device registration",
            "Suspicious user-agent patterns",
            "Correlation with phishing email delivery"
        ],
        
        "credential_stuffing": [
            f"Fail count: {features.get('fail_count_5min', 0)}",
            f"Distinct IPs: {features.get('distinct_ips', 0)}",
            "Moderate failure rates across multiple accounts",
            "Known breached credential patterns",
            "Distributed botnet behavior"
        ],
        
        "brute_force": [
            f"Fail count: {features.get('fail_count_5min', 0)}",
            f"Distinct IPs: {features.get('distinct_ips', 0)}",
            "High-frequency targeted attempts",
            "Password dictionary patterns",
            "Concentrated attack on specific accounts"
        ],
        
        "password_spraying": [
            f"Fail count: {features.get('fail_count_5min', 0)}",
            f"Distinct IPs: {features.get('distinct_ips', 0)}",
            "Low failure rate per account",
            "Widespread across user base", 
            "Common password patterns"
        ],
        
        "normal": [
            f"Fail count: {features.get('fail_count_5min', 0)}",
            f"Distinct IPs: {features.get('distinct_ips', 0)}",
            "Expected geographic patterns",
            "Familiar device usage",
            "Consistent access timing"
        ]
    }
    
    return "; ".join(analysis.get(attack_type, ["Standard authentication metrics"]))

def create_attack_summaries(prompts_dir):
    """Create event summaries matching your attack types"""
    event_summaries = [
        {
            "id": "session_hijack_example",
            "description": "User session appears simultaneously from New York and Tokyo within 10 minutes",
            "features": {
                "fail_count_5min": 0,
                "distinct_ips": 2,
                "geo_velocity_kmh": 10800,
                "concurrent_sessions": 2
            },
            "expected_label": "session_hijack"
        },
        {
            "id": "credential_stuffing_example",
            "description": "Multiple failed logins across different user accounts from distributed IPs",
            "features": {
                "fail_count_5min": 15,
                "distinct_ips": 8,
                "geo_velocity_kmh": 0,
                "accounts_affected": 12
            },
            "expected_label": "credential_stuffing"
        },
        {
            "id": "brute_force_example", 
            "description": "Rapid sequential password attempts on admin@company.com from single IP",
            "features": {
                "fail_count_5min": 45,
                "distinct_ips": 1,
                "geo_velocity_kmh": 0,
                "target_account": "admin@company.com"
            },
            "expected_label": "brute_force"
        },
        {
            "id": "password_spraying_example",
            "description": "Single common password attempted across multiple employee accounts",
            "features": {
                "fail_count_5min": 3,
                "distinct_ips": 2,
                "geo_velocity_kmh": 0,
                "common_password": "Company2024!"
            },
            "expected_label": "password_spraying"
        },
        {
            "id": "phishing_attempt_example",
            "description": "Login from known phishing infrastructure after suspicious email campaign",
            "features": {
                "fail_count_5min": 1,
                "distinct_ips": 1,
                "geo_velocity_kmh": 0,
                "suspicious_ip": "185.143.221.12"
            },
            "expected_label": "phishing_attempt"
        },
        {
            "id": "account_takeover_example",
            "description": "Successful login followed by password change and unusual data access",
            "features": {
                "fail_count_5min": 2,
                "distinct_ips": 3,
                "geo_velocity_kmh": 2500,
                "settings_changed": ["password", "recovery_email"]
            },
            "expected_label": "account_takeover"
        },
        {
            "id": "normal_example",
            "description": "Regular login from user's home office during business hours",
            "features": {
                "fail_count_5min": 0,
                "distinct_ips": 1,
                "geo_velocity_kmh": 0,
                "familiar_device": True
            },
            "expected_label": "normal"
        }
    ]
    
    summaries_path = prompts_dir / "event_summaries.json"
    with open(summaries_path, 'w', encoding='utf-8') as f:
        json.dump(event_summaries, f, indent=2)
    
    print(f"✅ Attack summaries created: {summaries_path}")

if __name__ == "__main__":
    count = generate_complete_corpus()
    print(f"🎉 SUCCESS! Generated {count} passages covering all 8 attack scenarios!")
    print("📊 Attack types included: account_takeover, session_hijack, phishing_attempt, credential_stuffing, brute_force, password_spraying, normal")