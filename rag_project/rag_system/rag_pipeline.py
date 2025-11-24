# rag_pipeline.py
import json
import faiss
import numpy as np
import requests
from typing import List, Dict
import os
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

# Load environment
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise RuntimeError("GROQ_API_KEY not found in environment.")

class SecurityRAG:
    def __init__(self):
        print("🚀 Initializing Universal Security RAG System...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.faiss_index, self.faiss_meta, self.corpus = self.load_faiss_resources()
        print("✅ Universal RAG System Ready for ALL Attack Types!")
    
    def load_faiss_resources(self):
        """Load FAISS index and corpus"""
        faiss_index = faiss.read_index("./prepared/faiss_index.bin")
        with open("./prepared/faiss_meta.json", "r") as f:
            faiss_meta = json.load(f)
        with open("./prepared/prompts/corpus_passages.json", "r") as f:
            corpus = json.load(f)
        print(f"✅ Loaded: {len(corpus)} security patterns, {faiss_index.ntotal} vectors")
        return faiss_index, faiss_meta, corpus

    def query_llama(self, prompt: str):
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        
        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "model": "llama-3.1-8b-instant",
            "temperature": 0.1,
            "max_tokens": 300
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                return response.json()['choices'][0]['message']['content']
            return f"API Error {response.status_code}"
        except Exception as e:
            return f"Request failed: {e}"

    def retrieve_relevant_patterns(self, query: str, k: int = 5):
        """Universal semantic search for ALL attack types"""
        # Encode query
        query_embedding = self.model.encode([query], normalize_embeddings=True)
        
        # Search FAISS
        scores, indices = self.faiss_index.search(query_embedding.astype('float32'), k=k)
        
        # Get relevant passages
        relevant_passages = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < len(self.faiss_meta['passage_ids']):
                passage_id = self.faiss_meta['passage_ids'][idx]
                # Find full passage content
                for passage in self.corpus:
                    if passage['passage_id'] == passage_id:
                        relevant_passages.append({
                            'passage_id': passage_id,
                            'content': passage['content'],
                            'score': float(score),
                            'tags': passage['tags']
                        })
                        break
        
        return relevant_passages

    def classify_security_event(self, event_data: Dict):
        """UNIVERSAL FUNCTION: Classify ANY security event using RAG"""
        
        # Create intelligent query from event data
        query = self.create_universal_query(event_data)
        print(f"🔍 RAG Query: {query}")
        
        # Retrieve relevant patterns using FAISS
        relevant_patterns = self.retrieve_relevant_patterns(query, k=5)
        
        print("📋 Retrieved Security Patterns:")
        for i, passage in enumerate(relevant_patterns):
            print(f"  {i+1}. {passage['passage_id']} - {passage['tags']} (score: {passage['score']:.3f})")
        
        # Build universal prompt for LLM
        prompt = self.build_universal_prompt(event_data, relevant_patterns)
        
        # Get classification from LLM
        llm_response = self.query_llama(prompt)
        
        return {
            'query': query,
            'retrieved_passages': relevant_patterns,
            'llm_response': llm_response,
            'event_data': event_data
        }

    def create_universal_query(self, event_data: Dict) -> str:
        """Create semantic query for ANY attack type"""
        features = event_data.get('features', {})
        recent_events = event_data.get('recent_events', [])
        
        query_parts = []
        
        # UNIVERSAL FEATURE ANALYSIS - COVERS ALL ATTACK TYPES
        
        # 1. Failure Analysis (Brute Force, Credential Stuffing)
        fail_count = features.get('fail_count_5min', 0)
        if fail_count > 15:
            query_parts.append("very high failure rate concentrated attacks")
        elif fail_count > 5:
            query_parts.append("multiple failed authentication attempts")
        
        # 2. IP Distribution Analysis (Credential Stuffing vs Brute Force)
        distinct_ips = features.get('distinct_ips', 1)
        if distinct_ips > 8:
            query_parts.append("highly distributed IP addresses credential testing")
        elif distinct_ips > 3:
            query_parts.append("multiple IP locations distributed attacks")
        elif distinct_ips == 1:
            query_parts.append("single IP source targeted attacks")
        
        # 3. Geographic Analysis (Session Hijack, Account Takeover)
        geo_velocity = features.get('geo_velocity', 0)
        if geo_velocity > 2000:
            query_parts.append("impossible geographic travel session compromise")
        elif geo_velocity > 500:
            query_parts.append("unusual geographic movement patterns")
        
        # 4. Device & Behavior Analysis (Phishing, Account Takeover)
        device_change = features.get('device_change', False)
        if device_change:
            query_parts.append("unfamiliar device usage behavior change")
        
        # 5. Success Pattern Analysis
        success_count = features.get('success_count', 0)
        if success_count > 0 and geo_velocity > 1000:
            query_parts.append("successful login impossible location account takeover")
        elif success_count > 0 and device_change:
            query_parts.append("successful login new device potential compromise")
        
        # 6. Password Patterns (Password Spraying)
        common_passwords = features.get('common_passwords_detected', False)
        if common_passwords:
            query_parts.append("common password usage spraying attacks")
        
        # 7. Timing Patterns (Automated attacks)
        rapid_attempts = features.get('attempts_per_minute', 0)
        if rapid_attempts > 20:
            query_parts.append("very rapid automated login attempts")
        elif rapid_attempts > 5:
            query_parts.append("elevated attempt frequency")
        
        return " ".join(query_parts) if query_parts else "security authentication event analysis"

    def build_universal_prompt(self, event_data: Dict, relevant_patterns: List) -> str:
        """Build universal prompt for ANY attack classification"""
        
        features = event_data.get('features', {})
        
        # Format retrieved patterns
        patterns_text = "\n".join([
            f"🔍 {p['passage_id']} (score: {p['score']:.3f}): {p['content']}" 
            for p in relevant_patterns
        ])
        
        prompt = f"""SECURITY EVENT CLASSIFICATION - UNIVERSAL DETECTION

EVENT DATA TO ANALYZE:
- Failures in 5min: {features.get('fail_count_5min', 0)}
- Distinct IPs: {features.get('distinct_ips', 1)}
- Geo Velocity: {features.get('geo_velocity', 0)} km/h
- Device Changes: {features.get('device_change', False)}
- Success Count: {features.get('success_count', 0)}
- Attempts per Minute: {features.get('attempts_per_minute', 0)}

RELEVANT SECURITY PATTERNS FOUND:
{patterns_text}

CLASSIFICATION INSTRUCTIONS:
Analyze the event data and match it with the relevant security patterns above.
Choose the MOST LIKELY attack type from this list:

- brute_force: High failures from single IP, rapid attempts
- credential_stuffing: Moderate failures from multiple IPs, distributed pattern  
- password_spraying: Low failures across many accounts, common passwords
- session_hijack: Impossible geographic travel, concurrent sessions
- account_takeover: Successful login + unusual activity, settings changes
- phishing_attempt: Login from suspicious infrastructure, new devices
- normal: Expected patterns, familiar devices, consistent behavior

RESPONSE FORMAT (JSON):
{{
  "label": "attack_type",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation based on patterns matched",
  "key_indicators": ["indicator1", "indicator2"]
}}

CLASSIFICATION ANALYSIS:"""

        return prompt

# UNIVERSAL TEST FUNCTION
def test_security_event(event_data: Dict, expected_type: str = None):
    """Test ANY security event with the universal RAG system"""
    rag = SecurityRAG()
    
    print(f"\n🎯 TESTING SECURITY EVENT DETECTION...")
    if expected_type:
        print(f"📊 Expected: {expected_type.upper()}")
    
    result = rag.classify_security_event(event_data)
    
    print(f"\n🤖 RAG CLASSIFICATION RESULT:")
    print(result['llm_response'])
    
    return result

# For backward compatibility
def detect_attack_type_improved(login_event: Dict):
    rag = SecurityRAG()
    result = rag.classify_security_event(login_event)
    return result['llm_response'], result['retrieved_passages']

if __name__ == "__main__":
    print("🛡️ UNIVERSAL SECURITY RAG SYSTEM - READY FOR ALL ATTACK TYPES!")
    print("Supported: brute_force, credential_stuffing, password_spraying, session_hijack, account_takeover, phishing_attempt, normal")
    print("\nUsage:")
    print("from rag_pipeline import SecurityRAG, test_security_event")
    print("rag = SecurityRAG()")
    print("result = rag.classify_security_event(your_event_data)")