# rag_pipeline.py
import json
import faiss
import numpy as np
import requests
from typing import List, Dict
import os
from dotenv import load_dotenv

# load .env from workspace root (adjust path if needed)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise RuntimeError("GROQ_API_KEY not found in environment. Set it in .env or your environment variables.")

def load_faiss_resources():
    faiss_index = faiss.read_index("./prepared/faiss_index.bin")
    with open("./prepared/faiss_meta.json", "r") as f:
        faiss_meta = json.load(f)
    with open("./prepared/corpus_passages.json", "r") as f:
        corpus = json.load(f)
    return faiss_index, faiss_meta, corpus

def query_llama(prompt: str):
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

def retrieve_relevant_patterns(query: str, faiss_index, corpus: List, k: int = 5):
    attack_terms = [
        "failed", "échec", "tentative", "brute", "force", "password", "mot de passe", "essais",
        "session", "hijack", "takeover", "simultaneous", "simultané", "geo", "velocity", "géographique",
        "device_change", "changement", "post_logout", "déconnexion", "renew", "renouvellement",
        "sensitive", "sensible", "action", "password_change", "changement_mot_passe",
        "multi", "géolocalisation", "travel", "voyage", "anomal", "impossible"
    ]
    query += " " + " ".join(attack_terms)
    
    query_terms = query.lower().split()
    
    scored_passages = []
    for passage in corpus:
        if isinstance(passage, dict) and 'content' in passage:
            text = passage['content'].lower()
            score = sum(1 for term in query_terms if term in text)
            if score > 0:
                scored_passages.append((score, passage['content']))
    
    scored_passages.sort(reverse=True)
    return [passage for _, passage in scored_passages[:k]]

def detect_attack_type_improved(login_event: Dict):  # CHANGED NAME HERE
    faiss_index, faiss_meta, corpus = load_faiss_resources()
    
    query = f"{login_event.get('event_type', 'login')} {login_event.get('outcome', '')} {login_event.get('ip', '')}"
    
    relevant_patterns = retrieve_relevant_patterns(query, faiss_index, corpus, k=5)
    
    # EXTRACTION des variables
    extra_features = login_event.get('extra_features', {})
    fail_count = extra_features.get('fail_count_5min', 0)
    distinct_ips = extra_features.get('distinct_ips', 1)
    geo_velocity = extra_features.get('geo_velocity', 'unknown')
    
    prompt = f"""CLASSIFY THIS SECURITY ATTACK - FOLLOW THESE RULES STRICTLY:

EVENT DATA:
- Failures in 5min: {fail_count}
- Distinct IPs: {distinct_ips}
- Geo Velocity: {geo_velocity}
- Outcome: {login_event.get('outcome')}

DECISION RULES (MUST FOLLOW):
1. IF distinct_ips > 2 AND fail_count = 1 → CREDENTIAL_STUFFING
2. IF fail_count > 3 AND distinct_ips = 1 → BRUTE_FORCE  
3. IF fail_count = 1 AND distinct_ips = 1 → PASSWORD_SPRAYING
4. IF geo_velocity = "high" → MULTI_GEO_ANOMALIES
5. IF outcome = "success" AND geo_velocity = "high" → ACCOUNT_TAKEOVER

SECURITY PATTERNS:
{chr(10).join([f"- {pattern}" for pattern in relevant_patterns])}

BASED ONLY ON THE RULES ABOVE, CLASSIFY: ATTACK_TYPE: [type]"""

    response = query_llama(prompt)
    return response, relevant_patterns