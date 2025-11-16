#!/usr/bin/env python3
# retrieve_and_build_prompt.py
import json
from pathlib import Path
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import os

PREP = Path("prepared")
OUT_PROMPTS = PREP / "prompts"
OUT_PROMPTS.mkdir(parents=True, exist_ok=True)

MODEL_EMB = "sentence-transformers/all-MiniLM-L6-v2"
INDEX_FILE = PREP / "faiss_index.bin"
META_FILE = PREP / "faiss_meta.json"
EVENT_SUMMARIES = PREP / "event_summaries.json"

K = 5  # top-k passages

def load_index_and_meta():
    index = faiss.read_index(str(INDEX_FILE))
    meta = json.load(open(META_FILE, "r", encoding="utf-8"))
    return index, meta

def build_query_from_event(event):
    # Create a compact textual query including features and recent_events
    features = event.get("features", {})
    recent = event.get("recent_events", [])
    return f"Features: {features}; Recent events: {recent}"

def retrieve_topk(query, index, meta, emb_model, k=5):
    q_emb = emb_model.encode([query], convert_to_numpy=True)
    D, I = index.search(np.array(q_emb, dtype='float32'), k)
    results = []
    for idx in I[0]:
        results.append(meta[idx])
    return results

def build_prompt(passages, event):
    # Compose prompt as in the template we designed
    passages_text = "\n\n".join([f"[{p['passage_id']}] {p['content']}" for p in passages])
    event_json = json.dumps(event, ensure_ascii=False)
    prompt = f"""Passages pertinents récupérés (RAG):
{passages_text}

Événement (event_summary) :
{event_json}

Instruction :
En te basant UNIQUEMENT sur les passages fournis ci‑dessus et sur l'event_summary, détermine le type d'alerte parmi :
credential_stuffing, brute_force, phishing_attempt, session_hijack, malware_activity, insider_threat, normal.

Répond EXCLUSIVEMENT par un JSON valide au format suivant :

{{
  "label": "<une des étiquettes listées ci-dessus>",
  "score": <nombre à virgule entre 0.0 et 1.0>,
  "top_indicators": ["indicateur court 1", "indicateur court 2"]
}}

Contraintes :
1. Le champ `label` doit être exactement l'un des 7 labels listés.
2. `score` est un score de confiance (0.0 faible → 1.0 élevé).
3. `top_indicators` : liste compacte (max 3) des indices tirés des passages ou de l'event_summary.
4. Si les passages sont insuffisants -> `label` = "normal", `score` = 0.0, `top_indicators` = [].
5. Ne fournis PAS d'autres clés ni de texte additionnel hors du JSON.
"""
    return prompt

def main():
    index, meta = load_index_and_meta()
    emb_model = SentenceTransformer(MODEL_EMB)
    events = json.load(open(EVENT_SUMMARIES, "r", encoding="utf-8"))
    # produce prompts for first N events (or all)
    for e in events[:200]:
        q = build_query_from_event(e)
        top = retrieve_topk(q, index, meta, emb_model, k=K)
        prompt = build_prompt(top, e)
        out_file = OUT_PROMPTS / f"prompt_{e['id']}.txt"
        out_file.write_text(prompt, encoding="utf-8")
    print("Prompts written to", OUT_PROMPTS)

    # OPTIONAL: pseudo-call LLM (example for OpenAI-like - fill your API key / endpoint)
    """
    import requests, os
    api_key = os.getenv('OPENAI_API_KEY')
    url = "https://api.openai.example/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role":"system","content":"Tu es... (rôle)"},
                     {"role":"user","content": prompt}],
        "temperature": 0.0,
        "max_tokens": 200
    }
    r = requests.post(url, headers=headers, json=payload)
    print(r.json())  # parse content and save to alerts table
    """

if __name__ == "__main__":
    main()
