# create_proper_faiss.py
import json
import faiss
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer

print("🎯 CREATING PROPER FAISS INDEX WITH REAL EMBEDDINGS...")

# 1. Load your corpus
corpus_path = Path("prepared/prompts/corpus_passages.json")
with open(corpus_path, 'r', encoding='utf-8') as f:
    corpus = json.load(f)

print(f"📚 Loaded {len(corpus)} security passages")

# 2. Load a proper embedding model
print("🤖 Loading embedding model...")
model = SentenceTransformer('all-MiniLM-L6-v2')  # Small but effective model

# 3. Extract text content
texts = [item['content'] for item in corpus]
print("📊 Generating REAL semantic embeddings...")

# 4. Create REAL embeddings that understand meaning
embeddings = model.encode(texts, normalize_embeddings=True)
print(f"✅ Generated {embeddings.shape[0]} semantic embeddings")

# 5. Create FAISS index
dimension = embeddings.shape[1]
index = faiss.IndexFlatIP(dimension)  # Cosine similarity
index.add(embeddings.astype('float32'))

# 6. Save everything
faiss.write_index(index, "prepared/faiss_index.bin")

metadata = {
    'passage_ids': [item['passage_id'] for item in corpus],
    'tags': [item['tags'] for item in corpus],
    'embedding_model': 'all-MiniLM-L6-v2',
    'dimension': dimension,
    'total_passages': len(corpus)
}

with open("prepared/faiss_meta.json", 'w', encoding='utf-8') as f:
    json.dump(metadata, f, indent=2)

print("✅ PROPER FAISS index created!")

# 7. TEST WITH REAL SECURITY QUERIES
print("\n🔍 TESTING WITH REAL SECURITY SCENARIOS...")

test_queries = [
    "multiple failed logins from different IP addresses",
    "user logged in from new york then tokyo in 10 minutes", 
    "rapid password attempts on single account",
    "normal user login from familiar device"
]

for query in test_queries:
    print(f"\nQuery: '{query}'")
    
    # Encode the query
    query_embedding = model.encode([query], normalize_embeddings=True)
    
    # Search
    scores, indices = index.search(query_embedding.astype('float32'), k=3)
    
    print("Top matches:")
    for i, (score, idx) in enumerate(zip(scores[0], indices[0])):
        passage_id = metadata['passage_ids'][idx]
        tags = metadata['tags'][idx]
        print(f"  {i+1}. {passage_id} (score: {score:.3f}) - {tags}")

print("\n🎉 NOW your RAG system understands SECURITY PATTERNS!")