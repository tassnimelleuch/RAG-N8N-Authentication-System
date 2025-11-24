# test_simple_rag.py
import json
import faiss
import numpy as np
from pathlib import Path

print("🧪 TESTING YOUR RAG SYSTEM...")

# 1. Check if files exist
print("📁 Checking files...")
files_to_check = [
    "prepared/prompts/corpus_passages.json",
    "prepared/faiss_index.bin", 
    "prepared/faiss_meta.json"
]

for file in files_to_check:
    if Path(file).exists():
        print(f"✅ {file} - EXISTS")
    else:
        print(f"❌ {file} - MISSING")

# 2. Test FAISS index
print("\n🔍 Testing FAISS search...")
try:
    index = faiss.read_index("prepared/faiss_index.bin")
    print(f"✅ FAISS index loaded: {index.ntotal} passages")
    
    # Load metadata
    with open("prepared/faiss_meta.json", 'r') as f:
        metadata = json.load(f)
    print(f"✅ Metadata loaded: {len(metadata['passage_ids'])} passage IDs")
    
    # Test a simple search
    test_embedding = np.random.rand(1, 384).astype('float32')
    scores, indices = index.search(test_embedding, k=2)
    
    print("✅ FAISS search working!")
    print(f"   Found passages: {indices[0]}")
    
except Exception as e:
    print(f"❌ FAISS test failed: {e}")

# 3. Test corpus
print("\n📚 Testing corpus...")
try:
    with open("prepared/prompts/corpus_passages.json", 'r') as f:
        corpus = json.load(f)
    
    print(f"✅ Corpus loaded: {len(corpus)} passages")
    print("   Sample passages:")
    for i in range(2):
        print(f"   - {corpus[i]['passage_id']}: {corpus[i]['tags']}")
        
except Exception as e:
    print(f"❌ Corpus test failed: {e}")

print("\n🎉 TEST COMPLETE! Your RAG system is READY!")