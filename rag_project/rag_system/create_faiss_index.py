# simple_faiss_creator.py
import json
import os
import sys
from pathlib import Path

def check_dependencies():
    """Check if we have the right dependencies"""
    try:
        import numpy as np
        print(f"✅ NumPy: {np.__version__}")
        
        # Try to import FAISS
        try:
            import faiss
            print("✅ FAISS: Available")
        except ImportError:
            print("❌ FAISS not installed. Installing...")
            os.system("pip install faiss-cpu")
            import faiss
            print("✅ FAISS: Installed successfully")
        
        # Try to import sentence transformers
        try:
            from sentence_transformers import SentenceTransformer
            print("✅ Sentence Transformers: Available")
        except ImportError:
            print("❌ Sentence Transformers not installed. Installing...")
            os.system("pip install sentence-transformers")
            from sentence_transformers import SentenceTransformer
            print("✅ Sentence Transformers: Installed successfully")
            
        return True
        
    except Exception as e:
        print(f"❌ Dependency error: {e}")
        return False

def create_simple_faiss_index():
    print("🐢 CREATING FAISS INDEX (SLOW AND STEADY)...")
    
    if not check_dependencies():
        print("❌ Please fix dependencies first")
        return
    
    # Now import after checking
    import numpy as np
    import faiss
    from sentence_transformers import SentenceTransformer
    
    # Check if corpus exists
    corpus_path = Path("prepared/prompts/corpus_passages.json")
    if not corpus_path.exists():
        print("❌ Corpus file not found! Run your corpus generator first.")
        return
    
    print("📖 Loading corpus...")
    with open(corpus_path, 'r', encoding='utf-8') as f:
        corpus = json.load(f)
    
    print(f"📚 Loaded {len(corpus)} passages")
    
    # Use a simple, reliable model
    print("🤖 Loading embedding model...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Extract texts
    texts = [item['content'] for item in corpus]
    passage_ids = [item['passage_id'] for item in corpus]
    
    print("📊 Generating embeddings (this may take a minute)...")
    embeddings = model.encode(texts, normalize_embeddings=True)
    
    print(f"✅ Generated {embeddings.shape[0]} embeddings")
    
    # Create FAISS index
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)  # Cosine similarity
    
    # Add to index
    index.add(embeddings.astype('float32'))
    
    # Save index
    output_dir = Path("prepared")
    index_path = output_dir / "faiss_index.bin"
    faiss.write_index(index, str(index_path))
    
    # Save metadata
    metadata = {
        'passage_ids': passage_ids,
        'embedding_model': 'all-MiniLM-L6-v2',
        'dimension': dimension,
        'total_passages': len(corpus)
    }
    
    metadata_path = output_dir / "faiss_meta.json"
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"✅ FAISS index saved: {index_path}")
    print(f"✅ Metadata saved: {metadata_path}")
    
    # Simple test
    print("\n🧪 Testing with simple query...")
    test_query = "failed login attempts"
    query_embedding = model.encode([test_query], normalize_embeddings=True)
    scores, indices = index.search(query_embedding.astype('float32'), k=2)
    
    print(f"Query: '{test_query}'")
    for i, (score, idx) in enumerate(zip(scores[0], indices[0])):
        passage_id = metadata['passage_ids'][idx]
        print(f"  Match {i+1}: {passage_id} (score: {score:.3f})")

if __name__ == "__main__":
    create_simple_faiss_index()