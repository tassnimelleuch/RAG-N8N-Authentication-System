# RAG Security Analyzer

A security analysis system using RAG (Retrieval Augmented Generation) to detect malicious login attempts.

## Features
- FAISS vector database for semantic search
- Groq LLM integration for analysis
- Pre-built security pattern corpus
- Real-time login event analysis

## Setup
1. Install requirements:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export GROQ_API_KEY="your_key_here"  # For Linux/Mac
# or
$env:GROQ_API_KEY="your_key_here"    # For Windows PowerShell
```

3. Run the analyzer:
```bash
python rag_pipeline.py
```

## Testing
To verify LLM integration:
```bash
$env:GROQ_NONCE_TEST="1"
python test_multi.py
```
