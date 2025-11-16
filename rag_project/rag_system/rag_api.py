from flask import Flask, request, jsonify
import sys
import os
import re

app = Flask(__name__)

# Importer VOTRE pipeline RAG exactement comme dans test_rag_on_mongodb.py
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from rag_pipeline import detect_attack_type_improved

@app.route('/predict', methods=['POST'])
@app.route('/predict', methods=['POST'])
def predict_attack():
    try:
        data = request.get_json()
        print("🔍 Données reçues pour VOTRE RAG:", data)
        
        # Préparer les données exactement comme dans test_rag_on_mongodb.py
        event_data = {
            'event_type': data.get('event_type', 'login'),
            'outcome': data.get('outcome', 'unknown'),
            'ip': data.get('ip', ''),
            'extra_features': data.get('extra_features', {})
        }
        
        print(f"🎯 Appel de VOTRE detect_attack_type_improved...")
        
        # Appeler VOTRE fonction RAG exactement comme vous le faites
        attack_result, relevant_patterns = detect_attack_type_improved(event_data)
        
        print(f"🤖 RÉSULTAT COMPLET DE VOTRE RAG: {attack_result}")
        
        # ANALYSE CORRECTE de la réponse de Llama
        is_attack = False
        attack_type = "normal"
        confidence = 0.1
        
        # Votre RAG a DÉTECTÉ BRUTE_FORCE mais le parsing était mauvais
        if "BRUTE_FORCE" in attack_result:
            is_attack = True
            attack_type = "BRUTE_FORCE"
            confidence = 0.9
            print("🚨 BRUTE_FORCE DÉTECTÉ PAR VOTRE RAG!")
        elif "CREDENTIAL_STUFFING" in attack_result:
            is_attack = True  
            attack_type = "CREDENTIAL_STUFFING"
            confidence = 0.8
            print("🚨 CREDENTIAL_STUFFING DÉTECTÉ!")
        elif "PASSWORD_SPRAYING" in attack_result:
            is_attack = True
            attack_type = "PASSWORD_SPRAYING" 
            confidence = 0.7
            print("🚨 PASSWORD_SPRAYING DÉTECTÉ!")
        elif "MULTI_GEO_ANOMALIES" in attack_result:
            is_attack = True
            attack_type = "MULTI_GEO_ANOMALIES"
            confidence = 0.85
            print("🚨 MULTI_GEO_ANOMALIES DÉTECTÉ!")
        elif "ACCOUNT_TAKEOVER" in attack_result:
            is_attack = True
            attack_type = "ACCOUNT_TAKEOVER"
            confidence = 0.95
            print("🚨 ACCOUNT_TAKEOVER DÉTECTÉ!")
        
        print(f"🎯 RÉSULTAT PARSÉ: is_attack={is_attack}, type={attack_type}, confidence={confidence}")
        
        return jsonify({
            'is_attack': is_attack,
            'attack_type': attack_type,
            'confidence': confidence,
            'explanation': attack_result,
            'relevant_patterns': relevant_patterns,
            'status': 'success',
            'rag_used': True
        })
        
    except Exception as e:
        print(f"❌ Erreur dans VOTRE RAG: {e}")
        return jsonify({
            'is_attack': False,
            'attack_type': 'error',
            'confidence': 0,
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'VOTRE RAG Pipeline'})

if __name__ == '__main__':
    print("🚀 API RAG - Utilisant VOTRE detect_attack_type_improved()")
    print("✅ Votre code RAG original est utilisé sans modifications")
    app.run(host='0.0.0.0', port=8000, debug=True)