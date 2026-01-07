from flask import Flask, request, jsonify
import vici
import socket
import logging
import time
import subprocess
import oqs
import base64
import os

app = Flask(__name__)
VICI_SOCKET = "/var/run/charon.vici"
AUTH_ALGO = "ML-DSA-65"
PUB_KEY_PATH = "/scripts/orchestrator_auth.pub"

logging.basicConfig(level=logging.INFO, format='[AGENT] %(asctime)s - %(message)s')
logger = logging.getLogger("VPN-Agent")

# --- CARREGAR CHAVE PÚBLICA DA AUTORIDADE ---
try:
    with open(PUB_KEY_PATH, "rb") as f:
        ORCHESTRATOR_PUB_KEY = f.read()
    logger.info("Chave Pública ML-DSA-65 carregada com sucesso.")
except Exception as e:
    logger.critical(f"ERRO FATAL: Nao foi possivel ler a chave publica: {e}")
    sys.exit(1)

def verify_signature(payload_bytes, signature_b64):
    """Verifica se o payload foi assinado pelo Orquestrador"""
    try:
        signature = base64.b64decode(signature_b64)
        verifier = oqs.Signature(AUTH_ALGO)
        return verifier.verify(payload_bytes, signature, ORCHESTRATOR_PUB_KEY)
    except Exception as e:
        logger.error(f"Erro na verificacao da assinatura: {e}")
        return False

# --- MIDDLEWARE DE AUTENTICAÇÃO ---
@app.before_request
def authenticate_request():
    # Ignora validação para healthcheck
    if request.path == '/health':
        return
        
    signature_header = request.headers.get('X-PQC-Signature')
    if not signature_header:
        return jsonify({"error": "Autenticacao PQC obrigatoria"}), 401
    
    # O payload exato (bytes) que foi assinado
    payload = request.get_data()
    
    if not verify_signature(payload, signature_header):
        logger.warning(f"Tentativa de comando NAO AUTORIZADO de {request.remote_addr}")
        return jsonify({"error": "Assinatura Digital Invalida"}), 403

# --- FUNÇÕES VICI (Mantivemos a lógica, removemos a repetição) ---
def get_vici_session():
    for i in range(5): 
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(VICI_SOCKET)
            return vici.Session(s)
        except: time.sleep(1)
    return None

def initialize_vpn():
    session = get_vici_session()
    if not session: return False
    subprocess.run(["swanctl", "--load-all"], capture_output=True)
    return True

# --- ROTAS (Agora protegidas pelo @before_request) ---

@app.route('/inject-key', methods=['POST'])
def inject_key():
    data = request.json
    try:
        session = get_vici_session()
        if not session: return jsonify({"error": "VICI off"}), 500
        
        # Limpa chave antiga e carrega nova
        try: session.unload_shared({'id': data['key_id']})
        except: pass
        
        session.load_shared({
            'type': 'ike',
            'data': bytes.fromhex(data['key_hex']),
            'owners': [data['key_id']]
        })
        return jsonify({"status": "verified_and_injected"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/terminate', methods=['POST'])
def terminate():
    data = request.json
    try:
        session = get_vici_session()
        if not session: return jsonify({"error": "VICI off"}), 500
        session.terminate({'ike': data.get('ike', 'alice-to-bob')})
        return jsonify({"status": "terminated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/rekey', methods=['POST'])
def rekey():
    data = request.json
    try:
        session = get_vici_session()
        if not session: return jsonify({"error": "VICI off"}), 500
        res = list(session.initiate({'child': data.get('ike', 'net-traffic'), 'timeout': '20000'}))
        return jsonify({"status": "rekeyed", "details": str(res)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "online", "auth": "ML-DSA-65"}), 200

if __name__ == '__main__':
    if initialize_vpn():
        app.run(host='0.0.0.0', port=5000)