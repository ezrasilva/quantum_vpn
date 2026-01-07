#!/usr/bin/env python3
import requests
import time
import os
import binascii
import logging
import hmac
import hashlib
import json
import base64

# Tenta importar liboqs
try:
    import oqs
    HAS_OQS = True
except ImportError:
    HAS_OQS = False
    print("ERRO CRITICO: liboqs nao encontrado. A autenticacao vai falhar.")

# --- CONFIGURAÇÕES ---
IKE_NAME = "alice-to-bob"
CHILD_NAME = "net-traffic"
AGENT_ALICE_URL = "http://10.100.1.10:5000"
AGENT_BOB_URL   = "http://10.100.2.10:5000"
AUTH_ALGO = "ML-DSA-65"
PRIV_KEY_PATH = "/scripts/orchestrator_auth.key"
HTTP_TIMEOUT = 10

logging.basicConfig(level=logging.INFO, format='[SDN] %(asctime)s - %(message)s')
logger = logging.getLogger("SDN")

# --- CARREGAR CHAVE PRIVADA ---
try:
    with open(PRIV_KEY_PATH, "rb") as f:
        SIGNING_KEY = f.read()
    logger.info("Chave Privada ML-DSA-65 carregada.")
except Exception as e:
    logger.error(f"Nao foi possivel carregar chave privada: {e}")
    exit(1)

def send_signed_request(url, endpoint, payload_dict):
    """Envia JSON assinado com ML-DSA-65"""
    try:
        # 1. Prepara o Payload (Bytes)
        payload_bytes = json.dumps(payload_dict).encode('utf-8')
        
        # 2. Assina (CORREÇÃO: Chave passada no construtor)
        with oqs.Signature(AUTH_ALGO, secret_key=SIGNING_KEY) as signer:
            signature = signer.sign(payload_bytes)
            
        # 3. Prepara Headers
        headers = {
            'Content-Type': 'application/json',
            'X-PQC-Signature': base64.b64encode(signature).decode('utf-8')
        }
        
        # 4. Envia
        resp = requests.post(f"{url}/{endpoint}", data=payload_bytes, headers=headers, timeout=HTTP_TIMEOUT)
        
        if resp.status_code == 200:
            return True, resp.json()
        elif resp.status_code == 403:
            logger.critical(f"FALHA DE AUTENTICACAO: O Agente {url} rejeitou nossa assinatura!")
            return False, resp.text
        else:
            logger.error(f"Erro {resp.status_code}: {resp.text}")
            return False, resp.text
            
    except Exception as e:
        logger.error(f"Excecao de rede: {e}")
        return False, str(e)

# --- FUNÇÕES DE ORQUESTRAÇÃO ---

def push_key(url, owner, key_bytes):
    payload = {
        "key_id": owner, 
        "key_hex": binascii.hexlify(key_bytes).decode()
    }
    success, _ = send_signed_request(url, "inject-key", payload)
    return success

def terminate_tunnel(url):
    success, _ = send_signed_request(url, "terminate", {"ike": IKE_NAME})
    return success

def initiate_tunnel(url):
    success, resp = send_signed_request(url, "rekey", {"ike": CHILD_NAME})
    if success and ("rekeyed" in str(resp) or "established" in str(resp)):
        return True
    return False

def main():
    logger.info(f"SDN Seguro Iniciado (Autenticado via {AUTH_ALGO})")
    cycle = 0
    
    while True:
        cycle += 1
        logger.info(f"--- Ciclo {cycle} ---")
        
        # Simulando Chave Híbrida
        final_key = os.urandom(32)
        
        # Injeção Assinada
        ok_a = push_key(AGENT_ALICE_URL, "bob", final_key)
        ok_b = push_key(AGENT_BOB_URL,   "alice", final_key)
        
        if ok_a and ok_b:
            if cycle > 1:
                logger.info("Rotacionando chaves (Drop -> Create)...")
                terminate_tunnel(AGENT_ALICE_URL)
                time.sleep(3)
                
            if initiate_tunnel(AGENT_ALICE_URL):
                logger.info(f"SUCESSO! Túnel renovado e autenticado.")
            else:
                logger.error("Falha ao subir túnel.")
        else:
            logger.error("Falha na injeção de chaves (Assinatura rejeitada?)")

        time.sleep(10)

if __name__ == "__main__":
    main()