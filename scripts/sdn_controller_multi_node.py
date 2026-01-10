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

# Importar módulos híbridos
try:
    from hybrid_key_gen import mix_keys, hkdf_extract, hkdf_expand
    from qukaydee_client import QuKayDeeClient
    HAS_HYBRID = True
except ImportError:
    HAS_HYBRID = False
    logger_placeholder = logging.getLogger("SDN-Multi")
    logger_placeholder.warning("Módulos híbridos (QKD/PQC) não disponíveis. Usando RNG clássico.")

# --- CONFIGURAÇÕES ---
AGENT_ALICE_URL = "http://10.100.1.10:5000"
AGENT_BOB_URL   = "http://10.100.1.11:5000"
AGENT_CAROL_URL = "http://10.100.1.12:5000"
AGENT_DAVE_URL  = "http://10.100.1.13:5000"

AUTH_ALGO = "ML-DSA-65"
PRIV_KEY_PATH = "/scripts/orchestrator_auth.key"
HTTP_TIMEOUT = 10

# --- CONFIGURAÇÕES HÍBRIDAS (PQC + QKD) ---
# QuKayDee é OBRIGATÓRIO. Fallback apenas para PQC puro (nunca RNG clássico).
PQC_ALGO = "ML-KEM-768"  # Algoritmo PQC pós-quântico
KEM_ALGO = "ML-KEM-768"  # Algoritmo para criptografia de envelope

# Tempo máximo de validade de uma mensagem (anti-replay)
MAX_MESSAGE_AGE_SECONDS = 30

# QuKayDee KME URLs (OBRIGATÓRIO)
ACCOUNT_ID = "2992"
URL_KME_ALICE = f"https://kme-1.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_BOB   = f"https://kme-2.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_CAROL = f"https://kme-3.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_DAVE  = f"https://kme-4.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"

CERT_DIR = "/scripts/certs"
CA_CERT  = f"{CERT_DIR}/account-{ACCOUNT_ID}-server-ca-qukaydee-com.crt"

CONNECTIONS = {
    'alice-bob': {
        'nodes': ('alice', 'bob'),
        'urls': (AGENT_ALICE_URL, AGENT_BOB_URL),
        'ike_name': 'alice-to-bob',
        'child_name': 'net-traffic',
        'initiator': 'alice'
    },
    'carol-dave': {
        'nodes': ('carol', 'dave'),
        'urls': (AGENT_CAROL_URL, AGENT_DAVE_URL),
        'ike_name': 'carol-to-dave',
        'child_name': 'net-traffic',
        'initiator': 'carol'
    }
}

logging.basicConfig(level=logging.INFO, format='[SDN-Multi] %(asctime)s - %(message)s')
logger = logging.getLogger("SDN-Multi")


try:
    with open(PRIV_KEY_PATH, "rb") as f:
        SIGNING_KEY = f.read()
    logger.info("Chave Privada ML-DSA-65 carregada.")
except Exception as e:
    logger.error(f"Nao foi possivel carregar chave privada: {e}")
    exit(1)

# Gerar par de chaves KEM para criptografia de envelope (uma vez por sessão)
try:
    kem = oqs.KeyEncapsulation(KEM_ALGO)
    KEM_PUBLIC_KEY = kem.generate_keypair()
    KEM_SECRET_KEY = kem.export_secret_key()
    logger.info(f"Par de chaves {KEM_ALGO} gerado para criptografia de envelope.")
except Exception as e:
    logger.error(f"Falha ao gerar chaves KEM: {e}")
    KEM_PUBLIC_KEY = None
    KEM_SECRET_KEY = None

def send_encrypted_signed_request(url, endpoint, payload_dict, agent_kem_public_key):
    """
    Envia JSON criptografado com ML-KEM e assinado com ML-DSA-65
    Proteção contra replay com timestamp + nonce
    """
    try:
        
        payload_dict['_timestamp'] = int(time.time())
        payload_dict['_nonce'] = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        payload_json = json.dumps(payload_dict)
        payload_bytes = payload_json.encode('utf-8')
        

        encrypted_payload = payload_bytes
        kem_ciphertext = None
        
        if agent_kem_public_key and HAS_OQS:
            try:
                with oqs.KeyEncapsulation(KEM_ALGO) as kem_client:
                    kem_ciphertext, shared_secret = kem_client.encap_secret(agent_kem_public_key)
                    
                    from hashlib import sha256
                    key = sha256(shared_secret).digest()
                    encrypted_payload = bytes(a ^ b for a, b in zip(payload_bytes, (key * ((len(payload_bytes) // 32) + 1))[:len(payload_bytes)]))
            except Exception as e:
                logger.warning(f"Falha na criptografia KEM: {e}. Enviando sem criptografia.")
        
       
        with oqs.Signature(AUTH_ALGO, secret_key=SIGNING_KEY) as signer:
            signature = signer.sign(encrypted_payload)
        
        
        headers = {
            'Content-Type': 'application/octet-stream',
            'X-PQC-Signature': base64.b64encode(signature).decode('utf-8'),
            'X-KEM-Encrypted': 'true' if kem_ciphertext else 'false'
        }
        
        if kem_ciphertext:
            headers['X-KEM-Ciphertext'] = base64.b64encode(kem_ciphertext).decode('utf-8')
        
        
        resp = requests.post(f"{url}/{endpoint}", data=encrypted_payload, headers=headers, timeout=HTTP_TIMEOUT)
        
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


AGENT_PUBLIC_KEYS = {}

def register_agent_public_key(url):
    """Obtém a chave pública KEM do agente (se disponível)"""
    try:
        resp = requests.get(f"{url}/public-key", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            pk_b64 = data.get('kem_public_key')
            if pk_b64:
                AGENT_PUBLIC_KEYS[url] = base64.b64decode(pk_b64)
                logger.debug(f"Chave pública KEM do agente {url} registrada.")
                return True
    except:
        pass
    
    logger.debug(f"Agente {url} não possui chave KEM. Usando apenas assinatura.")
    AGENT_PUBLIC_KEYS[url] = None
    return False



def push_key(url, owner, key_bytes):
    
    if url not in AGENT_PUBLIC_KEYS:
        register_agent_public_key(url)
    
    payload = {
        "key_id": owner, 
        "key_hex": binascii.hexlify(key_bytes).decode()
    }
    success, _ = send_encrypted_signed_request(url, "inject-key", payload, AGENT_PUBLIC_KEYS.get(url))
    return success

def terminate_tunnel(url, ike_name):
    if url not in AGENT_PUBLIC_KEYS:
        register_agent_public_key(url)
    
    success, _ = send_encrypted_signed_request(url, "terminate", {"ike": ike_name}, AGENT_PUBLIC_KEYS.get(url))
    return success

def initiate_tunnel(url, child_name):
    if url not in AGENT_PUBLIC_KEYS:
        register_agent_public_key(url)
    
    success, resp = send_encrypted_signed_request(url, "rekey", {"ike": child_name}, AGENT_PUBLIC_KEYS.get(url))
    if success and ("rekeyed" in str(resp) or "established" in str(resp)):
        return True
    return False



def generate_pqc_key(algo=PQC_ALGO):
    """Gera um segredo usando PQC (ML-KEM-768)"""
    try:
        if not HAS_OQS:
            logger.critical("ERRO CRÍTICO: liboqs não disponível. Impossível gerar chaves PQC.")
            exit(1)
        
        start = time.time()
        with oqs.KeyEncapsulation(algo) as kem:
            pk = kem.generate_keypair()
            ct, shared_secret = kem.encap_secret(pk)
        elapsed = (time.time() - start) * 1000
        
        logger.debug(f"  PQC {algo} gerado: {elapsed:.2f}ms")
        return shared_secret[:32]  # Truncar para 256 bits
    except Exception as e:
        logger.critical(f"ERRO CRÍTICO no PQC: {e}. Sistema não pode operar sem PQC.")
        exit(1)

def request_qkd_key(kme_url, peer_sae_id, cert_tuple=None, size=32):
    """
    Requisita uma chave QKD do KME (Key Management Entity).
    Levanta exceção se falhar - sem fallback para RNG.
    """
    try:
        if not os.path.exists(CERT_DIR):
            logger.warning(f"Diretório de certificados {CERT_DIR} não encontrado.")
            raise FileNotFoundError(f"Certificados não encontrados em {CERT_DIR}")
        
        if not cert_tuple:
            raise ValueError("Certificados não configurados para QuKayDee")
        
        client = QuKayDeeClient(kme_url, cert_tuple[0], cert_tuple[1], CA_CERT)
        
        start = time.time()
        batch = client.get_enc_key(peer_sae_id, number=1)
        elapsed = (time.time() - start) * 1000
        
        qkd_key = batch[0]['key'][:size]
        logger.info(f"  QKD {peer_sae_id}: {elapsed:.2f}ms")
        return qkd_key
        
    except Exception as e:
        logger.error(f"ERRO ao obter QKD: {e}")
        raise

def generate_hybrid_key(conn_name, node1, node2, kme_urls, certs):
    """
    Gera uma chave híbrida combinando QKD + PQC usando HKDF.
    
    Hierarquia:
    1. Tenta obter QKD do KME (obrigatório)
    2. Se QKD falhar, usa PQC puro (nunca RNG clássico)
    
    Args:
        conn_name: Nome da conexão (alice-bob, carol-dave)
        node1, node2: Nomes dos nós
        kme_urls: Dicionário com URLs dos KMEs {node: url}
        certs: Dicionário com certificados {node: (cert_path, key_path)}
    """
    try:
        logger.info(f"[{conn_name}] Gerando chave híbrida (QKD+PQC)...")
        
      
        qkd_key = None
        try:
            kme_url = kme_urls.get(node1)
            cert = certs.get(node1)
            if kme_url and cert:
                qkd_key = request_qkd_key(kme_url, node2, cert)
                logger.info(f"  [QKD] Chave obtida com sucesso")
        except Exception as e:
            logger.warning(f"  [QKD] Falha: {e}. Usando fallback PQC puro.")
            qkd_key = None
        
       
        pqc_secret = generate_pqc_key(PQC_ALGO)
        logger.info(f"  [PQC] {PQC_ALGO} gerado")
        
       
        if qkd_key:
            final_key = mix_keys(pqc_secret, qkd_key)
            logger.info(f"  ✓ Chave Final: PQC({PQC_ALGO}) + QKD + HKDF-SHA256")
        else:
            final_key = mix_keys(pqc_secret, b'\x00' * 32)  # Mix com zero para manter HKDF
            logger.warning(f"  ✓ Chave Final: PQC({PQC_ALGO}) PURO (QKD indisponível)")
        
        return final_key
        
    except Exception as e:
        logger.critical(f"ERRO ao gerar chave híbrida: {e}")
        exit(1)

def main():
    logger.info(f"SDN Seguro Multi-Nós Iniciado (Autenticado via {AUTH_ALGO})")
    logger.info(f"Gerenciando {len(CONNECTIONS)} conexões: {list(CONNECTIONS.keys())}")
    logger.info(f"MODO: QKD + PQC Obrigatório (PQC:{PQC_ALGO})")
    
    
    kme_urls = {
        'alice': URL_KME_ALICE,
        'bob': URL_KME_BOB,
        'carol': URL_KME_CAROL,
        'dave': URL_KME_DAVE
    }
    
   
    certs = {
        'alice': (f"{CERT_DIR}/sae-1.crt", f"{CERT_DIR}/sae-1.key"),
        'bob': (f"{CERT_DIR}/sae-2.crt", f"{CERT_DIR}/sae-2.key"),
        'carol': (f"{CERT_DIR}/sae-3.crt", f"{CERT_DIR}/sae-3.key"),
        'dave': (f"{CERT_DIR}/sae-4.crt", f"{CERT_DIR}/sae-4.key")
    }
    
    cycle = 0
    
    while True:
        cycle += 1
        logger.info(f"\n{'='*60}")
        logger.info(f"--- Ciclo {cycle} ---")
        logger.info(f"{'='*60}")
        
        for conn_name, conn_info in CONNECTIONS.items():
            node1, node2 = conn_info['nodes']
            url1, url2 = conn_info['urls']
            ike_name = conn_info['ike_name']
            child_name = conn_info['child_name']
            initiator = conn_info['initiator']
            
            logger.info(f"\n[{conn_name}] Processando conexão {node1} <-> {node2}...")
            
            # Gerar chave híbrida (QKD + PQC com fallback)
            final_key = generate_hybrid_key(conn_name, node1, node2, kme_urls, certs)
            
            # Injetar chaves em ambos os nós
            logger.info(f"  -> Injetando chave em {node1} (para {node2})")
            ok1 = push_key(url1, node2, final_key)
            
            logger.info(f"  -> Injetando chave em {node2} (para {node1})")
            ok2 = push_key(url2, node1, final_key)
            
            if ok1 and ok2:
                # Determinar qual URL deve iniciar o túnel
                initiator_url = url1 if initiator == node1 else url2
                
                if cycle > 1:
                    logger.info(f"  -> Rotacionando túnel {ike_name}...")
                    terminate_tunnel(initiator_url, ike_name)
                    time.sleep(2)
                
                logger.info(f"  -> Iniciando túnel a partir de {initiator}...")
                if initiate_tunnel(initiator_url, child_name):
                    logger.info(f"  ✓ SUCESSO: {conn_name} renovado e autenticado")
                else:
                    logger.error(f"  ✗ FALHA: Não foi possível subir {conn_name}")
            else:
                logger.error(f"  ✗ FALHA: Injeção de chaves rejeitada em {conn_name}")
            
            time.sleep(1)  # Pequeno delay entre conexões
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Ciclo {cycle} completo. Aguardando próximo ciclo...")
        logger.info(f"{'='*60}\n")
        time.sleep(10)

if __name__ == "__main__":
    main()
