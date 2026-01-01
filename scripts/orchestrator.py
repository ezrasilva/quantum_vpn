import time
import socket
import vici
import binascii
import oqs
import hashlib
import hmac
import os
from datetime import datetime

# Seus módulos locais
from hybrid_key_gen import mix_keys
from qukaydee_client import QuKayDeeClient

# --- CONFIGURAÇÕES DE REDE (VICI) ---
SOCKET_ALICE = "/sockets/alice/charon.vici"
SOCKET_BOB   = "/sockets/bob/charon.vici"
CONN_NAME = "alice-to-bob" 
KEY_ID_FIXO = "sdn-managed-key"
INTERVALO_ROTACAO = 30 

# --- CONFIGURAÇÕES DO QUKAYDEE ---
ID_SAE_ALICE = "sae-1"
ID_SAE_BOB   = "sae-2"

# Ajuste conforme o seu ID de conta (Account ID)
ACCOUNT_ID = "2992" 
URL_KME_ALICE = f"https://kme-1.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_BOB   = f"https://kme-2.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"

# --- CAMINHOS DOS CERTIFICADOS ---
CERT_DIR = "/scripts/certs"
CA_CERT  = f"{CERT_DIR}/account-{ACCOUNT_ID}-server-ca-qukaydee-com.crt" 

ALICE_CERT = f"{CERT_DIR}/sae-1.crt"
ALICE_KEY  = f"{CERT_DIR}/sae-1.key"

BOB_CERT   = f"{CERT_DIR}/sae-2.crt"
BOB_KEY    = f"{CERT_DIR}/sae-2.key"

def log(msg):
    print(f"[{datetime.now().time()}] {msg}")

def calculate_kcv(key_bytes):
    return hmac.new(key_bytes, b"KCV_CHECK_INTEGRITY", hashlib.sha256).hexdigest()

def inject_key_with_id(socket_path, key_hex):
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(socket_path)
        s = vici.Session(sock=sock)
        
        # 1. Limpeza
        try:
            s.unload_shared({'id': KEY_ID_FIXO})
        except Exception:
            pass 

        # 2. Injeção
        key_bytes = bytes.fromhex(key_hex)
        msg = {
            'type': 'IKE',
            'data': key_bytes,
            'owners': ['alice', 'bob'],
            'id': KEY_ID_FIXO     
        }
        
        s.load_shared(msg)
        sock.close()
    except Exception as e:
        log(f"[ERRO VICI] Falha ao injetar em {socket_path}: {e}")

def trigger_rekey_child(socket_path):
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(socket_path)
        s = vici.Session(sock=sock)
        
        log("[REKEY] Iniciando Child SA...")
        res = list(s.initiate({'child': 'net-traffic', 'timeout': '20000'}))
        sock.close()
        
        if any("established" in str(r) for r in res):
            log("[SUCESSO] Túnel Operacional!")
        else:
            log(f"[INFO] Resultado: {res}")
    except Exception as e:
        log(f"[ERRO REKEY] {e}")

def terminate_ike(socket_path):
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(socket_path)
        s = vici.Session(sock=sock)
        s.terminate({'ike': CONN_NAME})
        sock.close()
    except: pass

def get_fresh_key_pair(client_a, client_b):
    """
    Solicita UMA chave nova (Just-in-Time) para evitar expiração.
    """
    # 1. Alice pede 1 chave nova
    # log("Solicitando nova chave QKD ao KME...")
    batch = client_a.get_enc_key(ID_SAE_BOB, number=1)
    
    if not batch:
        raise Exception("KME não retornou nenhuma chave.")

    key_data = batch[0]
    key_id = key_data['key_id']
    qkd_key_alice = key_data['key']
    
    log(f"Chave QKD obtida: {key_id}")

    # 2. Bob recupera imediatamente
    qkd_key_bob = client_b.get_dec_key(ID_SAE_ALICE, key_id)
    
    return qkd_key_alice, qkd_key_bob

def run_orchestrator():
    print("\n--- ORQUESTRADOR HÍBRIDO (QUKAYDEE REAL-TIME) ---")
    
    if not os.path.exists(CA_CERT):
        log(f"[ERRO] Arquivo CA não encontrado: {CA_CERT}")
        return

    try:
        client_a = QuKayDeeClient(URL_KME_ALICE, ALICE_CERT, ALICE_KEY, CA_CERT)
        client_b = QuKayDeeClient(URL_KME_BOB,   BOB_CERT,   BOB_KEY,   CA_CERT)
    except Exception as e:
        log(f"[ERRO FATAL] Falha ao iniciar clientes: {e}")
        return

    cycle = 1
    
    while True:
        try:
            print(f"\n{'='*60}")
            log(f"Iniciando Ciclo #{cycle}")
            
            # 1. QKD (Sem Cache, sempre fresca)
            qkd_key_alice, qkd_key_bob = get_fresh_key_pair(client_a, client_b)

            # 2. PQC
            kemalg = "ML-KEM-768"
            try:
                with oqs.KeyEncapsulation(kemalg) as t: pass
            except: kemalg = "Kyber768"
                
            with oqs.KeyEncapsulation(kemalg) as client:
                with oqs.KeyEncapsulation(kemalg) as server:
                    pk = client.generate_keypair()
                    ct, pqc_secret_bob = server.encap_secret(pk)
                    pqc_secret_alice = client.decap_secret(ct)

            # 3. Mix & Validação
            final_key_alice = mix_keys(pqc_secret_alice, qkd_key_alice)
            final_key_bob   = mix_keys(pqc_secret_bob,   qkd_key_bob)
            
            kcv_alice = calculate_kcv(final_key_alice)
            kcv_bob   = calculate_kcv(final_key_bob)
            
            print(f"      -> KCV Alice: {kcv_alice[:8]}...")
            print(f"      -> KCV Bob:   {kcv_bob[:8]}...")

            if kcv_alice != kcv_bob:
                log("[ERRO FATAL] Divergência nas chaves!")
                time.sleep(5)
                continue 
            
            # 4. Injeção
            final_key_hex = binascii.hexlify(final_key_alice).decode()
            inject_key_with_id(SOCKET_ALICE, final_key_hex)
            inject_key_with_id(SOCKET_BOB, final_key_hex)
            
            time.sleep(1)

            # 5. Rotação
            if cycle > 1:
                terminate_ike(SOCKET_ALICE)
                time.sleep(3)
            
            trigger_rekey_child(SOCKET_ALICE)
            
            cycle += 1
            log(f"Aguardando {INTERVALO_ROTACAO}s...")
            time.sleep(INTERVALO_ROTACAO)

        except KeyboardInterrupt:
            break
        except Exception as e:
            log(f"[ERRO NO LOOP] {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_orchestrator()