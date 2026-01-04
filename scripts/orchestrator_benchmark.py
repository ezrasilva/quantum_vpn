import time
import socket
import vici
import binascii
import oqs
import hashlib
import hmac
import os
import csv
from datetime import datetime

# Seus módulos locais
from hybrid_key_gen import mix_keys
from qukaydee_client import QuKayDeeClient

# --- CONFIGURAÇÕES DE REDE (VICI) ---
SOCKET_ALICE = "/sockets/alice/charon.vici"
SOCKET_BOB   = "/sockets/bob/charon.vici"
CONN_NAME = "alice-to-bob" 
KEY_ID_FIXO = "sdn-managed-key"
INTERVALO_ROTACAO = 15  # Ciclos rápidos para gerar muitos dados

# --- CONFIGURAÇÕES DO QUKAYDEE (Ajuste o ID se necessário) ---
ACCOUNT_ID = "2992" 
URL_KME_ALICE = f"https://kme-1.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_BOB   = f"https://kme-2.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"

# Caminhos dos Certificados
CERT_DIR = "/scripts/certs"
CA_CERT  = f"{CERT_DIR}/account-{ACCOUNT_ID}-server-ca-qukaydee-com.crt" 
ALICE_CERT = f"{CERT_DIR}/sae-1.crt"
ALICE_KEY  = f"{CERT_DIR}/sae-1.key"
BOB_CERT   = f"{CERT_DIR}/sae-2.crt"
BOB_KEY    = f"{CERT_DIR}/sae-2.key"

# Ficheiro de Saída
CSV_FILE = "/scripts/resultados_benchmark.csv"

def init_csv():
    # Cria o arquivo CSV com cabeçalhos se não existir
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Ciclo", "Algoritmo", 
                "Tempo_QKD_Alice_ms", "Tempo_QKD_Bob_ms", 
                "Tempo_PQC_KeyGen_ms", "Tempo_PQC_Encap_ms", "Tempo_PQC_Decap_ms",
                "Tempo_Total_Hibrido_ms", "Tempo_IPsec_Rekey_ms"
            ])
        print(f"[BENCHMARK] Arquivo criado: {CSV_FILE}")

def log_result(row):
    with open(CSV_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(row)
    print(f"[BENCHMARK] Ciclo {row[0]} salvo. IPsec Rekey: {row[8]}ms")

# --- FUNÇÕES AUXILIARES IPSEC ---
def inject_key_with_id(socket_path, key_hex):
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(socket_path)
        s = vici.Session(sock=sock)
        try:
            s.unload_shared({'id': KEY_ID_FIXO})
        except: pass
        msg = {
            'type': 'IKE',
            'data': bytes.fromhex(key_hex),
            'owners': ['alice', 'bob'],
            'id': KEY_ID_FIXO     
        }
        s.load_shared(msg)
        sock.close()
    except Exception as e:
        print(f"Erro VICI ao injetar: {e}")

def trigger_rekey_child(socket_path):
    """
    Dispara o Rekey e mede o tempo de resposta do daemon Charon.
    Isso simula o 'Handshake Time' da Figura 5 do artigo.
    """
    start = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(socket_path)
        s = vici.Session(sock=sock)
        # Inicia a renegociação do Child SA
        list(s.initiate({'child': 'net-traffic', 'timeout': '20000'}))
        sock.close()
    except Exception as e:
        print(f"Erro no Rekey: {e}")
        return 0
    end = time.perf_counter()
    return (end - start) * 1000  # Retorna em ms

def terminate_ike(socket_path):
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(socket_path)
        s = vici.Session(sock=sock)
        s.terminate({'ike': CONN_NAME})
        sock.close()
    except: pass

# --- LOOP PRINCIPAL DE TESTES ---
def run_benchmark():
    print("\n--- INICIANDO BENCHMARK CIENTÍFICO (QKD + PQC + IPSEC) ---")
    init_csv()
    
    # Inicializa clientes API
    try:
        client_a = QuKayDeeClient(URL_KME_ALICE, ALICE_CERT, ALICE_KEY, CA_CERT)
        client_b = QuKayDeeClient(URL_KME_BOB,   BOB_CERT,   BOB_KEY,   CA_CERT)
    except Exception as e:
        print(f"Erro fatal nos certificados: {e}")
        return

    # Lista de algoritmos para variar (Gerar Fig. 3 do artigo)
    # Tenta usar variantes se disponíveis na liboqs do container
    algoritmos = ["ML-KEM-768"]
    
    cycle = 1
    MAX_CYCLES = 10000
    
    while cycle <= MAX_CYCLES:
        for kemalg in algoritmos:
            print(f"\n>>> Ciclo {cycle} | Algoritmo: {kemalg}")
            
            # Variáveis de tempo (iniciam zeradas para o caso clássico)
            time_qkd_alice = 0
            time_qkd_bob = 0
            time_pqc_keygen = 0
            time_pqc_encap = 0
            time_pqc_decap = 0
            
            # Lógica Condicional
            if kemalg == "Classical-RNG":
                # --- MODO CLÁSSICO (Simula geração local rápida) ---
                t0 = time.perf_counter()
                # Apenas gera 32 bytes aleatórios (simula uma chave AES-256 clássica)
                final_key_alice = os.urandom(32)
                t1 = time.perf_counter()
                
                # O tempo de "KeyGen" é apenas o tempo do RNG
                time_pqc_keygen = (t1 - t0) * 1000 
                # QKD e Encap/Decap ficam zerados
                
                final_key_hex = binascii.hexlify(final_key_alice).decode()
                
            else:
                # --- MODO HÍBRIDO (Seu código original) ---
                try:
                    # 1. QKD
                    t0 = time.perf_counter()
                    batch = client_a.get_enc_key("sae-2", number=1) 
                    t1 = time.perf_counter()
                    time_qkd_alice = (t1 - t0) * 1000
                    
                    key_data = batch[0]
                    qkd_key_alice = key_data['key']
                    key_id = key_data['key_id']

                    t0 = time.perf_counter()
                    qkd_key_bob = client_b.get_dec_key("sae-1", key_id)
                    t1 = time.perf_counter()
                    time_qkd_bob = (t1 - t0) * 1000

                    # 2. PQC
                    with oqs.KeyEncapsulation(kemalg) as client:      
                        with oqs.KeyEncapsulation(kemalg) as server:  
                            t0 = time.perf_counter()
                            pk = client.generate_keypair()
                            time_pqc_keygen = (time.perf_counter() - t0) * 1000
                            
                            t0 = time.perf_counter()
                            ct, pqc_secret_bob = server.encap_secret(pk)
                            time_pqc_encap = (time.perf_counter() - t0) * 1000
                            
                            t0 = time.perf_counter()
                            pqc_secret_alice = client.decap_secret(ct)
                            time_pqc_decap = (time.perf_counter() - t0) * 1000

                    # Mistura
                    final_key_alice = mix_keys(pqc_secret_alice, qkd_key_alice)
                    final_key_hex = binascii.hexlify(final_key_alice).decode()
                    
                except Exception as e:
                    print(f"Erro no ciclo Híbrido: {e}")
                    continue

            # --- PARTE COMUM (Injeção e Medição IPsec) ---
            # O custo do IPsec deve ser igual para ambos!
            
            time_total_hibrido = time_pqc_keygen + time_qkd_alice + time_pqc_encap + time_qkd_bob + time_pqc_decap

            inject_key_with_id(SOCKET_ALICE, final_key_hex)
            inject_key_with_id(SOCKET_BOB, final_key_hex)
            
            if cycle > 1:
                terminate_ike(SOCKET_ALICE)
                time.sleep(0.5) 

            time_ipsec = trigger_rekey_child(SOCKET_ALICE)

            log_result([
                cycle, kemalg,
                f"{time_qkd_alice:.2f}", f"{time_qkd_bob:.2f}",
                f"{time_pqc_keygen:.2f}", f"{time_pqc_encap:.2f}", f"{time_pqc_decap:.2f}",
                f"{time_total_hibrido:.2f}", f"{time_ipsec:.2f}"
            ])
            
            cycle += 1
            time.sleep(INTERVALO_ROTACAO)

if __name__ == "__main__":
    run_benchmark()