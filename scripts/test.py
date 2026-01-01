import vici
import socket
import sys
import time

def inject(socket_path, my_id, remote_id, key):
    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(socket_path)
        s = vici.Session(sock=sock)
        
        # Injeta chave simples
        s.load_shared({
            'type': 'IKE',
            'data': key,
            'owners': [my_id, remote_id]
        })
        print(f"Injetado em {socket_path}: OK")
        sock.close()
    except Exception as e:
        print(f"Erro: {e}")

# 1. Injeta a MESMA senha nos dois
KEY = "BATATA123"
print(f"Tentando injetar chave de teste: {KEY}")

inject("/sockets/alice/charon.vici", "alice", "bob", KEY)
inject("/sockets/bob/charon.vici",   "bob", "alice", KEY)

time.sleep(1)

# 2. Tenta conectar via Alice
try:
    sock = socket.socket(socket.AF_UNIX)
    sock.connect("/sockets/alice/charon.vici")
    s = vici.Session(sock=sock)
    
    print("Tentando derrubar conexão antiga...")
    try: s.terminate({'ike': 'alice-to-bob'})
    except: pass
    
    time.sleep(1)
    
    print("Tentando iniciar nova conexão...")
    res = list(s.initiate({'ike': 'alice-to-bob', 'timeout': '5000'}))
    print(f"Resultado: {res}")
    sock.close()
except Exception as e:
    print(f"Erro na conexão: {e}")