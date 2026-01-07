import oqs
import binascii

# Algoritmo de Assinatura Pós-Quântica (NIST Standard)
ALGO = "ML-DSA-65"

def main():
    print(f"Gerando par de chaves de Autoridade SDN ({ALGO})...")
    with oqs.Signature(ALGO) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        
        # Salva para o Orquestrador usar
        with open("/scripts/orchestrator_auth.key", "wb") as f:
            f.write(private_key)
            
        # Salva para os Agentes (Alice/Bob) usarem
        with open("/scripts/orchestrator_auth.pub", "wb") as f:
            f.write(public_key)
            
    print("Sucesso! Chaves salvas em /scripts/orchestrator_auth.*")

if __name__ == "__main__":
    main()