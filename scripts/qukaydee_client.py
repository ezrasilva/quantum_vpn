import requests
import json
import sys
import os
import base64

class QuKayDeeClient:
    def __init__(self, kme_url, cert_path, key_path, ca_cert_path):
        self.base_url = kme_url.rstrip('/')
        self.cert = (cert_path, key_path)
        self.verify = ca_cert_path
        print(f"   [QuKayDee] Cliente iniciado para: {self.base_url}")

    def get_enc_key(self, peer_sae_id, number=1):
        """
        Alice pede chaves para falar com o Bob (POST /enc_keys)
        """
        url = f"{self.base_url}/api/v1/keys/{peer_sae_id}/enc_keys"
        
        payload = {
            "number": number,
            "size": 256
        }

        try:
            response = requests.post(
                url, 
                json=payload, 
                cert=self.cert, 
                verify=self.verify,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            keys_list = data['keys']
            
            clean_keys = []
            for k in keys_list:
                # Tenta ler 'key_ID' (Padrão QuKayDee) ou 'key_id' (Padrão Genérico)
                k_id = k.get('key_ID') or k.get('key_id')
                
                # Descodifica Base64
                k_val_b64 = k['key']
                k_val_bytes = base64.b64decode(k_val_b64)
                
                clean_keys.append({
                    'key_id': k_id,
                    'key': k_val_bytes
                })
            
            print(f"   [QuKayDee] Recebidas {len(clean_keys)} chaves com sucesso.")
            return clean_keys

        except Exception as e:
            print(f"[ERRO QuKayDee-Alice] Falha ao obter chaves: {e}")
            if 'response' in locals() and response is not None:
                print(f"Detalhe: {response.text}")
            sys.exit(1)

    def get_dec_key(self, peer_sae_id, key_id):
        """
        Bob pede a chave específica pelo ID (POST /dec_keys)
        """
        url = f"{self.base_url}/api/v1/keys/{peer_sae_id}/dec_keys"
        
        # --- CORREÇÃO AQUI ---
        # O QuKayDee exige 'key_IDs' e 'key_ID' (Case Sensitive)
        payload = {
            "key_IDs": [{"key_ID": key_id}]
        }

        try:
            response = requests.post(
                url, 
                json=payload, 
                cert=self.cert, 
                verify=self.verify,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            keys_list = data['keys']
            
            if not keys_list:
                raise Exception("Chave não retornada pelo servidor")

            # Descodifica Base64
            k_val_b64 = keys_list[0]['key']
            return base64.b64decode(k_val_b64)

        except Exception as e:
            print(f"[ERRO QuKayDee-Bob] Falha ao recuperar chave {key_id}: {e}")
            if 'response' in locals() and response is not None:
                print(f"Detalhe: {response.text}")
            sys.exit(1)