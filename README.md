# VPN Resistente a Computadores Quânticos com Gerenciamento Híbrido de Chaves

## Visão Geral

Este projeto implementa um protótipo de prova de conceito de infraestrutura de Rede Privada Virtual (VPN) orquestrada por Redes Definidas por Software (SDN) com algoritmos criptográficos pós-quânticos e gerenciamento híbrido de chaves. O sistema combina Distribuição de Chaves Quânticas (QKD) com Criptografia Pós-Quântica (PQC) para fornecer segurança resistente a computadores quânticos para túneis IPsec host-to-host.

## Arquitetura

### Componentes do Sistema

1. **Nós VPN**: Quatro gateways IPsec baseados em strongSwan (Alice, Bob, Carol, Dave) operando em modo host-to-host
2. **Controlador SDN**: Orquestrador centralizado gerenciando distribuição de chaves híbridas e ciclo de vida de túneis
3. **Gerador de Chaves Híbrido**: Combina segredos QKD e PQC usando HKDF-SHA256
4. **Plano de Controle**: Canal de comunicação seguro com autenticação ML-DSA-65 e encriptação ML-KEM-768

### Topologia de Rede

```
┌─────────────────────────────────────────────────────┐
│              Controlador SDN                        │
│  (Orquestrador - 192.168.100.40)                   │
│  - Autenticação ML-DSA-65                           │
│  - Encriptação de Envelope ML-KEM-768              │
│  - Geração de Chaves Híbridas (PQC + QKD)          │
└────────────┬────────────────────────┬───────────────┘
             │                        │
    ┌────────┴────────┐      ┌───────┴────────┐
    │                 │      │                 │
┌───▼────┐      ┌────▼───┐  ┌────▼───┐  ┌────▼────┐
│ Alice  │◄────►│  Bob   │  │ Carol  │◄►│  Dave   │
│ .100.10│ ESP  │ .100.11│  │ .100.12│  │ .100.13 │
└────────┘      └────────┘  └────────┘  └─────────┘
  Túnel VPN     Túnel VPN
  Host-to-Host  Host-to-Host
```

### Pares de Conexão

- **alice-bob**: Túnel IPsec bidirecional (192.168.100.10 ↔ 192.168.100.11)
- **carol-dave**: Túnel IPsec bidirecional (192.168.100.12 ↔ 192.168.100.13)

### Traffic Selectors (Host-to-Host)

- Alice→Bob: `local_ts 192.168.100.10/32, remote_ts 192.168.100.11/32`
- Bob→Alice: `local_ts 192.168.100.11/32, remote_ts 192.168.100.10/32`
- Carol→Dave: `local_ts 192.168.100.12/32, remote_ts 192.168.100.13/32`
- Dave→Carol: `local_ts 192.168.100.13/32, remote_ts 192.168.100.12/32`

## Recursos de Segurança

### Criptografia Pós-Quântica

**Algoritmo de Assinatura (Autenticação)**
- ML-DSA-65 (CRYSTALS-Dilithium) para assinaturas digitais do plano de controle
- Fornece integridade e autenticidade de mensagens do orquestrador
- Resistente ao algoritmo de Shor em computadores quânticos

**Mecanismo de Encapsulamento de Chaves (Confidencialidade)**
- ML-KEM-768 (CRYSTALS-Kyber) para encapsulamento de chaves
- Encriptação de envelope de cargas do plano de controle
- Protege material de chaveamento contra interceptação quântica

### Geração de Chaves Híbridas

O sistema implementa uma abordagem híbrida combinando:

1. **Componente PQC**: Segredo compartilhado ML-KEM-768 (resistente a quântica)
2. **Componente QKD**: Chaves seguras contra quântica do QuKayDee KME (ETSI QKD API)
3. **Derivação de Chaves**: HKDF-SHA256 misturando ambos os componentes

```
Segredo_PQC (ML-KEM) + Chave_QKD → HKDF-SHA256 → Chave_IPsec_Final
```

**Política de Fallback Segura**
- QKD indisponível → PQC puro (ML-KEM-768)
- PQC falha → Aborta negociação (sem túnel inseguro)

### Segurança do Plano de Controle

**Proteção Multicamada**

1. **Encriptação de Envelope**: Mensagens de controle encriptadas com ML-KEM-768 (chave pública do agente)
2. **Assinatura Digital**: Todas as mensagens assinadas com ML-DSA-65 (chave privada do orquestrador)
3. **Proteção contra Reprodução**: Validação de timestamp + nonce único
4. **Expiração de Mensagem**: Janela de validade de 30 segundos

**Fluxo de Segurança**
```
[Controlador]
    ↓ Gerar carga útil + timestamp + nonce
    ↓ Encriptar com ML-KEM-768 (chave pública do agente)
    ↓ Assinar com ML-DSA-65 (chave privada do orquestrador)
    ↓ Enviar via HTTP

[Agente VPN]
    ↓ Verificar assinatura ML-DSA-65 (chave pública do orquestrador)
    ↓ Desencriptar com ML-KEM-768 (chave privada do agente)
    ↓ Validar timestamp (anti-reprodução)
    ↓ Verificar unicidade de nonce (cache local)
    ↓ Aplicar chaves via VICI → strongSwan
```

## Tecnologias

### Componentes Principais

- **strongSwan 5.9.x**: Daemon de VPN IKEv2/IPsec com suporte VICI
- **liboqs 0.10.x**: Biblioteca criptográfica Open Quantum Safe
- **Python 3.10+**: Orquestração SDN e agentes
- **Flask 2.x**: API REST para agentes VPN
- **Protocolo VICI**: Interface de controle strongSwan para instalação dinâmica de chaves

### Algoritmos Criptográficos

| Propósito | Algoritmo | Nível de Segurança NIST |
|-----------|-----------|------------------------|
| Assinatura | ML-DSA-65 | NIST Nível 3 (FIPS 204) |
| KEM | ML-KEM-768 | NIST Nível 3 (FIPS 203) |
| KDF | HKDF-SHA256 | Clássico (256-bit) |
| IPsec ESP | AES-256-GCM | 256-bit (128-bit quântico) |
| IPsec IKE | AES-256-SHA256 | 256-bit (128-bit quântico) |

### Integração QKD

- **QuKayDee**: Compatível com ETSI GS QKD 014 (Key Management API)
- **Autenticação**: TLS mútuo com certificados SAE
- **Tamanho de Chave**: Chaves quânticas de 256-bit
- **KMEs**: kme-1 (alice), kme-2 (bob), kme-3 (carol), kme-4 (dave)

## Instalação

### Pré-requisitos

```bash
# Pacotes do sistema (Ubuntu/Debian)
apt-get update
apt-get install -y strongswan strongswan-swanctl libcharon-extra-plugins \
                   iproute2 iputils-ping python3 python3-pip git cmake \
                   gcc libssl-dev ninja-build

# Docker e Docker Compose
docker --version  # >= 20.10
docker-compose --version  # >= 1.29
```

### Compilar e Implantar

```bash
# Clonar repositório
git clone <repository-url>
cd quantum_vpn

# Gerar chaves de autenticação do orquestrador (ML-DSA-65)
python3 scripts/generate_auth_keys.py

# Compilar imagens Docker
docker-compose build

# Iniciar infraestrutura
docker-compose up -d

# Verificar contêineres
docker-compose ps
```

### Saída Esperada

```
NAME            STATUS          PORTS
alice           running         5000/tcp
bob             running         5000/tcp
carol           running         5000/tcp
dave            running         5000/tcp
orchestrator    running
```

## Uso

### Iniciando o Sistema

O orquestrador inicia automaticamente e gerencia túneis VPN:

```bash
# Ver logs do orquestrador (distribuição de chaves)
docker logs -f orchestrator

# Ver logs de um agente específico
docker logs -f alice
docker logs -f bob
```

### Testando Conectividade

```bash
# Testar túnel Alice-Bob (tráfego passa por ESP cifrado)
docker exec alice ping -c 3 192.168.100.11

# Testar túnel Carol-Dave
docker exec carol ping -c 3 192.168.100.13

# Inspecionar Associações de Segurança IPsec
docker exec alice swanctl --list-sas
docker exec carol swanctl --list-sas

# Ver políticas IPsec
docker exec alice ip xfrm policy
docker exec alice ip xfrm state
```

### Testes de Aplicação

```bash
# Transferência de arquivo via túnel (Alice → Bob)
docker exec alice dd if=/dev/urandom of=/tmp/test.bin bs=1M count=50
docker exec alice python3 -m http.server 8000
docker exec bob wget http://192.168.100.10:8000/tmp/test.bin

# Teste de throughput (iperf3)
docker exec bob iperf3 -s  # servidor
docker exec alice iperf3 -c 192.168.100.11 -t 30  # cliente
```

### Rotação Manual de Chaves

O orquestrador realiza rotação automática de chaves periodicamente. Para disparar manualmente:

```bash
docker restart orchestrator
```

### Monitoramento

```bash
# Verificar saúde do agente
curl http://192.168.100.10:5000/health  # Alice
curl http://192.168.100.12:5000/health  # Carol

# Ver tráfego ESP (protocolo 50)
docker exec alice tcpdump -i eth0 'esp'
docker exec alice tcpdump -i eth0 -n 'proto 50'

# Logs do charon (strongSwan)
docker exec alice tail -f /var/log/charon.log
```

## Estrutura do Projeto

```
quantum_vpn/
├── alice/
│   └── swanctl.conf          # Configuração strongSwan de Alice
├── bob/
│   └── swanctl.conf          # Configuração strongSwan de Bob
├── carol/
│   └── swanctl.conf          # Configuração strongSwan de Carol
├── dave/
│   └── swanctl.conf          # Configuração strongSwan de Dave
├── scripts/
│   ├── sdn_controller_multi_node.py  # Orquestrador SDN principal
│   ├── vpn_agent.py          # Agente Flask para cada nó VPN
│   ├── hybrid_key_gen.py     # Mistura de chaves híbridas (HKDF)
│   ├── qukaydee_client.py    # Cliente QKD API (ETSI GS QKD 004)
│   ├── generate_auth_keys.py # Gerador de par de chaves ML-DSA-65
│   ├── entrypoint.sh         # Script de inicialização de contêiner
│   ├── orchestrator_auth.key # Chave privada do controlador
│   ├── orchestrator_auth.pub # Chave pública do controlador
│   └── certs/                # Certificados SAE para KMEs QuKayDee
│       ├── sae-1.crt, sae-1.key    # Alice
│       ├── sae-2.crt, sae-2.key    # Bob
│       ├── sae-3.crt, sae-3.key    # Carol
│       ├── sae-4.crt, sae-4.key    # Dave
│       └── account-{ID}-server-ca-qukaydee-com.crt
├── Dockerfile                 # Definição de imagem de contêiner
├── docker-compose.yml        # Orquestração de múltiplos contêineres
└── README.md                 # Este arquivo
```

## Configuração

### Modo Híbrido

Editar `scripts/sdn_controller_multi_node.py`:

```python
USE_HYBRID_MODE = True      # Habilitar chaves híbridas PQC+QKD
PQC_ALGO = "ML-KEM-768"     # Algoritmo KEM pós-quântico
QKD_KEY_SIZE = 256          # Tamanho da chave QKD em bits
```

### Integração QKD

Configurar credenciais QuKayDee em `scripts/sdn_controller_multi_node.py`:

```python
ACCOUNT_ID = "2992"
URL_KME_ALICE = f"https://kme-1.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_BOB = f"https://kme-2.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_CAROL = f"https://kme-3.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
URL_KME_DAVE = f"https://kme-4.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
CERT_DIR = "/scripts/certs"
```

Colocar certificados em `scripts/certs/`:
- `sae-1.crt`, `sae-1.key` (Alice)
- `sae-2.crt`, `sae-2.key` (Bob)
- `sae-3.crt`, `sae-3.key` (Carol)
- `sae-4.crt`, `sae-4.key` (Dave)
- `account-{ACCOUNT_ID}-server-ca-qukaydee-com.crt`

### Configurações de Rede

Modificar `docker-compose.yml` para ajustar endereçamento IP:

```yaml
networks:
  quantum_network:
    ipam:
      config:
        - subnet: 192.168.100.0/24
```

## Modelo de Ameaças

### Ameaças Mitigadas

1. **Ataques de Computador Quântico**: Algoritmos PQC (ML-DSA-65, ML-KEM-768) resistem ao algoritmo de Shor
2. **Man-in-the-Middle**: Assinaturas ML-DSA-65 fornecem autenticação do orquestrador
3. **Espionagem do Plano de Controle**: Encriptação ML-KEM-768 protege payloads de chaves
4. **Ataques de Reprodução**: Validação de timestamp (janela 30s) e nonce único
5. **Alteração de Mensagem**: Assinaturas criptográficas detectam modificações
6. **Harvest Now, Decrypt Later**: Chaves híbridas QKD+PQC protegem contra ataques futuros

### Riscos Residuais

- Ataques de canal lateral em implementações criptográficas (timing, cache)
- Negação de Serviço através de esgotamento de recursos (flood de requisições)
- Comprometimento do controlador SDN (ponto único de confiança)
- Vulnerabilidades em dependências (liboqs, strongSwan, Python)


## Referências

### Padrões e Especificações

- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- **RFC 7296**: Internet Key Exchange Protocol Version 2 (IKEv2)
- **RFC 4301**: Security Architecture for the Internet Protocol
- **ETSI GS QKD 004**: Quantum Key Distribution (QKD) Application Interface
- **ETSI GS QKD 014**: Protocol and data format of REST-based key delivery API

### Bibliotecas e Projetos

- **Open Quantum Safe**: https://openquantumsafe.org/
- **strongSwan**: https://www.strongswan.org/
- **liboqs**: https://github.com/open-quantum-safe/liboqs
- **liboqs-python**: https://github.com/open-quantum-safe/liboqs-python
- **QuKayDee**: https://qukaydee.com/ (ETSI QKD API testbed)

### Publicações Relacionadas

- Campagna, M., et al. (2024). *Quantum Safe Cryptography and Security*. ETSI White Paper.
- NIST (2024). *Post-Quantum Cryptography Standardization*.

## Licença

Este é um protótipo de pesquisa para fins acadêmicos e prova de conceito. Não destinado a uso em produção sem auditoria de segurança completa.

## Contribuidores

Projeto de pesquisa para demonstração SBRC 2026.

**Contato**: [informações de contato]

## Agradecimentos

Este trabalho utiliza a biblioteca liboqs do projeto Open Quantum Safe, a implementação flexível de IPsec do strongSwan, e a infraestrutura de testes QKD da plataforma QuKayDee. Agradecemos aos mantenedores dessas ferramentas de código aberto que tornaram este protótipo possível.
 
