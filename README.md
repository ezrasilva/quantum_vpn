# VPN Resistente a Computadores Quânticos com Gerenciamento Híbrido de Chaves

## Visão Geral

Este projeto implementa um protótipo de prova de conceito de infraestrutura de Rede Privada Virtual (VPN) orquestrada por Redes Definidas por Software (SDN) com algoritmos criptográficos pós-quânticos e gerenciamento híbrido de chaves. O sistema combina Distribuição de Chaves Quânticas (QKD) com Criptografia Pós-Quântica (PQC) para fornecer segurança resistente a computadores quânticos para túneis IPsec.

## Arquitetura

### Componentes do Sistema

1. **Nós VPN**: Quatro gateways IPsec baseados em strongSwan (Alice, Bob, Carol, Dave)
2. **Controlador SDN**: Orquestrador centralizado gerenciando distribuição de chaves e ciclo de vida de túneis
3. **Gerador de Chaves Híbrido**: Combina segredos QKD e PQC usando HKDF-SHA256
4. **Plano de Controle**: Canal de comunicação seguro com autenticação e encriptação PQC

### Topologia de Rede

```
┌─────────────────────────────────────────────────────┐
│              Controlador SDN                        │
│  (Orquestrador - 10.100.1.40)                      │
│  - Autenticação ML-DSA-65                           │
│  - Encriptação de Envelope ML-KEM-768              │
│  - Geração de Chaves Híbridas (PQC + QKD)          │
└────────────┬────────────────────────┬───────────────┘
             │                        │
    ┌────────┴────────┐      ┌───────┴────────┐
    │                 │      │                 │
┌───▼────┐      ┌────▼───┐  ┌────▼───┐  ┌────▼────┐
│ Alice  │◄────►│  Bob   │  │ Carol  │◄►│  Dave   │
│ .1.10  │      │  .1.11 │  │ .1.12  │  │  .1.13  │
└────────┘      └────────┘  └────────┘  └─────────┘
  Túnel VPN     Túnel VPN
```

### Pares de Conexão

- **alice-bob**: Túnel IPsec bidirecional
- **carol-dave**: Túnel IPsec bidirecional

## Recursos de Segurança

### Criptografia Pós-Quântica

**Algoritmo de Assinatura (Autenticação)**
- ML-DSA-65 (CRYSTALS-Dilithium) para assinaturas digitais
- Fornece integridade e autenticidade de mensagens do plano de controle

**Mecanismo de Encapsulamento de Chaves (Confidencialidade)**
- ML-KEM-768 (CRYSTALS-Kyber) para encapsulamento de chaves
- Encriptação de envelope de cargas do plano de controle

### Geração de Chaves Híbridas

O sistema implementa uma abordagem híbrida combinando:

1. **Componente PQC**: Segredo compartilhado ML-KEM-768
2. **Componente QKD**: Chaves seguras contra quântica do QuKayDee KME 
3. **Derivação de Chaves**: HKDF-SHA256 misturando ambos os componentes

```
Segredo_PQC (ML-KEM) + Chave_QKD → HKDF-SHA256 → Chave_IPsec_Final
```

### Segurança do Plano de Controle

**Proteção Multicamada**

1. **Encriptação de Envelope**: Mensagens de controle encriptadas com ML-KEM-768
2. **Assinatura Digital**: Todas as mensagens assinadas com ML-DSA-65
3. **Proteção contra Reprodução**: Validação de timestamp + nonce
4. **Expiração de Mensagem**: Janela de validade de 30 segundos

**Fluxo de Segurança**
```
[Controlador]
    ↓ Gerar carga útil + timestamp + nonce
    ↓ Encriptar com ML-KEM-768 (chave pública do agente)
    ↓ Assinar com ML-DSA-65
    ↓ Enviar via HTTP

[Agente]
    ↓ Verificar assinatura ML-DSA-65
    ↓ Desencriptar com ML-KEM-768 (chave privada do agente)
    ↓ Validar timestamp (anti-reprodução)
    ↓ Verificar unicidade de nonce (anti-reprodução)
    ↓ Executar comando
```

## Tecnologias

### Componentes Principais

- **strongSwan 5.9.x**: Daemon de VPN IKEv2/IPsec
- **liboqs 0.10.x**: Biblioteca criptográfica Open Quantum Safe
- **Python 3.10+**: Orquestração e agentes
- **Flask**: API REST para agentes VPN
- **Protocolo VICI**: Interface de controle strongSwan

### Algoritmos Criptográficos

| Propósito | Algoritmo | Nível de Segurança |
|-----------|-----------|-------------------|
| Assinatura | ML-DSA-65 | NIST Nível 3 |
| KEM | ML-KEM-768 | NIST Nível 3 |
| KDF | HKDF-SHA256 | Clássico |
| IPsec ESP | AES-256-GCM | 256-bit (128-bit quântico) |
| IPsec IKE | AES-256-SHA256 | 256-bit (128-bit quântico) |

### Integração QKD Opcional

- **API QuKayDee**: Compatível com ETSI QKD API
- **Autenticação de Cliente TLS**: TLS mútuo com certificados
- **Tamanho de Chave**: Chaves quânticas de 256-bit

## Instalação

### Pré-requisitos

```bash
# Pacotes do sistema
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

# Gerar chaves de autenticação (ML-DSA-65)
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
alice           running
bob             running
carol           running
dave            running
orchestrator    running
```

## Uso

### Iniciando o Sistema

O orquestrador inicia automaticamente e gerencia túneis VPN:

```bash
# Ver logs do orquestrador
docker logs -f orchestrator

# Ver logs de um agente específico
docker logs -f alice
docker logs -f bob
```

### Testando Conectividade

```bash
# Testar túnel Alice-Bob
docker exec alice ping -c 3 10.100.1.11

# Testar túnel Carol-Dave
docker exec carol ping -c 3 10.100.1.13

# Inspecionar Associações de Segurança IPsec
docker exec alice swanctl --list-sas
docker exec carol swanctl --list-sas
```

### Rotação Manual de Chaves

O orquestrador realiza rotação automática de chaves a cada 10 segundos. Para disparar manualmente:

```bash
docker restart orchestrator
```

### Monitoramento

```bash
# Verificar saúde do agente
curl http://10.100.1.10:5000/health  # Alice
curl http://10.100.1.12:5000/health  # Carol

# Ver tráfego ESP
docker exec alice tcpdump -i eth0 'esp'
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
│   ├── qukaydee_client.py    # Cliente QKD API (opcional)
│   ├── generate_auth_keys.py # Gerador de par de chaves ML-DSA-65
│   ├── entrypoint.sh         # Script de inicialização de contêiner
│   └── orchestrator_auth.key # Chave privada do controlador
│       orchestrator_auth.pub # Chave pública do controlador
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
```

### Integração QKD

Configurar credenciais QuKayDee em `scripts/sdn_controller_multi_node.py`:

```python
ACCOUNT_ID = "2992"
URL_KME_ALICE = f"https://kme-1.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
CERT_DIR = "/scripts/certs"
```

Colocar certificados em `scripts/certs/`:
- `sae-1.crt`, `sae-1.key` (Alice)
- `sae-2.crt`, `sae-2.key` (Bob)
- `account-{ACCOUNT_ID}-server-ca-qukaydee-com.crt`

### Configurações de Rede

Modificar `docker-compose.yml` para ajustar endereçamento IP:

```yaml
networks:
  rede_a:
    ipam:
      config:
        - subnet: 10.100.1.0/24
```

## Modelo de Ameaças

### Ameaças Mitigadas

1. **Ataques de Computador Quântico**: Algoritmos PQC resistem ao algoritmo de Shor
2. **Man-in-the-Middle**: Assinaturas ML-DSA-65 fornecem autenticação
3. **Espionagem**: Encriptação ML-KEM-768 protege o plano de controle
4. **Ataques de Reprodução**: Validação de timestamp e nonce
5. **Alteração de Mensagem**: Assinaturas criptográficas detectam modificações

### Riscos Residuais

- Ataques de canal lateral em implementações criptográficas
- Negação de Serviço através de esgotamento de recursos
- Comprometimento do controlador SDN (ponto único de falha)

## Considerações de Desempenho

### Overhead Criptográfico

| Operação | Latência Típica |
|----------|------------------|
| ML-DSA-65 Sign | 1-2 ms |
| ML-DSA-65 Verify | 1-2 ms |
| ML-KEM-768 KeyGen | 0.5-1 ms |
| ML-KEM-768 Encap | 0.5-1 ms |
| ML-KEM-768 Decap | 0.5-1 ms |
| Rekeying IPsec | 50-200 ms |

### Escalabilidade

- Implementação atual: 2 túneis simultâneos
- Capacidade teórica: Centenas de túneis por controlador
- Gargalo: Operações de socket VICI em nós VPN

## Troubleshooting

### Contêiner Falha ao Iniciar

```bash
# Verificar logs
docker logs alice

# Problemas comuns
# 1. Privilégios insuficientes (requer capacidade NET_ADMIN)
# 2. Conflitos de porta
# 3. Biblioteca liboqs ausente
```

### Erros de Conexão do Orquestrador

```bash
# Verificar conectividade de rede
docker exec orchestrator ping 10.100.1.10

# Verificar se agente está ouvindo
docker exec alice netstat -tlnp | grep 5000

# Testar endpoint de saúde do agente
docker exec orchestrator curl http://10.100.1.10:5000/health
```

### Túnel IPsec Não Estabelecido

```bash
# Verificar daemon charon
docker exec alice swanctl --list-conns
docker exec alice swanctl --list-sas

# Ver logs strongSwan
docker exec alice tail -f /var/log/charon.log

# Recarregar configuração
docker exec alice swanctl --load-all
```

## Desenvolvimento

### Executando Testes

```bash
# Testes unitários para geração de chave híbrida
python3 -m pytest scripts/test_hybrid_key_gen.py

# Teste de integração
docker exec orchestrator python3 /scripts/sdn_controller_multi_node.py
```

### Adicionando Novos Nós VPN

1. Criar diretório de configuração: `eve/swanctl.conf`
2. Adicionar serviço em `docker-compose.yml`
3. Atualizar dicionário `CONNECTIONS` em `sdn_controller_multi_node.py`
4. Recompilar e reiniciar: `docker-compose up -d --build`

## Referências

### Padrões e Especificações

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
- RFC 7296: Internet Key Exchange Protocol Version 2 (IKEv2)
- RFC 4301: Security Architecture for the Internet Protocol
- ETSI GS QKD 014: Quantum Key Distribution (QKD) Protocol and data format

### Bibliotecas e Projetos

- Open Quantum Safe: https://openquantumsafe.org/
- strongSwan: https://www.strongswan.org/
- liboqs: https://github.com/open-quantum-safe/liboqs
- liboqs-python: https://github.com/open-quantum-safe/liboqs-python

## Licença

Este é um protótipo de pesquisa para fins acadêmicos e prova de conceito. Não destinado a uso em produção.

## Contribuidores

Projeto de pesquisa para demonstração SBRC 2026.

## Agradecimentos

Este trabalho utiliza a biblioteca liboqs do projeto Open Quantum Safe e a implementação flexível de IPsec do strongSwan.
