# Quantum-Resistant VPN with Hybrid Key Management

## Overview

This project implements a proof-of-concept Software-Defined Networking (SDN) orchestrated Virtual Private Network (VPN) infrastructure with post-quantum cryptographic algorithms and hybrid key management. The system combines Quantum Key Distribution (QKD) with Post-Quantum Cryptography (PQC) to provide quantum-resistant security for IPsec tunnels.

## Architecture

### System Components

1. **VPN Nodes**: Four strongSwan-based IPsec gateways (Alice, Bob, Carol, Dave)
2. **SDN Controller**: Centralized orchestrator managing key distribution and tunnel lifecycle
3. **Hybrid Key Generator**: Combines QKD and PQC secrets using HKDF-SHA256
4. **Control Plane**: Secure communication channel with PQC authentication and encryption

### Network Topology

```
┌─────────────────────────────────────────────────────┐
│                 SDN Controller                      │
│  (Orchestrator - 10.100.1.40)                      │
│  - ML-DSA-65 Authentication                         │
│  - ML-KEM-768 Envelope Encryption                  │
│  - Hybrid Key Generation (PQC + QKD)               │
└────────────┬────────────────────────┬───────────────┘
             │                        │
    ┌────────┴────────┐      ┌───────┴────────┐
    │                 │      │                 │
┌───▼────┐      ┌────▼───┐  ┌────▼───┐  ┌────▼────┐
│ Alice  │◄────►│  Bob   │  │ Carol  │◄►│  Dave   │
│ .1.10  │      │  .1.11 │  │ .1.12  │  │  .1.13  │
└────────┘      └────────┘  └────────┘  └─────────┘
   VPN Tunnel       VPN Tunnel
```

### Connection Pairs

- **alice-bob**: Bidirectional IPsec tunnel
- **carol-dave**: Bidirectional IPsec tunnel

## Security Features

### Post-Quantum Cryptography

**Signature Algorithm (Authentication)**
- ML-DSA-65 (CRYSTALS-Dilithium) for digital signatures
- Provides integrity and authenticity of control plane messages

**Key Encapsulation Mechanism (Confidentiality)**
- ML-KEM-768 (CRYSTALS-Kyber) for key encapsulation
- Envelope encryption of control plane payloads

### Hybrid Key Generation

The system implements a hybrid approach combining:

1. **PQC Component**: ML-KEM-768 shared secret
2. **QKD Component**: Quantum-safe keys from QuKayDee KME 
3. **Key Derivation**: HKDF-SHA256 mixing both components

```
PQC_Secret (ML-KEM) + QKD_Key → HKDF-SHA256 → Final_IPsec_Key
```

### Control Plane Security

**Multi-Layer Protection**

1. **Envelope Encryption**: Control messages encrypted with ML-KEM-768
2. **Digital Signature**: All messages signed with ML-DSA-65
3. **Replay Protection**: Timestamp + nonce validation
4. **Message Expiry**: 30-second validity window

**Security Flow**
```
[Controller]
    ↓ Generate payload + timestamp + nonce
    ↓ Encrypt with ML-KEM-768 (agent's public key)
    ↓ Sign with ML-DSA-65
    ↓ Send via HTTP

[Agent]
    ↓ Verify ML-DSA-65 signature
    ↓ Decrypt with ML-KEM-768 (agent's private key)
    ↓ Validate timestamp (anti-replay)
    ↓ Check nonce uniqueness (anti-replay)
    ↓ Execute command
```

## Technologies

### Core Components

- **strongSwan 5.9.x**: IKEv2/IPsec VPN daemon
- **liboqs 0.10.x**: Open Quantum Safe cryptographic library
- **Python 3.10+**: Orchestration and agents
- **Flask**: REST API for VPN agents
- **VICI Protocol**: strongSwan control interface

### Cryptographic Algorithms

| Purpose | Algorithm | Security Level |
|---------|-----------|----------------|
| Signature | ML-DSA-65 | NIST Level 3 |
| KEM | ML-KEM-768 | NIST Level 3 |
| KDF | HKDF-SHA256 | Classical |
| IPsec ESP | AES-256-GCM | 256-bit (128-bit quantum) |
| IPsec IKE | AES-256-SHA256 | 256-bit (128-bit quantum) |

### Optional QKD Integration

- **QuKayDee API**: ETSI QKD API compliant
- **TLS Client Authentication**: Mutual TLS with certificates
- **Key Size**: 256-bit quantum keys

## Installation

### Prerequisites

```bash
# System packages
apt-get update
apt-get install -y strongswan strongswan-swanctl libcharon-extra-plugins \
                   iproute2 iputils-ping python3 python3-pip git cmake \
                   gcc libssl-dev ninja-build

# Docker and Docker Compose
docker --version  # >= 20.10
docker-compose --version  # >= 1.29
```

### Build and Deploy

```bash
# Clone repository
git clone <repository-url>
cd quantum_vpn

# Generate authentication keys (ML-DSA-65)
python3 scripts/generate_auth_keys.py

# Build Docker images
docker-compose build

# Start infrastructure
docker-compose up -d

# Verify containers
docker-compose ps
```

### Expected Output

```
NAME            STATUS          PORTS
alice           running
bob             running
carol           running
dave            running
orchestrator    running
```

## Usage

### Starting the System

The orchestrator automatically starts and manages VPN tunnels:

```bash
# View orchestrator logs
docker logs -f orchestrator

# View specific agent logs
docker logs -f alice
docker logs -f bob
```

### Testing Connectivity

```bash
# Test Alice-Bob tunnel
docker exec alice ping -c 3 10.100.1.11

# Test Carol-Dave tunnel
docker exec carol ping -c 3 10.100.1.13

# Inspect IPsec Security Associations
docker exec alice swanctl --list-sas
docker exec carol swanctl --list-sas
```

### Manual Key Rotation

The orchestrator performs automatic key rotation every 10 seconds. To trigger manually:

```bash
docker restart orchestrator
```

### Monitoring

```bash
# Check agent health
curl http://10.100.1.10:5000/health  # Alice
curl http://10.100.1.12:5000/health  # Carol

# View ESP traffic
docker exec alice tcpdump -i eth0 'esp'
```

## Project Structure

```
quantum_vpn/
├── alice/
│   └── swanctl.conf          # Alice's strongSwan configuration
├── bob/
│   └── swanctl.conf          # Bob's strongSwan configuration
├── carol/
│   └── swanctl.conf          # Carol's strongSwan configuration
├── dave/
│   └── swanctl.conf          # Dave's strongSwan configuration
├── scripts/
│   ├── sdn_controller_multi_node.py  # Main SDN orchestrator
│   ├── vpn_agent.py          # Flask agent for each VPN node
│   ├── hybrid_key_gen.py     # Hybrid key mixing (HKDF)
│   ├── qukaydee_client.py    # QKD API client (optional)
│   ├── generate_auth_keys.py # ML-DSA-65 keypair generator
│   ├── entrypoint.sh         # Container initialization script
│   └── orchestrator_auth.key # Controller private key
│       orchestrator_auth.pub # Controller public key
├── Dockerfile                 # Container image definition
├── docker-compose.yml        # Multi-container orchestration
└── README.md                 # This file
```

## Configuration

### Hybrid Mode

Edit `scripts/sdn_controller_multi_node.py`:

```python
USE_HYBRID_MODE = True      # Enable PQC+QKD hybrid keys
PQC_ALGO = "ML-KEM-768"     # Post-quantum KEM algorithm
```

### QKD Integration

Configure QuKayDee credentials in `scripts/sdn_controller_multi_node.py`:

```python
ACCOUNT_ID = "2992"
URL_KME_ALICE = f"https://kme-1.acct-{ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
CERT_DIR = "/scripts/certs"
```

Place certificates in `scripts/certs/`:
- `sae-1.crt`, `sae-1.key` (Alice)
- `sae-2.crt`, `sae-2.key` (Bob)
- `account-{ACCOUNT_ID}-server-ca-qukaydee-com.crt`

### Network Settings

Modify `docker-compose.yml` to adjust IP addressing:

```yaml
networks:
  rede_a:
    ipam:
      config:
        - subnet: 10.100.1.0/24
```

## Threat Model

### Mitigated Threats

1. **Quantum Computer Attacks**: PQC algorithms resist Shor's algorithm
2. **Man-in-the-Middle**: ML-DSA-65 signatures provide authentication
3. **Eavesdropping**: ML-KEM-768 encryption protects control plane
4. **Replay Attacks**: Timestamp and nonce validation
5. **Message Tampering**: Cryptographic signatures detect modifications

### Residual Risks

- Side-channel attacks on cryptographic implementations
- Denial-of-Service through resource exhaustion
- Compromise of SDN controller (single point of failure)

## Performance Considerations

### Cryptographic Overhead

| Operation | Typical Latency |
|-----------|----------------|
| ML-DSA-65 Sign | 1-2 ms |
| ML-DSA-65 Verify | 1-2 ms |
| ML-KEM-768 KeyGen | 0.5-1 ms |
| ML-KEM-768 Encap | 0.5-1 ms |
| ML-KEM-768 Decap | 0.5-1 ms |
| IPsec Rekey | 50-200 ms |

### Scalability

- Current implementation: 2 concurrent tunnels
- Theoretical capacity: Hundreds of tunnels per controller
- Bottleneck: VICI socket operations on VPN nodes

## Troubleshooting

### Container Fails to Start

```bash
# Check logs
docker logs alice

# Common issues
# 1. Insufficient privileges (requires NET_ADMIN capability)
# 2. Port conflicts
# 3. Missing liboqs library
```

### Orchestrator Connection Errors

```bash
# Verify network connectivity
docker exec orchestrator ping 10.100.1.10

# Check agent is listening
docker exec alice netstat -tlnp | grep 5000

# Test agent health endpoint
docker exec orchestrator curl http://10.100.1.10:5000/health
```

### IPsec Tunnel Not Established

```bash
# Check charon daemon
docker exec alice swanctl --list-conns
docker exec alice swanctl --list-sas

# View strongSwan logs
docker exec alice tail -f /var/log/charon.log

# Reload configuration
docker exec alice swanctl --load-all
```

## Development

### Running Tests

```bash
# Unit tests for hybrid key generation
python3 -m pytest scripts/test_hybrid_key_gen.py

# Integration test
docker exec orchestrator python3 /scripts/sdn_controller_multi_node.py
```

### Adding New VPN Nodes

1. Create configuration directory: `eve/swanctl.conf`
2. Add service in `docker-compose.yml`
3. Update `CONNECTIONS` dict in `sdn_controller_multi_node.py`
4. Rebuild and restart: `docker-compose up -d --build`

## References

### Standards and Specifications

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
- RFC 7296: Internet Key Exchange Protocol Version 2 (IKEv2)
- RFC 4301: Security Architecture for the Internet Protocol
- ETSI GS QKD 014: Quantum Key Distribution (QKD) Protocol and data format

### Libraries and Projects

- Open Quantum Safe: https://openquantumsafe.org/
- strongSwan: https://www.strongswan.org/
- liboqs: https://github.com/open-quantum-safe/liboqs
- liboqs-python: https://github.com/open-quantum-safe/liboqs-python

## License

This is a research prototype for academic and proof-of-concept purposes. Not intended for production use.

## Contributors

Research project for SBRC 2026 demonstration.

## Acknowledgments

This work utilizes the Open Quantum Safe project's liboqs library and strongSwan's flexible IPsec implementation.
