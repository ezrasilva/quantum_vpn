#!/bin/bash
set -e

echo "[BOOT] Configurando latência de rede..."
# O "|| true" impede que o script pare se o comando falhar (comum em containers sem privilégios totais)
tc qdisc add dev eth0 root netem delay 50ms || echo "Aviso: Não foi possível aplicar NetEm (falta --cap-add=NET_ADMIN?)"

echo "[BOOT] Iniciando StrongSwan Charon..."
# Iniciamos o Charon em background, mas forçamos logs para stdout para debugging
/usr/lib/ipsec/charon --debug-ike 2 --debug-knl 2 --debug-cfg 2 &
CHARON_PID=$!

# Espera um pouco para garantir que o processo não morreu imediatamente
sleep 2

if ! kill -0 $CHARON_PID > /dev/null 2>&1; then
    echo "[ERRO] O processo Charon morreu imediatamente! Verifique os logs acima."
    exit 1
fi

echo "[BOOT] Charon rodando (PID $CHARON_PID). Iniciando Agente VPN..."
python3 /scripts/vpn_agent.py