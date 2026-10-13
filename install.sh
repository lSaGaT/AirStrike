#!/usr/bin/env bash
# Instala o AirStrike no Kali Linux como o comando: sudo airstrike
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Permissao negada. Rode com sudo: sudo ./install.sh" >&2
    exit 1
fi

DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$DIR/airstrike.py" ]; then
    echo "airstrike.py nao encontrado ao lado deste install.sh" >&2
    exit 1
fi

echo "[*] Instalando dependencias (aircrack-ng, hcxtools, hashcat)..."
apt-get update
apt-get install -y aircrack-ng python3

if ! apt-get install -y hcxtools hashcat; then
    echo "[!] hcxtools/hashcat nao instalados: o ataque PMKID ficara desativado" >&2
fi

echo "[*] Instalando o AirStrike em /usr/local/bin/airstrike..."
install -m 0755 "$DIR/airstrike.py" /usr/local/bin/airstrike

echo "[+] AirStrike instalado com sucesso."
echo "[*] Use: sudo airstrike"
