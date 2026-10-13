# AirStrike

<pre>
   ###  ##### ####  ##### ##### ####  ##### #   # #####
  #   #   #   #   # #       #   #   #   #   #  #  #    
  #####   #   ####  #####   #   ####    #   ###   ####
  #   #   #   #  #      #   #   #  #    #   #  #  #    
  #   #   #   #   #     #   #   #   #   #   #   # #    
  #   # ##### #   # #####   #   #   # ##### #   # #####
</pre>

AirStrike e uma ferramenta de teste de senhas Wi-Fi para Kali Linux.
Ela faz a captura do trafego de uma rede WPA, WPA2 ou WEP e tenta
descobrir a senha automaticamente, com um unico comando.

## O que a ferramenta faz

O AirStrike executa sozinho todas as etapas de um teste de Wi-Fi:

1. Mostra o aviso legal e confirma que voce tem autorizacao para testar
2. Coloca a placa de rede em modo monitor
3. Varre as redes proximas e mostra a lista na tela
4. Voce escolhe a rede alvo pelo numero da lista ou pelo BSSID
5. Captura os pacotes somente da rede alvo
6. Envia pacotes de desconexao para forcar a reconexao de um cliente
7. Detecta o handshake ou o PMKID da rede capturada
8. Prepara a lista de senhas (descompacta o rockyou.txt se preciso)
9. Testa as senhas uma a uma e mostra a chave encontrada
10. Restaura a placa de rede e a conexao normal do computador

## Como a ferramenta faz

Cada etapa usa uma ferramenta padrao do Kali Linux. Abaixo o comando
exato que o AirStrike executa em cada fase:

| Etapa | Ferramenta | Comando executado |
|-------|------------|-------------------|
| Modo monitor | airmon-ng | `sudo airmon-ng check kill` e `sudo airmon-ng start wlan0` |
| Varredura | airodump-ng | `sudo airodump-ng --output-format csv wlan0mon` |
| Captura do alvo | airodump-ng | `sudo airodump-ng -c CANAL --bssid BSSID -w captura wlan0mon` |
| Desconexao | aireplay-ng | `sudo aireplay-ng -0 10 -a BSSID wlan0mon` |
| Handshake | aircrack-ng | `aircrack-ng -a2 -b BSSID -w /dev/null captura-01.cap` |
| PMKID | hcxpcapngtool | `hcxpcapngtool -o captura.22000 captura-01.cap` |
| Lista de senhas | gzip | `sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz` |
| Quebra WPA | aircrack-ng | `aircrack-ng -w rockyou.txt -b BSSID captura-01.cap` |
| Quebra PMKID | hashcat | `hashcat -m 22000 captura.22000 rockyou.txt` |
| Restauracao | airmon-ng | `sudo airmon-ng stop wlan0mon` e restart do NetworkManager |

O PMKID e uma alternativa ao handshake de 4 vias: ele aparece na primeira
mensagem EAPOL enviada pelo roteador, entao funciona melhor em redes com
poucos clientes conectados. O AirStrike detecta os dois e escolhe o
caminho automaticamente.

## Adaptador caiu? Ela religa sozinho

O nome da interface e sempre detectado automaticamente, sem voce digitar
nada. E se a placa Wi-Fi cair no meio do teste (USB removido e recolocado,
driver reiniciado, modo monitor perdido, airodump-ng morrendo)? O AirStrike
fica vigiando a cada 2 segundos e, ao detectar a queda, executa sozinho:

```bash
sudo airmon-ng check kill
sudo airmon-ng start NOME_DA_INTERFACE_DETECTADA
```

Depois de religar, ele reinicia a captura e continua o teste de onde parou.
A vigilancia vale durante a varredura e durante a captura. Se a placa nao
voltar em 60 segundos, ele avisa e encerra restaurando a rede normal.

## Aviso legal

Use apenas em redes proprias ou com autorizacao explicita do responsavel.
O teste de desconexao derruba os dispositivos conectados e sem autorizacao
isso e crime (Lei 12.737/2012, Lei Carolina Dieckmann). Por isso o
AirStrike pede para voce digitar AUTORIZADO antes de comecar.

## Requisitos

* Kali Linux
* Placa Wi-Fi com suporte a modo monitor (exemplo: ALFA AWUS036ACH)
* Permissao de root (sudo)
* Python 3.8 ou superior

## Instalacao dentro do Kali

Abra o terminal no Kali e rode os comandos abaixo, em ordem:

```bash
git clone https://github.com/lSaGaT/AirStrike.git
cd AirStrike
chmod +x install.sh airstrike.py
sudo ./install.sh
```

O install.sh faz duas coisas:

1. Instala as dependencias com apt: aircrack-ng, hcxtools e hashcat
2. Copia a ferramenta para /usr/local/bin/airstrike

Pronto. Depois da instalacao, para ativar a ferramenta e so digitar:

```bash
sudo airstrike
```

Para remover a ferramenta do computador:

```bash
sudo rm /usr/local/bin/airstrike
```

## Uso

```bash
sudo airstrike
```

No modo interativo a ferramenta varre as redes sozinha, voce escolhe o
alvo pelo numero da lista e tudo o resto roda automaticamente ate achar
a senha ou ate a lista de senhas acabar.

Atalhos do Ctrl+C:

* Durante a varredura: para e mostra a lista das redes ja encontradas
* Durante a captura: para e vai direto para a tentativa de quebra
* Durante a quebra: para o hashcat ou aircrack-ng e restaura a rede

### Exemplos

```bash
# Escolher o alvo direto pelo BSSID
sudo airstrike --bssid AA:BB:CC:DD:EE:FF

# BSSID mais canal, para quando a rede nao aparece na varredura
sudo airstrike --bssid AA:BB:CC:DD:EE:FF --channel 6

# Forcar o caminho do PMKID pelo hashcat
sudo airstrike --bssid AA:BB:CC:DD:EE:FF --cracker hashcat

# Hashcat no modo CPU com argumentos extras
sudo airstrike --bssid AA:BB:CC:DD:EE:FF --hashcat-args "-D 1 --force"

# Interface que ja esta em modo monitor
sudo airstrike --monitor wlan0mon

# Lista de senhas propria e sem pacotes de desconexao
sudo airstrike --wordlist /caminho/senhas.txt --deauth 0

# So capturar, sem testar senhas
sudo airstrike --bssid AA:BB:CC:DD:EE:FF --no-crack
```

### Opcoes

| Opcao | Padrao | Descricao |
|-------|--------|-----------|
| `--iface` | auto | placa wireless para o modo monitor |
| `--monitor` | nada | interface que ja esta em modo monitor |
| `--scan-time` | 15 | segundos de varredura |
| `--bssid` | nada | BSSID do alvo, pula o menu |
| `--channel` | nada | canal do alvo, usado junto com `--bssid` |
| `--wordlist` | rockyou.txt | lista de senhas |
| `--deauth` | 10 | pacotes de desconexao por rodada, 0 desativa |
| `--deauth-interval` | 15 | segundos entre as rodadas de desconexao |
| `--capture-time` | 180 | tempo maximo de captura em segundos |
| `--iv-target` | 20000 | quantidade minima de IVs no ataque WEP |
| `--cracker` | auto | quebrador WPA: auto, aircrack ou hashcat |
| `--hashcat-args` | nada | argumentos extras do hashcat entre aspas |
| `--out` | captures | pasta das capturas e resultados |
| `--no-crack` | nada | para apos a captura, sem testar senhas |
| `--keep` | nada | nao restaura a placa ao final |
| `--yes` | nada | pula o aviso de autorizacao |

Com `--cracker auto`, se o hcxpcapngtool extrair algum hash PMKID ou
EAPOL e o hashcat estiver instalado, a quebra e feita pelo hashcat no
formato 22000. Se nao, usa o aircrack-ng direto no arquivo .cap.

## Arquivos gerados

Tudo fica na pasta `captures` dentro de onde voce rodou o comando:

* `scan_*.csv` : redes encontradas na varredura
* `captura_*.cap` e `captura_*.csv` : pacotes capturados da rede alvo
* `captura_*.22000` : hashes PMKID e EAPOL no formato do hashcat
* `captura_*_chave.txt` : chave gravada quando a quebra funciona
* `resultado_*.txt` : resumo com data, BSSID, ESSID e a chave

## Dicas

* Para o handshake vir e preciso ter um dispositivo conectado a rede
  alvo. Deixe um celular ou notebook conectado durante o teste.
* Rede parada, sem clientes? O PMKID costuma aparecer mesmo assim, e
  para captura-lo de forma mais agressiva existe o hcxdumptool.
* WPA3, SAE e redes enterprise 802.1X nao sao quebraveis por lista de
  senhas. O AirStrike avisa quando detecta esse tipo de rede.
* WEP nao usa lista de senhas: o aircrack-ng recupera a chave direto
  dos IVs capturados.
* Se a quebra falhar, a captura fica salva. Tente outra lista sem
  refazer a captura:

```bash
sudo airstrike --monitor wlan0mon --no-crack --bssid AA:BB:CC:DD:EE:FF
sudo aircrack-ng -w outra_lista.txt -b AA:BB:CC:DD:EE:FF captures/captura_XXXX-01.cap
sudo hashcat -m 22000 captures/captura_XXXX.22000 outra_lista.txt
```

## Testes

```bash
python3 test_airstrike.py
```

O teste confere o parser do CSV do airodump-ng, a contagem de hashes
22000, o banner e a linha de comando. Ele nao executa nenhum ataque.
