"""Teste rápido do parser do AirStrike (não faz parte da ferramenta)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import airstrike as m

SAMPLE = """\
Airodump-ng 1.7

BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-10-13 10:00:00, 2026-10-13 10:01:00,  6,  54, WPA2, CCMP, PSK, -45, 120, 3456,   0.  0.  0.  0,  9, MinhaCasa,
11:22:33:44:55:66, 2026-10-13 10:00:00, 2026-10-13 10:01:00, 11,  54, WPA2 WPA3, CCMP, SAE, -70,  80, 12,   0.  0.  0.  0, 12, Rede, Com, Virgula,
FF:EE:DD:CC:BB:AA, 2026-10-13 10:00:00, 2026-10-13 10:01:00,  1,  54, WEP, WEP, OPN, -80,  10, 0,   0.  0.  0.  0,  0, ,
0A:1B:2C:3D:4E:5F, 2026-10-13 10:00:00, 2026-10-13 10:01:00,  3,  54, WPA2, CCMP, MGT, -60, 200, 100,   0.  0.  0.  0, 10, CorpWiFi,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
DE:AD:BE:EF:00:01, 2026-10-13 10:00:10, 2026-10-13 10:01:00, -50, 30, AA:BB:CC:DD:EE:FF,
DE:AD:BE:EF:00:02, 2026-10-13 10:00:10, 2026-10-13 10:01:00, -55, 12, AA:BB:CC:DD:EE:FF,
DE:AD:BE:EF:00:03, 2026-10-13 10:00:10, 2026-10-13 10:01:00, -60,  4, (not associated),
"""

HASH22000 = """\
WPA*01*1be0533e31276056369c8e9a5e0c30be*d46d6dd8d100*4aada961cf14*686173686361742d6573736964*0103005f00100100005003750020*
WPA*02*0103005f0010010000500375*d46d6dd8d100*4aada961cf14*686173686361742d6573736964*0103005f0010010000500375*
WPA*02*999999999999999999999999*aabbccddeeff*4aada961cf14*686173686361742d6573736964*0103005f0010010000500375*
"""

fails = []


def check(name, cond):
    print(("OK  " if cond else "FAIL") + " " + name)
    if not cond:
        fails.append(name)


tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "scan-01.csv")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(SAMPLE)

redes, clientes = m.parse_airodump_csv(path)

check("4 redes lidas", len(redes) == 4)
check("3 clientes lidos", len(clientes) == 3)
check("BSSID maiusculo", redes[0]["bssid"] == "AA:BB:CC:DD:EE:FF")
check("ESSID simples", redes[0]["essid"] == "MinhaCasa")
check("IVs inteiros", redes[0]["ivs"] == 3456)
check("canal", redes[0]["channel"] == "6")
check("ESSID com virgula", redes[1]["essid"] == "Rede, Com, Virgula")
check("ESSID oculto vazio", redes[2]["essid"] == "")
check("enc WEP", "WEP" in redes[2]["privacy"])
check("2 clientes no alvo", redes[0]["clients"] == 2)
check("sem clientes na rede oculta", redes[2]["clients"] == 0)
check("auth MGT detectada", "MGT" in redes[3]["auth"])

# ordenacao por sinal (mais forte primeiro)
redes_sorted = sorted(redes, key=lambda r: m._power_int(r["power"]), reverse=True)
check("ordem por potencia", redes_sorted[0]["power"] == "-45")

# tabela (apenas garantir que nao lanca excecao)
m.print_networks(redes)
m.print_networks([])

# regex de KEY FOUND
check("KEY FOUND simples", m.KEY_FOUND_RE.search("KEY FOUND! [ hunter2 ]").group(1) == "hunter2")
check("KEY FOUND com espacos", m.KEY_FOUND_RE.search("  KEY FOUND! [ minha senha ]  ").group(1) == "minha senha")

# ---------------------------------------------------------------------------
# PMKID / formato 22000
# ---------------------------------------------------------------------------
h22k = os.path.join(tmp, "hash.22000")
with open(h22k, "w", encoding="utf-8") as fh:
    fh.write(HASH22000)

check("22000: 1 PMKID + 2 EAPOL sem filtro", m.count_hashes_in_22000(h22k) == (1, 2))
check("22000: filtro por BSSID", m.count_hashes_in_22000(h22k, "D4:6D:6D:D8:D1:00") == (1, 1))
check("22000: BSSID sem correspondencia", m.count_hashes_in_22000(h22k, "00:11:22:33:44:55") == (0, 0))
check("22000: arquivo inexistente", m.count_hashes_in_22000(os.path.join(tmp, "nao.existe")) == (0, 0))

# extract_22000 devolve None quando nao ha hcxpcapngtool, ou tupla
r = m.extract_22000(os.path.join(tmp, "x.cap"), os.path.join(tmp, "x.22000"), "AA:BB:CC:DD:EE:FF")
check("extract_22000 devolve None ou tupla", r is None or isinstance(r, tuple))

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
linhas = m.render_banner("AirStrike")
check("banner tem 6 linhas", linhas is not None and len(linhas) == 6)
check("banner largura igual", len(set(len(l) for l in linhas)) == 1)
check("banner largura 53", len(linhas[0]) == 53)
check("banner render sem excecao", m.print_banner() is None)
check("nome do app AirStrike", m.__appname__ == "AirStrike")

# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------
p = m.build_parser()
a = p.parse_args(["--bssid", "AA:BB:CC:DD:EE:FF", "--deauth", "0", "--yes"])
check("argparse bssid", a.bssid == "AA:BB:CC:DD:EE:FF")
check("argparse deauth 0", a.deauth == 0)
check("argparse yes", a.yes is True)
check("argparse padrao wordlist", a.wordlist == "/usr/share/wordlists/rockyou.txt")
check("argparse cracker padrao auto", a.cracker == "auto")

a2 = p.parse_args(["--cracker", "hashcat", "--hashcat-args", "--force -D 1"])
check("argparse cracker hashcat", a2.cracker == "hashcat")
check("argparse hashcat-args", a2.hashcat_args == "--force -D 1")
check("shlex de hashcat-args", m.shlex.split(a2.hashcat_args) == ["--force", "-D", "1"])

try:
    p.parse_args(["--cracker", "wpaif"])
    check("argparse cracker invalido rejeitado", False)
except SystemExit:
    check("argparse cracker invalido rejeitado", True)

# ---------------------------------------------------------------------------
# Deteccao de interface e recuperacao automatica do adaptador
# ---------------------------------------------------------------------------
FAKE_IW_MANAGED = "phy#0\n\tInterface wlan0\n\t\tifindex 3\n\t\ttype managed\n"
FAKE_IW_MONITOR = "phy#0\n\tInterface wlan0mon\n\t\tifindex 4\n\t\ttype monitor\n"
FAKE_IW_EMPTY = ""


def fake_run_factory(iw_output):
    def _fake(cmd, timeout=None, stdin=None):
        if len(cmd) >= 2 and cmd[0] == "iw" and cmd[1] == "dev":
            return 0, iw_output
        return 1, "comando nao suportado no teste"
    return _fake


orig_run = m.run
try:
    m.run = fake_run_factory(FAKE_IW_MANAGED)
    check("iw: parseia managed", m.list_ifaces_with_type() == {"wlan0": "managed"})
    check("find_wireless_iface acha managed", m.find_wireless_iface() == "wlan0")
    ad = m.Adapter()
    ad.monitor = "wlan0mon"
    check("alive False quando a interface nao existe", ad.alive() is False)

    m.run = fake_run_factory(FAKE_IW_MONITOR)
    check("iw: parseia monitor", m.list_ifaces_with_type() == {"wlan0mon": "monitor"})
    ad.monitor = "wlan0mon"
    check("alive True em modo monitor", ad.alive() is True)
    ad.monitor = "wlan0"
    check("alive False com tipo errado", ad.alive() is False)

    m.run = fake_run_factory(FAKE_IW_EMPTY)
    check("alive False sem interfaces", ad.alive() is False)

    # setup_monitor com fatal=False devolve None em vez de sair do programa
    check("setup_monitor fatal=False devolve None", m.setup_monitor(None, fatal=False) is None)
finally:
    m.run = orig_run

# ---------------------------------------------------------------------------
# Pipeline de quebra: mascaras e estimativa
# ---------------------------------------------------------------------------
check("keyspace numeric8 = 10^8", m.mask_keyspace("?d" * 8) == 10 ** 8)
check("keyspace alnum8 = 62^8", m.mask_keyspace("?1" * 8, {"-1": "?l?u?d"}) == 62 ** 8)
check("keyspace charset 36 = 36^8", m.mask_keyspace("?1" * 8, {"-1": "?l?d"}) == 36 ** 8)
check("charset ?l?d = 36", m._charset_size("?l?d") == 36)
check("charset literal abc = 3", m._charset_size("abc") == 3)
check("keyspace incremento 1..8",
      m.mask_keyspace("?d" * 8, None, True) == sum(10 ** k for k in range(1, 9)))
check("keyspace mascara mista", m.mask_keyspace("?d?d?l?l") == 10 * 10 * 26 * 26)
check("keyspace com literais", m.mask_keyspace("ab?d?d") == 100)
check("parse_masks preset", m.parse_masks("numeric8")[0] == ("numeric8", "?d" * 8, None, False))
check("parse_masks cru", m.parse_masks("?l?l?d?d")[0][1] == "?l?l?d?d")
check("parse_masks vazio", m.parse_masks("") == [])
check("parse_masks dois presets", len(m.parse_masks("numeric8,factory")) == 4)
check("fmt_tempo segundos", m.fmt_tempo(45) == "45s")
check("fmt_tempo minutos", m.fmt_tempo(120) == "2min")
check("fmt_tempo horas", m.fmt_tempo(3600 * 2.5) == "2.5h")
check("fmt_tempo dias", m.fmt_tempo(86400 * 2) == "2.0dias")
check("estimate imprime sem excecao",
      m.print_estimate([{"nome": "wordlist rockyou.txt", "senhas": 14344392, "tipo": "wordlist"},
                        {"nome": "mascara numeric8", "keyspace": 10 ** 8, "tipo": "mascara"}],
                       150000) is None)
check("benchmark sem hashcat devolve None", m.benchmark_speed() is None or
      isinstance(m.benchmark_speed(), float))

a3 = p.parse_args(["--masks", "numeric8,factory", "--increment", "--bench", "--hspeed", "250000"])
check("argparse masks", a3.masks == "numeric8,factory")
check("argparse increment", a3.increment is True)
check("argparse bench", a3.bench is True)
check("argparse hspeed", a3.hspeed == 250000.0)
check("argparse rules padrao None", a3.rules is None)
check("argparse masks padrao numeric8", p.parse_args([]).masks == "numeric8")

print()
print("FALHAS: %d" % len(fails))
sys.exit(1 if fails else 0)
