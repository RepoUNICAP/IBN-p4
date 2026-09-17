#!/usr/bin/env python3
"""
intent.py - controlador de intencoes minimo.

    frase  ->  entender()  ->  JSON  ->  traduzir()  ->  comandos  ->  simple_switch_CLI

Uso (com o 'make run' rodando em outro terminal):
    python3 intent.py                         # interativo
    python3 intent.py "bloquear varreduras"   # uma intencao
"""
import json
import re
import socket
import subprocess
import sys
import threading
import zlib

HOSTS = {"h1": "10.0.1.1", "h2": "10.0.2.2", "h3": "10.0.3.3"}
LIMITE_PADRAO = 20
ATIVAS = {}          # intencoes em vigor: {"scan": frase} ou {ip: frase}


def idx_de(ip):
    """mesmo indice que o P4 calcula: crc32(IP) % 1024"""
    return zlib.crc32(socket.inet_aton(ip)) % 1024


def duracao_em(frase):
    """'por 30 segundos' / 'por 2 minutos' -> segundos; sem prazo -> 0 (indefinido)"""
    m = re.search(r"por (\d+)\s*(s\b|seg|segundos|min|minutos)", frase)
    if not m:
        return 0
    return int(m.group(1)) * (60 if m.group(2).startswith("min") else 1)


def cli(cmd):
    """manda UMA linha para o simple_switch_CLI (porta thrift 9090) e devolve a saida"""
    p = subprocess.run(["simple_switch_CLI", "--thrift-port", "9090"],
                       input=cmd + "\n", capture_output=True, text=True)
    return p.stdout.replace("RuntimeCmd: ", "").strip()


# ---------- [1] captar a intencao: frase -> JSON ----------
def entender(frase):
    f = frase.lower()
    m = re.search(r"(\d+\.\d+\.\d+\.\d+|\bh\d\b)", f)
    ip = HOSTS.get(m.group(1), m.group(1)) if m else None

    if re.search(r"varredura|scan|malicios|suspeit", f):
        if re.search(r"parar|desativar|desligar|liberar|desbloquear", f):
            return {"acao": "desligar_detector"}
        n = re.search(r"mais de (\d+)", f)
        return {"acao": "detectar_scan", "limite": int(n.group(1)) if n else LIMITE_PADRAO,
                "duracao_s": duracao_em(f)}          # 0 = bloqueia ate alguem liberar
    if ip and re.search(r"liberar|desbloquear|permitir", f):      # antes de "bloquear":
        return {"acao": "liberar", "host": ip}                       # "desbloquear" contem "bloquear"
    if ip and re.search(r"\b(bloquear|barrar)\b", f):
        return {"acao": "bloquear", "host": ip, "duracao_s": duracao_em(f)}
    if re.search(r"status|bloqueado|mostrar", f):
        return {"acao": "status"}
    raise ValueError("nao entendi. Exemplos: 'bloquear todos os ips maliciosos', "
                     "'bloquear h1', 'liberar h1', 'parar de bloquear varreduras', 'status'")


# ---------- [2] traduzir: JSON -> comandos do switch ----------
def traduzir(i):
    if i["acao"] == "detectar_scan":
        return [f"register_write MyIngress.limite 0 {i['limite']}",
                f"register_write MyIngress.duracao 0 {i['duracao_s'] * 1000000}"]
    if i["acao"] == "desligar_detector":
        return ["register_write MyIngress.limite 0 0",
                "register_reset MyIngress.syn_count",
                "register_reset MyIngress.bloqueado"]
    if i["acao"] == "bloquear":
        return [f"table_add MyIngress.acl MyIngress.drop {i['host']} =>"]
    if i["acao"] == "liberar":
        h = handle_de(i["host"])
        cmds = [f"table_delete MyIngress.acl {h}"] if h is not None else []
        idx = idx_de(i["host"])                                # so o slot DESSE host
        return cmds + [f"register_write MyIngress.bloqueado {idx} 0",
                       f"register_write MyIngress.syn_count {idx} 0"]
    return []


def handle_de(ip):
    """table_delete precisa do 'handle' da entrada; achamos ele no table_dump"""
    chave = "".join(f"{int(x):02x}" for x in ip.split("."))     # 10.0.1.1 -> 0a000101
    handle = None
    for linha in cli("table_dump MyIngress.acl").splitlines():
        if (m := re.match(r"Dumping entry 0x([0-9a-f]+)", linha)):
            handle = int(m.group(1), 16)
        elif handle is not None and chave in linha.lower():
            return handle
    return None


# ---------- [3] assurance: ler o que esta no switch ----------
def reg(nome, idx=0):
    m = re.search(r"=\s*(\d+)", cli(f"register_read {nome} {idx}"))
    return int(m.group(1)) if m else 0


def status():
    lim, dur = reg("MyIngress.limite"), reg("MyIngress.duracao") // 1000000
    if lim:
        print(f"  detector: ATIVO, limite {lim} SYNs em 10 s; bloqueio "
              + (f"por {dur} s" if dur else "ate alguem liberar"))
    else:
        print("  detector: desligado")
    for nome, ip in HOSTS.items():
        idx = idx_de(ip)
        n, b = reg("MyIngress.syn_count", idx), reg("MyIngress.bloqueado", idx)
        print(f"  {nome} ({ip}): {n} SYNs na janela" + ("  <- BLOQUEADO pelo detector" if b else ""))
    print("  regras 'bloquear host':\n    " + cli("table_dump MyIngress.acl").replace("\n", "\n    "))
    print("  ativas   :", " | ".join(ATIVAS.values()) or "nenhuma")


def executar(frase):
    try:
        intencao = entender(frase)
    except ValueError as e:
        print("  ", e)
        return
    print("  intencao :", json.dumps(intencao))
    if intencao["acao"] == "status":
        return status()
    for cmd in traduzir(intencao):
        print("  switch   <-", cmd)
        saida = cli(cmd)
        if saida:
            print("           ->", saida.splitlines()[-1])
    # "bloquear h1 por 30 segundos": o controlador agenda a liberacao
    if intencao["acao"] == "bloquear" and intencao["duracao_s"]:
        threading.Timer(intencao["duracao_s"],
                        lambda: executar(f"liberar {intencao['host']}")).start()
    # lembra o que esta em vigor: bloquear adiciona, liberar/desligar remove
    chave = intencao.get("host", "scan")
    if intencao["acao"] in ("detectar_scan", "bloquear"):
        ATIVAS[chave] = frase
    else:
        ATIVAS.pop(chave, None)
    print("  ativas   :", " | ".join(ATIVAS.values()) or "nenhuma")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        for frase in sys.argv[1:]:
            print(f"\nintent> {frase}")
            executar(frase)
    else:
        while True:
            try:
                frase = input("\nintent> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if frase in ("sair", "exit"):
                break
            if frase:
                executar(frase)
