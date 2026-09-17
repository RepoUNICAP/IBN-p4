#!/usr/bin/env python3

# ESQUELETO DO CODIGO BASEADO EM: P4I/O - Intent-Based Networking with P4
# (https://research.tudelft.nl/en/publications/p4io-intent-based-networking-with-p4/)
# e no listener do riftadi: https://github.com/riftadi/p4io/blob/master/src/intent_listener.py

import json
import re
import socket
import subprocess
import sys
import threading
import zlib

HOSTS = {"h1": "10.0.1.1", "h2": "10.0.2.2", "h3": "10.0.3.3"}
LIMITE_PADRAO = 20
ATIVAS = {}  #intencoees

def idx_de(ip):
    # calcula exatamente o mesmo indice que o p4
    return zlib.crc32(socket.inet_aton(ip)) % 1024


def duracao_em(frase):
    # min pra segundos, segundos pra segundos, nada pra 0
    m = re.search(r"por (\d+)\s*(s\b|seg|segundos|min|minutos)", frase)
    if not m:
        return 0
    return int(m.group(1)) * (60 if m.group(2).startswith("min") else 1)


def cli(cmd):
    # manda UMA unidade de uma linha para o simple_switch_CLI 
    p = subprocess.run(["simple_switch_CLI", "--thrift-port", "9090"],
                       input=cmd + "\n", capture_output=True, text=True)
    return p.stdout.replace("RuntimeCmd: ", "").strip()

################  C A P T A Ç Ã O   D E   I N T E N Ç Ã O  #############
# traduz a frase pra intenção do operador

def entender(frase):
    f = frase.lower()
    m = re.search(r"(\d+\.\d+\.\d+\.\d+|\bh\d\b)", f)
    ip = HOSTS.get(m.group(1), m.group(1)) if m else None

    if re.search(r"varredura|scan|malicios|suspeit|maltrapilh", f):
        if re.search(r"parar|desativar|desligar|liberar|desbloquear", f):
            return {"acao": "desligar_detector"}
        n = re.search(r"mais de (\d+)", f)
        return {"acao": "detectar_scan", "limite": int(n.group(1)) if n else LIMITE_PADRAO,
                "duracao_s": duracao_em(f)} # 0 = bloqueia ate alguem liberar
    if ip and re.search(r"liberar|desbloquear|permitir", f): # antes de "bloquear":
        return {"acao": "liberar", "host": ip}                       
    if ip and re.search(r"\b(bloquear|barrar)\b", f):
        return {"acao": "bloquear", "host": ip, "duracao_s": duracao_em(f)}
    if re.search(r"status|bloqueado|mostrar", f):
        return {"acao": "status"}
    raise ValueError("nao entendi. Exemplos: 'bloquear todos os ips maliciosos', "
                     "'bloquear h1', 'liberar h1', 'parar de bloquear varreduras', 'status'")

################  T R A D U Ç Ã O   E   A P L I C A Ç Ã O  #############
# dicionario paiton

def traduzir(i):
    if i["acao"] == "detectar_scan":  # detect
        return [f"register_write MyIngress.limite 0 {i['limite']}",
                f"register_write MyIngress.duracao 0 {i['duracao_s'] * 1000000}"]
    if i["acao"] == "desligar_detector":  # parôôoô
        return ["register_write MyIngress.limite 0 0",
                "register_reset MyIngress.syn_count",
                "register_reset MyIngress.bloqueado"]
    if i["acao"] == "bloquear":  # bloqueia o host
        return [f"table_add MyIngress.acl MyIngress.drop {i['host']} =>"]
    if i["acao"] == "liberar":
        h = handle_de(i["host"])
        cmds = [f"table_delete MyIngress.acl {h}"] if h is not None else []
        idx = idx_de(i["host"])                                # so o slot DESSE host
        return cmds + [f"register_write MyIngress.bloqueado {idx} 0",
                       f"register_write MyIngress.syn_count {idx} 0"]
    return []


def handle_de(ip):
    # procura o handle que bloqueia o host pra caso o operador queira liberar depois
    chave = "".join(f"{int(x):02x}" for x in ip.split("."))     # 10.0.1.1 -> 0a000101
    handle = None
    for linha in cli("table_dump MyIngress.acl").splitlines():
        if (m := re.match(r"Dumping entry 0x([0-9a-f]+)", linha)):
            handle = int(m.group(1), 16)
        elif handle is not None and chave in linha.lower():
            return handle
    return None

######################## A S S U R A N C E  ############################
# Lê o que ta no switch e mostra pro operador

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

################    E X E C U Ç Ã O   D O   C I C L O  ###################

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
    # controlador agenda a liberacao se o cara der o tempo
    if intencao["acao"] == "bloquear" and intencao["duracao_s"]:
        threading.Timer(intencao["duracao_s"],
                        lambda: executar(f"liberar {intencao['host']}")).start()
    # só lembra quais intenções tão ativas
    chave = intencao.get("host", "scan")
    if intencao["acao"] in ("detectar_scan", "bloquear"):
        ATIVAS[chave] = frase
    else:
        ATIVAS.pop(chave, None)
    print("  ativas   :", " | ".join(ATIVAS.values()) or "nenhuma")


if __name__ == "__main__":
    # python3 intent.py -> interativo
    #  python3 intent.py "frase" -> uma intencao so
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
