#!/usr/bin/env python3
# Adaptado do receive.py do tutorial basic_tunnel.
# Roda no SERVIDOR (h2) e mostra, em uma linha, cada pacote TCP que CHEGA.
# Durante a varredura voce ve um SYN por porta... ate o switch bloquear
# a origem: a partir dai a tela para de rolar.
#
#   mininet> xterm h2        (no xterm)  python3 traffic/receive.py [-v]
import os
import sys

from scapy.all import IP, TCP, get_if_list, sniff

VERBOSE = "-v" in sys.argv


def get_if():
    """mesma funcao do tutorial: acha a interface eth0 do host"""
    for i in get_if_list():
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    sys.exit(1)


def handle_pkt(pkt):
    if IP in pkt and TCP in pkt:
        t = pkt[TCP]
        # flags: S = SYN (abertura), SA = SYN-ACK, R = RST (porta fechada)
        print(f"{pkt[IP].src}:{t.sport:<5} -> {pkt[IP].dst}:{t.dport:<5} "
              f"flags={str(t.flags):<3} len={len(pkt)}")
        if VERBOSE:
            pkt.show2()
        sys.stdout.flush()


def main():
    iface = get_if()
    print(f"sniffing on {iface} (so TCP)")
    sys.stdout.flush()
    sniff(iface=iface, filter="tcp", prn=handle_pkt)


if __name__ == "__main__":
    main()
