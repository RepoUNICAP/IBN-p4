/* -*- P4_16 -*- */

// ESQUELETO DO CODIGO TIRADO DE: https://github.com/p4lang/tutorials

/*************************************************************************
**************  S E M I N A R I O   R E D E S   **************************
*************************************************************************/

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_TCP = 6;
const bit<48> JANELA    = 10000000;   /* 10 s, em microssegundos */

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*************************  H E A D E R S  *********************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<1>  ns;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

/*************************  P A R S E R  *********************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet { // Retira header ethernet do pacote
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;   /* novo: se for TCP, pega o header TCP */
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*******************  A Ç Ã O - C O R R E S P O N D Ê N C I A  ***********/

/*************************  I N G R E S S  *******************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1)    limite;       /* escrito pela intencao "bloquear varreduras"  */
    register<bit<48>>(1)    duracao;      /* 0 = bloqueio indefinido; senao, microsseg.    */
    register<bit<32>>(1024) syn_count;    /* SYNs por host (indice = hash do IP origem)    */
    register<bit<48>>(1024) inicio;       /* quando a janela de 10 s de cada host comecou  */
    register<bit<32>>(1024) bloqueado;    /* 1 = host flagrado pelo detector               */
    register<bit<48>>(1024) bloqueado_em; /* instante em que foi bloqueado                 */

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* intencao "bloquear host X": o controlador faz table_add acl drop X */
    table acl {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            /* 1) host bloqueado por intencao "bloquear host X"? (hit = ja foi p/ drop) */
            if (!acl.apply().hit) {

                bit<32> idx;
                bit<32> b;
                bit<48> now = standard_metadata.ingress_global_timestamp;
                hash(idx, HashAlgorithm.crc32, 32w0, { hdr.ipv4.srcAddr }, 32w1024);
                bloqueado.read(b, idx);

                /* 2) bloqueio do detector expirou? (so se a intencao deu um prazo) */
                if (b == 1) {
                    bit<48> d;
                    bit<48> tb;
                    duracao.read(d, 0);
                    bloqueado_em.read(tb, idx);
                    if (d != 0 && now - tb > d) {
                        b = 0;
                        bloqueado.write(idx, 0);
                        syn_count.write(idx, 0);
                    }
                }

                if (b == 1) {
                    drop();                       /* continua bloqueado: descarta tudo dele */
                } else {
                    /* 3) detector: conta SYN "puro" por host dentro da janela */
                    bit<1> scanner = 0;
                    if (hdr.tcp.isValid() && hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
                        bit<32> n;
                        bit<32> lim;
                        bit<48> t0;
                        syn_count.read(n, idx);
                        inicio.read(t0, idx);
                        if (now - t0 > JANELA) {
                            n = 0;
                            inicio.write(idx, now);
                        }
                        n = n + 1;
                        syn_count.write(idx, n);
                        limite.read(lim, 0);
                        if (lim != 0 && n > lim) {
                            scanner = 1;
                            bloqueado.write(idx, 1);      /* fica bloqueado ate alguem liberar */
                            bloqueado_em.write(idx, now); /* ...ou ate a duracao vencer        */
                        }
                    }

                    /* 4) encaminha ou descarta */
                    if (scanner == 1) {
                        drop();
                    } else {
                        ipv4_lpm.apply();
                    }
                }
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************  D E P A R S E R  ******************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
