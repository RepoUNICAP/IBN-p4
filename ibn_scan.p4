/* -*- P4_16 -*- */
/*************************************************************************
 * ibn_scan.p4 - plano de dados do demo "Roteamento Baseado em Intencao"
 *
 * IDEIA CENTRAL: o programa P4 e FIXO (compilado uma vez). As intencoes
 * NAO geram codigo P4 em tempo real; elas mudam o CONTEUDO das tabelas e
 * dos registradores abaixo, atraves do controlador (ibn/ibn_cli.py).
 *
 *   tabela ipv4_lpm      encaminhamento normal (igual ao tutorial basic)
 *   tabela acl           intencoes "bloquear host X" / "liberar host X"
 *   registradores cfg_*  parametros da intencao "bloquear varreduras"
 *   detector             conta SYNs para portas distintas, por IP origem
 *   contador intent_stats  lido na fase de "intent assurance"
 *
 * Pipeline de ingresso, por pacote IPv4:
 *   1) acl.apply()      -> host liberado? (pula detector)  host bloqueado? (drop)
 *   2) detector         -> se a intencao estiver ativa e for TCP SYN
 *   3) ipv4_lpm.apply() -> encaminha se ninguem mandou descartar
 *************************************************************************/
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_TCP = 6;
const bit<32> N_SLOTS   = 1024;   /* slots do detector: indice = hash(IP origem) */

/* indices do contador intent_stats (lidos pelo controlador) */
const bit<32> STAT_FWD       = 0; /* pacotes encaminhados               */
const bit<32> STAT_DROP_SCAN = 1; /* descartados pelo detector           */
const bit<32> STAT_DROP_ACL  = 2; /* descartados por "bloquear host"     */
const bit<32> STAT_ALLOW     = 3; /* pacotes de hosts liberados (bypass) */

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
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

/* Cabecalho TCP (20 bytes fixos; as opcoes ficam no payload, intocadas).
 * As flags sao campos de 1 bit para o codigo ficar legivel: hdr.tcp.syn */
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
    bit<32> idx;      /* slot do IP de origem no detector           */
    bit<1>  bypass;   /* 1 = host liberado por intencao (pula detector) */
    bit<1>  dropped;  /* 1 = alguem ja mandou descartar o pacote     */
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

/*************************************************************************
 *********************** P A R S E R  ************************************
 *************************************************************************/
/* Mesma logica do basic_tunnel, trocando o tunnel por TCP:
 *   start -> ethernet -(0x800)-> ipv4 -(proto 6)-> tcp -> accept        */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* ---- estado escrito pelas INTENCOES (via controlador) ---- */
    register<bit<32>>(1) cfg_enabled;    /* 1 = "bloquear varreduras" ativa   */
    register<bit<32>>(1) cfg_threshold;  /* portas distintas toleradas        */
    register<bit<48>>(1) cfg_window;     /* janela de observacao (microsseg.) */

    /* ---- estado do DETECTOR, um slot por IP de origem ---- */
    register<bit<32>>(N_SLOTS) syn_count;     /* SYNs p/ portas distintas na janela */
    register<bit<16>>(N_SLOTS) last_port;     /* ultima porta destino vista          */
    register<bit<48>>(N_SLOTS) window_start;  /* inicio da janela atual              */
    register<bit<32>>(N_SLOTS) blocked;       /* 1 = origem bloqueada                */
    register<bit<32>>(N_SLOTS) blocked_ip;    /* IP bloqueado (lido pelo controlador)*/

    /* ---- estatisticas para a fase de assurance ---- */
    counter(4, CounterType.packets) intent_stats;

    /* usada como default da ipv4_lpm (destino desconhecido) */
    action drop() {
        meta.dropped = 1;
        mark_to_drop(standard_metadata);
    }

    /* intencao "bloquear host X" */
    action acl_drop() {
        intent_stats.count(STAT_DROP_ACL);
        meta.dropped = 1;
        mark_to_drop(standard_metadata);
    }

    /* intencao "liberar host X": pula o detector */
    action allow_host() {
        intent_stats.count(STAT_ALLOW);
        meta.bypass = 1;
    }

    /* descarte decidido pelo detector de varredura */
    action detector_drop() {
        intent_stats.count(STAT_DROP_SCAN);
        meta.dropped = 1;
        mark_to_drop(standard_metadata);
    }

    /* igual ao tutorial basic */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        intent_stats.count(STAT_FWD);
    }

    /* Tabela preenchida pelas intencoes por host.
     * chave = IP de origem; acao = acl_drop (bloquear) ou allow_host (liberar) */
    table acl {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            acl_drop;
            allow_host;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    /* Tabela de encaminhamento (preenchida pelo s1-runtime.json) */
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
        meta.bypass  = 0;
        meta.dropped = 0;

        if (hdr.ipv4.isValid()) {

            /* ---- 1) intencoes explicitas por host ---- */
            acl.apply();
            if (meta.bypass == 1) {
                hash(meta.idx, HashAlgorithm.crc32, 32w0,
                     { hdr.ipv4.srcAddr }, N_SLOTS);
                blocked.write(meta.idx, 0);
                blocked_ip.write(meta.idx, 0);
                syn_count.write(meta.idx, 0);
            }

            /* ---- 2) detector de varredura de portas ---- */
            bit<32> enabled;
            cfg_enabled.read(enabled, 0);

            if (enabled == 1 && hdr.tcp.isValid() &&
                meta.bypass == 0 && meta.dropped == 0) {

                /* slot deste IP de origem */
                hash(meta.idx, HashAlgorithm.crc32, 32w0,
                     { hdr.ipv4.srcAddr }, N_SLOTS);

                bit<32> is_blocked;
                blocked.read(is_blocked, meta.idx);

                if (is_blocked == 1) {
                    /* ja foi flagrado antes: descarta TUDO dele */
                    detector_drop();

                } else if (hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
                    /* so pacotes de abertura de conexao (SYN puro) contam */
                    bit<32> threshold;
                    bit<48> win_us;
                    bit<48> win_start;
                    bit<32> n_ports;
                    bit<16> lastp;
                    cfg_threshold.read(threshold, 0);
                    cfg_window.read(win_us, 0);
                    window_start.read(win_start, meta.idx);
                    syn_count.read(n_ports, meta.idx);
                    last_port.read(lastp, meta.idx);

                    bit<48> now = standard_metadata.ingress_global_timestamp;

                    /* janela expirou? recomeca a contagem */
                    if (now - win_start > win_us) {
                        n_ports = 0;
                        window_start.write(meta.idx, now);
                    }

                    /* porta diferente da anterior = "porta nova" */
                    if (hdr.tcp.dstPort != lastp) {
                        n_ports = n_ports + 1;
                        last_port.write(meta.idx, hdr.tcp.dstPort);
                    }
                    syn_count.write(meta.idx, n_ports);

                    /* passou do limite definido pela intencao: bloqueia */
                    if (n_ports > threshold) {
                        blocked.write(meta.idx, 1);
                        blocked_ip.write(meta.idx, hdr.ipv4.srcAddr);
                        detector_drop();
                    }
                }
            }

            /* ---- 3) encaminhamento normal ---- */
            if (meta.dropped == 0) {
                ipv4_lpm.apply();
            }
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/
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

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);   /* emit so escreve se o header for valido */
    }
}

/*************************************************************************
 ***********************  S W I T C H  ***********************************
 *************************************************************************/
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
