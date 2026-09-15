//PROGRAMA EQUELETO TIRADO DO REPOSITORIO DO p4

// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_TUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
* This program skeleton defines minimal Ethernet and IPv4 headers and    *
* a simple LPM (Longest-Prefix Match) IPv4 forwarding pipeline.          *
* The exercise intentionally leaves TODOs for learners to implement.     *
*************************************************************************/

typedef bit<9>  egressSpec_t;   // Standard BMv2 uses 9 bits for egress_spec
typedef bit<48> macAddr_t;      // Ethernet MAC address
typedef bit<32> ip4Addr_t;      // IPv4 address


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header tunnel_t {
    bit<16>proto_id;
    bit<16>dst_id;
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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    tunnel_t tunnel;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  *************************************
* New to P4? A typical parser does this:
*   start -> parse_ethernet
*   parse_ethernet:
*       if etherType == TYPE_IPV4 -> parse_ipv4
*       else accept
*   parse_ipv4 -> accept
* This skeleton leaves the actual states as a TODO to implement later.   *
*************************************************************************/

/* TODO: add parser logic
         * Suggested outline:
         *   1) Extract Ethernet: packet.extract(hdr.ethernet);
         *   2) If hdr.ethernet.etherType == TYPE_IPV4 -> parse IPv4
         *   3) Otherwise -> transition accept
    */ 

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parser_ethernet;
    }

    //retira p header ethernet e ve se é do tipo ipv4
    state parser_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            // se for do tipo tunnel, manda pro parser
            TYPE_TUNNEL: parser_Tunnel;
            //se for ipv4, pega o headr
            TYPE_IPV4: parser_ipv4;
            // se n for, aceita
            default: accept;
        }
    }

    state parser_Tunnel {
        packet.extract(hdr.tunnel);
        transition select(hdr.tunnel.proto_id){
            TYPE_IPV4: parser_ipv4;
            default: accept;
        }
    }

    state parser_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}



/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
* High-level intent:
*   - Do an LPM lookup on IPv4 dstAddr
*   - On hit, call ipv4_forward(next-hop MAC, output port)
*   - Otherwise, drop or NoAction (as configured)                         *
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    //recebe ipv4 purissimo do mais alto calibre
    //ve pra onde vai com base no lpm
    action tunnel_ing(bit<16> dst_id){ //troca a porta
        hdr.tunnel.setValid();
        hdr.tunnel.proto_id = TYPE_IPV4;
        hdr.tunnel.dst_id = dst_id;
        hdr.ethernet.etherType = TYPE_TUNNEL;
    }
Prints (capturas de tela) claros evidenciando o funcionamento do laboratório/simulação que foi demonstrado ao vivo
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /*
            Action function for forwarding IPv4 packets.

            TODO: Implement the forwarding steps, for example:
              - standard_metadata.egress_spec = port;
              - hdr.ethernet.dstAddr = dstAddr;
              - (optionally) set hdr.ethernet.srcAddr to the switch MAC for 'port'
              - adjust IPv4 TTL and checksums as needed
        */

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

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
        default_action = NoAction();
    }

    action tunnel_foward(egressSpec_t port){ //manda pra proxima porta
        standard_metadata.egress_spec = port;
    }

    action tunnel_eg(macAddr_t dstAddr, egressSpec_t port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl -1; //BOMBA \
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.tunnel.setInvalid(); // tira o hdr tunnel do pacote
    }

    table tunnel_exact {
        key = {
            hdr.tunnel.dst_id: exact;
        }
        actions = {
            tunnel_foward;
            tunnel_eg;
            drop;
        }
        size = 1024;
        default_action = drop();
    }


    apply {
        /* TODO: fix ingress control logic
         *  - Good practice: apply ipv4_lpm only when the IPv4 header is valid, e.g.:
         *      if (hdr.ipv4.isValid()) { ipv4_lpm.apply(); }
         *    This skeleton currently applies unconditionally for the exercise.
         */
        if (hdr.ipv4.isValid() && !hdr.tunnel.isValid()){ipv4_lpm.apply();}

        if(hdr.tunnel.isValid()){tunnel_exact.apply();}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
* Often used for queue marks, mirroring, or post-routing edits.          *
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
* This block shows how to compute IPv4 header checksum when needed.      *
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
* The deparser serializes headers back onto the packet in order.         *
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /*
        Typical implementation (left as a TODO for learners):
            packet.emit(hdr.ethernet);
            packet.emit(hdr.ipv4);   // per P4_16 spec, emit appends a header
                                     // only if it is valid; no 'if' needed.
        */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.tunnel);
        packet.emit(hdr.ipv4);
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
