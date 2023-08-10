#include <core.p4>
#include <v1model.p4>
 
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
 
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
 
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}
 
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
 
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct meta_t {
    bit<1>  do_forward;
    bit<32> ipv4_sa;
    bit<32> ipv4_da;
    bit<16> tcp_sp;
    bit<16> tcp_dp;
    bit<32> nhop_ipv4;
    bit<32> if_ipv4_addr;
    bit<48> if_mac_addr;
    bit<1>  is_ext_if;
    bit<16> tcpLength;
    bit<8>  if_index;
}
 
struct mymetadata_t {
    bit<13> flowlet_map_index;
    bit<2>  flowlet_select;
}
 
struct metadata {
    meta_t       meta;
    mymetadata_t mymetadata;
    macAddr_t dstAddr;
    egressSpec_t port;
    bit<8>  lower;
    bit<8>  upper;    
    bit<8>  result;
    bit<1>  final;
    bit<2>  random;
}
 
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}
 
 
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
 
parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        meta.result=127;
        meta.final=0;
        meta.meta.if_index = (bit<8>)standard_metadata.ingress_port;
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.meta.ipv4_sa = hdr.ipv4.srcAddr;
        meta.meta.ipv4_da = hdr.ipv4.dstAddr;
        meta.meta.tcpLength = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.meta.tcp_sp = hdr.tcp.srcPort;
        meta.meta.tcp_dp = hdr.tcp.dstPort;
        transition accept;
    }
}
 
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
 
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action rewrite_sip(bit<32> sip) {
        hdr.ipv4.srcAddr = sip;
    }
    action nop() {
    }
    table send_frame {
        actions = {
            _drop;
            rewrite_sip;
            nop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}
 
register<bit<2>>(32w8192) flowlet_select;
 
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
 
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
 
    action set_ecmp_select() {
        hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
        meta.mymetadata.flowlet_select = (bit<2>)meta.random;
        flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, meta.mymetadata.flowlet_select);
    }
 
    action nop() {
    }
 
    action set_ecmp_nhop(bit<48> nhop_mac, bit<32> nhop_ipv4, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.dstAddr = nhop_ipv4;
        hdr.ethernet.dstAddr = nhop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
 
    action set_nhop(bit<48> dmac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
 
    action read_flowlet_select() {
        hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
        flowlet_select.read(meta.mymetadata.flowlet_select, (bit<32>)meta.mymetadata.flowlet_map_index);
    }
 
    action set_param1(bit<8> lower, bit<8> upper, bit<2> ran) {
        random(meta.result, (bit<8>)1,(bit<8>)100);
        meta.lower=lower;
        meta.upper=upper;
        meta.random=ran;
    }
 
    action set_param2(bit<8> lower, bit<8> upper, bit<2> ran) {
        meta.lower=lower;
        meta.upper=upper;
        meta.random=ran;
    }
 
    action myforward(){
        meta.final=1;
    }
 
    table ecmp_group {
        actions = {
            _drop;
            set_ecmp_select;
            nop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
 
    table ecmp_nhop {
        actions = {
            _drop;
            set_ecmp_nhop;
            nop;
        }
        key = {
            meta.mymetadata.flowlet_select: exact;
        }
        size = 1024;
    }
 
    table forward {
        actions = {
            _drop;
            set_nhop;
            nop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
 
    table forward1 {
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.final: exact;
        }
        actions = {
            _drop;
            set_param1;
            nop;
        }
        size = 1024;
    }
 
    table forward2 {
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.final: exact;
        }
        actions = {
            _drop;
            set_param2;
            nop;
        }
        size = 1024;
    }
   
    table forward3 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            _drop;
            read_flowlet_select;
            nop;
        }
        size = 1024;
    }
 
    apply {
        if (hdr.tcp.flags & 8w2 != 8w0) {
            forward1.apply();
            if (meta.result >= meta.lower && meta.result <= meta.upper){
                myforward();
            }
            if (meta.final==0){
                forward2.apply();
                if (meta.result >= meta.lower && meta.result <= meta.upper){
                  myforward();
                }
            }
            ecmp_group.apply();
        }
        if (hdr.tcp.flags & 8w16 != 8w0) {
            forward3.apply();
        }
        forward.apply();
        ecmp_nhop.apply();
    }
}
 
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
 
control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}
 
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
 
control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        verify_checksum_with_payload(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}
 
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
 
control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum_with_payload(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}
 
/*************************************************************************
 
***********************  S W I T C H  *******************************
 
*************************************************************************/
 
V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
