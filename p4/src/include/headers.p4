/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}
const bit<8> ETH_HEADER_LEN = 14;

// https://csie.nqu.edu.tw/smallko/sdn/p4_rtp_h264.htm
header arp_t {
    bit<16> hw_type;
    bit<16> protocol;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> opcode;
    bit<48> hw_src_addr;
    bit<32> proto_src_addr;
    bit<48> hw_dst_addr;
    bit<32> proto_dst_addr;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}
const bit<8> IPV4_MIN_HEAD_LEN = 20;

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header tcp_options_t {
    varbit<320> options;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}
const bit<8> UDP_HEADER_LEN = 8;

header tls_record_t {
    bit<8>  type;
    bit<16> legacy_record_version;
    bit<16> len;
}

header tls_handshake_t {
    bit<8>  msg_type;
    bit<24> len;
}

header tls_client_hello_t {
    bit<16>  legacy_version; // ja3[0]
    bit<256> random;
    // tls_session_t
    // tls_cipher_t
    // tls_compression_t
    // tls_extensions_t
}

header tls_session_t {
    bit<8>   session_id_len;
    varbit<256> legacy_session_id;
}

// header tls_cipher_t {
//     bit<16> cipher_suites_len;
//     varbit<1024> cipher_suites; // ja3[1], two bytes and `-`
// }
header tls_cipher_len_t {
    bit<16> len;
}

header tls_compression_t {
    bit<8> legacy_compression_methods_len;
    varbit<512> legacy_compression_methods;
}

/*
struct tls_extention_t {
    bit<16> type;
    bit<16> len; // in bytes
    varbit data;
}

struct tls_extensions_t {
    bit<16> extensions_len; // in bytes
    tls_extension_t[N];
}
*/
header tls_exts_len_t {
    bit<16> len;
}

// only for lookahead call
// header tls_extension_top_t {
//     bit<16> type;
//     bit<16> len;
// }
// header tls_extension_t {
//     bit<16> type; // ja3[2]
//     bit<16> len;
//     varbit<1024> data; // type == 0x0a: ja3[3], type == 0x0b: ja3[4]
// }

// header tls_extensions_t {
//     bit<16> extensions_len;
//     varbit<1024> extensions; // type, len, data
//     // type: ja3[2], `-` join each type
//     // type == 0x0a, data = [group_len, group(ja3[3])]
//     // type == 0x0b, data = [ec_len, ec(ja3[4])]
// }

header one_byte_t {
    bit<8> data;
}

header two_byte_t {
    bit<16> data;
}

error {
  noAppLayerData,
  TcpDataOffsetTooSmall
}

#endif
