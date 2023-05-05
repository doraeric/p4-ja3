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

#ifndef __PARSERS__
#define __PARSERS__

#include "headers.p4"
#include "defines.p4"

parser parser_impl(
        packet_in packet,
        out headers_t hdr,
        inout local_metadata_t meta,
        inout standard_metadata_t stdmeta) {

    bit<16> reamin_exts_len = 0;
    bit<16> remain_ext_len = 0;
    bit<16> remain_ciphers_len = 0;
    bit<16> grp_len = 0;
    bit<16> grp_idx = 0;
    bit<16> grp = 0;
    bit<16> ext_idx = 0;
    bit<16> ext_type = 0;
    bit<8>  ec_idx = 0;
    state start {
        transition select(stdmeta.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            ETH_TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.l4_src_port = hdr.tcp.src_port;
        meta.l4_dst_port = hdr.tcp.dst_port;
        meta.tcp_len = hdr.ipv4.len - (bit<16>)hdr.ipv4.ihl * 4;
        meta.update_tcp_checksum = false;
        verify(hdr.tcp.data_offset >=5, error.TcpDataOffsetTooSmall);
        transition select(hdr.tcp.data_offset){
            5: parse_app_len;
            default: parse_tcp_options;
        }
    }

    state parse_tcp_options {
        bit<10> len = ((bit<10>)(hdr.tcp.data_offset - 5) * 4 * 8);
        packet.extract(hdr.tcp_options, (bit<32>)len);
        transition parse_app_len;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.l4_src_port = hdr.udp.src_port;
        meta.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_app_len {
        // cast to bit<16> first to prevent overflow
        meta.app_len =
            hdr.ipv4.len - ((bit<16>)hdr.ipv4.ihl + (bit<16>)hdr.tcp.data_offset) * 4;
        transition select(meta.app_len) {
            0: accept;
            default: parse_app;
        }
    }

    state parse_app {
        transition select(hdr.tcp.dst_port) {
            443: parse_tls_record;
            default: accept;
        }
    }

    state parse_tls_record {
        packet.extract(hdr.tls_record);
        transition select(hdr.tls_record.type) {
            TLS_TYPE_HANDSHAKE: parse_tls_handshake;
            default: accept;
        }
    }

    state parse_tls_handshake {
        packet.extract(hdr.tls_hsk);
        transition select(hdr.tls_hsk.msg_type) {
            TLS_HSK_TYPE_CLIENT_HELLO: parse_tls_client_hello;
            default: accept;
        }
    }

    state parse_tls_client_hello {
        packet.extract(hdr.tls_client_hello);
        transition parse_tls_session;
    }

    state parse_tls_session {
        bit<8> tls_sess_len = packet.lookahead<bit<8>>();
        packet.extract(hdr.tls_session, (bit<32>)tls_sess_len*8);
        transition parse_tls_cipher;
    }

    state parse_tls_cipher {
        // bit<16> tls_cipher_len = packet.lookahead<bit<16>>();
        // packet.extract(hdr.tls_cipher, (bit<32>)tls_cipher_len*8);
        packet.extract(hdr.tls_cipher_len);
        remain_ciphers_len = hdr.tls_cipher_len.len;
        transition parse_tls_cipher_entry;
    }
    state parse_tls_cipher_entry {
        transition select(remain_ciphers_len) {
            0: parse_tls_compress;
            default: parse_tls_cipher_entry_2;
        }
    }
    state parse_tls_cipher_entry_2 {
        packet.extract(hdr.tls_ciphers.next);
        remain_ciphers_len = remain_ciphers_len - 2;
        transition parse_tls_cipher_entry;
    }

    state parse_tls_compress {
        bit<8> tls_comp_len = packet.lookahead<bit<8>>();
        packet.extract(hdr.tls_compression, (bit<32>)tls_comp_len*8);
        transition parse_tls_extensions_len;
    }

    state parse_tls_extensions_len {
        packet.extract(hdr.tls_exts_len);
        reamin_exts_len = hdr.tls_exts_len.len;
        ext_idx = 0;
        transition parse_tls_extensions;
    }

    state parse_tls_extensions {
        bit<1> loop = reamin_exts_len > 0 ? 1w1 : 0;
        transition select(loop) {
            1: parse_tls_extension;
            default: accept;
        }
    }

    state parse_tls_extension {
        ext_type = packet.lookahead<bit<16>>();
        packet.extract(hdr.tls_ext_buffer.next);
        packet.extract(hdr.tls_ext_buffer.next);
        bit<16> ext_len = packet.lookahead<bit<16>>();
        packet.extract(hdr.tls_ext_buffer.next);
        packet.extract(hdr.tls_ext_buffer.next);
        reamin_exts_len = reamin_exts_len - 4;
        remain_ext_len = ext_len;
        transition select(ext_idx) {
            0:  save_tls_ext_type_0;
            1:  save_tls_ext_type_1;
            2:  save_tls_ext_type_2;
            3:  save_tls_ext_type_3;
            4:  save_tls_ext_type_4;
            5:  save_tls_ext_type_5;
            6:  save_tls_ext_type_6;
            7:  save_tls_ext_type_7;
            8:  save_tls_ext_type_8;
            9:  save_tls_ext_type_9;
            10: save_tls_ext_type_10;
            11: save_tls_ext_type_11;
            12: save_tls_ext_type_12;
            13: save_tls_ext_type_13;
            14: save_tls_ext_type_14;
            15: save_tls_ext_type_15;
            16: save_tls_ext_type_16;
            17: save_tls_ext_type_17;
            18: save_tls_ext_type_18;
            19: save_tls_ext_type_19;
            20: save_tls_ext_type_20;
            21: save_tls_ext_type_21;
            22: save_tls_ext_type_22;
            23: save_tls_ext_type_23;
            24: save_tls_ext_type_24;
            25: save_tls_ext_type_25;
            26: save_tls_ext_type_26;
            27: save_tls_ext_type_27;
            28: save_tls_ext_type_28;
            29: save_tls_ext_type_29;
            30: save_tls_ext_type_30;
            31: save_tls_ext_type_31;
            default: parse_tls_extension_2;
        }
    }
    state parse_tls_extension_2 {
        transition select(ext_type) {
            0xa: parse_tls_ext_supported_grp;
            0xb: parse_tls_ext_ec_point;
            default: parse_tls_ext_data;
        }
    }
#define save_ext(N) state save_tls_ext_type_##N { \
    meta.tls_ext_type_##N = ext_type; \
    ext_idx = ext_idx + 1; \
    meta.tls_ext_type_len = ext_idx; \
    transition parse_tls_extension_2; \
}
    save_ext(0) save_ext(1) save_ext(2) save_ext(3) save_ext(4) save_ext(5)
    save_ext(6) save_ext(7) save_ext(8) save_ext(9) save_ext(10) save_ext(11)
    save_ext(12) save_ext(13) save_ext(14) save_ext(15) save_ext(16) save_ext(17)
    save_ext(18) save_ext(19) save_ext(20) save_ext(21) save_ext(22) save_ext(23)
    save_ext(24) save_ext(25) save_ext(26) save_ext(27) save_ext(28) save_ext(29)
    save_ext(30) save_ext(31)

    state parse_tls_ext_supported_grp {
        grp_len = packet.lookahead<bit<16>>();
        meta.tls_ext_grp_len = grp_len;
        grp_idx = 0;
        packet.extract(hdr.tls_ext_buffer.next);
        packet.extract(hdr.tls_ext_buffer.next);
        reamin_exts_len = reamin_exts_len - 2;
        remain_ext_len = remain_ext_len - 2;
        transition select(remain_ext_len) {
            0: parse_tls_extensions;
            default: parse_tls_ext_supported_grp_2;
        }
    }
    state parse_tls_ext_supported_grp_2 {
        grp = packet.lookahead<bit<16>>();
        packet.extract(hdr.tls_ext_buffer.next);
        packet.extract(hdr.tls_ext_buffer.next);
        // packet.extract(hdr.tls_ext_buffer.next);
        // grp = (bit<16>)hdr.tls_ext_buffer.last.data;
        // packet.extract(hdr.tls_ext_buffer.next);
        // grp = (grp << 8) | (bit<16>)hdr.tls_ext_buffer.last.data;
        reamin_exts_len = reamin_exts_len - 2;
        remain_ext_len = remain_ext_len - 2;
        // meta.tls_ext_grps[grp_idx].setValid();
        // meta.tls_ext_grps[grp_idx].data = grp;
        // transition select (remain_ext_len) {
        //     0: parse_tls_extensions;
        //     default: parse_tls_ext_supported_grp_2;
        // }
        transition select(grp_idx) {
            0:  save_tls_ext_supported_grp_0;
            1:  save_tls_ext_supported_grp_1;
            2:  save_tls_ext_supported_grp_2;
            3:  save_tls_ext_supported_grp_3;
            4:  save_tls_ext_supported_grp_4;
            5:  save_tls_ext_supported_grp_5;
            6:  save_tls_ext_supported_grp_6;
            7:  save_tls_ext_supported_grp_7;
            8:  save_tls_ext_supported_grp_8;
            9:  save_tls_ext_supported_grp_9;
            10: save_tls_ext_supported_grp_10;
            11: save_tls_ext_supported_grp_11;
            12: save_tls_ext_supported_grp_12;
            13: save_tls_ext_supported_grp_13;
            14: save_tls_ext_supported_grp_14;
            15: save_tls_ext_supported_grp_15;
            16: save_tls_ext_supported_grp_16;
            17: save_tls_ext_supported_grp_17;
            18: save_tls_ext_supported_grp_18;
            19: save_tls_ext_supported_grp_19;
            20: save_tls_ext_supported_grp_20;
            21: save_tls_ext_supported_grp_21;
            22: save_tls_ext_supported_grp_22;
            23: save_tls_ext_supported_grp_23;
            24: save_tls_ext_supported_grp_24;
            25: save_tls_ext_supported_grp_25;
            26: save_tls_ext_supported_grp_26;
            27: save_tls_ext_supported_grp_27;
            28: save_tls_ext_supported_grp_28;
            29: save_tls_ext_supported_grp_29;
            30: save_tls_ext_supported_grp_30;
            31: save_tls_ext_supported_grp_31;
            default: parse_tls_ext_supported_grp_3;
        }
    }
    state parse_tls_ext_supported_grp_3 {
        transition select (remain_ext_len) {
            0: parse_tls_extensions;
            default: parse_tls_ext_supported_grp_2;
        }
    }
#define save_grp(N) state save_tls_ext_supported_grp_##N { \
    meta.tls_ext_grps_##N = grp; \
    grp_idx = grp_idx + 1; \
    transition parse_tls_ext_supported_grp_3; \
}

    save_grp(0) save_grp(1) save_grp(2) save_grp(3) save_grp(4) save_grp(5)
    save_grp(6) save_grp(7) save_grp(8) save_grp(9) save_grp(10) save_grp(11)
    save_grp(12) save_grp(13) save_grp(14) save_grp(15) save_grp(16) save_grp(17)
    save_grp(18) save_grp(19) save_grp(20) save_grp(21) save_grp(22) save_grp(23)
    save_grp(24) save_grp(25) save_grp(26) save_grp(27) save_grp(28) save_grp(29)
    save_grp(30) save_grp(31)

    state parse_tls_ext_ec_point {
        // ec_point_len
        packet.extract(hdr.tls_ext_buffer.next);
        reamin_exts_len = reamin_exts_len - 1;
        remain_ext_len = remain_ext_len - 1;
        ec_idx = 0;
        transition select (remain_ext_len) {
            0: parse_tls_extensions;
            default: parse_tls_ext_ec_point_2;
        }
    }
    state parse_tls_ext_ec_point_2 {
        packet.extract(hdr.tls_ext_buffer.next);
        reamin_exts_len = reamin_exts_len - 1;
        remain_ext_len = remain_ext_len - 1;
        transition select(ec_idx) {
            0: save_tls_ext_ec_0;
            1: save_tls_ext_ec_1;
            2: save_tls_ext_ec_2;
            3: save_tls_ext_ec_3;
            4: save_tls_ext_ec_4;
            5: save_tls_ext_ec_5;
            6: save_tls_ext_ec_6;
            7: save_tls_ext_ec_7;
            default: parse_tls_ext_ec_point_3;
        }
    }
    state parse_tls_ext_ec_point_3 {
        transition select (remain_ext_len) {
            0: parse_tls_extensions;
            default: parse_tls_ext_ec_point_2;
        }
    }
#define save_ec(N) state save_tls_ext_ec_##N { \
    meta.tls_ext_ec_##N = hdr.tls_ext_buffer.last.data; \
    ec_idx = ec_idx + 1; \
    meta.tls_ext_ec_len = ec_idx; \
    transition parse_tls_ext_ec_point_3; \
}
    save_ec(0) save_ec(1) save_ec(2) save_ec(3)
    save_ec(4) save_ec(5) save_ec(6) save_ec(7)

    state parse_tls_ext_data {
        transition select(remain_ext_len) {
            0: parse_tls_extensions;
            default: parse_tls_ext_data_2;
        }
    }
    state parse_tls_ext_data_2 {
        packet.extract(hdr.tls_ext_buffer.next);
        reamin_exts_len = reamin_exts_len - 1;
        remain_ext_len = remain_ext_len - 1;
        transition select(remain_ext_len) {
            0: parse_tls_extensions;
            default: parse_tls_ext_data_2;
        }
    }

    // state parse_tls_extension {
    //     bit<16> ext_len = packet.lookahead<tls_extension_top_t>().len;
    //     packet.extract(hdr.tls_ext.next, (bit<32>)ext_len*8);
    //     reamin_exts_len = reamin_exts_len - 4 - ext_len;
    //     // transition parse_tls_extensions;
    //     transition select(hdr.tls_ext.last.type) {
    //         0xa: record_tls_ext_supported_grp;
    //         0xb: record_tls_ext_ec_point;
    //         default: parse_tls_extensions;
    //     }
    // }

    // state record_tls_ext_supported_grp {
    //     // meta.tls_ext_supported_grp = hdr.tls_ext.last.data;
    //     meta.tls_ext_supported_grp.data = hdr.tls_ext.last.data;
    //     hdr.tls_ext.last.data = hdr.tls_ext.last.data >> 8;
    //     transition parse_tls_extensions;
    // }
    // state record_tls_ext_ec_point {
    //     // meta.tls_ext_ec_point.data = hdr.tls_ext.last.data;
    //     transition parse_tls_extensions;
    // }
}

control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options);
        packet.emit(hdr.udp);
        packet.emit(hdr.tls_record);
        packet.emit(hdr.tls_hsk);
        packet.emit(hdr.tls_client_hello);
        packet.emit(hdr.tls_session);
        // packet.emit(hdr.tls_cipher);
        packet.emit(hdr.tls_cipher_len);
        packet.emit(hdr.tls_ciphers);
        packet.emit(hdr.tls_compression);
        // packet.emit(hdr.tls_ext);
        packet.emit(hdr.tls_exts_len);
        packet.emit(hdr.tls_ext_buffer);
    }
}

#endif
