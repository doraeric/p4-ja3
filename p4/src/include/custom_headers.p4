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

#ifndef __CUSTOM_HEADERS__
#define __CUSTOM_HEADERS__
struct headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    tcp_options_t tcp_options;
    tls_record_t tls_record;
    tls_handshake_t tls_hsk;
    tls_client_hello_t tls_client_hello;
    tls_session_t tls_session;
    // tls_cipher_t tls_cipher;
    tls_cipher_len_t tls_cipher_len;
    two_byte_t[128] tls_ciphers;
    tls_compression_t tls_compression;
    tls_exts_len_t tls_exts_len;
    // tls_extension_t[64] tls_ext;
    one_byte_t[256] tls_ext_buffer;
}

struct local_metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
    next_hop_id_t next_hop_id;
    bool skip_next; // skip control pipelines
    @field_list(1)
    bool          update_tcp_checksum;
    @field_list(1)
    bit<16>       app_len; // app-layer length in bytes
    @field_list(1)
    bit<16> tcp_len;
    bit<16> tls_ext_type_len;
    bit<16> tls_ext_type_0;
    bit<16> tls_ext_type_1;
    bit<16> tls_ext_type_2;
    bit<16> tls_ext_type_3;
    bit<16> tls_ext_type_4;
    bit<16> tls_ext_type_5;
    bit<16> tls_ext_type_6;
    bit<16> tls_ext_type_7;
    bit<16> tls_ext_type_8;
    bit<16> tls_ext_type_9;
    bit<16> tls_ext_type_10;
    bit<16> tls_ext_type_11;
    bit<16> tls_ext_type_12;
    bit<16> tls_ext_type_13;
    bit<16> tls_ext_type_14;
    bit<16> tls_ext_type_15;
    bit<16> tls_ext_type_16;
    bit<16> tls_ext_type_17;
    bit<16> tls_ext_type_18;
    bit<16> tls_ext_type_19;
    bit<16> tls_ext_type_20;
    bit<16> tls_ext_type_21;
    bit<16> tls_ext_type_22;
    bit<16> tls_ext_type_23;
    bit<16> tls_ext_type_24;
    bit<16> tls_ext_type_25;
    bit<16> tls_ext_type_26;
    bit<16> tls_ext_type_27;
    bit<16> tls_ext_type_28;
    bit<16> tls_ext_type_29;
    bit<16> tls_ext_type_30;
    bit<16> tls_ext_type_31;
    bit<16> tls_ext_grp_len;
    // https://github.com/jafingerhut/p4-guide/blob/master/README-header-stacks.md
    // two_byte_t[32] tls_ext_grps;
    bit<16> tls_ext_grps_0;
    bit<16> tls_ext_grps_1;
    bit<16> tls_ext_grps_2;
    bit<16> tls_ext_grps_3;
    bit<16> tls_ext_grps_4;
    bit<16> tls_ext_grps_5;
    bit<16> tls_ext_grps_6;
    bit<16> tls_ext_grps_7;
    bit<16> tls_ext_grps_8;
    bit<16> tls_ext_grps_9;
    bit<16> tls_ext_grps_10;
    bit<16> tls_ext_grps_11;
    bit<16> tls_ext_grps_12;
    bit<16> tls_ext_grps_13;
    bit<16> tls_ext_grps_14;
    bit<16> tls_ext_grps_15;
    bit<16> tls_ext_grps_16;
    bit<16> tls_ext_grps_17;
    bit<16> tls_ext_grps_18;
    bit<16> tls_ext_grps_19;
    bit<16> tls_ext_grps_20;
    bit<16> tls_ext_grps_21;
    bit<16> tls_ext_grps_22;
    bit<16> tls_ext_grps_23;
    bit<16> tls_ext_grps_24;
    bit<16> tls_ext_grps_25;
    bit<16> tls_ext_grps_26;
    bit<16> tls_ext_grps_27;
    bit<16> tls_ext_grps_28;
    bit<16> tls_ext_grps_29;
    bit<16> tls_ext_grps_30;
    bit<16> tls_ext_grps_31;
    bit<8> tls_ext_ec_len;
    bit<8> tls_ext_ec_0;
    bit<8> tls_ext_ec_1;
    bit<8> tls_ext_ec_2;
    bit<8> tls_ext_ec_3;
    bit<8> tls_ext_ec_4;
    bit<8> tls_ext_ec_5;
    bit<8> tls_ext_ec_6;
    bit<8> tls_ext_ec_7;
}

#endif
