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

#ifndef __TABLE0__
#define __TABLE0__

#include "headers.p4"
#include "defines.p4"

control Acl(
        inout headers_t hdr,
        inout local_metadata_t meta,
        inout standard_metadata_t stdmeta) {

    direct_counter(CounterType.packets_and_bytes) acl_counter;

    action set_next_hop_id(next_hop_id_t next_hop_id) {
        meta.next_hop_id = next_hop_id;
        acl_counter.count();
    }

    action send_to_cpu() {
        stdmeta.egress_spec = CPU_PORT;
        acl_counter.count();
    }

    action clone_to_cpu() {
        // https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4#L537
        // extern void clone(in CloneType type, in bit<32> session);
        // session: map session to clone port from controll plane
        clone(CloneType.I2E, (bit<32>)CPU_PORT);
    }

    action set_egress_port(port_t port) {
        stdmeta.egress_spec = port;
        acl_counter.count();
    }

    action drop() {
        mark_to_drop(stdmeta);
        meta.skip_next = true;
        acl_counter.count();
    }

    action nop_acl() {
        acl_counter.count();
    }

    table acl {
        key = {
            stdmeta.ingress_port    : ternary @name("ig_port");
            hdr.ethernet.src_addr   : ternary @name("eth_src");
            hdr.ethernet.dst_addr   : ternary @name("eth_dst");
            hdr.ethernet.ether_type : ternary @name("eth_type");
            hdr.ipv4.src_addr       : ternary @name("ipv4_src");
            hdr.ipv4.dst_addr       : ternary @name("ipv4_dst");
            hdr.ipv4.protocol       : ternary @name("ip_proto");
            hdr.tcp.ctrl            : ternary @name("tcp_flag");
            meta.l4_src_port        : ternary @name("l4_sport");
            meta.l4_dst_port        : ternary @name("l4_dport");
            // TLS
            hdr.tls_hsk.msg_type    : ternary @name("tls_hsk_type");
            // ja3[0]
            hdr.tls_client_hello.legacy_version: ternary @name("tls_version");
            // ja3[1]
            hdr.tls_ciphers[0].data   : ternary @name("tls_cipher_0");
            hdr.tls_ciphers[1].data   : ternary @name("tls_cipher_1");
            hdr.tls_ciphers[2].data   : ternary @name("tls_cipher_2");
            hdr.tls_ciphers[3].data   : ternary @name("tls_cipher_3");
            hdr.tls_ciphers[4].data   : ternary @name("tls_cipher_4");
            hdr.tls_ciphers[5].data   : ternary @name("tls_cipher_5");
            hdr.tls_ciphers[6].data   : ternary @name("tls_cipher_6");
            hdr.tls_ciphers[7].data   : ternary @name("tls_cipher_7");
            hdr.tls_ciphers[8].data   : ternary @name("tls_cipher_8");
            hdr.tls_ciphers[9].data   : ternary @name("tls_cipher_9");
            hdr.tls_ciphers[10].data  : ternary @name("tls_cipher_10");
            hdr.tls_ciphers[11].data  : ternary @name("tls_cipher_11");
            hdr.tls_ciphers[12].data  : ternary @name("tls_cipher_12");
            hdr.tls_ciphers[13].data  : ternary @name("tls_cipher_13");
            hdr.tls_ciphers[14].data  : ternary @name("tls_cipher_14");
            hdr.tls_ciphers[15].data  : ternary @name("tls_cipher_15");
            hdr.tls_ciphers[16].data  : ternary @name("tls_cipher_16");
            hdr.tls_ciphers[17].data  : ternary @name("tls_cipher_17");
            hdr.tls_ciphers[18].data  : ternary @name("tls_cipher_18");
            hdr.tls_ciphers[19].data  : ternary @name("tls_cipher_19");
            hdr.tls_ciphers[20].data  : ternary @name("tls_cipher_20");
            hdr.tls_ciphers[21].data  : ternary @name("tls_cipher_21");
            hdr.tls_ciphers[22].data  : ternary @name("tls_cipher_22");
            hdr.tls_ciphers[23].data  : ternary @name("tls_cipher_23");
            hdr.tls_ciphers[24].data  : ternary @name("tls_cipher_24");
            hdr.tls_ciphers[25].data  : ternary @name("tls_cipher_25");
            hdr.tls_ciphers[26].data  : ternary @name("tls_cipher_26");
            hdr.tls_ciphers[27].data  : ternary @name("tls_cipher_27");
            hdr.tls_ciphers[28].data  : ternary @name("tls_cipher_28");
            hdr.tls_ciphers[29].data  : ternary @name("tls_cipher_29");
            hdr.tls_ciphers[30].data  : ternary @name("tls_cipher_30");
            hdr.tls_ciphers[31].data  : ternary @name("tls_cipher_31");
            hdr.tls_ciphers[32].data  : ternary @name("tls_cipher_32");
            hdr.tls_ciphers[33].data  : ternary @name("tls_cipher_33");
            hdr.tls_ciphers[34].data  : ternary @name("tls_cipher_34");
            hdr.tls_ciphers[35].data  : ternary @name("tls_cipher_35");
            hdr.tls_ciphers[36].data  : ternary @name("tls_cipher_36");
            hdr.tls_ciphers[37].data  : ternary @name("tls_cipher_37");
            hdr.tls_ciphers[38].data  : ternary @name("tls_cipher_38");
            hdr.tls_ciphers[39].data  : ternary @name("tls_cipher_39");
            hdr.tls_ciphers[40].data  : ternary @name("tls_cipher_40");
            hdr.tls_ciphers[41].data  : ternary @name("tls_cipher_41");
            hdr.tls_ciphers[42].data  : ternary @name("tls_cipher_42");
            hdr.tls_ciphers[43].data  : ternary @name("tls_cipher_43");
            hdr.tls_ciphers[44].data  : ternary @name("tls_cipher_44");
            hdr.tls_ciphers[45].data  : ternary @name("tls_cipher_45");
            hdr.tls_ciphers[46].data  : ternary @name("tls_cipher_46");
            hdr.tls_ciphers[47].data  : ternary @name("tls_cipher_47");
            hdr.tls_ciphers[48].data  : ternary @name("tls_cipher_48");
            hdr.tls_ciphers[49].data  : ternary @name("tls_cipher_49");
            hdr.tls_ciphers[50].data  : ternary @name("tls_cipher_50");
            hdr.tls_ciphers[51].data  : ternary @name("tls_cipher_51");
            hdr.tls_ciphers[52].data  : ternary @name("tls_cipher_52");
            hdr.tls_ciphers[53].data  : ternary @name("tls_cipher_53");
            hdr.tls_ciphers[54].data  : ternary @name("tls_cipher_54");
            hdr.tls_ciphers[55].data  : ternary @name("tls_cipher_55");
            hdr.tls_ciphers[56].data  : ternary @name("tls_cipher_56");
            hdr.tls_ciphers[57].data  : ternary @name("tls_cipher_57");
            hdr.tls_ciphers[58].data  : ternary @name("tls_cipher_58");
            hdr.tls_ciphers[59].data  : ternary @name("tls_cipher_59");
            hdr.tls_ciphers[60].data  : ternary @name("tls_cipher_60");
            hdr.tls_ciphers[61].data  : ternary @name("tls_cipher_61");
            hdr.tls_ciphers[62].data  : ternary @name("tls_cipher_62");
            hdr.tls_ciphers[63].data  : ternary @name("tls_cipher_63");
            hdr.tls_ciphers[64].data  : ternary @name("tls_cipher_64");
            hdr.tls_ciphers[65].data  : ternary @name("tls_cipher_65");
            hdr.tls_ciphers[66].data  : ternary @name("tls_cipher_66");
            hdr.tls_ciphers[67].data  : ternary @name("tls_cipher_67");
            hdr.tls_ciphers[68].data  : ternary @name("tls_cipher_68");
            hdr.tls_ciphers[69].data  : ternary @name("tls_cipher_69");
            hdr.tls_ciphers[70].data  : ternary @name("tls_cipher_70");
            hdr.tls_ciphers[71].data  : ternary @name("tls_cipher_71");
            hdr.tls_ciphers[72].data  : ternary @name("tls_cipher_72");
            hdr.tls_ciphers[73].data  : ternary @name("tls_cipher_73");
            hdr.tls_ciphers[74].data  : ternary @name("tls_cipher_74");
            hdr.tls_ciphers[75].data  : ternary @name("tls_cipher_75");
            hdr.tls_ciphers[76].data  : ternary @name("tls_cipher_76");
            hdr.tls_ciphers[77].data  : ternary @name("tls_cipher_77");
            hdr.tls_ciphers[78].data  : ternary @name("tls_cipher_78");
            hdr.tls_ciphers[79].data  : ternary @name("tls_cipher_79");
            hdr.tls_ciphers[80].data  : ternary @name("tls_cipher_80");
            hdr.tls_ciphers[81].data  : ternary @name("tls_cipher_81");
            hdr.tls_ciphers[82].data  : ternary @name("tls_cipher_82");
            hdr.tls_ciphers[83].data  : ternary @name("tls_cipher_83");
            hdr.tls_ciphers[84].data  : ternary @name("tls_cipher_84");
            hdr.tls_ciphers[85].data  : ternary @name("tls_cipher_85");
            hdr.tls_ciphers[86].data  : ternary @name("tls_cipher_86");
            hdr.tls_ciphers[87].data  : ternary @name("tls_cipher_87");
            hdr.tls_ciphers[88].data  : ternary @name("tls_cipher_88");
            hdr.tls_ciphers[89].data  : ternary @name("tls_cipher_89");
            hdr.tls_ciphers[90].data  : ternary @name("tls_cipher_90");
            hdr.tls_ciphers[91].data  : ternary @name("tls_cipher_91");
            hdr.tls_ciphers[92].data  : ternary @name("tls_cipher_92");
            hdr.tls_ciphers[93].data  : ternary @name("tls_cipher_93");
            hdr.tls_ciphers[94].data  : ternary @name("tls_cipher_94");
            hdr.tls_ciphers[95].data  : ternary @name("tls_cipher_95");
            hdr.tls_ciphers[96].data  : ternary @name("tls_cipher_96");
            hdr.tls_ciphers[97].data  : ternary @name("tls_cipher_97");
            hdr.tls_ciphers[98].data  : ternary @name("tls_cipher_98");
            hdr.tls_ciphers[99].data  : ternary @name("tls_cipher_99");
            hdr.tls_ciphers[100].data : ternary @name("tls_cipher_100");
            hdr.tls_ciphers[101].data : ternary @name("tls_cipher_101");
            hdr.tls_ciphers[102].data : ternary @name("tls_cipher_102");
            hdr.tls_ciphers[103].data : ternary @name("tls_cipher_103");
            hdr.tls_ciphers[104].data : ternary @name("tls_cipher_104");
            hdr.tls_ciphers[105].data : ternary @name("tls_cipher_105");
            hdr.tls_ciphers[106].data : ternary @name("tls_cipher_106");
            hdr.tls_ciphers[107].data : ternary @name("tls_cipher_107");
            hdr.tls_ciphers[108].data : ternary @name("tls_cipher_108");
            hdr.tls_ciphers[109].data : ternary @name("tls_cipher_109");
            hdr.tls_ciphers[110].data : ternary @name("tls_cipher_110");
            hdr.tls_ciphers[111].data : ternary @name("tls_cipher_111");
            hdr.tls_ciphers[112].data : ternary @name("tls_cipher_112");
            hdr.tls_ciphers[113].data : ternary @name("tls_cipher_113");
            hdr.tls_ciphers[114].data : ternary @name("tls_cipher_114");
            hdr.tls_ciphers[115].data : ternary @name("tls_cipher_115");
            hdr.tls_ciphers[116].data : ternary @name("tls_cipher_116");
            hdr.tls_ciphers[117].data : ternary @name("tls_cipher_117");
            hdr.tls_ciphers[118].data : ternary @name("tls_cipher_118");
            hdr.tls_ciphers[119].data : ternary @name("tls_cipher_119");
            hdr.tls_ciphers[120].data : ternary @name("tls_cipher_120");
            hdr.tls_ciphers[121].data : ternary @name("tls_cipher_121");
            hdr.tls_ciphers[122].data : ternary @name("tls_cipher_122");
            hdr.tls_ciphers[123].data : ternary @name("tls_cipher_123");
            hdr.tls_ciphers[124].data : ternary @name("tls_cipher_124");
            hdr.tls_ciphers[125].data : ternary @name("tls_cipher_125");
            hdr.tls_ciphers[126].data : ternary @name("tls_cipher_126");
            hdr.tls_ciphers[127].data : ternary @name("tls_cipher_127");
            // ja3[2]
            meta.tls_ext_type_0     : ternary @name("tls_ext_type_0");
            meta.tls_ext_type_1     : ternary @name("tls_ext_type_1");
            meta.tls_ext_type_2     : ternary @name("tls_ext_type_2");
            meta.tls_ext_type_3     : ternary @name("tls_ext_type_3");
            meta.tls_ext_type_4     : ternary @name("tls_ext_type_4");
            meta.tls_ext_type_5     : ternary @name("tls_ext_type_5");
            meta.tls_ext_type_6     : ternary @name("tls_ext_type_6");
            meta.tls_ext_type_7     : ternary @name("tls_ext_type_7");
            meta.tls_ext_type_8     : ternary @name("tls_ext_type_8");
            meta.tls_ext_type_9     : ternary @name("tls_ext_type_9");
            meta.tls_ext_type_10    : ternary @name("tls_ext_type_10");
            meta.tls_ext_type_11    : ternary @name("tls_ext_type_11");
            meta.tls_ext_type_12    : ternary @name("tls_ext_type_12");
            meta.tls_ext_type_13    : ternary @name("tls_ext_type_13");
            meta.tls_ext_type_14    : ternary @name("tls_ext_type_14");
            meta.tls_ext_type_15    : ternary @name("tls_ext_type_15");
            meta.tls_ext_type_16    : ternary @name("tls_ext_type_16");
            meta.tls_ext_type_17    : ternary @name("tls_ext_type_17");
            meta.tls_ext_type_18    : ternary @name("tls_ext_type_18");
            meta.tls_ext_type_19    : ternary @name("tls_ext_type_19");
            meta.tls_ext_type_20    : ternary @name("tls_ext_type_20");
            meta.tls_ext_type_21    : ternary @name("tls_ext_type_21");
            meta.tls_ext_type_22    : ternary @name("tls_ext_type_22");
            meta.tls_ext_type_23    : ternary @name("tls_ext_type_23");
            meta.tls_ext_type_24    : ternary @name("tls_ext_type_24");
            meta.tls_ext_type_25    : ternary @name("tls_ext_type_25");
            meta.tls_ext_type_26    : ternary @name("tls_ext_type_26");
            meta.tls_ext_type_27    : ternary @name("tls_ext_type_27");
            meta.tls_ext_type_28    : ternary @name("tls_ext_type_28");
            meta.tls_ext_type_29    : ternary @name("tls_ext_type_29");
            meta.tls_ext_type_30    : ternary @name("tls_ext_type_30");
            meta.tls_ext_type_31    : ternary @name("tls_ext_type_31");
            // ja3[3]
            meta.tls_ext_grps_0     : ternary @name("tls_grp_0");
            meta.tls_ext_grps_1     : ternary @name("tls_grp_1");
            meta.tls_ext_grps_2     : ternary @name("tls_grp_2");
            meta.tls_ext_grps_3     : ternary @name("tls_grp_3");
            meta.tls_ext_grps_4     : ternary @name("tls_grp_4");
            meta.tls_ext_grps_5     : ternary @name("tls_grp_5");
            meta.tls_ext_grps_6     : ternary @name("tls_grp_6");
            meta.tls_ext_grps_7     : ternary @name("tls_grp_7");
            meta.tls_ext_grps_8     : ternary @name("tls_grp_8");
            meta.tls_ext_grps_9     : ternary @name("tls_grp_9");
            meta.tls_ext_grps_10    : ternary @name("tls_grp_10");
            meta.tls_ext_grps_11    : ternary @name("tls_grp_11");
            meta.tls_ext_grps_12    : ternary @name("tls_grp_12");
            meta.tls_ext_grps_13    : ternary @name("tls_grp_13");
            meta.tls_ext_grps_14    : ternary @name("tls_grp_14");
            meta.tls_ext_grps_15    : ternary @name("tls_grp_15");
            meta.tls_ext_grps_16    : ternary @name("tls_grp_16");
            meta.tls_ext_grps_17    : ternary @name("tls_grp_17");
            meta.tls_ext_grps_18    : ternary @name("tls_grp_18");
            meta.tls_ext_grps_19    : ternary @name("tls_grp_19");
            meta.tls_ext_grps_20    : ternary @name("tls_grp_20");
            meta.tls_ext_grps_21    : ternary @name("tls_grp_21");
            meta.tls_ext_grps_22    : ternary @name("tls_grp_22");
            meta.tls_ext_grps_23    : ternary @name("tls_grp_23");
            meta.tls_ext_grps_24    : ternary @name("tls_grp_24");
            meta.tls_ext_grps_25    : ternary @name("tls_grp_25");
            meta.tls_ext_grps_26    : ternary @name("tls_grp_26");
            meta.tls_ext_grps_27    : ternary @name("tls_grp_27");
            meta.tls_ext_grps_28    : ternary @name("tls_grp_28");
            meta.tls_ext_grps_29    : ternary @name("tls_grp_29");
            meta.tls_ext_grps_30    : ternary @name("tls_grp_30");
            meta.tls_ext_grps_31    : ternary @name("tls_grp_31");
            // ja3[4]
            meta.tls_ext_ec_0 : ternary @name("tls_ec_0");
            meta.tls_ext_ec_1 : ternary @name("tls_ec_1");
            meta.tls_ext_ec_2 : ternary @name("tls_ec_2");
            meta.tls_ext_ec_3 : ternary @name("tls_ec_3");
            meta.tls_ext_ec_4 : ternary @name("tls_ec_4");
            meta.tls_ext_ec_5 : ternary @name("tls_ec_5");
            meta.tls_ext_ec_6 : ternary @name("tls_ec_6");
            meta.tls_ext_ec_7 : ternary @name("tls_ec_7");
        }
        actions = {
            set_egress_port;
            send_to_cpu;
            clone_to_cpu;
            set_next_hop_id;
            drop;
            nop_acl;
        }
        const default_action = nop_acl();
        size = ACL_TABLE_SIZE;
        counters = acl_counter;
    }

    apply {
        acl.apply();
     }
}

#endif
