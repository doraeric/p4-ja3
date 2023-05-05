#ifndef __TLS_P4__
#define __TLS_P4__

#include "headers.p4"
#include "defines.p4"

struct tls_ja3_t {
    bit<16> tls_version;
    bit<16> cipher_len;
    bit<16> cipher_0;
    bit<16> tls_ext_type_len;
    bit<16> tls_ext_type_0;
    bit<16> grp_len;
    bit<16> grp_0;
    bit<8>  ec_len;
    bit<8>  ec_0;
}

control tls(
        inout headers_t hdr,
        inout local_metadata_t meta,
        inout standard_metadata_t stdmeta) {
    apply {
        if (hdr.tls_exts_len.isValid()) {
            digest<tls_ja3_t>(1, {
                hdr.tls_client_hello.legacy_version,
                hdr.tls_cipher_len.len/2,
                hdr.tls_ciphers[0].data,
                meta.tls_ext_type_len,
                meta.tls_ext_type_0,
                meta.tls_ext_grp_len,
                meta.tls_ext_grps_0,
                meta.tls_ext_ec_len,
                meta.tls_ext_ec_0
            });
        }
    }
}

#endif // __TLS_P4__
