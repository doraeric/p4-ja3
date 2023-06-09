from utils.p4sh_helper import P4RTClient
from utils import protocol


def rst_entry(
    client: P4RTClient,
    src_ip: bytes, dst_ip: bytes, src_port: bytes, dst_port: bytes
):
    te = client.TableEntry('ingress.http_ingress.conn')(
        action='add_bad_meta')
    te.match["hdr.ipv4.src_addr"] = src_ip
    te.match["hdr.ipv4.dst_addr"] = dst_ip
    te.match["hdr.tcp.src_port"] = src_port
    te.match["hdr.tcp.dst_port"] = dst_port
    return te


def drop_syn(client: P4RTClient, src_ip: bytes, dst_ip: bytes):
    te = client.TableEntry('ingress.acl.acl')(action='ingress.acl.drop')
    te.priority = 1
    te.match["eth_type"] = protocol.ETH_TYPE_IPV4
    te.match["ip_proto"] = protocol.IP_PROTO_TCP
    te.match["ipv4_src"] = src_ip
    te.match["ipv4_dst"] = dst_ip
    te.match["tcp_flag"] = b'\x02'
    return te


def drop_by_ja3(client: P4RTClient, ja3: str):
    te = client.TableEntry('ingress.acl.acl')(action='ingress.acl.drop')
    te.priority = 80
    ja3 = ja3.split(',')
    te.match['tls_version'] = ja3[0]
    ciphers = ja3[1].split('-')
    for i, cipher in enumerate(ciphers):
        te.match[f'tls_cipher_{i}'] = cipher
        if i >= 128:
            break
    types = ja3[2].split('-')
    for i, typ in enumerate(types):
        te.match[f'tls_ext_type_{i}'] = typ
        if i >= 32:
            break
    groups = ja3[3].split('-')
    for i, grp in enumerate(groups):
        te.match[f'tls_grp_{i}'] = grp
        if i >= 32:
            break
    ecs = ja3[4].split('-')
    for i, ec in enumerate(ecs):
        te.match[f'tls_ec_{i}'] = ec
        if i >= 8:
            break
    return te


def clone_tls_client_hello(client: P4RTClient):
    te = client.TableEntry('ingress.acl.acl')(
        action='ingress.acl.clone_to_cpu')
    te.priority = 10
    te.match['tls_hsk_type'] = '1'
    return te
