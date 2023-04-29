#!/usr/bin/env python3
import argparse
from dataclasses import dataclass, field
from hexdump import hexdump
import json
import logging
import logging.handlers
import os
from pathlib import Path
import readline # noqa
import time
import threading

import IPython
import p4runtime_sh.shell as sh

from gen_full_netcfg import set_default_net_config
from utils import p4sh_helper
from utils.p4sh_helper import P4RTClient
from utils.threading import EventThread

log = logging.getLogger('p4_control')
# Do not propagate to root log
log.propagate = False
formatter = logging.Formatter(
    ('%(asctime)s.%(msecs)03d: %(levelname).1s/%(name)s: '
     '%(filename)s:%(lineno)d: %(message)s'),
    datefmt='%H:%M:%S',
)
default_max_conns = [8, 8, 4]
default_min_conns = [2, 2, 1]


@dataclass
class IpPairInfo:
    # the order is: short_get, short_other, long_other
    index: int
    client: P4RTClient
    max_conns: list[int] = field(default_factory=lambda: [8, 8, 4])
    n_conns: list[int] = field(default_factory=lambda: [0, 0, 0])
    accu_error: list[int] = field(default_factory=lambda: [0, 0, 0])
    error_ts: list[int] = field(default_factory=lambda: [0, 0, 0])


@dataclass
class AppContext:
    net_config: dict
    ip_counter: int = 0
    ip_pair_info: dict[tuple, IpPairInfo] = field(default_factory=dict)
    conns: dict = field(default_factory=dict)
    eth_addr: dict = field(default_factory=dict)


_app_context = AppContext(None)
P4INFO = os.getenv('P4INFO', '../../p4/build/p4info.txt')
P4BIN = os.getenv('P4BIN', '../../p4/build/bmv2.json')


def setup_all_switches() -> None:
    net_config = _app_context.net_config
    for switch in net_config['devices_by_name'].keys():
        client = setup_one_switch(switch)
        client.tear_down()


def setup_one_switch(switch: str) -> P4RTClient:
    log.info('===  Configure switch %s  ===', switch)
    net_config = _app_context.net_config
    switch_info = net_config['devices_by_name'][switch]
    client = P4RTClient(
        device_id=1,
        grpc_addr=f'localhost:{switch_info["basic"]["p4rt_port"]}',
        election_id=(0, 1),  # (high, low)
        p4info_path=P4INFO,
        bin_path=P4BIN,
    )
    sh.context.set_p4info(client.p4i.pb)
    # sh.setup(
    #     device_id=1,
    #     grpc_addr=f'localhost:{switch_info["basic"]["p4rt_port"]}',
    #     election_id=(0, 1),  # (high, low)
    #     config=sh.FwdPipeConfig(P4INFO, P4BIN),
    # )
    # routerIpv4: 10.0.0.1/24
    router_ipv4_net = switch_info['segmentrouting']['routerIpv4']
    router_ipv4_addr = router_ipv4_net.split('/')[0]
    # arp
    target_addr = switch_info['segmentrouting']['routerMac']
    log.info('insert arp %s -> %s', router_ipv4_addr, target_addr)
    te = client.TableEntry('ingress.next.arp_table')(
        action='ingress.next.arp_reply')
    te.match["hdr.arp.opcode"] = "1"
    te.match["hdr.arp.proto_dst_addr"] = router_ipv4_addr
    te.action['target_addr'] = target_addr
    te.insert()
    # default action for no matching packet in subnet: drop
    log.info('drop no matching packet in %s', router_ipv4_net)
    te = client.TableEntry('ingress.next.ipv4_lpm')(
        action='ingress.next.drop')
    te.match["hdr.ipv4.dst_addr"] = router_ipv4_net
    te.insert()
    # forward known destination
    for link in net_config['links_from'][switch]:
        dst_type = link['to']['type']
        dst_name = link['to']['name']
        if dst_type == 'host':
            dst_info = net_config['hosts_by_name'][dst_name]['basic']
            dst_ip = dst_info['ips'][0].split('/')[0]
            log.info('forward dst=%s/32 to host', dst_ip)
            log.debug(
                'dst_addr=%s, port=%s', dst_info['mac'], link['from']['port'])
            te = client.TableEntry('ingress.next.ipv4_lpm')(
                action='ingress.next.ipv4_forward')
            te.match["hdr.ipv4.dst_addr"] = dst_ip + '/32'
            te.action['dst_addr'] = dst_info['mac']
            te.action["port"] = str(link['from']['port'])
            te.insert()
        elif dst_type == 'device':
            dst_info = (net_config['devices_by_name'][dst_name]
                        ['segmentrouting'])
            dst_ip = dst_info['routerIpv4']
            log.info('forward dst=%s to device', dst_ip)
            te = client.TableEntry('ingress.next.ipv4_lpm')(
                action='ingress.next.ipv4_forward')
            te.match["hdr.ipv4.dst_addr"] = dst_ip
            te.action['dst_addr'] = dst_info['routerMac']
            te.action["port"] = str(link['from']['port'])
            te.insert()
    # default gateway, interface or link
    set_gw = False
    for port_info in net_config['ports_by_device'].get(switch, {}).values():
        if not port_info['default_gateway']:
            continue
        port = port_info['port']
        if port_info.get('interfaces') is not None:
            dst_addr = port_info['interfaces'][0]['gw_mac']
        else:
            other = net_config['links_from'][f'device:{switch}/{port}']
            if other['type'] == 'host':
                dst_addr = (net_config['hosts_by_name'][other['name']]
                            ['basic']['mac'])
            else:
                dst_addr = (net_config['devices_by_name'][other['name']]
                            ['segmentrouting']['routerMac'])
        log.info('default gateway: %s', dst_addr)
        te = client.TableEntry('ingress.next.ipv4_lpm')(
            action='ingress.next.ipv4_forward')
        te.action['dst_addr'] = dst_addr
        te.action["port"] = port
        te.insert()
        set_gw = True
        break
    if not set_gw:
        # insert no action as default table entry for consistent behaviour
        log.info('default gateway: no action')
        te = client.TableEntry('ingress.next.ipv4_lpm')(action='NoAction')
        te.insert()
        set_gw = True
    # clone packet to port
    for i in list(range(1, 4)) + [255]:
        clone_entry = client.CloneSessionEntry(session_id=i)
        clone_entry.add(egress_port=i)
        clone_entry.insert()
    return client


def to_tcp_key(members: list[bytes]):
    """Convert bytes to tcp_key for _app_context.conns"""
    assert len(members) == 4
    assert all(len(i) == 4 for i in members[:2])
    ip_str = ['.'.join([str(i) for i in ip]) for ip in members[:2]]
    tcp_ports = [int.from_bytes(i, 'big') for i in members[2:]]
    tcp_key = tuple(sorted(zip(ip_str, tcp_ports)))
    return tcp_key


def handle_digest_timestamp(packet):
    members = packet.data[0].struct.members
    ts = int.from_bytes(members[0].bitstring, 'big')
    ip = int.from_bytes(members[1].bitstring, 'big')
    print(f'ingress_global_timestamp = {ts} us, {ts/1000000} s')
    print(f'ipv4 = {ip>>24&0xff}.{ip>>16&0xff}.{ip>>8&0xff}.{ip&0xff}')


def req_register_read(client: P4RTClient, index: int = 0):
    payload = index
    p = client.PacketOut(b'\2' + payload.to_bytes(2, 'big'))
    p.metadata['handler'] = '2'
    p.send()


def send_updates(updates: list, client: P4RTClient):
    if len(updates) == 0:
        return
    p = client.PacketOut(b'\3%c' % len(updates) + b''.join(updates))
    p.metadata['handler'] = '2'
    p.send()


def handle_new_ip(packet, client: P4RTClient):
    ip_pair_info = _app_context.ip_pair_info
    members = [i.bitstring for i in packet.data[0].struct.members]
    ips = members[:2]
    ip_str = ['.'.join([str(i) for i in ip]) for ip in ips]
    key = tuple(sorted(ips))
    if key in ip_pair_info:
        return
    index = _app_context.ip_counter
    _app_context.ip_counter += 1
    ip_pair_info[key] = IpPairInfo(index=index, client=client)
    info = ip_pair_info[key]
    _app_context.eth_addr[ips[0]] = members[2].rjust(6, b"\0")
    _app_context.eth_addr[ips[1]] = members[3].rjust(6, b"\0")
    # Initialize ip pair register
    # instruction, (index, max_short_get, max_short_other, max_long_other)
    payload = ((index << 12) + (info.max_conns[0] << 8) +
               (info.max_conns[1] << 4) + info.max_conns[2])
    p = client.PacketOut(b'\1' + payload.to_bytes(3, 'big'))
    p.metadata['handler'] = '2'
    # bidirectional
    for ip1, ip2 in [ips, ips[::-1]]:
        te = client.TableEntry('ingress.http_ingress.ip_pair')(
            action='add_meta')
        te.match["hdr.ipv4.src_addr"] = ip1
        te.match["hdr.ipv4.dst_addr"] = ip2
        te.action['index'] = str(index)
        te.insert()
    p.send()
    log.info('> ip_pair[%s] = %s <-> %s', index, ip_str[0], ip_str[1])


def reg_update(index: int, id2: int, op: str, value: int) -> bytes:
    payload = (index << 24) + (id2 << 16) + (ord(op) << 8) + value
    payload = payload.to_bytes(7, 'big')
    return payload


def handle_conn_match(packet, p4i: p4sh_helper.P4Info):
    # names = p4i.get_member_names(packet.digest_id)
    # members = packet.data[0].struct.members
    # values = [int.from_bytes(i.bitstring, 'big') for i in members]
    # msg = dict(zip(names, values))
    # log.info('conn_match: %s', msg)
    pass


def handle_digest_debug(packet):
    pass


def enable_digest(p4i: p4sh_helper.P4Info, name: str) -> None:
    update = p4i.DigestEntry(name).as_update()
    sh.client.write_update(update)
    log.info('Enable digest: %s', name)


def clock(pill: threading.Event):
    while True:
        now = int(time.time())
        for info in _app_context.ip_pair_info.values():
            updates = []
            for i in range(3):
                info.accu_error[i] = 0
                if (info.max_conns[i] < default_max_conns[i] and
                        now - info.error_ts[i] > 60):
                    info.max_conns[i] += 1
                    updates.append(reg_update(info.index, i+3, '+', 1))
                    log.info(
                        '> reg_update(index=%s, id2=%s, op=%s, value=%s)',
                        info.index, i+3, '+', 1
                    )
            if len(updates) > 0:
                p = info.client.PacketOut(
                    b'\3%c' % len(updates)+b''.join(updates))
                p.metadata['handler'] = '2'
                p.send()
        pill.wait(60)
        if pill.is_set():
            break


def setup_switch_listen(switch: str, app_exit: threading.Event) -> P4RTClient:
    """Setup event handler for p4runtime client"""
    client = setup_one_switch(switch)
    p4i = client.p4i

    # Insert digest
    client.enable_all_digest()

    # Listening
    print('Listening on controller for switch "{}"'.format(switch))
    stream_client = p4sh_helper.StreamClient(client, app_exit)

    # callbacks
    @stream_client.on('packet')
    def packet_in_handler(packet):
        print('PacketIn.payload')
        hexdump(packet.payload)
        ingress_port = int.from_bytes(packet.metadata[0].value, 'big')
        print(f'PacketIn.metadata[0]: ingress_port={ingress_port}')

    @stream_client.on('digest')
    def digest_handler(packet):
        name = p4i.get_digest_name(packet.digest_id)
        # log.info('< Receive digest %s #%s len=%s',
        #          name, packet.list_id, len(packet.data))
        if len(packet.data) == 1:
            names = p4i.get_member_names(packet.digest_id)
            members = [i.bitstring for i in packet.data[0].struct.members]
            msg = {k: int.from_bytes(v, 'big') if not k.endswith('_addr')
                   else ('.'.join(str(i) for i in v) if len(v) == 4
                         else ':'.join(f'{i:02x}' for i in v))
                   for k, v in zip(names, members)}
            log.debug('< %s', msg)
        else:
            log.debug(packet)
        if name == 'timestamp_digest_t':
            handle_digest_timestamp(packet)
        elif name == 'debug_digest_t':
            handle_digest_debug(packet)
        elif name == 'conn_match_t':
            handle_conn_match(packet, p4i)
        elif name == 'new_ip_t':
            handle_new_ip(packet, client)

    stream_client.recv_bg()
    return client


def cmd_each(args):
    """Setup each switch and sniff.

    Args:
        args.switch: Switch names. Both `-s 1 2` and `-s s1 s2` are acceptable.
    """
    switches = args.switch
    switches = ['s' + i if not i.startswith('s') else i for i in switches]
    if args.all:
        net_config = _app_context.net_config
        for s in net_config['devices_by_name'].keys():
            if s in switches:
                continue
            client = setup_one_switch(s)
            client.tear_down()
    if not args.listen:
        for switch in switches:
            client = setup_one_switch(switch)
            client.tear_down()
    else:
        app_exit = threading.Event()
        time_thread = EventThread(clock, app_exit)
        time_thread.start()
        clients = {i: setup_switch_listen(i, app_exit) for i in switches}

        # Open IPython shell
        IPython.embed(colors="neutral")
        app_exit.set()
        for client in clients.values():
            client.tear_down()
    return


def setup_logging(logs: list[logging.Logger], args):
    if args.log_level is not None:
        level = logging.getLevelName(args.log_level)
    else:
        level = logging.INFO
    for log in logs:
        log.propagate = False
        log.setLevel(level)
    handlers = []
    if len(args.log) == 0:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        handlers.append(console)
    for log_dest in args.log:
        if log_dest.startswith('tcp:'):
            tcp = log_dest.split(':')
            tcp = logging.handlers.SocketHandler(tcp[1], int(tcp[2]))
            # https://blog.csdn.net/mvpboss1004/article/details/54425819
            tcp.makePickle = lambda r: (tcp.format(r) + '\n').encode('utf-8')
            tcp.setFormatter(formatter)
            handlers.append(tcp)
        elif log_dest.endswith('.log'):
            file_handler = logging.FileHandler(log_dest)
            file_handler.setFormatter(logging.Formatter(
                formatter._fmt, datefmt='%Y-%m-%d %H:%M:%S'))
            handlers.append(file_handler)
        elif log_dest == 'stdout':
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            handlers.append(console)
    for handler in handlers:
        for log in logs:
            log.addHandler(handler)


def main():
    pser = argparse.ArgumentParser()
    pser.add_argument('--log', action='append', default=[],
                      help='log to stdout, tcp:<ip>:<port>, or <file.log>')
    # https://stackoverflow.com/questions/14097061
    pser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Set the logging level")
    pser.add_argument(
        '--debug', '-d', action="store_const", const=logging.DEBUG,
        dest='log_level', help="Set the logging level to debug")
    pser.add_argument('--topo', default='topos/netcfg.json',
                      help='Path to net config json')
    subparsers = pser.add_subparsers(
        required=True, help='Setup rules for all switches or one switch')
    pser_all = subparsers.add_parser('all')
    pser_all.set_defaults(func=lambda args: setup_all_switches())
    pser_each = subparsers.add_parser('each')
    pser_each.add_argument(
        '-s', '--switch', required=True, nargs='+',
        help='The switch name in mininet')
    pser_each.add_argument(
        '-l', '--listen', action='store_true',
        help='Listen on controller for packet in')
    pser_each.add_argument(
        '-a', '--all', action='store_true',
        help='Add rules for all switches, but listening only works for '
        'specified switch')
    pser_each.set_defaults(func=cmd_each)
    args = pser.parse_args()

    setup_logging((log, logging.getLogger('p4sh_helper')), args)
    print(f'P4INFO={Path(P4INFO).resolve()}')
    print(f'P4BIN={Path(P4BIN).resolve()}')
    topo_path = Path(__file__, '..', args.topo).resolve()
    net_config = json.load(topo_path.open())
    set_default_net_config(net_config)
    _app_context.net_config = net_config
    args.func(args)


if __name__ == '__main__':
    main()
