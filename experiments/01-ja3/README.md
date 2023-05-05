# JA3 Experiment

## Install Dependencies
```sh
python3 -m pip install git+https://github.com/p4lang/p4runtime-shell
python3 -m pip install dpkt
```

## Network Topology

Generate topo from netcfg.json. The same format as ONOS Network Configuration Service.

See [ONOS Network Configuration guide](https://wiki.onosproject.org/display/ONOS/The+Network+Configuration+Service)

### Topology of netcfg.json
```
┌────┐  ┌───────────┐
│ s1 ├──┤    s2     │
└─┬──┘  └──┬─────┬──┘
  │        │     │
┌─┴──┐  ┌──┴─┐ ┌─┴──┐
│ h1 │  │ h2 │ │ h3 │
└────┘  └────┘ └────┘
```
- s1, s2: switch
- h1: server
- h2, h3: client
