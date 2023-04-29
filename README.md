# P4 DDoS Defense

## Prerequisites

- linux environment for the scripts
- [docker](https://www.docker.com/) for compiling P4 and data plane
- [p4runtime-shell](https://github.com/p4lang/p4runtime-shell) for control plane
- nc: optional for logging, `apt install netcat-openbsd`

See environment/README.md for more.

## Compile P4

```sh
cd p4
make
```

## Start data plane

```sh
cd experiments/01-ja3
mn --custom mn_custom.py --topo netcfg
```

## Start control plane

Show logging message in the same terminal:

```sh
cd experiments/01-ja3
./10_p4_control.py --topo topos/netcfg.json each -s 1 2 -l -a
```

To show log in a separate terminal, use the following commands:

```
# window 1
nc -klvp 3000

# window 2
./10_p4_control.py --log tcp:localhost:3000 --topo topos/netcfg.json each -s 1 2 -l -a
```

## Start traffic generation

```sh
cd experiments/01-ja3
./20-bg-traffic.sh
```
