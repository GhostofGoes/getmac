`/proc/net/route` captured in a Linux network namespace (kernel 6.18) whose `eth0` is `192.0.2.10/24`. The kernel shows the interface of these routes as `*`, and sets `RTF_REJECT` (`0x0200`) for unreachable and prohibit routes. All addresses are made up for the test network.

| File | Routes | Default interface |
|------|--------|-------------------|
| `proc_net_route_unreachable_only.out` | `ip route add unreachable default`, no other default | None |
| `proc_net_route_unreachable.out` | `unreachable default metric 10`, then `default via 192.0.2.1 dev eth0 metric 100` | `eth0` |
| `proc_net_route_prohibit.out` | `prohibit default metric 10`, then the `eth0` default at metric 100 | `eth0` |
| `proc_net_route_blackhole.out` | `blackhole default metric 10`, then the `eth0` default at metric 100 | `eth0` |
