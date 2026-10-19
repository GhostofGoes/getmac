`/proc/net/route` captured from a client in a Linux network namespace (kernel 6.18), connected over a veth pair to a server in a second namespace. The client's `eth0` is `192.0.2.10/24` with its default route via `192.0.2.1`. All addresses are documentation or private ranges made up for the test network.

| File | VPN | Client setup | Default interface |
|------|-----|--------------|-------------------|
| `proc_net_route_openvpn_def1_tun.out` | OpenVPN 2.6.19 | `--dev tun0 --redirect-gateway def1`, `eth0` default at metric 100 | `eth0` |
| `proc_net_route_openvpn_def1_tap.out` | OpenVPN 2.6.19 | `--dev tap0 --redirect-gateway def1` | `eth0` |
| `proc_net_route_openvpn_redirect_gateway.out` | OpenVPN 2.6.19 | `--dev tun0 --redirect-gateway` (replaces the default) | `tun0` |
| `proc_net_route_openvpn_split.out` | OpenVPN 2.6.19 | `--dev tun0 --route 198.51.100.0 255.255.255.0` | `eth0` |
| `proc_net_route_wireguard_full.out` | wg-quick, wireguard-go 0.0.20230223 | `AllowedIPs = 0.0.0.0/0` (wg-quick uses a policy routing table, so the main table is unchanged) | `eth0` |
| `proc_net_route_wireguard_def1.out` | wg-quick, wireguard-go 0.0.20230223 | `AllowedIPs = 0.0.0.0/1, 128.0.0.0/1` | `eth0` |
| `proc_net_route_wireguard_table_main.out` | wg-quick, wireguard-go 0.0.20230223 | `AllowedIPs = 0.0.0.0/0`, `Table = main`, `eth0` default at metric 100 | `wg0` |
| `proc_net_route_wireguard_split.out` | wg-quick, wireguard-go 0.0.20230223 | `AllowedIPs = 10.66.0.0/24, 198.51.100.0/24` | `eth0` |
