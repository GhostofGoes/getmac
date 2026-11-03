# Link aggregations, VLANs, and IPMP

Real output from the same VM as the parent directory, from a separate boot, with more
types of links added as root:

- `aggr0`: a link aggregation of two simulated NICs (`dladm create-simnet`, then
  `dladm create-aggr`), since the VM only has one NIC
- `vlan5`: a VLAN on the NIC
- `vnic1` and `vnic2`: VNICs on the NIC, in the IPMP group `ipmp0` (address `10.9.9.9`)
- `stub0` and `vnic9`: an etherstub, and a VNIC on it

The aggregation and the VLAN are temporary (`-t`), so they don't have IP interfaces,
which is why `ifconfig aggr0` fails. `non-root/` is the same commands as a regular user.
