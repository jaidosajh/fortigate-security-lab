# Build the isolated lab

## Requirements and assumptions

- Two licensed FortiGate VMs or spare appliances, console access, and snapshots/backups.
- FortiOS 7.4 syntax reference; confirm each command against your actual build. Use a currently supported, patched firmware version appropriate to your model.
- HQ port1: isolated WAN transit, port2: tagged VLAN trunk, port3: dedicated management connection.
- Branch port1: same transit, port2: branch LAN, port3: management.
- A transit router at 192.0.2.1 if exercising egress. Documentation-range addresses here are lab placeholders, not usable public internet addresses.
- Static endpoint addresses; DHCP, AD, DNS servers, security subscriptions, and remote access VPN are outside this initial lab.

## Build order

1. Snapshot both devices. Keep console access open. Start with clean devices: existing rules, switch membership, SD-WAN, central NAT, VDOMs, or zones can change behavior. Use root VDOM, policy NAT, and no SD-WAN for this exercise.
2. Wire isolated transit and trunk networks. Remove port2/port3 from default hardware or software switches as needed using model-specific instructions. Do not connect the lab trunk to a production switch.
3. Configure HQ using `configs/hq-interfaces.conf`. The trunk carries VLAN IDs 10, 20, 30, and 99; test endpoints use `.1` as their gateway. Dedicated port3 management is 10.255.0.1/24; admin workstation is 10.255.0.10. Disable WAN management and verify trusted administrator access before changing it. VLAN99 is an infrastructure segment; port3 is the firewall's management path.
4. Configure branch using `configs/branch-interfaces.conf`; branch endpoint gateway is 10.20.10.1. Branch port3 is 10.255.1.1/24, administered locally from 10.255.1.10.
5. Review HQ address/service definitions and policy IDs in `configs/hq-policies.conf`, then apply to the clean HQ. Policies are evaluated in displayed order. Users may reach only the lab web server and public egress services listed in the matrix; guest access to internal ranges is explicitly denied and logged.
6. On a local copy of both VPN templates, replace `__LOCAL_PSK__` with the same strong generated secret. Never commit rendered files. Apply HQ and branch templates only after interfaces and HQ policies exist. Branch VPN template includes its own address and service objects.
7. Use static IPs for endpoints in each VLAN. Configure public resolvers on user/guest endpoints for the optional egress exercise; the example allows DNS over TCP/UDP 53. Server endpoint 10.10.20.10 should listen on HTTPS 443. Keep its host firewall enabled.
8. Apply the transit default routes only when a lab router exists. Run `get router info routing-table all`, `show firewall policy`, and VPN checks from the validation guide.
9. Set device time/NTP for correlated evidence. Configure a dedicated log destination appropriate to your model/license; policy logging alone does not guarantee persistent logs. Memory logging can be enabled in a disposable VM if supported (`config log memory setting`, `set status enable`, `end`). Confirm actual logs before collecting evidence.

The minimal lab omits IPS/AV subscriptions, TLS inspection, administrator account hardening, local-in policies, and production identity integration. Those require separate design and testing. Forwarding policies do not restrict access to the FortiGate itself; interface allowaccess and administrator trusted hosts must be reviewed separately.

## Rollback

Disconnect lab transit if unexpected connectivity occurs. Restore both snapshots or saved configurations using console access. Delete locally rendered VPN files when finished; rotate the lab PSK if it was exposed. Re-run the traffic matrix after each configuration change.
