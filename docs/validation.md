# Validate on a live lab

No live-device results are supplied. Record each result in the evidence template.

1. Inspect interfaces and trunk tags: `show system interface`. Check endpoint IP, gateway, VLAN ID, and host firewall first.
2. Inspect policy order: `show firewall policy`. HQ order after VPN import must be 10, 20, 30, 40, 50, 90. Confirm no earlier existing rule overrides segmentation.
3. Inspect routes: `get router info routing-table all`. Verify connected VLANs and remote routes through the tunnel. The optional default route must lead to a working isolated transit router.
4. Inspect VPN: `get vpn ipsec tunnel summary` and `diagnose vpn tunnel list`. Initiate HTTPS traffic from branch to HQ web and confirm both peers' phase2 selectors and increasing counters. Check PSK, proposals, route, policy, and return path if negotiation or traffic fails.
5. For every traffic-matrix row, start a fresh connection. On Windows use `Test-NetConnection 10.10.20.10 -Port 443`; on Linux use `curl --connect-timeout 5 https://10.10.20.10/` with a locally trusted server certificate. A TLS certificate error after connection is not a firewall denial. Use a known listening service for allow tests.
6. For deny tests, prove the destination service works from an allowed path, then correlate the denied attempt with the matching policy log. A timeout alone does not prove segmentation: host firewall, routing, or absent service can also cause it.
7. Capture a small packet sample when needed: `diagnose sniffer packet any 'host 10.10.20.10 and port 443' 4 20 l`. Confirm the command is supported on your build and end capture after the test. For guest egress, inspect both internal and transit interfaces to verify translated source addresses.
8. Export only sanitized logs/config snippets. Run the offline tools on their supported format. Do not publish PSKs, encrypted passwords, serial numbers, real client addresses, or internal names.

Python CI proves the offline tools and sample expectations. It does not validate FortiOS parsing, licensing, negotiated tunnels, routing, packet behavior, or hardware performance.
