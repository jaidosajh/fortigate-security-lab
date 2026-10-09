# Expected traffic matrix

Use endpoints on the stated VLANs and new sessions after policy changes. Return traffic belongs to the established session and does not require a reverse initiation rule.

| Source | Destination | Service | Expected | HQ rule |
| --- | --- | --- | --- | --- |
| Users 10.10.10.10 | Web 10.10.20.10 | TCP 443 | Allow | 20 |
| Users | Any server | TCP 445 or 3389 | Deny | 90 |
| Guest 10.10.30.10 | Internal RFC1918 ranges, including branch | Any | Deny | 10 |
| Guest | Public destination through lab router | TCP 443, TCP/UDP 53 | Allow + SNAT | 30 |
| Guest | Public destination | TCP 22 or 80 | Deny | 90 |
| Users | Public destination through lab router | TCP 443, TCP/UDP 53 | Allow + SNAT | 40 |
| Branch 10.20.10.10 | HQ web 10.10.20.10 over VPN | TCP 443 | Allow, no NAT | 50 on both peers |
| Branch | HQ servers | TCP 445 | Deny | 90 |
| HQ server initiating a new session | Branch | Any | Deny | 90 |
| Management VLAN | Other VLANs | Any | Deny | 90 |

Administration of the firewall via dedicated port3 is device-local traffic and is outside this forwarding matrix. Validate administrator trusted hosts and interface access separately. No ingress VIP/port forwarding is configured. The catch-all deny logs intentionally permitted-to-test failures; it cannot override earlier accepts or pre-existing rules.
