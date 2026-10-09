# Offline tool contracts

## Policy audit

Input: plain UTF-8 CLI text with at least one flat `config firewall policy` table. Other config tables are skipped. VDOM wrappers, nested policy tables, `unset`, `append`, `move`, repeated edits/settings, missing required explicit fields, and unknown policy actions fail with exit 2. This is a static settings review, not a complete FortiOS parser. Extract a standalone policy table from an actual `show` export before use; VPN templates include commands outside the supported audit subset.

Checks on enabled policies: session logging (`logtraffic all`), literal `ALL` service on accepts, literal `all` on both source and destination addresses, and literal `any` interfaces on accepts. Deny rules are checked only for logging. Disabled policies are counted but skipped. Omitted status assumes enabled; omitted logtraffic assumes the documented `utm` default. Custom services, groups, internet-service settings, negate flags, VIPs, policy order, routing, identity, and local-in access are not evaluated. A zero-finding result means only these narrow checks passed.

Output: JSON with policy counts and findings. Exit 0 for a successfully parsed audit; `--fail-on-findings` changes findings to exit 1. Input errors exit 2. No writes or connections are made.

## Log triage

Input: plain key=value FortiGate traffic logs, including quoted values. Comments/blank lines are skipped. Raw syslog prefixes, JSON logs, CSV, duplicate fields, invalid IPs/ports, incomplete forward events, and malformed quotes are rejected. Strip syslog framing during a trusted export step; the tool does not silently guess fields. Non-forward records with a type field are counted and ignored.

Only literal `action=deny` forward events are counted. `close`, `accept`, UTM blocks, local-in traffic, session duplicates, IPv4/IPv6 mapping, and deny causes are not correlated. Counts cover the whole file, not a time window. `--threshold` is a positive integer; the flag asks for review without attributing malicious intent.

Output: JSON with event counts, denied sources, destination ports, and review flags. Valid input exits 0; invalid input exits 2. The tool uses the Python standard library and never connects to a device.
