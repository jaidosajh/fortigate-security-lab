# Denied-traffic triage runbook

## Trigger

The offline log tool reports a source with at least the chosen number of denied forward-traffic events in the supplied file. This is a count-based triage signal, not a maliciousness verdict or time-window detector.

## Investigate

1. Confirm event timestamps/timezone, device, log coverage, source asset owner, destination ports, and policy IDs in the original sanitized logs.
2. Separate expected test traffic or application retries from unexpected cross-segment access. Check DHCP/asset records and endpoint telemetry to associate a source IP with a host at the event time.
3. Correlate authentication, EDR, and server logs. Evaluate whether the source is a misconfigured service, vulnerability scanner, or compromised endpoint.
4. Preserve raw evidence and document time range, query, count, uncertainty, and affected assets. Do not infer attack severity from denied-session count alone.

## Contain and recover

If evidence supports compromise, follow the organization's incident process, isolate the endpoint through approved controls, and scope affected identities. Any firewall change needs a defined destination/service scope, expiry, owner, rollback, and connectivity validation. Avoid broad blocking solely on this tool's output.

After remediation, re-run the traffic matrix and confirm business traffic and segmentation. Record lessons learned and detection tuning without publishing customer incident data.
