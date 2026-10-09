"""Audit explicit settings in a narrow, flat FortiOS IPv4 policy export."""
import argparse
import json
import shlex
import sys
from pathlib import Path


def parse_policies(text):
    policies, current, stack = [], None, []
    seen = set()
    required = {"srcintf", "dstintf", "srcaddr", "dstaddr", "service", "action"}
    for number, line in enumerate(text.splitlines(), 1):
        parts = shlex.split(line, comments=True)
        if not parts:
            continue
        in_policy = stack == ["firewall policy"]
        command = parts[0]
        if command == "config":
            if in_policy:
                raise ValueError(f"line {number}: nested policy tables unsupported")
            if parts[1:] == ["firewall", "policy"] and stack:
                raise ValueError("VDOM-wrapped policy exports unsupported; extract root policy table")
            if len(parts) < 2:
                raise ValueError(f"line {number}: missing config table")
            stack.append(" ".join(parts[1:]))
        elif command == "end":
            if len(parts) != 1 or not stack or (in_policy and current is not None):
                raise ValueError(f"line {number}: unmatched end or missing next")
            stack.pop()
        elif in_policy:
            if command == "edit":
                if current is not None or len(parts) != 2 or not parts[1].isdigit() or int(parts[1]) <= 0:
                    raise ValueError(f"line {number}: invalid edit")
                if int(parts[1]) in seen:
                    raise ValueError(f"line {number}: duplicate policy id")
                seen.add(int(parts[1]))
                current = {"id": int(parts[1])}
            elif command == "set":
                if current is None or len(parts) < 3:
                    raise ValueError(f"line {number}: invalid set")
                if parts[1] in current:
                    raise ValueError(f"line {number}: duplicate setting {parts[1]}")
                current[parts[1]] = parts[2:]
            elif command == "next":
                if len(parts) != 1 or current is None:
                    raise ValueError(f"line {number}: invalid next")
                if not required.issubset(current):
                    raise ValueError(f"policy {current['id']}: incomplete explicit policy settings")
                if current['action'] not in (["accept"], ["deny"]):
                    raise ValueError(f"policy {current['id']}: unsupported action")
                for key, allowed in {"status": {"enable", "disable"}, "logtraffic": {"all", "utm", "disable"}}.items():
                    if key in current and (len(current[key]) != 1 or current[key][0] not in allowed):
                        raise ValueError(f"policy {current['id']}: invalid {key}")
                policies.append(current)
                current = None
            else:
                raise ValueError(f"line {number}: unsupported policy command {command}")
        elif not stack:
            raise ValueError(f"line {number}: command outside config table")
    if stack or current is not None:
        raise ValueError("unterminated configuration")
    if not policies:
        raise ValueError("no supported firewall policies found")
    return policies


def audit(text):
    policies = parse_policies(text)
    findings = []
    def flag(policy, code, severity, message):
        findings.append({"policy_id": policy["id"], "code": code, "severity": severity, "message": message})
    active = 0
    for p in policies:
        if p.get("status") == ["disable"]:
            continue
        active += 1
        if p.get("logtraffic", ["utm"]) != ["all"]:
            flag(p, "LOGGING_INCOMPLETE", "medium", "Log all sessions for lab evidence; omitted logtraffic defaults to utm.")
        if p["action"] == ["deny"]:
            continue
        if "ALL" in p["service"]:
            flag(p, "ANY_SERVICE", "high", "Accepted policy includes the ALL service.")
        if "all" in p["srcaddr"] and "all" in p["dstaddr"]:
            flag(p, "ANY_ADDRESS", "high", "Accepted policy permits any source and destination address.")
        if "any" in p["srcintf"] or "any" in p["dstintf"]:
            flag(p, "ANY_INTERFACE", "high", "Accepted policy uses an any interface.")
    return {"policies_parsed": len(policies), "active_policies": active, "findings": findings}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = audit(args.config.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if args.fail_on_findings and result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
