"""Count denied FortiGate forward-traffic events in key=value log text."""
import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import shlex
import sys


def triage(text, threshold=3):
    if threshold < 1:
        raise ValueError("threshold must be a positive integer")
    counts, ports, total, ignored = Counter(), {}, 0, 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = {}
        for token in shlex.split(line):
            if "=" not in token:
                raise ValueError(f"line {number}: expected key=value log tokens")
            key, value = token.split("=", 1)
            if not key or key in fields:
                raise ValueError(f"line {number}: empty or duplicate field")
            fields[key] = value
        if "type" not in fields:
            raise ValueError(f"line {number}: missing type")
        total += 1
        if fields.get("type") != "traffic" or fields.get("subtype") != "forward":
            ignored += 1
            continue
        if not {"srcip", "dstip", "action"}.issubset(fields):
            raise ValueError(f"line {number}: incomplete forward-traffic event")
        source = str(ipaddress.ip_address(fields["srcip"]))
        ipaddress.ip_address(fields["dstip"])
        port = None
        if "dstport" in fields:
            port = int(fields["dstport"])
            if not 0 <= port <= 65535:
                raise ValueError(f"line {number}: invalid destination port")
        if fields["action"] == "deny":
            counts[source] += 1
            if port is not None:
                ports.setdefault(source, set()).add(port)
    if not total:
        raise ValueError("no log events found")
    return {"events_parsed": total, "non_forward_events_ignored": ignored,
            "denied_events": sum(counts.values()), "threshold": threshold,
            "window": "entire input file; no time-window correlation",
            "sources": [{"srcip": source, "denied_events": count,
                         "destination_ports": sorted(ports.get(source, set())),
                         "needs_review": count >= threshold}
                        for source, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        result = triage(args.log.read_text(encoding="utf-8"), args.threshold)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
