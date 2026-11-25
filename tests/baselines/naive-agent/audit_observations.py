"""Summarize the network responses that actually reached a blind Detector."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re


ENTRY = re.compile(r'\{"device":\s*"([\w-]+)",\s*"exit":\s*(\d+),\s*"output":\s*"')


def summarize(directory, target=None, applied_rule=None):
    successes = Counter()
    ssh_errors = Counter()
    calls = Counter()
    operations = defaultdict(set)
    relevant = set()
    responses_with_errors = 0
    timeouts = Counter()
    with (directory / "events.jsonl").open() as stream:
        for line in stream:
            event = json.loads(line)
            item = event.get("item", {})
            if (
                event.get("type") != "item.completed"
                or item.get("type") != "mcp_tool_call"
                or item.get("tool") != "observe"
            ):
                continue
            args = item.get("arguments", {})
            network = args.get("network", "")
            op = args.get("observation", "")
            calls[network] += 1
            if (
                item.get("status") == "failed"
                and "timed out" in (item.get("error") or {}).get("message", "").lower()
            ):
                timeouts[network] += 1
            for block in (item.get("result") or {}).get("content", []):
                try:
                    envelope = json.loads(block.get("text", ""))
                except (ValueError, TypeError):
                    if block.get("text"):
                        responses_with_errors += 1
                    continue
                if not isinstance(envelope, dict) or not isinstance(
                    envelope.get("data"), str
                ):
                    continue
                page = envelope["data"]
                entries = list(ENTRY.finditer(page))
                for i, entry in enumerate(entries):
                    device, code = entry.group(1), int(entry.group(2))
                    if code == 255:
                        ssh_errors[network] += 1
                    if code:
                        continue
                    successes[network] += 1
                    operations[device].add(op)
                    if device != target:
                        continue
                    end = entries[i + 1].start() if i + 1 < len(entries) else len(page)
                    visible = page[entry.end() : end]
                    if op in (
                        "configuration",
                        "connections",
                        "sessions",
                        "policies",
                        "states",
                    ):
                        if re.search(r"\bmode\s*=\s*transport\b", visible, re.I):
                            relevant.add("transport mode in " + op)
                        if "127.0.0.2" in visible:
                            relevant.add("loopback peer in " + op)
                    if op == "firewall4" and applied_rule:
                        if applied_rule in visible.replace(r"\n", "\n").splitlines():
                            relevant.add("the inserted IPv4 rule in " + op)
    return {
        "query_count_by_network": dict(calls),
        "visible_success_rows_by_network": dict(successes),
        "visible_ssh_error_rows_by_network": dict(ssh_errors),
        "non_json_error_responses": responses_with_errors,
        "reader_timeouts_by_network": dict(timeouts),
        "target_operations_visible": sorted(operations.get(target, [])),
        "visible_target_settings": sorted(relevant),
        "scope": "Counts cover visible device row headers in returned result pages. A page that begins in the middle of a record can contain more information.",
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("--target")
    a = p.parse_args()
    print(json.dumps(summarize(a.directory, a.target), indent=2))
