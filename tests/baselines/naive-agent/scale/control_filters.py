"""Arrange existing permits on freshly provisioned healthy benchmark replicas."""

from itertools import groupby, permutations
import shlex


def filter_rotations(devices, variant_index):
    rotations = {}
    for role in ("inner", "outer", "firewall"):
        names = sorted(d["id"] for d in devices if d["role"] == role)
        rotations.update((name, i + variant_index) for i, name in enumerate(names))
    return rotations


def movable_permit(row):
    words = shlex.split(row)
    if len(words) < 4 or words[-2:] != ["-j", "ACCEPT"]:
        return False
    matches = words[2:-2]
    if len(matches) % 2:
        return False
    flags = {"-s", "-d", "-i", "-o", "-p", "--sport", "--dport", "--sports", "--dports",
             "--dir", "--pol", "--reqid", "--mode", "--u32"}
    modules = {"tcp", "udp", "multiport", "policy", "u32"}
    return all(flag in flags or (flag == "-m" and arg in modules)
               for flag, arg in zip(matches[::2], matches[1::2]))


def healthy_rule_order(rows, rotation):
    ordered = rows[:1]
    for movable, group in groupby(rows[1:], movable_permit):
        block = list(group)
        if movable:
            window = sorted(block[:4], key=shlex.split)
            orders = list(permutations(window))
            block[:len(window)] = orders[rotation % len(orders)]
        ordered.extend(block)
    return ordered


def healthy_filter_table(text, rotation):
    lines = text.splitlines(keepends=True)
    if [s.strip() for s in lines if s.startswith("*")] != ["*filter"]:
        raise ValueError("Expected one IPv4 filter table")
    for hook in ("INPUT", "FORWARD"):
        positions = [i for i, row in enumerate(lines) if row.startswith("-A " + hook + " ")]
        ordered = healthy_rule_order([lines[i] for i in positions], rotation)
        for i, row in zip(positions, ordered):
            lines[i] = row
    return "".join(lines)
