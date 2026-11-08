"""Add peer-bound source-port IPsec UDP rules while preserving earlier filters."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def mirrored_program(value):
    parts = value.strip().split(",")
    instructions = [tuple(map(int, item.split())) for item in parts[1:]]
    if len(instructions) != 62 or int(parts[0]) != 62:
        raise ValueError("Expected the 62-instruction framing program")
    if instructions[29] != (72, 0, 0, 2):
        raise ValueError("Unexpected UDP destination-port load")
    instructions[29] = (72, 0, 0, 0)
    return "62," + ",".join(" ".join(map(str, item)) for item in instructions)


def extend_rules(text, original, mirrored):
    existing = {tuple(shlex.split(line)) for line in text.splitlines() if line.startswith("-A ")}
    result, additions = [], []
    for line in text.splitlines():
        result.append(line)
        if not line.startswith("-A "):
            continue
        tokens = shlex.split(line)
        if "--dports" not in tokens or "--bytecode" not in tokens:
            continue
        if tokens[tokens.index("--dports") + 1] != "500,4500":
            continue
        if tokens[tokens.index("--bytecode") + 1] != original:
            raise ValueError("Unrecognized framing guard; refusing to change rules")
        if tokens[tokens.index("-j") + 1] != "ACCEPT":
            continue
        if "-s" not in tokens or "-d" not in tokens:
            raise ValueError("The existing allowance is not bound to both peers")
        tokens[tokens.index("--dports")] = "--sports"
        tokens[tokens.index("--bytecode") + 1] = mirrored
        if tuple(tokens) in existing:
            continue
        rendered = " ".join('"' + token + '"' if " " in token else token for token in tokens)
        result.append(rendered)
        additions.append(rendered)
    return "\n".join(result) + "\n", additions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--containers", nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    original = Path(__file__).with_name("ipsec-udp-framing-options-bytecode.txt").read_text().strip()
    mirrored = mirrored_program(original)
    records, changed = [], []
    def command(argv, stdin=None):
        result = subprocess.run(argv, input=stdin, text=True, capture_output=True, timeout=30)
        records.append({"at": datetime.now(timezone.utc).isoformat(), "argv": argv,
                        "returncode": result.returncode, "stdout": result.stdout,
                        "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout
    plans = []
    try:
        for container in args.containers:
            if not container.replace("_", "").replace("-", "").isalnum():
                raise ValueError("Invalid container name")
            before = command(["docker", "exec", container, "iptables-save"])
            proposed, additions = extend_rules(before, original, mirrored)
            (args.output / (container + ".before.rules")).write_text(before)
            (args.output / (container + ".proposed.rules")).write_text(proposed)
            plans.append({"container": container, "additions": additions})
            if args.apply and additions:
                command(["docker", "exec", "-i", container, "iptables-restore", "--test"], proposed)
                changed.append((container, before))
                command(["docker", "exec", "-i", container, "iptables-restore"], proposed)
            after = command(["docker", "exec", container, "iptables-save"])
            (args.output / (container + ".after.rules")).write_text(after)
            if args.apply:
                actual = {tuple(shlex.split(line)) for line in after.splitlines() if line.startswith("-A ")}
                if any(tuple(shlex.split(line)) not in actual for line in additions):
                    raise RuntimeError("Read-back is missing an installed reply rule")
    except Exception:
        for container, before in reversed(changed):
            command(["docker", "exec", "-i", container, "iptables-restore"], before)
        raise
    finally:
        (args.output / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        (args.output / "plan.json").write_text(json.dumps({"applied": args.apply, "devices": plans}, indent=2) + "\n")
        (args.output / "source-port-bytecode.txt").write_text(mirrored + "\n")
        (args.output / "collector.py").write_bytes(Path(__file__).read_bytes())
        manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.output.iterdir() if p.is_file()}
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"applied": args.apply, "devices": len(plans), "added_rules": sum(len(p["additions"]) for p in plans)}))


if __name__ == "__main__":
    main()
