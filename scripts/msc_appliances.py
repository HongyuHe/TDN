"""Retain configured startup and namespace-wide appliance observations."""

import json
import re
import shlex

try:
    from msc_operational import parse_resolver
except ModuleNotFoundError:
    from scripts.msc_operational import parse_resolver


LOCAL_ENTRYPOINT = [
    "set -e",
    "ip link set lo up 2>/dev/null || true",
    "rm -f /var/run/frr/*.pid 2>/dev/null || true",
    'exec "$@"',
]

OVS_ENTRYPOINT = r'''
set -e
ip link set lo up 2>/dev/null || true
mkdir -p /var/run/openvswitch /var/log/openvswitch /etc/openvswitch
if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db \
        /usr/share/openvswitch/vswitch.ovsschema
fi
ovsdb-server /etc/openvswitch/conf.db \
    --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile=/var/run/openvswitch/ovsdb-server.pid \
    --log-file=/var/log/openvswitch/ovsdb-server.log \
    --detach
ovs-vsctl --no-wait init
ovs-vswitchd unix:/var/run/openvswitch/db.sock \
    --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
    --log-file=/var/log/openvswitch/ovs-vswitchd.log \
    --detach
exec "$@"
'''


def startup_program(entrypoint, command, script, ovs=None):
    """Interpret only the complete audited startup shape; retain unknown code."""
    if not entrypoint and command == ["sleep", "infinity"] and not script:
        return ["idle"]
    lines = [line.strip() for line in script.splitlines()
             if line.strip() and not line.strip().startswith("#")]
    if (entrypoint == ["/usr/local/bin/twinet-entrypoint"] and
            command == ["sleep", "infinity"] and lines == LOCAL_ENTRYPOINT):
        return ["loopbackUp", "clearStalePID", "idle"]
    if (entrypoint == ["/usr/local/bin/twinet-entrypoint"] and command == ["sleep", "infinity"] and
            lines == [line.strip() for line in OVS_ENTRYPOINT.splitlines() if line.strip()] and ovs is not None):
        peers = re.findall(r"(?m)^\s*(?:Manager|Controller) (.+)$", ovs)
        return ["loopbackUp", {"startSwitch": peers}, "idle"]
    return [{"unknown": json.dumps({"entrypoint": entrypoint, "command": command, "script": script})}]


def host_sources(text):
    rows = []
    for line in text.splitlines():
        body = line.split("#", 1)[0].strip()
        if body.startswith("hosts:"):
            rows.append(shlex.split(body.removeprefix("hosts:")))
    if len(rows) != 1:
        raise ValueError("missing or duplicate name-service hosts configuration")
    return rows[0]


def parse_appliance(observation):
    facts, errors = observation["facts"], observation.get("errors", {})
    if "appliance" not in facts or "appliance" in errors:
        return None
    raw = json.loads(facts["appliance"])
    fields = {"containers", "processes", "worker_before", "worker_after", "device_clock", "ntp_synchronized"}
    if set(raw) != fields or type(raw["ntp_synchronized"]) is not bool:
        raise ValueError("unsupported appliance observation")
    for key in ["worker_before", "worker_after", "device_clock"]:
        if type(raw[key]) is not int or raw[key] < 0:
            raise ValueError("invalid appliance clock")
    if not isinstance(raw["containers"], list) or not isinstance(raw["processes"], list):
        raise ValueError("invalid appliance inventory")
    containers = []
    for row in raw["containers"]:
        if set(row) != {"name", "entrypoint", "command", "script", "resolver", "name_service"}:
            raise ValueError("unsupported startup observation")
        for key in ["name", "script", "resolver", "name_service"]:
            if not isinstance(row[key], str):
                raise ValueError("invalid startup text")
        entrypoint = [] if row["entrypoint"] is None else row["entrypoint"]
        command = [] if row["command"] is None else row["command"]
        if any(not isinstance(xs, list) or any(not isinstance(x, str) for x in xs)
               for xs in [entrypoint, command]):
            raise ValueError("invalid startup arguments")
        ovs = facts.get("ovs") if "ovs" not in errors else None
        containers.append({"name": row["name"], "entrypoint": entrypoint, "command": command,
                           "script": row["script"], "program": startup_program(entrypoint, command, row["script"], ovs),
                           "resolver": {"servers": parse_resolver(row["resolver"]),
                                        "hostSources": host_sources(row["name_service"])}})
    processes = []
    for row in raw["processes"]:
        if (set(row) != {"pid", "name", "executable"} or type(row["pid"]) is not int or row["pid"] <= 0 or
                any(not isinstance(row[k], str) for k in ["name", "executable"])):
            raise ValueError("invalid namespace process")
        processes.append(row)
    return {"device": observation["device"], "containers": containers, "processes": processes,
            "workerBefore": raw["worker_before"], "workerAfter": raw["worker_after"],
            "deviceClock": raw["device_clock"], "ntpSynchronized": raw["ntp_synchronized"]}


def render_appliance(value, record, sequence, quoted):
    def program(action):
        if isinstance(action, str):
            return "." + action
        if "startSwitch" in action:
            return ".startSwitch " + sequence(quoted(peer) for peer in action["startSwitch"])
        return ".unknown " + quoted(action["unknown"])

    def render(v):
        if isinstance(v, bool):
            return str(v).lower()
        if isinstance(v, str):
            return quoted(v)
        if isinstance(v, int):
            return str(v)
        if isinstance(v, list):
            return sequence(render(x) for x in v)
        if isinstance(v, dict):
            return record(**{k: sequence(program(x) for x in item) if k == "program" else render(item)
                             for k, item in v.items()})
        raise ValueError("unsupported appliance field")

    return render(value)
