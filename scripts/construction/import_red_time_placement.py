"""Bind one actual time service to its Inner client's Red bridge."""
import argparse
import json
from pathlib import Path
import re

from import_service_authorization import validate_public_bundle, require


def one(rows, command):
    selected = [r for r in rows if r["command"] == command]
    require(len(selected) == 1 and selected[0]["returncode"] == 0, "Missing successful exact placement command")
    return selected[0]


def parse(clocks, setup):
    clocks, setup = Path(clocks), Path(setup)
    clock = validate_public_bundle(clocks)
    installed = validate_public_bundle(setup)
    require(clock["error"] is None, "Clock placement collection failed")
    setup_error = installed["error"]
    require(setup_error is None or (isinstance(setup_error, str) and
            "/usr/local/libexec/ipsec/charon" in setup_error and
            "timed out after 45 seconds" in setup_error),
            "Unreviewed setup failure")
    #* The retained setup failed after the successful attachment prefix.
    #* Later current guest and source-veth observations corroborate that prefix.
    rows, initial = clock["records"], installed["records"]
    used = []
    for command in [
        ["ip", "link", "add", "nt3h0", "type", "veth", "peer", "name", "nt3p0"],
        ["ip", "link", "set", "nt3h0", "master", "nd3b0"],
        ["ip", "link", "set", "nt3p0", "netns", "tcv3-clock-0"],
        ["ip", "netns", "exec", "tcv3-clock-0", "ip", "addr", "add", "10.1.1.20/24", "dev", "nt3p0"]]:
        used.append(one(rows, command))
    link = one(rows, ["ip", "-j", "-d", "link", "show", "nt3h0"])
    value = json.loads(link["stdout"])
    require(len(value) == 1 and value[0]["ifname"] == "nt3h0" and value[0]["master"] == "nd3b0" and
            value[0]["linkinfo"]["info_kind"] == "veth" and "UP" in value[0]["flags"],
            "Current service bridge binding differs")
    used.append(link)
    guests = [r for r in rows if r["command"][0] == "ssh" and "-p" in r["command"] and
              r["command"][r["command"].index("-p")+1] == "22222" and
              r["command"][-1] == "ifconfig vtnet2; netstat -rn"]
    require(len(guests) == 1 and guests[0]["returncode"] == 0, "Missing current Inner interface")
    guest = guests[0]
    require("\tether 02:6f:60:3f:1b:b7\n" in guest["stdout"] and
            "\tinet 10.1.1.1 netmask 0xffffff00" in guest["stdout"] and
            "10.1.1.0/24" in guest["stdout"], "Current guest MAC/address binding differs")
    used.append(guest)
    setup_rows = [one(initial, command) for command in [
        ["ip", "link", "add", "nd3b0", "type", "bridge", "stp_state", "0"],
        ["ip", "tuntap", "add", "dev", "nd3t0", "mode", "tap"],
        ["ip", "link", "set", "nd3t0", "master", "nd3b0"]]]
    def monitor(suffix):
        matches = [r for r in initial if r["command"][0] == "qemu-monitor" and
                   r["command"][1].endswith("/monitor-v2-0.sock") and r["command"][-1] == suffix]
        require(len(matches) == 1 and matches[0]["returncode"] == 0, "Missing VM tap/MAC attachment")
        return matches[0]
    setup_rows += [monitor("netdev_add tap,id=nd3red,ifname=nd3t0,script=no,downscript=no"),
                   monitor("device_add virtio-net-pci,id=nd3rednic,netdev=nd3red,mac=02:6f:60:3f:1b:b7")]
    inner = [d for d in installed["spec"]["devices"] if d["id"] == "ND_I_A1"]
    require(len(inner) == 1 and inner[0]["role"] == "inner" and
            any(i["name"] == "red" and i["zone"] == "red" and i["address"] == "10.1.1.1/24"
                for i in inner[0]["interfaces"]), "Declared Inner inside-network identity differs")
    adjustments = [r for r in rows if r["command"][0] == "ssh" and "-p" in r["command"] and
                   r["command"][r["command"].index("-p")+1] == "22222" and
                   r["command"][-1] == "ntpdate -b -u 10.1.1.20"]
    require(len(adjustments) == 1 and adjustments[0]["returncode"] == 0 and
            "step time server 10.1.1.20 offset" in adjustments[0]["stdout"]+adjustments[0]["stderr"],
            "No actual selected source correction")
    used += adjustments
    return {"clock_bundle": str(clocks), "setup_bundle": str(setup),
            "retained_setup_failure": setup_error,
            "client": "ND_I_A1", "source": "10.1.1.20",
            "inside_bridge": "nd3b0", "source_bridge": value[0]["master"],
            "clock_observations": [r["id"] for r in used],
            "setup_observations": [r["id"] for r in setup_rows],
            "scope": "SR1 and SR3 location subclauses for one actual Red time source and Inner client; no source trust, long-term synchronization or Gray Management placement claim.",
            "contract": "Collector truth; declared Red-interface zoning; unchanged VM tap-to-bridge attachment between setup and clock capture, corroborated by the same current guest MAC/address and current source-veth master. Prefix equality alone is not the binding."}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--clocks", required=True)
    p.add_argument("--setup", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--report", required=True)
    a = p.parse_args()
    d = parse(a.clocks, a.setup)
    Path(a.report).write_text(json.dumps(d, indent=2)+"\n")
    Path(a.output).write_text("""import TDN.Requirements.ServicePlacement

namespace TDN.Deployments.FreshRedTimePlacement

def networkZone (bridge : String) : Zone := if bridge = "nd3b0" then .red else .black
def insideBridge : String := "nd3b0"
def serviceBridge : String := "nd3b0"

theorem actual_time_source_is_on_selected_red_network : networkZone serviceBridge = .red :=
  Requirements.service_location_from_shared_bridge networkZone insideBridge serviceBridge (by native_decide) (by native_decide)

end TDN.Deployments.FreshRedTimePlacement
""")
    print(json.dumps({"client": d["client"], "source": d["source"], "bridge": d["source_bridge"]}))


if __name__ == "__main__":
    main()
