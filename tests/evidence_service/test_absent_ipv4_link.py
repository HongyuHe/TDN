import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tdn_evidence.parsers.disconnected import ipv4_link_view
from tdn_evidence.parsers.snapshot import EvidenceError


class VerifiedLinkAbsence(unittest.TestCase):
    def evidence(self, root, *, later_flags=(), stderr=None):
        devices = ["firewall", "gateway"]
        link = {
            "a": {"device": devices[0], "interface": "inside"},
            "b": {"device": devices[1], "interface": "wan"},
        }
        (root / "spec.json").write_text(json.dumps({"links": [link]}))
        observations = {}
        for d in devices:
            for kind in ("interfaces", "convergence-interfaces"):
                identity = d + "-" + kind
                ports = (
                    []
                    if d == "firewall"
                    else [
                        {
                            "ifname": "wan",
                            "operstate": "DOWN",
                            "linkinfo": {"info_kind": "veth"},
                            "flags": list(later_flags)
                            if kind == "convergence-interfaces"
                            else [],
                        }
                    ]
                )
                path = identity + ".json"
                (root / path).write_text(json.dumps({"stdout": json.dumps(ports)}))
                observations[identity] = dict(
                    device_id=d,
                    kind=kind,
                    id=identity,
                    returncode=0,
                    parse_status="parsed",
                    raw_path=path,
                    command=["docker", "exec", d, "ip", "-j", "-d", "address", "show"],
                )
        key = "ipv6-settings"
        observations[key] = dict(
            device_id="firewall",
            kind=key,
            id=key,
            returncode=1,
            command=[
                "docker",
                "exec",
                "firewall",
                "sysctl",
                "net.ipv6.conf.inside.forwarding",
            ],
            raw_path="settings.json",
        )
        err = "sysctl: cannot stat /proc/sys/net/ipv6/conf/inside/forwarding: No such file or directory"
        (root / "settings.json").write_text(
            json.dumps({"stderr": err if stderr is None else stderr})
        )
        snapshot = {
            "links": [
                {
                    "endpoint_interface_ids": ["firewall:inside", "gateway:wan"],
                    "relation": "veth",
                    "status": "configured",
                }
            ],
            "devices": [
                dict(
                    id=d,
                    namespace=d,
                    observation_ids=[
                        o["id"] for o in observations.values() if o["device_id"] == d
                    ],
                )
                for d in devices
            ],
            "scope": {
                "expected_device_ids": devices,
                "expected_interface_ids": ["firewall:inside", "gateway:wan"],
            },
            "interfaces": [{"id": "gateway:wan"}],
        }
        manifest = dict(
            convergence={"consistent": True},
            files=[{"path": "spec.json"}],
            collection_failures=[{"observation_id": key}],
        )
        return snapshot, manifest, observations

    def test_missing_interface_and_down_peer_allow_an_ipv4_projection(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, manifest, observations = self.evidence(root)
            observed = ipv4_link_view(snapshot, manifest, root, observations)
            self.assertEqual(observed["absent_interfaces"], ["firewall:inside"])
            self.assertEqual(observed["unlinked_interfaces"], ["gateway:wan"])
            self.assertEqual(observed["omitted_ipv6_observations"], ["ipv6-settings"])
            self.assertEqual(snapshot["links"], [])

    def test_unrelated_settings_error_and_live_peer_each_prevent_use(self):
        for args, message in [
            ({"stderr": "sysctl: permission denied"}, "Unrelated settings failure"),
            ({"later_flags": ["LOWER_UP"]}, "Unresolved live or unstable link"),
        ]:
            with self.subTest(args=args), TemporaryDirectory() as tmp:
                root = Path(tmp)
                snapshot, manifest, observations = self.evidence(root, **args)
                with self.assertRaisesRegex(EvidenceError, message):
                    ipv4_link_view(snapshot, manifest, root, observations)
