"""Check route witness generation against an independent exhaustive route-selection oracle."""
import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import json

from route_certificates import generate, make_certificate, paths, tree
from acl_certificates import make_table, generate as generate_acl


def values(node):
    if node == "empty":
        return []
    if "leaf" in node:
        return [node["leaf"]["value"]]
    return values(node["branch"]["left"]) + values(node["branch"]["right"])


def lookup(node, path):
    for direction in path:
        if not isinstance(node, dict) or "branch" not in node:
            return None
        node = node["branch"]["right" if direction else "left"]
    return node["leaf"]["value"] if isinstance(node, dict) and "leaf" in node else None


def selected(routes, destination):
    result = []
    for route in routes:
        if not route["destPrefixLow"] <= destination <= route["destPrefixHigh"]:
            continue
        competitors = [other for other in routes if other["ingress"] == route["ingress"]
                       and other["destPrefixLow"] <= destination <= other["destPrefixHigh"]]
        if all(route["tablePriority"] < other["tablePriority"] or
               route["tablePriority"] == other["tablePriority"] and
               (route["prefixLength"] > other["prefixLength"] or
                route["prefixLength"] == other["prefixLength"] and route["metric"] <= other["metric"])
               for other in competitors):
            result.append(route)
    return result


class RouteCertificatesTest(unittest.TestCase):
    def test_complete_balanced_indices(self):
        for size in [0, 1, 2, 3, 31, 32, 33, 500, 2422]:
            source = list(range(size))
            indexed = tree(source)
            self.assertEqual(values(indexed), source)
            for value, path in enumerate(paths(size)):
                self.assertEqual(lookup(indexed, path), value)
                self.assertLessEqual(len(path), (size - 1).bit_length())

    def test_priority_boundaries_equal_cost_and_multiple_interfaces(self):
        rng = random.Random(741)
        for case in range(60):
            routes = []
            for _ in range(case):
                low, high = sorted([rng.randrange(32), rng.randrange(32)])
                routes.append(dict(ingress=rng.randrange(4), egress=rng.randrange(5),
                                   destPrefixLow=low, destPrefixHigh=high,
                                   tablePriority=rng.randrange(3), prefixLength=rng.randrange(6),
                                   metric=rng.randrange(3)))
            for destination in range(33):
                certificate = make_certificate(routes, destination)
                self.assertEqual(values(certificate["retained"]), selected(routes, destination))
                for route, path in zip(values(certificate["retained"]), values(certificate["origins"])):
                    self.assertEqual(lookup(tree(routes), path), route)

    def test_empty_capture_and_reproducibility(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            source.write_text(json.dumps({"routes": [], "pairs": []}))
            self.assertEqual(generate(source), generate(source))
            self.assertEqual(generate(source)["certificates"], [])

    def test_retained_certificates_are_current(self):
        root = Path(__file__).resolve().parents[2]
        source = root / "data/evidence/continuation/GrayFirewallSharedFields.json"
        for generate_records, name in [(generate, "GrayFirewallSharedRoutes.json"),
                                       (generate_acl, "GrayFirewallSharedAcls.json")]:
            actual = json.loads((root / "data/evidence/certificates" / name).read_text())
            self.assertEqual(actual, generate_records(source))

    def test_acl_ambiguous_witness_keys_are_rejected(self):
        rule = {"verdict": "allow", "atoms": [
            {"sourceRange": {"low": 1, "high": 1}}, {"protocol": {"name": "esp"}}]}
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            make_table([rule, rule])

    def test_unsupported_deny_rule_requires_an_explicit_witness(self):
        with self.assertRaisesRegex(ValueError, "exclusion witness"):
            make_table([{"verdict": "deny", "atoms": [{"protocol": {"name": "esp"}}]}])

    def test_acl_ranges_require_a_different_index(self):
        rule = {"verdict": "allow", "atoms": [
            {"sourceRange": {"low": 1, "high": 2}}, {"protocol": {"name": "esp"}}]}
        with self.assertRaisesRegex(ValueError, "exact source"):
            make_table([rule])


if __name__ == "__main__":
    unittest.main()
