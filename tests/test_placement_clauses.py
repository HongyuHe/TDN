import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from analyze_topology import validated_graph
from import_placement_clauses import BASE, generate, path_to_outer


class PlacementClauseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared_path = BASE / "native-shared-four-levels-20261024T015300Z-coverage-v1"
        cls.redundant_path = BASE / "native-redundant-20261024T020100Z"
        cls.shared = validated_graph(cls.shared_path)
        cls.redundant = validated_graph(cls.redundant_path)

    def generated(self, shared=None, redundant=None):
        with patch("import_placement_clauses.validated_graph",
                   side_effect=[shared or self.shared, redundant or self.redundant]):
            return generate(self.shared_path, self.redundant_path)

    def test_actual_scope(self):
        _, report = self.generated()
        self.assertEqual(len(report["independent_branches"]), 8)
        self.assertEqual(len(report["red_hosts"]), 8)
        self.assertEqual(len(report["redundant_outers"]), 4)
        self.assertEqual(report["black_transports"], ["NR_BLACK"])

    def test_gray_router_not_classified_black_by_transport_role(self):
        _, report = self.generated()
        self.assertNotIn("NR_GR_A", report["black_transports"])

    def test_branch_through_other_inner_is_rejected(self):
        graph = {"gray_edges": {(0,1),(1,2)}, "outer":[2], "inner":[0,1]}
        with self.assertRaises(ValueError):
            path_to_outer(graph,0)

    def test_red_bypass_is_rejected(self):
        graph = copy.deepcopy(self.shared)
        graph["edges"].add((2,5))
        with self.assertRaisesRegex(ValueError,"attachment cut"):
            self.generated(shared=graph)

    def test_empty_redundant_inventory_is_rejected(self):
        graph = copy.deepcopy(self.redundant)
        graph["outer"]=[]
        with self.assertRaises(ValueError):
            self.generated(redundant=graph)

    def test_missing_black_zone_is_rejected(self):
        graph = copy.deepcopy(self.redundant)
        for interface in graph["snapshot"]["interfaces"]:
            if interface["zone"]=="black":
                interface["zone"]="gray"
        with self.assertRaises(ValueError):
            self.generated(redundant=graph)


if __name__ == "__main__":
    unittest.main()
