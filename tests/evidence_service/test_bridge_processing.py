"""Reject unsupported bridging and link-filter behavior in saved bridge views."""

import unittest

from tdn_evidence.bridge_processing import link_hook_inventory, normal_tables


def table(rows):
    headings = list(rows[0]) if rows else ["_uuid"]
    return {"headings": headings, "data": [[row[key] for key in headings] for row in rows]}


def normal_records():
    empty = ["set", []]
    values = {
        "bridge": table([{"_uuid": ["uuid", "bridge"], "controller": empty,
                           "datapath_type": "system", "other_config": ["map", []]}]),
        "port": table([{"_uuid": ["uuid", "port"], "tag": empty, "trunks": empty,
                         "vlan_mode": empty, "bond_mode": empty, "other_config": ["map", []]}]),
        "interface": table([]), "controller": table([]),
        "flows": " reset_counts priority=0 actions=NORMAL\n",
        "groups": "OFPST_GROUP_DESC reply (OF1.3) (xid=0x2):\n",
        "meters": "OFPST_METER_CONFIG reply (OF1.3) (xid=0x2):\n",
    }
    return {kind: {"raw_value": value} for kind, value in values.items()}


class BridgeProcessingTests(unittest.TestCase):
    def test_normal_flow_and_empty_link_hooks(self):
        self.assertEqual(len(normal_tables(normal_records())["port"]), 1)
        observed = {"nftables": [{"metainfo": {"json_schema_version": 1}},
                    {"table": {"family": "ip", "name": "filter"}}]}
        result = link_hook_inventory(observed)
        self.assertEqual(result["absentLinkFamilies"], ["bridge", "netdev"])
        self.assertEqual(result["completeRuleset"], observed)

    def test_packet_changing_and_dropping_flows_rejected(self):
        for actions in ["drop", "set_field:42->ip_dscp,NORMAL", "group:1", "output:2"]:
            with self.subTest(actions=actions):
                records = normal_records()
                records["flows"]["raw_value"] = "reset_counts priority=0 actions=" + actions
                with self.assertRaises(ValueError):
                    normal_tables(records)

    def test_tagged_trunk_and_bonded_ports_rejected(self):
        for field, value in [("tag", 7), ("trunks", ["set", [7, 8]]),
                             ("vlan_mode", "native-tagged"), ("bond_mode", "balance-slb")]:
            with self.subTest(field=field):
                records = normal_records()
                port = records["port"]["raw_value"]
                port["data"][0][port["headings"].index(field)] = value
                with self.assertRaises(ValueError):
                    normal_tables(records)

    def test_groups_and_meters_rejected(self):
        for kind in ["groups", "meters"]:
            with self.subTest(kind=kind):
                records = normal_records()
                records[kind]["raw_value"] += "configured object\n"
                with self.assertRaises(ValueError):
                    normal_tables(records)

    def test_present_link_hooks_are_not_silently_ignored(self):
        for family in ["bridge", "netdev"]:
            with self.subTest(family=family):
                with self.assertRaises(ValueError):
                    link_hook_inventory({"nftables": [{"chain": {
                        "family": family, "table": "filter", "name": "ingress",
                        "hook": "ingress", "policy": "drop"}}]})

    def test_unknown_nft_objects_rejected(self):
        with self.assertRaises(ValueError):
            link_hook_inventory({"nftables": [{"flowtable": {"name": "unexpected"}}]})


if __name__ == "__main__":
    unittest.main()
