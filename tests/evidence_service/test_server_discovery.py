"""Exercise capability discovery through the MCP tool argument schema."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mcp.server.fastmcp.exceptions import ToolError
from tdn_evidence.server import create_server
from tdn_evidence.service import EvidenceService


class ServerDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = Path(self.temp.name) / 'config.json'
        self.config.write_text(json.dumps({
            'store': 'store',
            'networks': [{'id': 'router-network', 'devices': [{
                'id': 'router', 'worker': 'local', 'container': 'router', 'adapters': ['linux']}]}],
            'saved_experiments': {
                'certificates': {'path': 'unused', 'parser': 'native-authentication-services-v1'},
                'security-labels': {'path': 'unused', 'parser': 'security-level-assignment-v1'}},
        }))
        self.service = EvidenceService(self.config)
        with patch('tdn_evidence.server.EvidenceService', return_value=self.service):
            self.server = create_server(self.config)

    def tearDown(self):
        self.service.pool.shutdown(wait=True)
        self.temp.cleanup()

    async def result(self, arguments):
        result = await self.server.call_tool('describe_capabilities', arguments)
        if isinstance(result, tuple):
            return result[1]
        return result

    async def test_saved_collection_alias_selects_its_adapter(self):
        for collection, expected in [('certificates', 'native_authentication_services'),
                                     ('security-labels', 'security_level_assignments')]:
            with self.subTest(collection=collection):
                by_collection = await self.result({'collection': collection})
                by_network = await self.result({'network': collection})
                self.assertEqual(by_collection, by_network)
                self.assertEqual(by_collection['saved_experiment']['lean_views'], [expected])
                self.assertTrue(by_collection['saved_experiment']['scope'])

    async def test_live_network_selects_only_its_adapters(self):
        self.assertEqual(set(await self.result({'network': 'router-network'})), {'linux'})

    async def test_no_argument_returns_live_adapter_catalog(self):
        result = await self.result({})
        self.assertIn('linux', result)
        self.assertNotIn('saved_experiment', result)

    async def test_two_identifiers_are_rejected(self):
        with self.assertRaisesRegex(ToolError, 'either network or collection'):
            await self.result({'network': 'router-network', 'collection': 'certificates'})

    async def test_tool_schema_exposes_collection_argument(self):
        tool = next(t for t in await self.server.list_tools() if t.name == 'describe_capabilities')
        self.assertIn('collection', tool.inputSchema['properties'])


if __name__ == '__main__':
    unittest.main()
