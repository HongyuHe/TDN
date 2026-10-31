"""Run with python -m tdn_evidence.server --config PATH."""
import argparse
import json
from typing import Any
from mcp.server.fastmcp import FastMCP
from .service import EvidenceService


def create_server(config):
    service = EvidenceService(config)
    mcp = FastMCP("TDN network evidence")

    @mcp.tool(structured_output=True)
    def list_networks() -> dict[str, Any]:
        """List configured live networks and immutable captured collections."""
        return service.list_networks()

    @mcp.tool(structured_output=True)
    def describe_capabilities(network: str | None = None) -> dict[str, Any]:
        """List supported device observations and the interpretation each parser provides."""
        return service.describe_capabilities(network)

    @mcp.tool(structured_output=True)
    def collect_evidence(network: str, capabilities: list[str] | None = None) -> dict[str, Any]:
        """Start read-only capture across configured workers. Poll collection_status for completion."""
        return service.collect_evidence(network, capabilities)

    @mcp.tool(structured_output=True)
    def collection_status(collection: str) -> dict[str, Any]:
        """Get collection completion, failure, or cancellation status."""
        return service.collection_status(collection)

    @mcp.tool(structured_output=True)
    def cancel_collection(collection: str) -> dict[str, Any]:
        """Cancel an unfinished capture between bounded collection commands."""
        return service.cancel_collection(collection)

    @mcp.tool(structured_output=True)
    def query_evidence(collection: str, capability: str | None = None, device: str | None = None, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """Query saved records with provenance, explicit coverage, and pagination. Does not collect live state."""
        return service.query_evidence(collection, capability, device, offset, limit)

    @mcp.tool(structured_output=True)
    def prepare_lean_bundle(collection: str, view: str = "inventory") -> dict[str, Any]:
        """Export checked JSON data for Lean. Reject unsupported or incomplete forwarding observations."""
        return service.prepare_lean_bundle(collection, view)

    @mcp.resource("evidence://{collection}/manifest")
    def manifest(collection: str) -> str:
        return json.dumps(service.read_manifest(collection), indent=2)

    @mcp.resource("evidence://{collection}/raw/{observation}")
    def raw(collection: str, observation: str) -> str:
        return service.read_raw(collection, observation)

    @mcp.resource("evidence://{collection}/stderr/{observation}")
    def stderr(collection: str, observation: str) -> str:
        return service.read_stderr(collection, observation)

    return mcp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    create_server(args.config).run(transport="stdio")


if __name__ == "__main__":
    main()
