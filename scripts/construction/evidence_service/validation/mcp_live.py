"""Exercise actual stdio MCP tools and resources against configured live workers."""
import asyncio
import json
from pathlib import Path
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[4]
CONFIG = ROOT / "scripts/construction/evidence_service/live-validation.json"


async def main():
    parameters = StdioServerParameters(command=sys.executable, args=["-m", "scripts.construction.evidence_service.server", "--config", str(CONFIG)], cwd=str(ROOT))
    results = {}
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            results["tools"] = [t.name for t in (await session.list_tools()).tools]
            async def call(name, args):
                result = await session.call_tool(name, args)
                if result.isError:
                    raise RuntimeError(str(result.content))
                return result.structuredContent
            results["capabilities"] = await call("describe_capabilities", {"network": "bird-validation"})
            for network, capabilities in [("bird-validation", ["linux.fib4", "linux.fib6", "linux.rules4", "linux.interfaces", "bird.routes", "bird.version", "bird.protocols", "bird.config"]), ("msc-multiworker", ["linux.addresses"])]:
                job = await call("collect_evidence", {"network": network, "capabilities": capabilities})
                for _ in range(180):
                    status = await call("collection_status", {"collection": job["id"]})
                    if status["status"] != "running":
                        break
                    await asyncio.sleep(1)
                assert status["status"] == "complete", status
                results[network] = status
                query = await call("query_evidence", {"collection": job["id"], "limit": 1})
                results[network]["query"] = query
                assert query["records"] and query["next_offset"] is not None
                manifest = await session.read_resource(f"evidence://{job['id']}/manifest")
                results[network]["resource_read"] = bool(manifest.contents)
                if network == "bird-validation":
                    routes = await call("query_evidence", {"collection": job["id"], "capability": "bird.routes"})
                    assert all(o["status"] == "observed" for o in routes["coverage"]), routes
                    assert any(r["record"]["protocol"] == "peer" for r in routes["records"])
                    results[network]["bird_routes"] = routes
                    results[network]["lean_bundle"] = await call("prepare_lean_bundle", {"collection": job["id"]})
    destination = ROOT / "artifacts/evidence-service/validation.json"
    if "lean_bundle" in results.get("bird-validation", {}):
        published = Path(results["bird-validation"]["lean_bundle"]["path"])
        results["bird-validation"]["lean_bundle"]["path"] = str(published.relative_to(ROOT))
    destination.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({k: {x: v[x] for x in ["id", "status"]} for k, v in results.items() if isinstance(v, dict) and "id" in v}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
