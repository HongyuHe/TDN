"""Expose the shared parsers to historical scripts run with plain Python."""
from pathlib import Path
import sys

#* Historical script entry points can run without installing the MCP server.
package_root = str(Path(__file__).resolve().parents[2] / "mcp")
if package_root not in sys.path:
    sys.path.insert(0, package_root)
