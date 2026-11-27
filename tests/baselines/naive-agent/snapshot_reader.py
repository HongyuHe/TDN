"""Read the supplied PDF and saved device observations over local standard input/output."""
import base64
from functools import lru_cache
import gzip
import json
from pathlib import Path
import sys
import time

import pymupdf


ROOT = Path(__file__).resolve().parent
from cohort import NETWORKS
STRING = {"type": "string"}
STRINGS = {"type": "array", "items": STRING}
TOOLS = {
    "document": ("Read the supplied PDF by page, search its text or view a page image.", {
        "search": STRING, "page": {"type": "integer", "minimum": 1},
        "pages": {"type": "integer", "minimum": 1, "maximum": 8}, "image": {"type": "boolean"}}),
    "networks": ("List networks. Select a network for its device inventory and available saved observations. "
                 "The optional offset and count select an inventory page. "
                 "Each view lists the number of records, field names and available command names.", {
                     "network": STRING, "offset": {"type":"integer","minimum":0}, "count": {"type":"integer","minimum":1,"maximum":100}}),
    "observe": ("Read saved snapshot records. Choose a network and view from networks. Optionally select devices, "
                "exact command names (kinds), a case-insensitive literal filter, or a list of fields to return. "
                "Matching is on the full record before field selection. Results are newline-delimited JSON, paged by "
                "character offset. Commands listed in raw and processing identify previously collected output.", {
                    "network": STRING, "view": STRING, "devices": STRINGS, "kinds": STRINGS, "filter": STRING,
                    "fields": STRINGS, "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 100, "maximum": 32000}}),
}


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def content(value):
    return [{"type": "text", "text": value if isinstance(value, str) else encode(value)}]


@lru_cache(maxsize=4)
def capture(network):
    if network not in NETWORKS:
        raise ValueError("Unknown network. Use networks to list the available names.")
    with gzip.open(ROOT / (network + ".json.gz"), "rt") as source:
        return json.load(source)


def read_pdf(args):
    with pymupdf.open(ROOT / "document.pdf") as document:
        if args.get("search"):
            term = args["search"].casefold()
            return content([{"page": p.number + 1, "line": line} for p in document
                            for line in p.get_text().splitlines() if term in line.casefold()][:150])
        page = args.get("page", 1)
        if not 1 <= page <= len(document):
            raise ValueError("Page out of range")
        if args.get("image"):
            png = document[page-1].get_pixmap().tobytes("png")
            return [{"type": "image", "mimeType": "image/png", "data": base64.b64encode(png).decode()}]
        return content([{"page": i + 1, "pages_in_document": len(document), "text": document[i].get_text()}
                        for i in range(page-1, min(len(document), page-1+max(1, min(8, args.get("pages", 1))))) ])


def read(tool, args):
    if tool not in TOOLS or set(args) - TOOLS[tool][1].keys():
        raise ValueError("Unknown tool or argument.")
    if tool == "document":
        return read_pdf(args)
    if tool == "networks" and not args.get("network"):
        return content(list(NETWORKS))
    bundle = capture(args["network"])
    if tool == "networks":
        cat = bundle["catalogue"]
        offset = max(0, args.get("offset", 0))
        count = min(100, max(1, args.get("count", 20)))
        page = {"views": cat["views"], "device_count": len(cat["devices"]), "offset": offset,
                "devices": cat["devices"][offset:offset+count]}
        if "links" in cat:
            page.update(link_count=len(cat["links"]), links=cat["links"][offset:offset+count])
        if "evidence_scope" in cat:
            page["evidence_scope"] = cat["evidence_scope"]
        return content(page)
    view = args["view"]
    if view not in bundle["views"]:
        raise ValueError("Unknown view. Use networks with the network name for available views.")
    devices, kinds = set(args.get("devices", [])), set(args.get("kinds", []))
    fields, needle = args.get("fields", []), args.get("filter", "").casefold()
    lines = []
    for entry in bundle["views"][view]:
        if devices and not devices.intersection(entry["devices"]):
            continue
        row = entry["record"]
        if kinds and row.get("kind") not in kinds:
            continue
        line = encode(row)
        if needle and needle not in line.casefold():
            continue
        lines.append(encode({k: row[k] for k in fields if k in row}) if fields else line)
    data = "\n".join(lines)
    start, limit = max(0, args.get("offset", 0)), max(100, min(32000, args.get("limit", 20000)))
    return content({"records": len(lines), "characters": len(data), "offset": start, "data": data[start:start+limit]})


def main():
    for line in sys.stdin:
        req = json.loads(line)
        if "id" not in req:
            continue
        method = req.get("method")
        if method == "initialize":
            result = {"protocolVersion": req["params"]["protocolVersion"], "capabilities": {"tools": {}},
                      "serverInfo": {"name": "reader", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": [{"name": n, "description": description,
                      "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
                      "inputSchema": {"type": "object", "properties": schema, "additionalProperties": False,
                                      "required": ["network", "view"] if n == "observe" else []}}
                      for n, (description, schema) in TOOLS.items()]}
        elif method == "tools/call":
            name, args = req["params"]["name"], req["params"].get("arguments", {})
            start = time.monotonic()
            try:
                result = {"content": read(name, args)}
            except (ValueError, KeyError, TypeError, OSError) as exc:
                message = str(exc) if type(exc) is ValueError else "Invalid request or unavailable record."
                result = {"content": content(message), "isError": True}
            text = result["content"][0]
            count = returned_characters = None
            if name == "observe" and not result.get("isError"):
                page = json.loads(text["text"])
                count, returned_characters = page["records"], len(page["data"])
            with (ROOT / "access.jsonl").open("a") as log:
                log.write(encode({"time": time.time(), "tool": name, "arguments": args, "ok": not result.get("isError", False),
                                  "records": count, "returned_characters": returned_characters,
                                  "response_bytes": len(text.get("text", text.get("data", ""))),
                                  "seconds": time.monotonic()-start})+"\n")
        elif method in {"resources/list", "resources/templates/list", "prompts/list", "ping"}:
            key = {"resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}
            result = {key[method]: []} if method in key else {}
        else:
            print(encode({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32601, "message": "Unknown method"}}), flush=True)
            continue
        print(encode({"jsonrpc": "2.0", "id": req["id"], "result": result}), flush=True)


if __name__ == "__main__":
    main()
