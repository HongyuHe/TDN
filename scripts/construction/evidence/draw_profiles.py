"""Render the five current MSC profiles directly from their device/link records."""

import hashlib
import html
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
PROFILES = HERE / "profiles"
CASES = [
    ("native-ipsec-baseline", "Two-site baseline", "Dedicated Outer encryptor and Outer Firewall for each level."),
    ("native-shared-same-level", "Two networks at one security level", "Network 1 and Network 2 share Outer devices; their identities remain separate."),
    ("native-shared-four-levels", "Four levels with shared Outer devices", "Each Inner connects through the Gray Firewall before reaching the shared Outer."),
    ("native-redundant-four-levels", "Four levels with redundant Outer paths", "A Gray router connects four Gray LANs to two Outer paths at each site."),
    ("native-management-independent", "Independent management at both sites", "The baseline adds separate management switches and administration devices."),
]
COLORS = {"host": ("#fff0f2", "#ad2850"), "inner": ("#e7f5ff", "#17638b"),
          "switch": ("#edf1f6", "#536176"), "gray-firewall": ("#fff2d8", "#99620a"),
          "outer": ("#e5f6f4", "#087e7c"), "firewall": ("#fff0df", "#aa561b"),
          "transport": ("#e9edf5", "#27384e"), "admin": ("#f3eaff", "#7950a4")}
ROLES = {"host": "Red host", "inner": "Inner encryptor", "switch": "Gray switch",
         "gray-firewall": "Gray Firewall", "outer": "Outer encryptor", "firewall": "Outer Firewall",
         "transport": "Black router", "admin": "Admin / services"}
W, NODE_W, NODE_H = 1600, 140, 62


def text(x, y, value, size=16, color="#23344b", weight=400, anchor="start"):
    return f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}" text-anchor="{anchor}">{html.escape(value)}</text>'


def render(stem, title, subtitle):
    source = PROFILES / (stem + ".json")
    spec = json.loads(source.read_text())
    devices = {d["id"]: d for d in spec["devices"]}
    prefix = next(iter(devices)).split("_")[0]
    short = {key: key[len(prefix) + 1:] for key in devices}
    redundant = "redundant" in stem
    inline = "four-levels" in stem
    management = "management" in stem
    same = "same-level" in stem
    n = 4 if inline else 2
    panel_h = 650 if management else (570 if inline else 405)
    tops = {"A": 170, "B": 170 + panel_h + 40}
    height = tops["B"] + panel_h + 80
    pos = {}
    row_labels = []
    for site, top in tops.items():
        first = top + (170 if management else 115)
        spacing = 145 if n == 2 else 115
        rows = [first + i * spacing for i in range(n)]
        middle = (rows[0] + rows[-1]) / 2
        for i, y in enumerate(rows, 1):
            pos[f"{prefix}_R_{site}{i}"] = (130, y)
            pos[f"{prefix}_I_{site}{i}"] = (330, y)
            pos[f"{prefix}_G_{site}{i}"] = (870 if redundant else (790 if inline else 560), y)
            level = devices[f"{prefix}_R_{site}{i}"].get("level", "")
            level = {"TOP_SECRET": "Top Secret", "SECRET_US_ONLY": "Secret / US only", "SECRET_COALITION": "Secret / Coalition", "UNCLASSIFIED": "Unclassified", "S1": "Level 1", "S2": "Level 2"}.get(level, level)
            row_labels.append((60, y - 45, f"Network {i} / Secret / US only" if same else level))
        pos[f"{prefix}_GF_{site}"] = (510 if inline else 770, middle)
        if redundant:
            pos[f"{prefix}_GR_{site}"] = (690, middle)
        outer_count = 2 if redundant or not (inline or same) else 1
        for i in range(1, outer_count + 1):
            y = (middle + (-85 if i == 1 else 85)) if redundant else (middle if outer_count == 1 else rows[i - 1])
            pos[f"{prefix}_O_{site}{i}"] = (1090 if inline else 1010, y)
            pos[f"{prefix}_OF_{site}{i}"] = (1290 if inline else 1230, y)
        if management:
            for i, y in [(1, top + 75), (2, top + 415)]:
                pos[f"{prefix}_AW_{site}{i}"] = (130, y)
                pos[f"{prefix}_M_{site}{i}"] = (330, y)
            pos[f"{prefix}_AW_{site}99"] = (560, top + 550)
            pos[f"{prefix}_M_{site}99"] = (770, top + 550)
    pos[f"{prefix}_BLACK"] = (1490, (tops["A"] + tops["B"] + panel_h) / 2)
    assert set(pos) == set(devices), (set(pos) - set(devices), set(devices) - set(pos))
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{height}" viewBox="0 0 {W} {height}" font-family="Arial, Helvetica, sans-serif">',
             f'<rect width="{W}" height="{height}" fill="#ffffff"/>',
             text(40, 43, title, 28, weight=700), text(40, 73, subtitle, 17),
             text(40, 101, f'{len(devices)} devices / {len(spec["links"])} virtual links. Device IDs have the prefix {prefix}_.', 15, "#56677d")]
    for x, color, label in [(40, "#ad2850", "Red link"), (230, "#66758b", "Gray link"), (430, "#27384e", "Black link"), (640, "#8a53b1", "Management link (dashed)")]:
        if x == 640 and not management:
            continue
        dash = 'stroke-dasharray="7 5"' if x == 640 else ''
        parts.append(f'<path d="M{x} 133 h35" stroke="{color}" stroke-width="3" fill="none" {dash}/>')
        parts.append(text(x + 45, 138, label, 14))
    for site, top in tops.items():
        parts.append(f'<rect x="30" y="{top}" width="1365" height="{panel_h}" rx="15" fill="#f8fafc" stroke="#dbe3ed"/>')
        parts.append(text(55, top + 34, f"Site {site}", 21, weight=700))
    rendered_links = []
    for idx, link in enumerate(spec["links"]):
        a, b = link["a"], link["b"]
        da, db = devices[a["device"]], devices[b["device"]]
        x1, y1 = pos[a["device"]]
        x2, y2 = pos[b["device"]]
        zones = {i["zone"] for d, e in [(da, a), (db, b)] for i in d["interfaces"] if i["name"] == e["interface"]}
        mgmt = "management" in zones or a["interface"] == "mgmt" or b["interface"] == "mgmt"
        color = "#8a53b1" if mgmt else ("#ad2850" if "red" in zones else ("#27384e" if "black" in zones else "#66758b"))
        label = f'{a["device"]}:{a["interface"]} ↔ {b["device"]}:{b["interface"]}'
        if mgmt and (short[a["device"]].startswith("M_") or short[b["device"]].startswith("M_")):
            #* Place device-to-management links in the open space below the data chains.
            if short[a["device"]].startswith("M_"):
                a, b, x1, y1, x2, y2 = b, a, x2, y2, x1, y1
            if not short[a["device"]].startswith("AW_") and short[b["device"]].endswith("99"):
                name = short[a["device"]]
                port = {"gray-firewall": 0, "outer": 1, "firewall": 3}[devices[a["device"]]["role"]]
                if name.endswith("2"):
                    port += 1
                lane = tops[devices[a["device"]]["site"]] + 465 + port * 12
                x2 += (port - 2) * 24
                y2 -= NODE_H / 2
                if port == 0:
                    y1 += NODE_H / 2
                    route = f'M{x1},{y1} V{lane} H{x2} V{y2}'
                else:
                    x1 += NODE_W / 2
                    y1 += 16
                    corridor = x1 + (18 if name.endswith("1") else 31)
                    route = f'M{x1},{y1} H{corridor} V{lane} H{x2} V{y2}'
            elif abs(x1 - x2) < 1:
                sign = 1 if y2 > y1 else -1
                route = f'M{x1},{y1 + sign * NODE_H / 2} V{y2 - sign * NODE_H / 2}'
            else:
                route = f'M{x1 + NODE_W / 2},{y1} L{x2 - NODE_W / 2},{y2}'
        elif same and {da["role"], db["role"]} == {"switch", "outer"}:
            #* Route the shared-Outer connections above and below the Gray Firewall.
            if da["role"] == "outer":
                x1, y1, x2, y2 = x2, y2, x1, y1
            x1 += NODE_W / 2
            y2 += -NODE_H / 2 if y1 < y2 else NODE_H / 2
            route = f'M{x1},{y1} H{x2} V{y2}'
        elif a["device"].endswith("BLACK") or b["device"].endswith("BLACK"):
            if a["device"].endswith("BLACK"):
                x1, y1, x2, y2 = x2, y2, x1, y1
            x1 += NODE_W / 2
            x2 -= NODE_W / 2
            route = f'M{x1},{y1} C{x1 + 60},{y1} {x2 - 15},{y2} {x2},{y2}'
        else:
            if x1 > x2:
                a, b, x1, y1, x2, y2 = b, a, x2, y2, x1, y1
            #* Each parallel firewall-to-router interface retains its own visible line.
            if redundant and {da["role"], db["role"]} == {"gray-firewall", "transport"}:
                offset = (int(a["interface"][1:]) - 2.5) * 14
                y1 += offset
                y2 += offset
            x1 += NODE_W / 2
            x2 -= NODE_W / 2
            route = f'M{x1},{y1} L{x2},{y2}'
        dash = 'stroke-dasharray="7 5"' if mgmt else ''
        parts.append(f'<path id="link-{idx}" d="{route}" stroke="{color}" stroke-width="2.2" {dash} fill="none"><title>{html.escape(label)}</title></path>')
        rendered_links.append(label)
    for x, y, label in row_labels:
        parts.append(text(x, y, label, 14, "#8a3551", 600))
    for identity, device in devices.items():
        x, y = pos[identity]
        fill, color = COLORS[device["role"]]
        role = ROLES[device["role"]]
        if device.get("level") == "management" and device["role"] == "switch":
            fill, color, role = "#f3eaff", "#7950a4", "Mgmt switch"
        if short[identity].startswith("GR_"):
            role = "Gray router"
        parts.extend([f'<g id="device-{identity}"><title>{html.escape(identity + ": " + role)}</title>',
                      f'<rect x="{x - NODE_W / 2}" y="{y - NODE_H / 2}" width="{NODE_W}" height="{NODE_H}" rx="9" fill="{fill}" stroke="{color}" stroke-width="1.7"/>',
                      text(x, y - 4, short[identity], 17, color, 700, "middle"),
                      text(x, y + 17, role, 13, color, anchor="middle"), '</g>'])
    parts.append(text(40, height - 49, "Lines are virtual interface connections. Crossings without a device box are not junctions.", 15, "#56677d"))
    parts.append(text(40, height - 24, "IPsec tunnels use those links. FRR helper containers are omitted.", 15, "#56677d"))
    parts.append('</svg>')
    svg = PROFILES / (stem + ".svg")
    png = PROFILES / (stem + ".png")
    svg.write_text('\n'.join(parts))
    subprocess.run(['rsvg-convert', '-z', '1.5', '-o', str(png), str(svg)], check=True)
    return {"profile": source.name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "devices": len(devices), "links": len(rendered_links), "device_ids": list(devices),
            "virtual_links": rendered_links, "png": png.name, "svg": svg.name, "width": W, "height": height}


if __name__ == '__main__':
    results = [render(*case) for case in CASES]
    (PROFILES / 'visualization-manifest.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps([{k: row[k] for k in ['profile', 'devices', 'links', 'png']} for row in results], indent=2))
