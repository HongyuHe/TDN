"""Record public MKA messages at send, receive, and successful integrity checks."""
import argparse
import hashlib
import json
from pathlib import Path


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Absent or ambiguous source anchor: " + before[:80])
    return source.replace(before, after, 1)


def patch(root):
    path = root / "src/pae/ieee802_1x_kay.c"
    before = path.read_text()
    if 'tdn_public_record("MKA_' in before:
        raise ValueError("Use a fresh copy of the public-handshake source")
    anchor = "\tl2_packet_send(kay->l2_mka, NULL, 0, wpabuf_head(buf), wpabuf_len(buf));"
    replacement = '''    {
        int result;
        tdn_public_record("MKA_SEND", wpabuf_head(buf), wpabuf_len(buf));
        result = l2_packet_send(kay->l2_mka, NULL, 0, wpabuf_head(buf), wpabuf_len(buf));
        wpa_printf(MSG_INFO, "TDN_MKA_SEND interface=%s result=%d", kay->if_name, result);
    }'''
    after = replace_once(before, anchor, replacement)
    anchor = '\twpa_hexdump(MSG_DEBUG, "KaY: RX EAPOL-MKA", buf, len);'
    after = replace_once(after, anchor,
        '    tdn_public_record("MKA_RECEIVE", buf, len);\n' + anchor)
    anchor = '    wpa_printf(MSG_INFO, "TDN_MKA_AUTH interface=%s peer=" MACSTR " result=0",'
    after = replace_once(after, anchor,
        '    tdn_public_record("MKA_AUTHENTICATED", buf, len);\n' + anchor)
    path.write_text(after)
    return {"path": str(path), "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(after.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest.exists():
        raise ValueError("Preserve the previous patch manifest")
    records = [patch(args.root / product) for product in ["hostapd-2.12", "wpa_supplicant-2.12"]]
    args.manifest.write_text(json.dumps({"changes": records, "scope":
        "Exact public MKA Ethernet frames and actual send return values. Successful receive integrity checks are recorded after ICV verification. Private keys remain excluded."}, indent=2) + "\n")


if __name__ == "__main__":
    main()
