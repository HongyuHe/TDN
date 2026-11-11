"""Record exact public messages connecting AS completion to peer success."""
import argparse
import hashlib
import json
from pathlib import Path


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Absent or ambiguous source anchor: " + before[:80])
    return source.replace(before, after, 1)


def patch(root):
    records = []

    def save(relative, transform):
        path = root / relative
        before = path.read_text()
        if any(marker in before for marker in ["RADIUS_RESPONSE_SEND", "EAP_SUCCESS_SEND", "EAP_SUCCESS_RECEIVE"]):
            raise ValueError("Use a fresh copy of the public MKA source tree")
        after = transform(before)
        path.write_text(after)
        records.append({"path": relative, "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
                        "after_sha256": hashlib.sha256(after.encode()).hexdigest()})

    def server(source):
        start = source.index("\nsend_reply:\n")
        end = source.index("\n}\n", start)
        body = source[start:end]
        anchor = "\t\tbuf = radius_msg_get_buf(reply);\n\t\tres = sendto"
        body = replace_once(body, anchor, '''\t\tbuf = radius_msg_get_buf(reply);
        if (radius_msg_get_hdr(reply)->code == RADIUS_CODE_ACCESS_ACCEPT)
            tdn_public_record("RADIUS_RESPONSE_SEND", wpabuf_head(buf), wpabuf_len(buf));
\t\tres = sendto''')
        anchor = "\t\tif (res < 0) {"
        body = replace_once(body, anchor, '''        if (radius_msg_get_hdr(reply)->code == RADIUS_CODE_ACCESS_ACCEPT)
            wpa_printf(MSG_INFO, "TDN_RADIUS_RESPONSE_SEND result=%d size=%lu", res,
                       (unsigned long) wpabuf_len(buf));
''' + anchor)
        return source[:start] + body + source[end:]

    def authenticator(source):
        start = source.index("static void ieee802_1x_send(")
        end = source.index("\n}\n", start)
        body = source[start:end]
        body = replace_once(body, "\t\tint link_id = -1;", "\t\tint link_id = -1;\n        int result;\n        int success = type == IEEE802_1X_TYPE_EAP_PACKET && data &&\n            datalen == 4 && data[0] == 3 && WPA_GET_BE16(data + 2) == 4;")
        body = replace_once(body, "\t\thostapd_drv_hapd_send_eapol(", '''        if (success)
            tdn_public_record("EAP_SUCCESS_SEND", buf, len);
\t\tresult = hostapd_drv_hapd_send_eapol(''')
        anchor = "\t\t\tencrypt, hostapd_sta_flags_to_drv(sta->flags), link_id);"
        body = replace_once(body, anchor, anchor + '''
        if (success)
            wpa_printf(MSG_INFO, "TDN_EAP_SUCCESS_SEND result=%d size=%lu", result,
                       (unsigned long) len);''')
        return source[:start] + body + source[end:]

    def supplicant(source):
        start = source.index("int eapol_sm_rx_eapol(")
        end = source.index("\n}\n", start)
        body = source[start:end]
        anchor = "\tdata_len = plen + sizeof(*hdr);"
        body = replace_once(body, anchor, anchor + '''
    if (hdr->type == IEEE802_1X_TYPE_EAP_PACKET && plen == 4 &&
        buf[sizeof(*hdr)] == 3 && WPA_GET_BE16(buf + sizeof(*hdr) + 2) == 4) {
        tdn_public_record("EAP_SUCCESS_RECEIVE", buf, data_len);
    }
''')
        return source[:start] + body + source[end:]

    save("hostapd-2.12/src/radius/radius_server.c", server)
    save("hostapd-2.12/src/ap/ieee802_1x.c", authenticator)
    save("wpa_supplicant-2.12/src/eapol_supp/eapol_supp_sm.c", supplicant)
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest.exists():
        raise ValueError("Preserve the previous patch manifest")
    records = patch(args.root)
    args.manifest.write_text(json.dumps({"changes": records, "scope":
        "Public Access-Accept send bytes and return value; forwarded EAP-Success send/receive bytes. No plaintext key material is recorded."}, indent=2) + "\n")


if __name__ == "__main__":
    main()
