"""Record public TLS handshake and authenticated RADIUS bytes in an isolated lab."""
import argparse
import hashlib
import json
from pathlib import Path


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Source anchor is absent or ambiguous: " + before[:80])
    return source.replace(before, after, 1)


def patch(root):
    records = []

    def save(relative, transform):
        path = root / relative
        before = path.read_text()
        if "TDN_PUBLIC" in before or "tdn_public_record" in before:
            raise ValueError("Use a fresh copy of the correlation-instrumented tree")
        after = transform(before)
        path.write_text(after)
        records.append({"path": str(path), "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
                        "after_sha256": hashlib.sha256(after.encode()).hexdigest()})

    def debug(source):
        helper = '''void tdn_public_record(const char *type, const void *buf, size_t len)
{
    char *encoded;
    if (!buf || len > 65535)
        return;
    encoded = os_malloc(2 * len + 1);
    if (!encoded)
        return;
    wpa_snprintf_hex(encoded, 2 * len + 1, buf, len);
    wpa_printf(MSG_INFO, "TDN_PUBLIC type=%s size=%lu hex=%s", type,
               (unsigned long) len, encoded);
    os_free(encoded);
}


'''
        anchor = 'static void tdn_trace_ref('
        source = replace_once(source, anchor, helper + anchor)
        anchor = 'void wpa_hexdump(int level, const char *title, const void *buf, size_t len)\n{'
        return replace_once(source, anchor, anchor + '\n    if (os_strcmp(title, "TDN_EAP_SESSION") == 0)\n        tdn_public_record("EAP_SESSION", buf, len);')

    def tls(source):
        start = source.index('static void tls_msg_cb(')
        end = source.index('\n}\n', start)
        function = source[start:end]
        anchor = '\tconst u8 *pos = buf;'
        trace = '''
    if ((write_p == 0 || write_p == 1) && content_type == 22 && len >= 4 &&
        (pos[0] != 4 && pos[0] != 24)) {
        wpa_printf(MSG_INFO, "TDN_TLS_MESSAGE ssl=%p direction=%s type=%u",
                   ssl, write_p ? "write" : "read", pos[0]);
        tdn_public_record("TLS_HANDSHAKE", buf, len);
    }
'''
        function = replace_once(function, anchor, anchor + trace)
        return source[:start] + function + source[end:]

    def radius(source):
        start = source.index('ieee802_1x_receive_auth(struct radius_msg *msg,')
        end = source.index('\n}\n', start)
        function = source[start:end]
        anchor = '\tsm->radius_identifier = -1;'
        trace = '''    if (hdr->code == RADIUS_CODE_ACCESS_ACCEPT) {
        struct wpabuf *request = radius_msg_get_buf(req);
        struct wpabuf *response = radius_msg_get_buf(msg);
        wpa_printf(MSG_INFO, "TDN_RADIUS_ACCEPT interface=%s peer=" MACSTR " identifier=%u verified=1",
                   hapd->conf->iface, MAC2STR(sta->addr), hdr->identifier);
        tdn_public_record("RADIUS_REQUEST", wpabuf_head(request), wpabuf_len(request));
        tdn_public_record("RADIUS_RESPONSE", wpabuf_head(response), wpabuf_len(response));
    }

'''
        function = replace_once(function, anchor, trace + anchor)
        return source[:start] + function + source[end:]

    save('src/utils/wpa_debug.c', debug)
    save('src/utils/wpa_debug.h', lambda source: replace_once(source, '#include "wpabuf.h"',
         '#include "wpabuf.h"\n\nvoid tdn_public_record(const char *type, const void *buf, size_t len);'))
    save('src/crypto/tls_openssl.c', tls)
    if root.name == 'hostapd-2.12':
        save('src/ap/ieee802_1x.c', radius)
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    if args.manifest.exists():
        raise ValueError("Preserve the existing manifest and choose a fresh source copy")
    records = []
    for product in ['hostapd-2.12', 'wpa_supplicant-2.12']:
        records.extend(patch(args.root / product))
    args.manifest.write_text(json.dumps({"changes": records, "scope":
        "Public initial TLS handshake messages, public EAP session ID and authenticated EAP RADIUS records. Secret keys, application data, session tickets and key logs are excluded."}, indent=2) + '\n')
    print('Patched', len(records), 'source files')


if __name__ == '__main__':
    main()
