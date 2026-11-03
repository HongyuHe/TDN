"""Add public correlation records to an isolated hostap source copy."""
import argparse
import hashlib
import json
from pathlib import Path


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Source anchor is absent or ambiguous: " + before[:80])
    return source.replace(before, after, 1)


def patch_tree(root):
    changes = []

    def save(relative, transform):
        path = root / relative
        original = path.read_text()
        if "TDN_REF" in original or "TDN_INSTALL" in original or "TDN_PEER_CERT" in original:
            raise ValueError("Use an unmodified source copy")
        updated = transform(original)
        path.write_text(updated)
        changes.append({"path": str(path), "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
                        "after_sha256": hashlib.sha256(updated.encode()).hexdigest()})

    def debug(source):
        source = replace_once(source, '#include "common.h"', '#include "common.h"\n#include "crypto/crypto.h"')
        helper = '''static void tdn_trace_ref(const char *title, const void *buf, size_t len)
{
    const u8 *bytes = buf;
    u8 digest[32];
    char encoded[65];
    if (!buf || sha256_vector(1, &bytes, &len, digest))
        return;
    wpa_snprintf_hex(encoded, sizeof(encoded), digest, sizeof(digest));
    wpa_printf(MSG_INFO, "TDN_REF title=%s size=%lu digest=%s", title,
               (unsigned long) len, encoded);
}


'''
        anchor = 'void wpa_hexdump(int level, const char *title, const void *buf, size_t len)\n{'
        source = replace_once(source, anchor, helper + anchor + '''
    if (os_strstr(title, "Session-Id") || os_strstr(title, "Derived CKN") ||
        os_strstr(title, "SA keyid") || os_strstr(title, "TDN_")) {
        tdn_trace_ref(title, buf, len);
    }''')
        anchor = 'void wpa_hexdump_key(int level, const char *title, const void *buf, size_t len)\n{'
        source = replace_once(source, anchor, anchor + '''
    if (os_strstr(title, "MSK") || os_strstr(title, "Derived key") ||
        os_strstr(title, "CAK") || os_strstr(title, "SAK") || os_strstr(title, "SA key")) {
        tdn_trace_ref(title, buf, len);
        if (len >= 32 && (os_strstr(title, "MSK") || os_strstr(title, "Derived key")))
            tdn_trace_ref("TDN_MSK_PREFIX32", buf, 32);
    }''')
        return source

    def tls(source):
        start = source.index('static int tls_verify_cb(')
        end = source.index('\n}\n', start)
        function = source[start:end]
        position = function.rfind('\treturn preverify_ok;')
        if position < 0:
            raise ValueError("TLS verification return is absent")
        trace = '''    if (depth == 0 && preverify_ok) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        char encoded[2 * EVP_MAX_MD_SIZE + 1];
        if (X509_digest(err_cert, EVP_sha256(), digest, &length)) {
            wpa_snprintf_hex(encoded, sizeof(encoded), digest, length);
            wpa_printf(MSG_INFO, "TDN_PEER_CERT ssl=%p sha256=%s subject=%s verified=1",
                       ssl, encoded, buf);
        }
    }
'''
        function = function[:position] + trace + function[position:]
        return source[:start] + function + source[end:]

    def driver(source):
        for direction in ['receive', 'transmit']:
            start = source.index('static int macsec_drv_create_' + direction + '_sa(')
            end = source.index('\n}\n', start)
            function = source[start:end]
            anchor = '\tret = nl_send_recv(ctx->sk, msg);'
            trace = '''
    if (ret == 0) {
        wpa_printf(MSG_INFO, "TDN_INSTALL direction=DIRECTION interface=%s sci=" SCISTR " an=%u result=0",
                   drv->ifname, SCI2STR(sa->sc->sci.addr, sa->sc->sci.port), sa->an);
        wpa_hexdump(MSG_INFO, "TDN_INSTALLED_KEY_ID_DIRECTION",
                    &sa->pkey->key_identifier, sizeof(sa->pkey->key_identifier));
        wpa_hexdump_key(MSG_INFO, "TDN_SAK_INSTALLED_DIRECTION", sa->pkey->key, sa->pkey->key_len);
    }'''.replace('DIRECTION', direction)
            function = replace_once(function, anchor, anchor + trace)
            source = source[:start] + function + source[end:]
        return source

    def kay(source):
        start = source.index('static int ieee802_1x_kay_mkpdu_validity_check(')
        end = source.index('\n}\n', start)
        function = source[start:end]
        anchor = '\treturn 0;'
        trace = '''    wpa_printf(MSG_INFO, "TDN_MKA_AUTH interface=%s peer=" MACSTR " result=0",
               kay->if_name, MAC2STR(eth_hdr->src));
    wpa_hexdump_key(MSG_INFO, "TDN_MKA_AUTH_CAK", participant->cak.key, participant->cak.len);
    wpa_hexdump(MSG_INFO, "TDN_MKA_AUTH_CKN", body->ckn, ckn_len);
'''
        function = replace_once(function, anchor, trace + anchor)
        return source[:start] + function + source[end:]

    def actor(source):
        anchor = '\t/* Derive CAK from MSK */'
        trace = '\twpa_hexdump(MSG_INFO, "TDN_EAP_SESSION", sid, sid_len);\n\twpa_hexdump_key(MSG_INFO, "TDN_MSK_KDF_INPUT", msk->key, msk->len);\n\n'
        return replace_once(source, anchor, trace + anchor)

    def server_session(source):
        anchor = '\treturn eap_server_tls_derive_session_id(sm, &data->ssl, EAP_TYPE_TLS,\n\t\t\t\t\t\tlen);'
        replacement = '\tu8 *sid = eap_server_tls_derive_session_id(sm, &data->ssl, EAP_TYPE_TLS, len);\n\tif (sid)\n\t\twpa_hexdump(MSG_INFO, "TDN_EAP_SESSION", sid, *len);\n\treturn sid;'
        return replace_once(source, anchor, replacement)

    if root.name == 'hostapd-2.12':
        save('src/ap/wpa_auth_kay.c', actor)
        save('src/eap_server/eap_server_tls.c', server_session)
    else:
        save('wpa_supplicant/wpas_kay.c', actor)

    save('src/utils/wpa_debug.c', debug)
    save('src/crypto/tls_openssl.c', tls)
    save('src/drivers/driver_macsec_linux.c', driver)
    save('src/pae/ieee802_1x_kay.c', kay)
    return changes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    if args.manifest.exists():
        raise ValueError("Keep the earlier patch manifest and use a new source copy")
    records = []
    for name in ['hostapd-2.12', 'wpa_supplicant-2.12']:
        records.extend(patch_tree(args.root / name))
    args.manifest.write_text(json.dumps({'changes': records,
        'scope': 'Observational SHA-256 identifiers; secret key dumps remain disabled'}, indent=2) + '\n')
    print('Patched', len(records), 'source files')


if __name__ == '__main__':
    main()
