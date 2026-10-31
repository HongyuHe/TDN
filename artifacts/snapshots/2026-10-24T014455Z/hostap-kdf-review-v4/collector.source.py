import hashlib,json,shutil
from pathlib import Path
from datetime import datetime,timezone
run=Path('artifacts/construction/2026-10-24T014455Z');base=Path('artifacts/snapshots/2026-10-24T014455Z');out=base/'hostap-kdf-review-v4';out.mkdir();checks=[]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for name in ['hostap-kdf-vectors-v3','hostap-kdf-bindings-v4']:
 d=base/name;m=json.loads((d/'manifest.json').read_text())
 for row in m['files']:assert sha(d/row['path'])==row['sha256']
 o=json.loads((d/'observations.json').read_text());assert not o.get('error')
 probes=[r for r in o['records']if'expected_result'in r];assert all(r['expected_result']==r['observed_result']for r in probes)
 checks.append({'path':str(d),'manifest_sha256':sha(d/'manifest.json'),'finite_vectors':len(probes),'records':len(o['records'])})
assert checks[0]['finite_vectors']==12
for name in ['ieee8021x-university-publication','ieee8021x-indexed-kdf-review']:
 shutil.copytree(run/'references'/name,out/'references'/name)
(out/'interpretation.md').write_text("""# Bounded IEEE KDF and algorithm-agility review

The visible primary IEEE publication text supports review of Sections 6.2.1, 6.2.2 and 9.3 plus Annex G.1 through G.6. The university URL returns 404 during live retrieval. Search-indexed publication text remains available, and its edition/title/DOI match the official IEEE catalog and official RFC bibliography. No complete PDF, issuer-hosted bytes or cryptographic authenticity is claimed.

Section 6.2.1 specifies the AES-CMAC counter-mode KDF with a one-byte counter, separator, context and two-byte big-endian output bit length. The key length selects AES-CMAC-128 or AES-CMAC-256. Section 6.2.2 selects the first16 or32 MSK bytes for128- or256-bit CAKs, sorted source MACs and the EAP Session-ID for the16-byte CKN. Section 9.3 identifies00-80-C2-01 and derives ICK/KEK using CAK and the padded first16 CKN bytes. Those visible clauses are available source evidence.

Both final EAP wrapper sources request32 MSK bytes and set the CAK length to32. Their retrieval functions clamp the copied prefix to that requested length. Both leave the CKN length at16. The shared derivation functions sort the MAC addresses and use the exact labels and contexts. The shared KAY code uses identifier00-80-C2-01 despite its older internal constant name. It selects the recorded derivation functions, sets ICK/KEK lengths equal to CAK length and rejects a different incoming agility identifier in its source check.

The harness includes the exact official ieee802_1x_key.c without editing its derivation functions. It compiles the original OpenSSL CMAC function bytes from crypto_openssl.c in the pinned OpenSSL3.5.5 image. Both final hostapd and wpa_supplicant full source files match those tested official files byte for byte. Final binary hashes and library linkage are separately captured. The harness calls freshly compiled functions; it does not call functions extracted from the already linked runtime ELF.

All12 published128/256-bit Annex G KDF, CAK, CKN, KEK, ICK and SAK vectors match. The CAK and CKN calls reverse the supplied MAC order to exercise sorting. G3 uses the complete Session-ID visible on p285. Its indexed repeat on p286 contains an odd-length hexadecimal group. Both captures and the interpretation are retained.

The result supports the specific256-bit CAK/KEK/ICK choice and its visible derivation clauses. It does not establish full IEEE standard conformance, independent implementation interoperability, all error paths, every MKA lifecycle event, product approval or live-secret correctness. No live MSK, CAK, KEK, ICK or SAK is exported. All test inputs are published noncredential examples.
""")
scope=['Visible IEEE 802.1X-2020 Sections 6.2.1, 6.2.2 and9.3 plus Annex G.1–G.6 now support bounded source review; the publication hosting/indexing/authenticity caveat remains explicit. Known visible clauses are no longer labeled absent.','All12 published128/256-bit KDF, CAK, CKN, KEK, ICK and SAK vectors match actual unchanged official derivation source and original OpenSSL CMAC function bytes in the pinned OpenSSL3.5.5 runtime. Exact final authenticator and supplicant source hashes match that tested source.','Both EAP wrappers use the first32 MSK bytes for the32-byte CAK and16-byte CKN; shared KAY uses agility00-80-C2-01 and CAK-sized ICK/KEK. Code and line locations are retained, with final binary hashes and linkage.','This finite source/vector result does not establish full-standard conformance, independent interoperability, all lifecycle/error behavior, product approval or any live secret value. The existing v18 functional and delay results remain separate.']
spacing={'first16':'first 16','first32':'first 32','first16 or32':'first 16 or 32','for128- or256-bit':'for 128- or 256-bit','the16-byte':'the 16-byte','identifies00':'identifies 00','request32':'request 32','to32':'to 32','at16':'at 16','identifier00':'identifier 00','OpenSSL3.5.5':'OpenSSL 3.5.5','All12':'All 12','published128':'published 128','specific256':'specific 256','and9.3':'and 9.3','the32-byte':'the 32-byte','and16-byte':'and 16-byte','agility00':'agility 00'}
text=(out/'interpretation.md').read_text()
for before,after in spacing.items():text=text.replace(before,after)
(out/'interpretation.md').write_text(text)
for before,after in spacing.items():scope=[s.replace(before,after)for s in scope]
(out/'review.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'checks':checks,'scope':scope},indent=2)+'\n');(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':str(p.relative_to(out)),'sha256':sha(p)}for p in out.rglob('*')if p.is_file()]},indent=2)+'\n')
response={'id':'IEEE-KDF-REVIEW-v4','at':datetime.now(timezone.utc).isoformat(),'status':'ready-bounded-primary-publication-and-twelve-vectors','groups':['RG-025','RG-026','RG-027','RG-028'],'bundle_paths':[str(base/'hostap-kdf-vectors-v3'),str(base/'hostap-kdf-bindings-v4'),str(out)],'checks':checks,'scope':scope}
(run/'responses/IEEE-KDF-REVIEW-v4.json').write_text(json.dumps(response,indent=2)+'\n');print(str(run/'responses/IEEE-KDF-REVIEW-v4.json'))
