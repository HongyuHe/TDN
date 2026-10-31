import difflib,hashlib,json,shutil,subprocess
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-continuation-2026-10-24T014455Z');out=root/'exports/hostap-delay-build-v3';out.mkdir();tree=root/'hostap-delay/wpa_supplicant-2.12';records=[];error=None
try:
 shutil.copytree(root/'hostap/wpa_supplicant-2.12',tree)
 h=tree/'src/pae/ieee802_1x_kay.h';c=tree/'src/pae/ieee802_1x_kay.c';before_h=h.read_text();before_c=c.read_text()
 after_h=before_h.replace('\tu32 next_pn; /* PN nextPN (read only) */','\tu32 next_pn; /* PN nextPN (read only) */\n\tu32 evidence_delay_pn[8];\n\tstruct os_reltime evidence_delay_time[8];\n\tu8 evidence_delay_next;',1)
 after_c=before_c
 needle='\t\tkay->mka_hello_time = MKA_HELLO_TIME;';offset=after_c.rfind(needle);assert offset>=0;after_c=after_c[:offset]+after_c[offset:].replace(needle,'\t\tkay->mka_hello_time = MKA_BOUNDED_HELLO_TIME;',1)
 after_c=after_c.replace('eloop_register_timeout(kay->mka_hello_time / 1000, 0,','eloop_register_timeout(kay->mka_hello_time / 1000,\n\t\t\t       (kay->mka_hello_time % 1000) * 1000,')
 needle='''			lpn = (txsa->next_pn > 0) ? (txsa->next_pn - 1) : 0;'''
 replacement='''			if (principal->kay->mka_hello_time <= MKA_BOUNDED_HELLO_TIME) {
				struct os_reltime now;
				unsigned int slot, latest, j;
				long age, best_age = 0x7fffffff;
				os_get_reltime(&now);
				secy_get_transmit_next_pn(principal->kay, txsa);
				slot = txsa->evidence_delay_next;
				latest = (slot + 7) % 8;
				age = (now.sec - txsa->evidence_delay_time[latest].sec) *
					1000000 + now.usec -
					txsa->evidence_delay_time[latest].usec;
				if (!txsa->evidence_delay_time[latest].sec || age >= 400000) {
					txsa->evidence_delay_pn[slot] = txsa->next_pn;
					txsa->evidence_delay_time[slot] = now;
					txsa->evidence_delay_next = (slot + 1) % 8;
				}
				lpn = 1;
				for (j = 0; j < 8; j++) {
					if (!txsa->evidence_delay_time[j].sec)
						continue;
					age = (now.sec - txsa->evidence_delay_time[j].sec) *
						1000000 + now.usec -
						txsa->evidence_delay_time[j].usec;
					if (age >= 1000000 && age < best_age) {
						lpn = txsa->evidence_delay_pn[j];
						best_age = age;
					}
				}
				wpa_printf(MSG_DEBUG,
					"EVIDENCE delay LPN=%u normalHello=%u boundedHello=%u lifetime=%u",
					lpn, MKA_HELLO_TIME, principal->kay->mka_hello_time,
					MKA_LIFE_TIME);
				break;
			}
			lpn = (txsa->next_pn > 0) ? (txsa->next_pn - 1) : 0;'''
 assert after_c.count(needle)==1;after_c=after_c.replace(needle,replacement)
 for name,path,before,after in [('ieee802_1x_kay.h',h,before_h,after_h),('ieee802_1x_kay.c',c,before_c,after_c)]:
  (out/(name+'.before')).write_text(before);(out/(name+'.after')).write_text(after);(out/(name+'.patch')).write_text(''.join(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),fromfile='a/src/pae/'+name,tofile='b/src/pae/'+name)));path.write_text(after)
 work=tree/'wpa_supplicant';(out/'wpa_supplicant.config').write_bytes((work/'.config').read_bytes())
 for cmd in [['make','clean'],['make','-j4'],['sha256sum','./wpa_supplicant'],['./wpa_supplicant','-v'],['ldd','./wpa_supplicant']]:
  r=subprocess.run(cmd,cwd=work,capture_output=True,text=True,timeout=180);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':cmd,'cwd':str(work),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if r.returncode:raise RuntimeError(r.stderr[-2000:])
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Owned experimental hostap 2.12 build enables 500 ms bounded MKA transmission while retaining normal Hello 2000 ms and lifetime 6000 ms constants. The timer preserves subsecond units.','A bounded one-second PN sample history replaces the old get_lpn method that explicitly assumed a two-second transmit interval. The advertised lower bound uses next PN so idle transmission does not preserve an old frame indefinitely.','The history and finite delayed-frame tests are experimental implementation work. Full IEEE 802.1X normative conformance and every key rollover/control-delay case remain separate. The original hostap receive-delay code already programs Linux receive lowest PN.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error}))
