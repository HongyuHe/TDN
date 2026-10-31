#include "src/pae/ieee802_1x_key.c"
#include <openssl/crypto.h>
void *os_zalloc(size_t n) { return calloc(1,n); }
void wpa_printf(int level, const char *fmt, ...) { }
static int decode(const char *s,u8 *out) { int n=strlen(s);if(n%2)return -1;for(int i=0;i<n/2;i++){unsigned int x;if(sscanf(s+2*i,"%2x",&x)!=1)return -1;out[i]=x;}return n/2; }
int main(int argc,char **argv) {
 if(argc==2&&!strcmp(argv[1],"VERSION")){puts(OpenSSL_version(OPENSSL_VERSION));return 0;}
 if(argc!=5)return 2;
 u8 key[256],ctx[4096],out[64];int k=decode(argv[2],key),c=decode(argv[3],ctx),n=atoi(argv[4]),r=-1;
 if(k<0||c<0||n<1||n>32)return 2;
 if(!strcmp(argv[1],"KDF"))r=aes_kdf(key,k*8,"HI THERE",ctx,c*8,n*8,out);
 else if(!strcmp(argv[1],"CAK")&&c==12)r=ieee802_1x_cak_aes_cmac(key,k,ctx+6,ctx,out,n);
 else if(!strcmp(argv[1],"CKN")&&c>=12)r=ieee802_1x_ckn_aes_cmac(key,k,ctx+c-6,ctx+c-12,ctx,c-12,out);
 else if(!strcmp(argv[1],"KEK"))r=ieee802_1x_kek_aes_cmac(key,k,ctx,c,out,n);
 else if(!strcmp(argv[1],"ICK"))r=ieee802_1x_ick_aes_cmac(key,k,ctx,c,out,n);
 else if(!strcmp(argv[1],"SAK"))r=ieee802_1x_sak_aes_cmac(key,k,ctx,c,out,n);
 if(r)return 3;
 for(int i=0;i<n;i++)printf("%02x",out[i]);
 puts("");return 0;
}
