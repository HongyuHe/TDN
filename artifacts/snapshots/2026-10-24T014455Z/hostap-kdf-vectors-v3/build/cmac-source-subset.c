#include "utils/includes.h"
#include "utils/common.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#define TEST_FAIL() 0
int omac1_aes_vector(const u8 *key, size_t key_len, size_t num_elem,
		     const u8 *addr[], const size_t *len, u8 *mac)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MAC_CTX *ctx = NULL;
	EVP_MAC *emac;
	int ret = -1;
	size_t outlen, i;
	OSSL_PARAM params[2];
	char *cipher = NULL;

	if (TEST_FAIL())
		return -1;

	emac = EVP_MAC_fetch(NULL, "CMAC", NULL);

	if (key_len == 32)
		cipher = "aes-256-cbc";
	else if (key_len == 24)
		cipher = "aes-192-cbc";
	else if (key_len == 16)
		cipher = "aes-128-cbc";

	params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher, 0);
	params[1] = OSSL_PARAM_construct_end();

	if (!emac || !cipher ||
	    !(ctx = EVP_MAC_CTX_new(emac)) ||
	    EVP_MAC_init(ctx, key, key_len, params) != 1) {
		wpa_printf(MSG_INFO,
			   "OpenSSL: EVP_MAC_init(cmac,cipher=%s) failed: %s",
			   cipher, ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	for (i = 0; i < num_elem; i++) {
		if (!EVP_MAC_update(ctx, addr[i], len[i]))
			goto fail;
	}
	if (EVP_MAC_final(ctx, mac, &outlen, 16) != 1 || outlen != 16)
		goto fail;

	ret = 0;
fail:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(emac);
	return ret;
#else /* OpenSSL version >= 3.0 */
	CMAC_CTX *ctx;
	int ret = -1;
	size_t outlen, i;

	if (TEST_FAIL())
		return -1;

	ctx = CMAC_CTX_new();
	if (ctx == NULL)
		return -1;

	if (key_len == 32) {
		if (!CMAC_Init(ctx, key, 32, EVP_aes_256_cbc(), NULL))
			goto fail;
	} else if (key_len == 24) {
		if (!CMAC_Init(ctx, key, 24, EVP_aes_192_cbc(), NULL))
			goto fail;
	} else if (key_len == 16) {
		if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL))
			goto fail;
	} else {
		goto fail;
	}
	for (i = 0; i < num_elem; i++) {
		if (!CMAC_Update(ctx, addr[i], len[i]))
			goto fail;
	}
	if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16)
		goto fail;

	ret = 0;
fail:
	CMAC_CTX_free(ctx);
	return ret;
#endif /* OpenSSL version >= 3.0 */
}


int omac1_aes_128_vector(const u8 *key, size_t num_elem,
			 const u8 *addr[], const size_t *len, u8 *mac)
{
	return omac1_aes_vector(key, 16, num_elem, addr, len, mac);
}


int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
	return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}


int omac1_aes_256(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
	return omac1_aes_vector(key, 32, 1, &data, &data_len, mac);
}


