/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "hmac.h"

#if USE_NETTLE
#include <nettle/hmac.h>
#elif defined(CONFIG_LIBJUICE_USE_MBEDTLS)
#include <mbedtls/md.h>
#else
#include "picohash.h"
#endif

void hmac_sha1(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
#if USE_NETTLE
	struct hmac_sha1_ctx ctx;
	hmac_sha1_set_key(&ctx, key_size, key);
	hmac_sha1_update(&ctx, size, message);
	hmac_sha1_digest(&ctx, HMAC_SHA1_SIZE, digest);
#elif defined(CONFIG_LIBJUICE_USE_MBEDTLS)
    const mbedtls_md_type_t alg = MBEDTLS_MD_SHA1;
    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    /* prepare context and load key */
    // the last argument to setup is 1 to enable HMAC (not just hashing)
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(alg);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, key, key_size);

    /* compute HMAC(key, msg1_part1 | msg1_part2) */
    mbedtls_md_hmac_update(&ctx, message, size);
    mbedtls_md_hmac_finish(&ctx, digest);
    //print_buf("hmac_sha256: ", digest, mbedtls_md_get_size(info));
    mbedtls_md_free(&ctx);
#else
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha1, key, key_size);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}

void hmac_sha256(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
#if USE_NETTLE
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, key_size, key);
	hmac_sha256_update(&ctx, size, message);
	hmac_sha256_digest(&ctx, HMAC_SHA256_SIZE, digest);
#elif defined(CONFIG_LIBJUICE_USE_MBEDTLS)
    const mbedtls_md_type_t alg = MBEDTLS_MD_SHA256;
    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    /* prepare context and load key */
    // the last argument to setup is 1 to enable HMAC (not just hashing)
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(alg);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, key, key_size);

    /* compute HMAC(key, msg1_part1 | msg1_part2) */
    mbedtls_md_hmac_update(&ctx, message, size);
    mbedtls_md_hmac_finish(&ctx, digest);
    //print_buf("hmac_sha256: ", digest, mbedtls_md_get_size(info));
    mbedtls_md_free(&ctx);
#else
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha256, key, key_size);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}
