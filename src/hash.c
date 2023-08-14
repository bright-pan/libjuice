/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#if !defined(JUICE_CONFIG_FILE)
#include "juice/juice_config.h"
#else
#include JUICE_CONFIG_FILE
#endif

#include "hash.h"

#if USE_NETTLE
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#elif defined(CONFIG_LIBJUICE_USE_MBEDTLS)
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#else
#include "picohash.h"
#endif

void hash_md5(const void *message, size_t size, void *digest) {
#if USE_NETTLE
	struct md5_ctx ctx;
	md5_init(&ctx);
	md5_update(&ctx, size, message);
	md5_digest(&ctx, HASH_MD5_SIZE, digest);
#elif defined(CONFIG_LIBJUICE_USE_MBEDTLS)
	mbedtls_md5(message, size, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_md5(&ctx);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}

void hash_sha1(const void *message, size_t size, void *digest) {
#if USE_NETTLE
	struct sha1_ctx ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, size, message);
	sha1_digest(&ctx, HASH_SHA1_SIZE, digest);
#elif defined(CONFIG_LIBJUICE_USE_MBEDTLS)
	mbedtls_sha1(message, size, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_sha1(&ctx);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}

void hash_sha256(const void *message, size_t size, void *digest) {
#if USE_NETTLE
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, size, message);
	sha256_digest(&ctx, HASH_SHA256_SIZE, digest);
#elif defined(CONFIG_LIBJUICE_USE_MBEDTLS)
	mbedtls_sha256(message, size, digest, 0);
#else
	picohash_ctx_t ctx;
	picohash_init_sha256(&ctx);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}
