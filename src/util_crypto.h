/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2009 Sebastien Vincent <sebastien.vincent@turnserver.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

/*
 * Copyright (C) 2008-2009 Sebastien Vincent.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * This product includes software developed by the OpenSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 */

/**
 * \file util_crypto.h
 * \brief Some helper cryptographic functions.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#ifndef UTIL_CRYPTO_H
#define UTIL_CRYPTO_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef _MSC_VER
/* Microsoft compiler does not have stdint.h */
#include <stdint.h>
#else
/* replacement for stdint.h */
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#endif

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

/**
 * \brief Initialize the PRNG.
 * \return 0 if successfull, -1 if seed is cryptographically weak
 */
int seed_prng_init(void);

/**
 * \brief Cleanup the PRNG.
 * \return 0 if successfull, -1 if seed is cryptographically weak
 */
void seed_prng_cleanup(void);

/**
 * \brief Generate random bytes.
 * \param id buffer that will be filled with random value
 * \param len length of id
 * \return 0 if successfull, -1 if the random number is cryptographically weak
 */
int random_bytes_generate(uint8_t* id, size_t len);

/**
 * \brief Generate a SHA1 hash.
 * \param hash buffer with at least 20 bytes length
 * \param text text to hash
 * \param len text length
 * \return 0 if success, -1 otherwise
 */
int sha1_generate(unsigned char* hash, const unsigned char* text, size_t len);

/**
 * \brief Generate a MD5 hash.
 * \param hash buffer with at least 16 bytes length
 * \param text text to hash
 * \param len text length
 * \return 0 if success, -1 otherwise
 */
int md5_generate(unsigned char* hash, const unsigned char* text, size_t len);

/**
 * \brief Generate a HMAC-SHA1 hash.
 * \param hash buffer with at least 20 bytes length
 * \param text text to hash
 * \param text_len text length
 * \param key key used for HMAC
 * \param key_len key length
 * \return 0 if success, -1 otherwise
 */
int hmac_sha1_generate(unsigned char* hash, const unsigned char* text,
    size_t text_len, const unsigned char* key, size_t key_len);

/**
 * \brief Generate a HMAC-MD5 hash.
 * \param hash buffer with at least 16 bytes length
 * \param text text to hash
 * \param text_len text length
 * \param key key used for HMAC
 * \param key_len key length
 * \return 0 if success, -1 otherwise
 */
int hmac_md5_generate(unsigned char* hash, const unsigned char* text,
    size_t text_len, const unsigned char* key, size_t key_len);

/**
 * \brief Generate a CRC-32 (ISO 3309, ITU-T V.42 8.1.1.6.2, RFC 1952).
 * \param data data
 * \param len length of data
 * \param prev previous value
 * \return CRC-32 of data
 */
uint32_t crc32_generate(const uint8_t* data, size_t len, uint32_t prev);

/**
 * \brief Print a digest.
 * \param buf buffer
 * \param len length of buffer
 */
void digest_print(const unsigned char* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_CRYPTO_H */

