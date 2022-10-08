/*	$OpenBSD: bcrypt.c,v 1.31 2014/03/22 23:02:03 tedu Exp $	*/

/*
 * Copyright (c) 1997 Niels Provos <provos@umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This password hashing algorithm was designed by David Mazieres
 * <dm@lcs.mit.edu> and works as follows:
 *
 * 1. state := InitState ()
 * 2. state := ExpandKey (state, salt, password)
 * 3. REPEAT rounds:
 *    	state := ExpandKey (state, 0, password)
 *    state := ExpandKey (state, 0, salt)
 * 4. ctext := "OrpheanBeholderScryDoubt"
 * 5. REPEAT 64:
 *    	ctext := Encrypt_ECB (state, ctext);
 * 6. RETURN Concatenate (salt, ctext);
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "bcrypt_impl.h"

namespace bcrypt {

/* This implementation is adaptable to current computing power.
 * You can have up to 2^31 rounds which should be enough for some
 * time to come.
 */

static void encode_base64(u_int8_t *, u_int8_t *, u_int16_t);
static void decode_base64(u_int8_t *, u_int16_t, u_int8_t *);

const static u_int8_t Base64Code[] =
"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

constexpr u_int8_t index_64[128] = {
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 0, 1, 54, 55,
  56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
  255, 255, 255, 255, 255, 2, 3, 4, 5, 6,
  7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
  255, 255, 255, 255, 255, 255, 28, 29, 30,
  31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
  51, 52, 53, 255, 255, 255, 255, 255
};

inline
constexpr uint8_t ToChar64(u_int8_t c) { return c > 127 ? 255 : index_64[c]; }

static void
decode_base64(u_int8_t *buffer, u_int16_t len, u_int8_t *data)
{
  u_int8_t *bp = buffer;
  u_int8_t *p = data;

  while (bp < buffer + len) {
    u_int8_t c1 = ToChar64(*p);
    u_int8_t c2 = ToChar64(*(p + 1));

    /* Invalid data */
    if (c1 == 255 || c2 == 255) break;

    *bp++ = (c1 << 2) | ((c2 & 0x30) >> 4);
    if (bp >= buffer + len) break;

    u_int8_t c3 = ToChar64(*(p + 2));
    if (c3 == 255) break;

    *bp++ = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);
    if (bp >= buffer + len) break;

    u_int8_t c4 = ToChar64(*(p + 3));
    if (c4 == 255) break;

    *bp++ = ((c3 & 0x03) << 6) | c4;

    p += 4;
  }
}

static void
encode_base64(u_int8_t *buffer, u_int8_t *data, u_int16_t len)
{
  u_int8_t *bp = buffer;
  u_int8_t *p = data;
  while (p < data + len) {
    u_int8_t c1 = *p++;
    *bp++ = Base64Code[(c1 >> 2)];
    c1 = (c1 & 0x03) << 4;
    if (p >= data + len) {
      *bp++ = Base64Code[c1];
      break;
    }
    u_int8_t c2 = *p++;
    c1 |= (c2 >> 4) & 0x0f;
    *bp++ = Base64Code[c1];
    c1 = (c2 & 0x0f) << 2;
    if (p >= data + len) {
      *bp++ = Base64Code[c1];
      break;
    }
    c2 = *p++;
    c1 |= (c2 >> 6) & 0x03;
    *bp++ = Base64Code[c1];
    *bp++ = Base64Code[c2 & 0x3f];
  }
  *bp = '\0';
}

} // namespace bcrypt
