/* $OpenBSD: blf.h,v 1.7 2007/03/14 17:59:41 grunk Exp $ */
/*
 * Blowfish - a fast block cipher designed by Bruce Schneier
 *
 * Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#pragma once

#include <cstdint>

namespace bcrypt {
/* Schneier specifies a maximum key length of 56 bytes.
 * This ensures that every key bit affects every cipher
 * bit.  However, the subkeys can hold up to 72 bytes.
 * Warning: For normal blowfish encryption only 56 bytes
 * of the key affect all cipherbits.
 */

// Number of Subkeys
constexpr std::uint8_t kNumSubkeys = 16;
// 448 bits
constexpr std::uint8_t kMaxKeyLen = (kNumSubkeys-2)*4;

/* Blowfish context */
struct Context {
  std::uint32_t S[4][256]; /* S-Boxes */
  std::uint32_t P[kNumSubkeys + 2]; /* Subkeys */
};

/* Raw access to customized Blowfish
 *  blf_key is just:
 *  Blowfish_initstate( state )
 *  Blowfish_expand0state( state, key, keylen )
 */

void Blowfish_encipher(Context* ctx, std::uint32_t*, std::uint32_t *);
void Blowfish_initstate(Context* ctx);
void Blowfish_expand0state(Context* ctx, const std::uint8_t *, std::uint16_t);
void Blowfish_expandstate(
    Context* context,
    const std::uint8_t *,
    std::uint16_t,
    const std::uint8_t *,
    std::uint16_t);

/* Standard Blowfish */
void blf_enc(Context* ctx, std::uint32_t*, std::uint16_t);

/* Converts u_int8_t to u_int32_t */
std::uint32_t Blowfish_stream2word(const std::uint8_t*, std::uint16_t , std::uint16_t *);
} // namespace bcrypt
