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
#include <cstdint>

namespace bcrypt {
/**
 * Returns the number of bytes needed to hold the base64 encoding of |num_bytes|
 * of binary data from ToBase64. 
 */
constexpr std::uint32_t
ToSize(std::uint32_t num_bytes) noexcept;

/**
 * Returns the number of bytes needed to hold the binary data of |num_bytes|
 * of decoded base64 data from FromBase64.
 */
constexpr std::uint32_t
FromSize(std::uint32_t num_bytes) noexcept;

/**
 * Converts binary data to base 64 with using BCrypt's encoding.
 *
 * @param from The buffer containing the binary data.
 * @param num_bytes The number of bytes to convert from |from|.
 * @param to The buffer where the base 64 encoding is written to. It must be
 *  large enough to hold the encoding data. The size of buffer has to be at
 *  least ToSize(num_bytes) bytes large. No nullbyte is appended.
 */
void
ToBase64(const std::uint8_t* from, std::uint32_t num_bytes, std::uint8_t* to);

/**
 * Converts BCrypt's base 64 encoding to binary data.
 *
 * @param from The buffer containing the base 64 encoded data.
 * @param num_bytes The total number of bytes in |from|.
 * @param to The buffer where the binary data is written to. It must be large
 *  enough to hold the decoded data, at last FromSize(num_bytes) bytes. Null
 *  bytes is not appended.
 */
void
FromBase64(const std::uint8_t* from, std::uint32_t num_bytes, std::uint8_t* to);
} // namespace bcrypt
