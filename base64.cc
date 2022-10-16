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
#include "base64.h"

#include <cstdint>

namespace bcrypt {
namespace {
// Base 64 code used by BCrypt.
constexpr std::uint8_t kBase64Code[] =
  "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// Used to convert base 64 to binary.
constexpr std::uint8_t kIndex64[128] = {
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 0, 1, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 255, 255, 255, 255, 255,
  255, 255, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, 26, 27, 255, 255, 255, 255, 255, 255, 28, 29, 30, 31, 32,
  33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
  52, 53, 255, 255, 255, 255, 255
};

inline constexpr std::uint8_t
ToChar64(std::uint8_t c) { return kIndex64[c & 0x7f]; }
} // namespace

std::uint32_t
ToSize(std::uint32_t num_bytes) noexcept
{
  auto q = num_bytes / 3;
  auto r = num_bytes % 3;
  return (q * 4) + (r ? r + 1 : 0);
}

std::uint32_t
FromSize(std::uint32_t num_bytes) noexcept {
  auto q = num_bytes / 4;
  auto r = num_bytes % 4;
  return (q * 3) + (r ? r - 1 : 0);
}

// --------|--------|--------
// ------|------|------|------
void
ToBase64(const std::uint8_t* from, std::uint32_t num_bytes, std::uint8_t* to)
{
  auto* last = from + num_bytes;
  // Process three bytes at a time to simplify logic and reduce number of
  // branches in tight loop. We handle remaining bytes below.
  for (; from <= last - 3; from += 3, to += 4) {
    const auto f1 = from[0];
    const auto f2 = from[1];
    const auto f3 = from[2];

    const auto t1 = f1 >> 2;
    const auto t2 = ((f1 & 0x03) << 4) | (f2 >> 4);
    const auto t3 = ((f2 & 0x0f) << 2) | (f3 >> 6);
    const auto t4 = f3 & 0x3f;

    to[0] = kBase64Code[t1];
    to[1] = kBase64Code[t2];
    to[2] = kBase64Code[t3];
    to[3] = kBase64Code[t4];
  }

  const auto diff = last - from;
  if (diff == 1) {
    const auto f1 = from[0];
    const auto t1 = f1 >> 2;
    const auto t2 = (f1 & 0x03) << 4;
    to[0] = kBase64Code[t1];
    to[1] = kBase64Code[t2];
    to += 2;
  } else if (diff == 2) {
    const auto f1 = from[0];
    const auto f2 = from[1];
    const auto t1 = f1 >> 2;
    const auto t2 = ((f1 & 0x03) << 4) | (f2 >> 4);
    const auto t3 = (f2 & 0x0f) << 2;
    to[0] = kBase64Code[t1];
    to[1] = kBase64Code[t2];
    to[2] = kBase64Code[t3];
    to += 3;
  }
}

// ------|------|------|------
// --------|--------|--------
// t1 = f1(6).f2(2)
// t2 = f2(4).f3(4)
// t2 = f3(2).f4(6)
void
FromBase64(const std::uint8_t* from, std::uint32_t num_bytes, std::uint8_t* to)
{
  auto* last = from + num_bytes;
  // Process 4 bytes at a time to simplify logic and reduce number of
  // branches in tight loop. We handle remaining bytes below.
  for (; from <= last - 4; from += 4, to += 3) {
    const auto f1 = ToChar64(from[0]);
    const auto f2 = ToChar64(from[1]);
    const auto f3 = ToChar64(from[2]);
    const auto f4 = ToChar64(from[3]);
    to[0] = (f1 << 2) | (f2 >> 4);
    to[1] = (f2 << 4) | (f3 >> 2);
    to[2] = (f3 << 6) | f4;
  }

  const auto diff = last - from;
  if (diff == 2) {
    const auto f1 = ToChar64(from[0]);
    const auto f2 = ToChar64(from[1]);
    *to++ = (f1 << 2) | ((f2 >> 4) & 0x03);
  } else if (diff == 3) {
    const auto f1 = ToChar64(from[0]);
    const auto f2 = ToChar64(from[1]);
    const auto f3 = ToChar64(from[2]);
    to[0] = (f1 << 2) | (f2 >> 4);
    to[1] = (f2 << 4) | (f3 >> 2);
    to += 2;
  }
}
} // namespace bcrypt
