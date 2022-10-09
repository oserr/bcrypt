#include "bcrypt.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <functional>
#include <optional>
#include <random>
#include <stdexcept>
#include <string_view>

#include <fmt/core.h>
#include <fmt/format.h>

#include "bcrypt_b64.h"
#include "blowfish.h"

namespace bcrypt {
namespace {
// Ciphertext blocks.
constexpr std::uint8_t kBcryptBlocks = 6;

// The maximum size of the password that can be used by the algorithm.
constexpr std::uint32_t kMaxPwdSize = 72;

// The maximum number of bytes for the encoded password hash.
constexpr std::uint32_t kEncodedHashSize = 31;

// The maximum number of bytes for the base 64 encoded salt.
constexpr std::uint32_t kEncodedSaltSize = 22;

// Used internally to decode a bcrypt hash. These parameters are used to
// recompute the hash and verify that a password is correct. We don't use the
// versions here since we hardcode '2b'.
struct BcryptParams {
  PwdHash pwd_hash;
  Salt salt;
  std::uint32_t rounds = 0;
};

// Returns the parameters if they are decoded correctly.
// $--$--$-----------------------------------------------------
// 012345678901234567890123456789012345678901234567890123456789
//        |                     |
//        Salt begins here      Password hash begins here
std::optional<BcryptParams>
DecodeBcrypt(const BcryptArr& arr) {
  if (arr[0] != '$') return std::nullopt;
  if (arr[1] != '2') return std::nullopt;
  if (arr[2] != 'b') return std::nullopt;
  if (arr[3] != '$') return std::nullopt;

  BcryptParams params;
  auto* first = &arr[4];
  const auto result = std::from_chars(first, first+2, params.rounds);
  // This implies from_chars did not find a match.
  if (first == result.ptr) return std::nullopt;

  if (params.rounds < 4 || params.rounds > 31) return std::nullopt;

  FromBase64(reinterpret_cast<const std::uint8_t*>(&arr[7]),
             kEncodedSaltSize,
             reinterpret_cast<std::uint8_t*>(params.salt.data()));
  FromBase64(reinterpret_cast<const std::uint8_t*>(&arr[29]),
             kEncodedHashSize,
             reinterpret_cast<std::uint8_t*>(params.pwd_hash.data()));

  return params;
}

BcryptArr
EncodeBcrypt(const PwdHash& hsh, const Salt& salt, std::uint32_t rounds)
{
  char b64_hash[kEncodedHashSize+1];
  ToBase64(reinterpret_cast<const std::uint8_t*>(hsh.data()),
           hsh.size(),
           reinterpret_cast<std::uint8_t*>(b64_hash));

  char b64_salt[kEncodedSaltSize+1];
  ToBase64(reinterpret_cast<const std::uint8_t*>(salt.data()),
           salt.size(),
           reinterpret_cast<std::uint8_t*>(b64_salt));

  BcryptArr bcrypt_arr;
  fmt::format_to_n(bcrypt_arr.begin(), bcrypt_arr.size(),
      FMT_STRING("$2b${:>0}${}{}"), rounds, b64_salt, b64_hash);

  return bcrypt_arr;
}

// Computes the hash of the password, i.e. the BCrypt algorithm.
PwdHash
GenHash(std::string_view pwd, const Salt& salt, std::uint32_t rounds) noexcept
{
  // Cap number of password bytes to 72.
  if (pwd.size() > kMaxPwdSize)
    pwd.remove_suffix(pwd.size()-kMaxPwdSize);

  // Setting up S-Boxes and Subkeys
  Context ctx;
  Blowfish_initstate(&ctx);
  Blowfish_expandstate(
      &ctx, reinterpret_cast<const std::uint8_t*>(salt.data()),
      salt.size(), reinterpret_cast<const std::uint8_t*>(pwd.data()),
      pwd.size());
  for (std::uint32_t k = 0; k < rounds; ++k) {
    Blowfish_expand0state(
        &ctx, reinterpret_cast<const std::uint8_t*>(pwd.data()), pwd.size());
    Blowfish_expand0state(
        &ctx, reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size());
  }

  // This can be precomputed later.
  std::uint32_t cdata[kBcryptBlocks];
  std::uint8_t ciphertext[4*kBcryptBlocks+1] = "OrpheanBeholderScryDoubt";
  std::uint16_t j = 0;
  for (std::uint8_t i = 0; i < kBcryptBlocks; ++i)
    cdata[i] = Blowfish_stream2word(ciphertext, 4 * kBcryptBlocks, &j);

  // Now do the encryption.
  for (int k = 0; k < 64; ++k)
    blf_enc(&ctx, cdata, kBcryptBlocks / 2);

  for (std::uint8_t i = 0; i < kBcryptBlocks; ++i) {
    const auto chr = cdata[i];
    const auto k = i * 4;
    ciphertext[k+3] = chr & 0xff;
    ciphertext[k+2] = (chr >> 8) & 0xff;
    ciphertext[k+1] = (chr >> 16) & 0xff;
    ciphertext[k+0] = (chr >> 24) & 0xff;
  }

  PwdHash pwd_hash;
  std::copy_n(ciphertext, pwd_hash.size(), pwd_hash.data());

  // Clear memory.
  std::fill_n(reinterpret_cast<char*>(&ctx), sizeof(ctx), 0);
  std::fill_n(ciphertext, 4*kBcryptBlocks+1, 0);
  std::fill_n(cdata, kBcryptBlocks, 0);

  return pwd_hash;
}

std::function<char()>
CreateRandGenerator() {
  std::random_device rd;
  std::mt19937 generator(rd());
  return std::bind(std::uniform_int_distribution<char>(), generator);
}
} // namespace

///////////////////////////////////////////////////////////////////////////////
// PwdHasher
///////////////////////////////////////////////////////////////////////////////

PwdHasher::PwdHasher() noexcept
  : random_char_fn_(CreateRandGenerator()) {}

PwdHasher::PwdHasher(std::function<char()> random_char_fn)
  : random_char_fn_(random_char_fn)
{
  if (not random_char_fn)
    throw std::invalid_argument("random_char_fn is not set.");
}

Salt
PwdHasher::GenSalt() const noexcept {
  Salt salt;
  std::generate(salt.begin(), salt.end(), random_char_fn_);
  return salt;
}

BcryptArr
PwdHasher::Generate(std::string_view pwd, std::uint32_t rounds) const
{
  if (pwd.empty())
    throw std::invalid_argument("Password cannot be empty.");
  if (rounds < 4 or rounds > 31)
    throw std::invalid_argument("rounds should be in the range [4, 31].");
  const auto salt = GenSalt();
  const auto pwd_hash = GenHash(pwd, salt, rounds);
  return EncodeBcrypt(pwd_hash, salt, rounds);
}

bool
PwdHasher::IsSamePwd(std::string_view pwd, const BcryptArr& str) const noexcept
{
  if (pwd.empty()) return false;

  const auto params = DecodeBcrypt(str);
  if (not params) return false;

  return params->pwd_hash == GenHash(pwd, params->salt, params->rounds);
}
} // namespace bcrypt
