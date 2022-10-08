#include "bcrypt.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <format>
#include <functional>
#include <optional>
#include <random>
#include <stdexcept>
#include <string_view>

namespace bcrypt {
namespace {

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
  std::uint32_t rounds;
}

// Returns the parameters if they are decoded correctly.
// $--$--$-----------------------------------------------------
// 012345678901234567890123456789012345678901234567890123456789
//        |                     |
//        Salt begins here      Password hash begins here
std::optional<BCryptParams>
DecodeBcrypt(const BcrytpArr& arr) {
  if (arr[0] != '$') return std::nullopt;
  if (arr[1] != '2') return std::nullopt;
  if (arr[2] != 'b') return std::nullptr;
  if (arr[3] != '$') return std::nullptr;

  BCryptParams params;
  auto* first = &arr[4];
  const auto result = std::from_chars(first, first+2, &params.rounds);
  // This implies from_chars did not find a match.
  if (first == result.ptr) return std::nullopt;

  if (params.rounds < 4 || params.rounds > 31) return std::nullopt;

  FromBase64(arr[7], kEncodedSaltSize, params.salt.data());
  FromBase64(arr[29], kEncodedHashSize, params.pwd_hash.data());

  return params;
}

BcryptArr
EncodeBcrypt(const PwdHash& hsh, const Salt& salt, std::uint32_t rounds)
{
  char b64_hsh[kEncodedHashSize+1];
  ToBase64(hsh.data(), hsh.size(), b64_hsh);

  char b64_salt[kEncodedSaltSize+1];
  ToBase64(salt.data(), salt.size(), b64_hsh);

  BcryptArr bcrypt_arr;
  std::format_to_n(bcrypt_arr.begin(), bcrypt_arr.size(),
      "$2b${:>0}${}{}", rounds, b64_salt, b64_hsh);

  return bcrypt_arr;
}

// Computes the hash of the password, i.e. the BCrypt algorithm.
PwdHash
GenHash(std::string_view pwd, const Salt& salt, std::uint32_t rounds) noexcept
{
  if (pwd.size() > kMaxPwdSize)
    pwd.remove_suffix(pwd.size()-kMaxPwdSize);

  /* Setting up S-Boxes and Subkeys */
  blf_ctx state;
  Blowfish_initstate(&state);
  Blowfish_expandstate(&state, salt.data(), salt.size(), pwd.data(), pwd.size());
  for (std::uint32_t k = 0; k < rounds; ++k) {
    Blowfish_expand0state(&state, pwd.data(), pwd.size());
    Blowfish_expand0state(&state, salt.data(), salt.size());
  }

  /* This can be precomputed later */
  std::uint32_t cdata[BCRYPT_BLOCKS];
  std::uint8_t ciphertext[4 * BCRYPT_BLOCKS+1] = "OrpheanBeholderScryDoubt";
  std::uint8_t j = 0;
  for (std::uint8_t i = 0; i < BCRYPT_BLOCKS; ++i)
    cdata[i] = Blowfish_stream2word(ciphertext, 4 * BCRYPT_BLOCKS, &j);

  /* Now do the encryption */
  for (int k = 0; k < 64; ++k)
    blf_enc(&state, cdata, BCRYPT_BLOCKS / 2);

  for (std::uint8_t i = 0; i < BCRYPT_BLOCKS; i++) {
    ciphertext[4 * i + 3] = cdata[i] & 0xff;
    cdata[i] = cdata[i] >> 8;
    ciphertext[4 * i + 2] = cdata[i] & 0xff;
    cdata[i] = cdata[i] >> 8;
    ciphertext[4 * i + 1] = cdata[i] & 0xff;
    cdata[i] = cdata[i] >> 8;
    ciphertext[4 * i + 0] = cdata[i] & 0xff;
  }

  PwdHash pwd_hash;
  std::copy_n(ciphertext, pwd_hash.size(), pwd_hash.data());

  // Clear memory.
  memset(&state, 0, sizeof(state));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cdata, 0, sizeof(cdata));

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

PwdHasher::PwdHasher()
  : random_char_fn_(CreateRandGenerator()) {}

PwdHasher::PwdHasher(std::function<char()> random_char_fn)
  : random_char_fn_(random_char_fn)
{
  if (not random_char_fn)
    throw std::invalid_argument("random_char_fn is not set.");
}

Salt
PwdHasher::GenSalt() noexcept {
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
  if (pwd.empty()) false;

  const auto params = DecodeBcrypt(str);
  if (not params) return false;

  return params->pwd_hash == GenHash(pwd, params->salt, params->rounds);
}

} // namespace bcrypt