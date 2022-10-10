#include <array>
#include <cstdint>
#include <functional>
#include <random>
#include <string_view>

namespace bcrypt {

// Creates a random generator.
std::function<char()>
CreateRandCharGenerator(
    std::random_device::result_type seed = std::random_device()());

// Format is $2b$Cost$SaltHash and contains a total of 60 bytes.
// The dollar signs are part of the format:
// - 2b: the version of the algorithm.
// - Cost: The input cost, e.g. log2(cost). Number in range [4, 31].
// - Salt: 22 base64 encoded random bytes (16 total).
// - Hash: 31 base64 encoded bytes from the first 23 hashed bytes of the
//   password.
using BcryptArr = std::array<char, 60>;

// The first 23 bytes of the hash of the password, in binary form.
using PwdHash = std::array<char, 23>;

// 16 byte salt in binary form.
using Salt = std::array<char, 16>;

// Uses the bcrypt algorithm to hash and verify passwords. There are different
// versions of the bcrypt algorithm, e.g. 2a vs 2b, but PwdHasher always uses
// version 2b since there is no reason to use an older version.
class PwdHasher {
public:
  // Initializes the password hasher with a uniform random generator.
  PwdHasher() noexcept;

  // Initializes the password hasher with a uniform random generator.
  // If random_char_fn is not set, then it throws an exception.
  explicit PwdHasher(std::function<char()> random_char_fn);

  // Generates the hashed password and bcrypt metadata. Returns an error if the
  // password is empty or the number of rounds is not in the range [4, 31].
  BcryptArr
  Generate(std::string_view pwd, std::uint32_t rounds = 10) const;

  // Returns true if the password is the hashed password.
  bool
  IsSamePwd(std::string_view pwd, const BcryptArr& arr) const noexcept;

private:
  // Generates a salt with 16 random bytes.
  Salt
  GenSalt() const noexcept;

  // Random char generator. Used to generate salts.
  std::function<char()> random_char_fn_;
};

} // namespace bcrypt
