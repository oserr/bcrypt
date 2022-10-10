#include "bcrypt.h"

#include <algorithm>
#include <array>
#include <functional>
#include <stdexcept>
#include <string_view>

#include "gmock/gmock.h"

namespace bcrypt {
namespace {

class PwdHasherTest : public testing::Test {
protected:
  PwdHasher pwd_hasher_;
};

TEST_F(PwdHasherTest, CtorThrowsIfRandomGeneratorIsNotSet) {
  EXPECT_THROW(PwdHasher(std::function<char()>()), std::invalid_argument);
}

TEST_F(PwdHasherTest, GenerateThrowsWithEmptyPassword) {
  EXPECT_THROW(pwd_hasher_.Generate("", 10), std::invalid_argument);
}

TEST_F(PwdHasherTest, GenerateThrowsWhenRoundsIsLessThan4) {
  EXPECT_THROW(pwd_hasher_.Generate("password", 3), std::invalid_argument);
}

TEST_F(PwdHasherTest, GenerateThrowsWhenRoundsIsMoreThan31) {
  EXPECT_THROW(pwd_hasher_.Generate("password", 32), std::invalid_argument);
}

TEST_F(PwdHasherTest, IsSamePwdReturnsTrueForGeneratedPassword) {
  auto random_char_fn = CreateRandCharGenerator();
  // Here capture by reference otherwise the function is copied by std::generate
  // and the state is not changed on the generator, so every other call to
  // std::generate produces the same sequence.
  auto rand_fn = [&random_char_fn]() -> char { return random_char_fn(); };
  std::array<char, 64> pwd_arr;
  for (int i = 0; i < 100; ++i) {
    std::generate(pwd_arr.begin(), pwd_arr.end(), rand_fn);
    std::string_view pwd(pwd_arr.data(), pwd_arr.size());
    const auto bcrypt_arr = pwd_hasher_.Generate(pwd);
    EXPECT_TRUE(pwd_hasher_.IsSamePwd(pwd, bcrypt_arr));
  }
}

} // namespace
} // namespace poker
