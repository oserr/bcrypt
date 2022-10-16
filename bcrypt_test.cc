#include "bcrypt.h"

#include <algorithm>
#include <array>
#include <functional>
#include <random>
#include <stdexcept>
#include <string_view>

#include "gmock/gmock.h"

namespace bcrypt {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Optional;

TEST(FormattingDecodingTest, WorksCorrectly) {
  PwdHash pwd_hash{
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w'};

  Salt salt{'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
            'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'};
  auto arr = EncodeBcrypt(pwd_hash, salt, 10);
  auto params = DecodeBcrypt(arr);
  EXPECT_THAT(params,
     Optional(AllOf(Field("pwd_hash", &BcryptParams::pwd_hash, Eq(pwd_hash)),
                    Field("salt", &BcryptParams::salt, Eq(salt)))));
}

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
  std::mt19937 gen(0);
  std::uniform_int_distribution<std::uint8_t> dist;
  auto random_fn = std::bind_front(dist, gen);

  std::vector<char> pwd_arr;
  pwd_arr.reserve(100);
  for (int i = 1; i < 100; ++i) {
    for (int j = 0; j < i; ++j)
      pwd_arr.push_back(random_fn());
    std::string_view pwd(pwd_arr.data(), pwd_arr.size());
    const auto bcrypt_arr = pwd_hasher_.Generate(pwd);
    EXPECT_TRUE(pwd_hasher_.IsSamePwd(pwd, bcrypt_arr));
    pwd_arr.clear();
  }
}

} // namespace
} // namespace bcrypt
