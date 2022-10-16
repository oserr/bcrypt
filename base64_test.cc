#include "base64.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <random>

#include "gmock/gmock.h"

namespace bcrypt {
namespace {

TEST(ToSize, WorksCorrectly) {
  std::array<std::uint32_t, 10> values = {0, 2, 3, 4, 6, 7, 8, 10, 11, 12};
  for (std::uint32_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(ToSize(i), values[i]);
  }
}

TEST(FromSize, WorksCorrectly) {
  std::array<std::uint32_t, 10> values = {0, 0, 1, 2, 3, 3, 4, 5, 6, 6};
  for (std::uint32_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(FromSize(i), values[i]);
  }
}

TEST(ToBase64, WorksCorrectly) {
  auto rand_fn = std::bind_front(std::uniform_int_distribution<std::uint8_t>(),
                                 std::mt19937(0));

  std::uint8_t from[1024];
  std::uint8_t b64[1024];
  std::uint8_t to[1024];

  for (int i = 1; i < 256; ++i) {
    for (int j = 0; j < i; ++j)
      from[j] = rand_fn();
    from[i] = 0;
    ToBase64(from, i, b64);
    const auto b = ToSize(i);
    b64[b] = 0;
    FromBase64(b64, b, to);
    EXPECT_TRUE(std::equal(from, from+i, to))
      << "unable to convert base 64 " << b64 << " back to it's original for i = " << i;
  }
}

} // namespace
} // namespace poker
