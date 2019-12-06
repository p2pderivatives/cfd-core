#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::RandomNumberUtil;
using cfd::core::SigHashType;
using cfd::core::SigHashAlgorithm;

// GetRandomBytes--------------------------------------------------------------
TEST(RandomNumberUtil, GetRandomBytes4) {
  int size = 4;
  std::vector<uint8_t> bytes = RandomNumberUtil::GetRandomBytes(size);
  std::vector<uint8_t> bytes2 = RandomNumberUtil::GetRandomBytes(size);
  EXPECT_EQ(bytes.size(), static_cast<size_t>(size));
  EXPECT_EQ(bytes2.size(), static_cast<size_t>(size));
  EXPECT_STRNE(ByteData(bytes).GetHex().c_str(),
               ByteData(bytes2).GetHex().c_str());
}

TEST(RandomNumberUtil, GetRandomBytes16) {
  int size = 16;
  std::vector<uint8_t> bytes = RandomNumberUtil::GetRandomBytes(size);
  std::vector<uint8_t> bytes2 = RandomNumberUtil::GetRandomBytes(size);
  EXPECT_EQ(bytes.size(), static_cast<size_t>(size));
  EXPECT_EQ(bytes2.size(), static_cast<size_t>(size));
  EXPECT_STRNE(ByteData(bytes).GetHex().c_str(),
               ByteData(bytes2).GetHex().c_str());
}

TEST(RandomNumberUtil, GetRandomBytes18) {
  int size = 18;
  std::vector<uint8_t> bytes = RandomNumberUtil::GetRandomBytes(size);
  std::vector<uint8_t> bytes2 = RandomNumberUtil::GetRandomBytes(size);
  EXPECT_EQ(bytes.size(), static_cast<size_t>(size));
  EXPECT_EQ(bytes2.size(), static_cast<size_t>(size));
  EXPECT_STRNE(ByteData(bytes).GetHex().c_str(),
               ByteData(bytes2).GetHex().c_str());
}

TEST(RandomNumberUtil, GetRandomBytesEmpty) {
  int size = 0;
  std::vector<uint8_t> bytes = RandomNumberUtil::GetRandomBytes(size);
  EXPECT_STREQ(ByteData(bytes).GetHex().c_str(), "");
  EXPECT_EQ(bytes.size(), static_cast<size_t>(size));
}

TEST(RandomNumberUtil, GetRandomIndexesEmpty) {
  uint32_t length = 0;
  std::vector<uint32_t> indexes = RandomNumberUtil::GetRandomIndexes(length);
  EXPECT_EQ(indexes.size(), static_cast<size_t>(length));
}

// GetRandomIndexes------------------------------------------------------------
TEST(RandomNumberUtil, GetRandomIndexes1) {
  uint32_t length = 1;
  std::vector<uint32_t> indexes = RandomNumberUtil::GetRandomIndexes(length);
  EXPECT_EQ(indexes.size(), static_cast<size_t>(length));
}

TEST(RandomNumberUtil, GetRandomIndexes2) {
  uint32_t length = 2;
  std::vector<uint32_t> indexes = RandomNumberUtil::GetRandomIndexes(length);
  EXPECT_EQ(indexes.size(), static_cast<size_t>(length));
}

TEST(RandomNumberUtil, GetRandomIndexes3) {
  uint32_t length = 2;
  std::vector<uint32_t> indexes = RandomNumberUtil::GetRandomIndexes(length);
  EXPECT_EQ(indexes.size(), static_cast<size_t>(length));
}

// GetRandomBool---------------------------------------------------------------
TEST(RandomNumberUtil, GetRandomBool) {
  std::vector<bool> cashe;
  EXPECT_NO_THROW(RandomNumberUtil::GetRandomBool(&cashe));
}
