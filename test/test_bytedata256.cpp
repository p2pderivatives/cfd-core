#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;

TEST(ByteData256, DefaultConstructor) {
  ByteData256 byte_data;

  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_TRUE(byte_data.IsEmpty());
  EXPECT_STREQ(
    byte_data.Serialize().GetHex().c_str(),
    "200000000000000000000000000000000000000000000000000000000000000000");
  ByteData byte_class_data;
  EXPECT_NO_THROW(byte_class_data = byte_data.GetData());
  EXPECT_EQ(byte_data.GetBytes(), byte_class_data.GetBytes());
  EXPECT_TRUE(byte_data.Empty());   // TODO(k-matsuzawa): deprecated API
}

TEST(ByteData256, HexConstructor) {
  std::string target(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData256 byte_data = ByteData256(target);

  EXPECT_STREQ(byte_data.GetHex().c_str(), target.c_str());
  EXPECT_FALSE(byte_data.IsEmpty());
  EXPECT_STREQ(
    byte_data.Serialize().GetHex().c_str(),
    "201234567890123456789012345678901234567890123456789012345678901234");
  ByteData byte_class_data;
  EXPECT_NO_THROW(byte_class_data = byte_data.GetData());
  EXPECT_EQ(byte_data.GetBytes(), byte_class_data.GetBytes());
}

TEST(ByteData256, BytesConstructor) {
  std::vector<uint8_t> target(32);
  uint8_t byte = 1;
  for (size_t i = 0; i < target.size(); i++) {
    target[i] = byte;
    byte++;
    if (byte > 9) {
      byte = 0;
    }
  }
  ByteData256 byte_data = ByteData256(target);
  bool is_equals = (byte_data.GetBytes() == target);

  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "0102030405060708090001020304050607080900010203040506070809000102");
  EXPECT_TRUE(is_equals);
}

TEST(ByteData256, ByteDataConstructor) {
  ByteData data("1234567890123456789012345678901234567890123456789012345678901234");
  ByteData256 byte_data = ByteData256(data);

  EXPECT_STREQ(byte_data.GetHex().c_str(), data.GetHex().c_str());
  EXPECT_FALSE(byte_data.IsEmpty());
  EXPECT_STREQ(
    byte_data.Serialize().GetHex().c_str(),
    "201234567890123456789012345678901234567890123456789012345678901234");
  ByteData byte_class_data;
  EXPECT_NO_THROW(byte_class_data = byte_data.GetData());
  EXPECT_EQ(byte_data.GetBytes(), byte_class_data.GetBytes());
}

TEST(ByteData256, HexConstructorException) {
  try {
    ByteData256 byte_data = ByteData256(
        "123456789012345678901234567890123456789000");
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "ByteData256 size unmatch.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(ByteData256, BytesConstructorException) {
  try {
    std::vector<uint8_t> target(25);
    ByteData256 byte_data = ByteData256(target);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "ByteData256 size unmatch.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(ByteData256, EqualsMatch) {
  ByteData256 byte_data1 = ByteData256(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData256 byte_data2 = ByteData256(
      "1234567890123456789012345678901234567890123456789012345678901234");
  bool is_equals = byte_data1.Equals(byte_data2);

  EXPECT_TRUE(is_equals);
}

TEST(ByteData256, EqualsUnMatch) {
  ByteData256 byte_data1 = ByteData256(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData256 byte_data2 = ByteData256(
      "0234567890123456789012345678901234567890123456789012345678901234");
  bool is_equals = byte_data1.Equals(byte_data2);

  EXPECT_FALSE(is_equals);
}

TEST(ByteData256, PushBack) {
  ByteData256 base("1111111111111111111111111111111111111111111111111111111111111111");
  ByteData data1("2233");
  ByteData160 data2("4444444444444444444444444444444444444444");
  ByteData256 data3("5555555555555555555555555555555555555555555555555555555555555555");
  ByteData result;

  EXPECT_NO_THROW(result = base.PushBack(data1));
  EXPECT_STREQ(result.GetHex().c_str(), "11111111111111111111111111111111111111111111111111111111111111112233");

  EXPECT_NO_THROW(result = base.PushBack(data2));
  EXPECT_STREQ(result.GetHex().c_str(), "11111111111111111111111111111111111111111111111111111111111111114444444444444444444444444444444444444444");

  EXPECT_NO_THROW(result = base.PushBack(data3));
  EXPECT_STREQ(result.GetHex().c_str(), "11111111111111111111111111111111111111111111111111111111111111115555555555555555555555555555555555555555555555555555555555555555");
}

TEST(ByteData256, Join) {
  ByteData256 base("1111111111111111111111111111111111111111111111111111111111111111");
  ByteData data1("2233");
  ByteData160 data2("4444444444444444444444444444444444444444");
  ByteData256 data3("5555555555555555555555555555555555555555555555555555555555555555");
  ByteData result;

  EXPECT_NO_THROW(result = base.Join(data1, data2, data3));
  EXPECT_STREQ(result.GetHex().c_str(), "1111111111111111111111111111111111111111111111111111111111111111223344444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555");
}

TEST(ByteData256, Concat) {
  ByteData256 base("1111111111111111111111111111111111111111111111111111111111111111");
  ByteData data1("2233");
  ByteData160 data2("4444444444444444444444444444444444444444");
  ByteData256 data3("5555555555555555555555555555555555555555555555555555555555555555");
  ByteData result;

  EXPECT_NO_THROW(result = base.Concat(data1, data2, data3));
  EXPECT_STREQ(result.GetHex().c_str(), "1111111111111111111111111111111111111111111111111111111111111111223344444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555");
}
