#include "gtest/gtest.h"
#include <vector>
#include <limits>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;

TEST(ByteData, DefaultConstructor) {
  ByteData byte_data;
  size_t size = 0;

  EXPECT_STREQ(byte_data.GetHex().c_str(), "");
  EXPECT_EQ(byte_data.GetDataSize(), size);
  EXPECT_TRUE(byte_data.IsEmpty());
  EXPECT_STREQ(
    byte_data.Serialize().GetHex().c_str(),
    "00");
}

TEST(ByteData, HexConstructor) {
  std::string target(
      "123456789012345678901234567890123456789012345678901234567890123456");
  ByteData byte_data = ByteData(target);

  EXPECT_STREQ(byte_data.GetHex().c_str(), target.c_str());
  EXPECT_EQ(byte_data.GetDataSize(), (target.size() / 2));
  EXPECT_FALSE(byte_data.IsEmpty());
  // TODO: fujita Serialize
  EXPECT_STREQ(
    byte_data.Serialize().GetHex().c_str(),
    "21123456789012345678901234567890123456789012345678901234567890123456");
}

TEST(ByteData, BytesConstructor) {
  std::vector<uint8_t> target(20);
  uint8_t byte = 1;
  for (size_t i = 0; i < target.size(); i++) {
    target[i] = byte;
    byte++;
    if (byte > 9) {
      byte = 0;
    }
  }
  ByteData byte_data = ByteData(target);
  bool is_equals = (byte_data.GetBytes() == target);

  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "0102030405060708090001020304050607080900");
  EXPECT_TRUE(is_equals);
  EXPECT_EQ(byte_data.GetDataSize(), target.size());
  EXPECT_FALSE(byte_data.IsEmpty());
  EXPECT_STREQ(
    byte_data.Serialize().GetHex().c_str(),
    "140102030405060708090001020304050607080900");
}

TEST(ByteData, ByteDataConstructor) {
  uint8_t target[20];
  uint32_t size = 20;
  uint8_t byte = 1;
  for (uint32_t i = 0; i < size; i++) {
    target[i] = byte;
    byte++;
    if (byte > 9) {
      byte = 0;
    }
  }
  ByteData byte_data = ByteData(target, size);

  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "0102030405060708090001020304050607080900");
  EXPECT_EQ(byte_data.GetDataSize(), size);
  EXPECT_FALSE(byte_data.IsEmpty());
  EXPECT_STREQ(
    byte_data.Serialize().GetHex().c_str(),
    "140102030405060708090001020304050607080900");
}

TEST(ByteData, Serialize) {
  auto blank_str = [](uint16_t len){
    std::string ret;
    ret.reserve(len*2);
    ret.resize(len*2, '0');
    return ret;
  };

  // FIXME(fujita-cg):  32/64byte長については、capasityの限界によりテスト不可
  //                    capasityが解決したらテストを修正する
  const uint64_t vi_max8 = 252;
  const uint64_t vi_max16 = std::numeric_limits<uint16_t>::max();
  // const uint64_t vi_max32 = std::numeric_limits<uint32_t>::max();
  // const uint64_t vi_max64 = std::numeric_limits<uint64_t>::max();
  std::map<std::string, std::string> test_vector = {
    {"", "00"},
    {blank_str(1), "01" + blank_str(1)},
    {blank_str(vi_max8-1), ("fb" + blank_str(vi_max8-1))},
    {blank_str(vi_max8), ("fc" + blank_str(vi_max8))},
    {blank_str(vi_max8+1), ("fdfd00" + blank_str(vi_max8+1))},
    {blank_str(vi_max16-1), ("fdfeff" + blank_str(vi_max16-1))},
    {blank_str(vi_max16), ("fdffff" + blank_str(vi_max16))},
    // {blank_str(vi_max16+1), ("fe00000100" + blank_str(vi_max16+1))},
    // {blank_str(vi_max32-1), ("fefeffffff" + blank_str(vi_max32-1))},
    // {blank_str(vi_max32), ("feffffffff" + blank_str(vi_max32))},
    // {blank_str(vi_max32+1), ("ff0000000001000000" + blank_str(vi_max32+1))},
    // {blank_str(vi_max64-1), ("fffeffffffffffffff" + blank_str(vi_max64-1))},
    // {blank_str(vi_max64), ("ffffffffffffffffff" + blank_str(vi_max64))},
  };

  ByteData serialized;
  ByteData data;
  decltype(test_vector)::const_iterator citr = test_vector.cbegin();
  while (citr != test_vector.cend()) {
    EXPECT_NO_THROW(data = ByteData(citr->first));
    EXPECT_NO_THROW(serialized = data.Serialize());
    EXPECT_STREQ(serialized.GetHex().c_str(), ByteData(citr->second).GetHex().c_str());
    EXPECT_EQ(data.GetSerializeSize(), serialized.GetDataSize());
    ++citr;
  }
}

TEST(ByteData, EqualsMatch) {
  ByteData byte_data1 = ByteData(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData byte_data2 = ByteData(
      "1234567890123456789012345678901234567890123456789012345678901234");
  bool is_equals = byte_data1.Equals(byte_data2);

  EXPECT_TRUE(is_equals);
}

TEST(ByteData, EqualsUnMatch) {
  ByteData byte_data1 = ByteData(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData byte_data2 = ByteData(
      "0234567890123456789012345678901234567890123456789012345678901234");
  bool is_equals = byte_data1.Equals(byte_data2);

  EXPECT_FALSE(is_equals);
}

TEST(ByteData, GetVariableIntTest) {
  const uint8_t vi_max8 = 252;
  std::map<const uint64_t, const std::string> test_vector = {
    {0, "00"},
    {1, "01"},
    {static_cast<uint64_t>(vi_max8)-1, "fb"},
    {static_cast<uint64_t>(vi_max8), "fc"},
    {static_cast<uint64_t>(vi_max8)+1, "fdfd00"},
    {static_cast<uint64_t>(std::numeric_limits<uint16_t>::max())-1, "fdfeff"},
    {static_cast<uint64_t>(std::numeric_limits<uint16_t>::max()), "fdffff"},
    {static_cast<uint64_t>(std::numeric_limits<uint16_t>::max())+1, "fe00000100"},
    {static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())-1, "fefeffffff"},
    {static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()), "feffffffff"},
    {static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())+1, "ff0000000001000000"},
    {std::numeric_limits<uint64_t>::max()-1, "fffeffffffffffffff"},
    {std::numeric_limits<uint64_t>::max(), "ffffffffffffffffff"},
  };

  ByteData var_int_bytes;
  decltype(test_vector)::const_iterator citr = test_vector.cbegin();
  while (citr != test_vector.cend()) {
    EXPECT_NO_THROW(var_int_bytes = ByteData::GetVariableInt(citr->first));
    EXPECT_STREQ(var_int_bytes.GetHex().c_str(), citr->second.c_str());
    ++citr;
  }
}

TEST(ByteData, PushBack) {
  ByteData base("0011");
  ByteData data1("2233");
  ByteData160 data2("4444444444444444444444444444444444444444");
  ByteData256 data3("5555555555555555555555555555555555555555555555555555555555555555");
  ByteData result;

  EXPECT_NO_THROW(result = base.PushBack(data1));
  EXPECT_STREQ(result.GetHex().c_str(), "00112233");

  EXPECT_NO_THROW(result = base.PushBack(data2));
  EXPECT_STREQ(result.GetHex().c_str(), "00114444444444444444444444444444444444444444");

  EXPECT_NO_THROW(result = base.PushBack(data3));
  EXPECT_STREQ(result.GetHex().c_str(), "00115555555555555555555555555555555555555555555555555555555555555555");
}

TEST(ByteData, Join) {
  ByteData base("0011");
  ByteData data1("2233");
  ByteData160 data2("4444444444444444444444444444444444444444");
  ByteData256 data3("5555555555555555555555555555555555555555555555555555555555555555");
  ByteData result;

  EXPECT_NO_THROW(result = base.Join(data1, data2, data3));
  EXPECT_STREQ(result.GetHex().c_str(), "0011223344444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555");
}

TEST(ByteData, Concat) {
  ByteData base("0011");
  ByteData data1("2233");
  ByteData160 data2("4444444444444444444444444444444444444444");
  ByteData256 data3("5555555555555555555555555555555555555555555555555555555555555555");
  ByteData result;

  EXPECT_NO_THROW(result = base.Concat(data1, data2, data3));
  EXPECT_STREQ(result.GetHex().c_str(), "0011223344444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555");
}

TEST(ByteData, Push) {
  ByteData base("0011");
  ByteData data1("2233");
  ByteData160 data2("4444444444444444444444444444444444444444");
  ByteData256 data3("5555555555555555555555555555555555555555555555555555555555555555");
  ByteData data = base;

  EXPECT_NO_THROW(data.Push(data1));
  EXPECT_STREQ(data.GetHex().c_str(), "00112233");

  EXPECT_NO_THROW(data.Push(data2));
  EXPECT_STREQ(data.GetHex().c_str(), "001122334444444444444444444444444444444444444444");

  EXPECT_NO_THROW(data.Push(data3));
  EXPECT_STREQ(data.GetHex().c_str(), "0011223344444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555");
}
