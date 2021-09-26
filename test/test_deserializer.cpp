#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::Deserializer;

TEST(Deserializer, Normal) {
  std::vector<uint8_t> empty_data;
  Deserializer empty_parser(empty_data);

  Deserializer parser(ByteData("010203040506070808090a0b0c0d0e0f"));
  EXPECT_EQ(1, parser.ReadUint8());
  std::vector<uint8_t> exp_buf = {2, 3};
  auto buf = parser.ReadBuffer(2);

  EXPECT_EQ(exp_buf.size(), buf.size());
  if (exp_buf.size() == buf.size()) {
    for (size_t idx=0; idx<buf.size(); ++idx) {
      EXPECT_EQ(exp_buf[idx], buf[idx]);
    }
  }

  EXPECT_EQ(3, parser.GetReadSize());
  EXPECT_EQ(0x07060504, parser.ReadUint32());
  EXPECT_STREQ("08090a0b0c0d0e0f",
      parser.ReadVariableData().GetHex().c_str());
  EXPECT_EQ(16, parser.GetReadSize());
  EXPECT_TRUE(parser.HasEof());

  Deserializer parser2;
  parser2 = parser;
  EXPECT_TRUE(parser2.HasEof());
}

TEST(Deserializer, BigEndian) {
  Deserializer parser(ByteData("010203040506070808090a0b0c0d0e0f"));
  Deserializer parser2(parser);
  EXPECT_FALSE(parser2.HasEof());

  EXPECT_EQ(1, parser.ReadUint8());
  auto buf = parser.ReadBuffer(2);
  EXPECT_EQ("0203", ByteData(buf).GetHex());
  EXPECT_EQ(0x04050607, parser.ReadUint32FromBigEndian());
  EXPECT_EQ(7, parser.GetReadSize());
  EXPECT_FALSE(parser.HasEof());
  EXPECT_STREQ("08090a0b0c0d0e0f",
      parser.ReadVariableData().GetHex().c_str());
  EXPECT_EQ(16, parser.GetReadSize());
  EXPECT_TRUE(parser.HasEof());
}
