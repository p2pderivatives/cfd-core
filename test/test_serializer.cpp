#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::Serializer;

TEST(Serializer, Normal) {
  Serializer builder;
  builder.AddDirectNumber(uint32_t{1});
  builder.AddDirectNumber(uint64_t{2});
  builder.AddDirectByte(3);
  builder.AddVariableInt(0x01ffff);
  builder.AddVariableBuffer(ByteData("f1f2"));
  builder.AddPrefixBuffer(0xe1e2e3e4, ByteData("d1d2d3d4"));
  builder.AddDirectBytes(ByteData("c1c2c3c4"));

  EXPECT_STREQ("01000000020000000000000003feffff010002f1f209fee4e3e2e1d1d2d3d4c1c2c3c4",
      builder.Output().GetHex().c_str());
}
