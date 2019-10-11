#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::BlockHash;

TEST(BlockHash, Constractor_hex) {
  // empty
  EXPECT_THROW(BlockHash blockhash(""), CfdException);

  BlockHash blockhash(
      "3412907856341290785634129078563412907856341290785634129078563412");
  EXPECT_STREQ(
      blockhash.GetHex().c_str(),
      "3412907856341290785634129078563412907856341290785634129078563412");
  EXPECT_EQ(blockhash.GetData().GetDataSize(), 32);
  EXPECT_STREQ(
      blockhash.GetData().GetHex().c_str(),
      "1234567890123456789012345678901234567890123456789012345678901234");
}

TEST(BlockHash, Constractor_bytedata) {
  ByteData256 bytes(
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  BlockHash blockhash(bytes);
  EXPECT_STREQ(
      blockhash.GetHex().c_str(),
      "7981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18");
  EXPECT_EQ(blockhash.GetData().GetDataSize(), 32);
  EXPECT_STREQ(
      blockhash.GetData().GetHex().c_str(),
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
}

#endif  // CFD_DISABLE_ELEMENTS
