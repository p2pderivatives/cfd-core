#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::OutPoint;
using cfd::core::Txid;
using cfd::core::ByteData256;
using cfd::core::CfdException;

TEST(OutPoint, OutPointEmpty) {
  OutPoint outpoint;
  EXPECT_STREQ(outpoint.GetTxid().GetHex().c_str(), "");
  EXPECT_EQ(outpoint.GetTxid().GetData().GetDataSize(), 0);
  EXPECT_EQ(outpoint.GetVout(), 0);
  EXPECT_FALSE(outpoint.IsValid());
}

TEST(OutPoint, Constructor) {
  ByteData256 byte_data = ByteData256(
      "3412907856341290785634129078563412907856341290785634129078563412");
  Txid txid = Txid(byte_data);
  OutPoint outpoint(txid, 1);
  EXPECT_STREQ(
      outpoint.GetTxid().GetHex().c_str(),
      "1234567890123456789012345678901234567890123456789012345678901234");
  EXPECT_EQ(outpoint.GetVout(), 1);
}

TEST(OutPoint, Equals) {
  ByteData256 byte_data = ByteData256(
      "3412907856341290785634129078563412907856341290785634129078563412");
  Txid txid = Txid(byte_data);
  ByteData256 byte_data2 = ByteData256(
      "9812907856341290785634129078563412907856341290785634129078563412");
  Txid txid2 = Txid(byte_data2);
  OutPoint outpoint1(txid, 1);
  OutPoint outpoint2(txid, 1);
  OutPoint outpoint3(txid, 2);
  OutPoint outpoint4(txid2, 1);

  EXPECT_TRUE((outpoint1 == outpoint2));
  EXPECT_FALSE((outpoint1 == outpoint3));
  EXPECT_FALSE((outpoint1 == outpoint4));
}

TEST(OutPoint, NotEquals) {
  ByteData256 byte_data = ByteData256(
      "3412907856341290785634129078563412907856341290785634129078563412");
  Txid txid = Txid(byte_data);
  ByteData256 byte_data2 = ByteData256(
      "9812907856341290785634129078563412907856341290785634129078563412");
  Txid txid2 = Txid(byte_data2);
  OutPoint outpoint1(txid, 1);
  OutPoint outpoint2(txid, 1);
  OutPoint outpoint3(txid, 2);
  OutPoint outpoint4(txid2, 1);

  EXPECT_FALSE((outpoint1 != outpoint2));
  EXPECT_TRUE((outpoint1 != outpoint3));
  EXPECT_TRUE((outpoint1 != outpoint4));
}

TEST(OutPoint, Operators) {
  ByteData256 byte_data = ByteData256(
      "3412907856341290785634129078563412907856341290785634129078563412");
  Txid txid = Txid(byte_data);
  ByteData256 byte_data2 = ByteData256(
      "9812907856341290785634129078563412907856341290785634129078563412");
  Txid txid2 = Txid(byte_data2);
  OutPoint outpoint1(txid, 1);
  OutPoint outpoint2(txid, 1);
  OutPoint outpoint3(txid, 2);
  OutPoint outpoint4(txid2, 1);

  EXPECT_TRUE((outpoint1 >= outpoint2));
  EXPECT_FALSE((outpoint1 >= outpoint3));
  EXPECT_TRUE((outpoint1 >= outpoint4));

  EXPECT_FALSE((outpoint1 > outpoint2));
  EXPECT_FALSE((outpoint1 > outpoint3));
  EXPECT_TRUE((outpoint1 > outpoint4));

  EXPECT_TRUE((outpoint1 <= outpoint2));
  EXPECT_TRUE((outpoint1 <= outpoint3));
  EXPECT_FALSE((outpoint1 <= outpoint4));

  EXPECT_FALSE((outpoint1 < outpoint2));
  EXPECT_TRUE((outpoint1 < outpoint3));
  EXPECT_FALSE((outpoint1 < outpoint4));

  EXPECT_TRUE((outpoint4 < outpoint3));
}
