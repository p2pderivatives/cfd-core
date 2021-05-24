#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::Txid;
using cfd::core::ByteData256;
using cfd::core::CfdException;

TEST(Txid, TxidEmpty) {
  // cfd::core::CfdCoreHandle handle = nullptr;
  // cfd::core::Initialize(&handle);
  Txid txid;
  EXPECT_STREQ(txid.GetHex().c_str(), "");
  EXPECT_EQ(txid.GetData().GetDataSize(), 0);
}

TEST(Txid, Txid256bit) {
  ByteData256 byte_data = ByteData256(
      "3412907856341290785634129078563412907856341290785634129078563412");
  Txid txid = Txid(byte_data);
  EXPECT_STREQ(
      txid.GetHex().c_str(),
      "1234567890123456789012345678901234567890123456789012345678901234");
  EXPECT_EQ(txid.GetData().GetDataSize(), 32);
}

TEST(Txid, TxidFromHex) {
  Txid txid = Txid(
      "1234567890123456789012345678901234567890123456789012345678901234");
  EXPECT_STREQ(
      txid.GetHex().c_str(),
      "1234567890123456789012345678901234567890123456789012345678901234");
  EXPECT_EQ(txid.GetData().GetDataSize(), 32);
  EXPECT_STREQ(
      txid.GetData().GetHex().c_str(),
      "3412907856341290785634129078563412907856341290785634129078563412");
}

TEST(Txid, TxidFromHexError) {
  EXPECT_THROW(
      Txid txid = Txid( "123456789012345678901234567890123456789012345678901234567890123412"),
      CfdException);
}

TEST(Txid, TxidEqualsMatch) {
  Txid txid1 = Txid(
      "1234567890123456789012345678901234567890123456789012345678901234");
  Txid txid2 = Txid(
      "1234567890123456789012345678901234567890123456789012345678901234");
  EXPECT_TRUE(txid1.Equals(txid2));
}

TEST(Txid, TxidEqualsUnMatch) {
  Txid txid1 = Txid(
      "1234567890123456789012345678901234567890123456789012345678901234");
  Txid txid2 = Txid(
      "0234567890123456789012345678901234567890123456789012345678901234");
  EXPECT_FALSE(txid1.Equals(txid2));
}

TEST(Txid, TxidEqualsGetByte) {
  std::vector<uint8_t> list1(32);
  list1[2] = 8;
  list1[4] = 64;
  list1[6] = 32;
  ByteData256 byte_data = ByteData256(list1);
  Txid txid = Txid(byte_data);
  bool is_equals = (txid.GetData().GetBytes() == list1);
  EXPECT_TRUE(is_equals);
}

TEST(Txid, IsValid) {
  ByteData256 bytes(
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  Txid txid(bytes);
  EXPECT_TRUE(txid.IsValid());

  Txid empty_txid;
  EXPECT_FALSE(empty_txid.IsValid());
}
