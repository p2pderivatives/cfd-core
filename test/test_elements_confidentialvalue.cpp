#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ConfidentialValue;
using cfd::core::Amount;

TEST(ConfidentialValue, Constractor) {
  ConfidentialValue value;

  EXPECT_STREQ(value.GetHex().c_str(), "");
  EXPECT_EQ(value.GetData().GetDataSize(), 0);
  EXPECT_EQ(value.HasBlinding(), false);
  int64_t satoshi = 0;
  EXPECT_NO_THROW((satoshi = value.GetAmount().GetSatoshiValue()));
  EXPECT_EQ(satoshi, 0);
}

TEST(ConfidentialValue, Constractor_hex0) {
  // 0byte
  ConfidentialValue value("");
  EXPECT_STREQ(value.GetHex().c_str(), "");
  EXPECT_EQ(value.GetData().GetDataSize(), 0);
  EXPECT_EQ(value.HasBlinding(), false);
  int64_t satoshi = 0;
  EXPECT_NO_THROW((satoshi = value.GetAmount().GetSatoshiValue()));
  EXPECT_EQ(satoshi, 0);
}

TEST(ConfidentialValue, Constractor_hex8) {
  // 8byte
  ConfidentialValue value("0000000005f5e100");
  EXPECT_STREQ(value.GetHex().c_str(), "010000000005f5e100");
  EXPECT_EQ(value.GetData().GetDataSize(), 9);
  EXPECT_EQ(value.HasBlinding(), false);
  EXPECT_EQ(value.GetAmount().GetSatoshiValue(), 100000000);
}

TEST(ConfidentialValue, Constractor_hex9) {
  // 9byte
  ConfidentialValue value("010000000005f5e100");
  EXPECT_STREQ(value.GetHex().c_str(), "010000000005f5e100");
  EXPECT_EQ(value.GetData().GetDataSize(), 9);
  EXPECT_EQ(value.HasBlinding(), false);
  EXPECT_EQ(value.GetAmount().GetSatoshiValue(), 100000000);
}

TEST(ConfidentialValue, Constractor_hex33) {
  // 33byte
  ConfidentialValue value(
      "09b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226");
  EXPECT_STREQ(
      value.GetHex().c_str(),
      "09b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226");
  EXPECT_EQ(value.GetData().GetDataSize(), 33);
  EXPECT_EQ(value.HasBlinding(), true);
  EXPECT_EQ(value.GetAmount().GetSatoshiValue(), 0);
}

TEST(ConfidentialValue, Constractor_hex9_version0) {
  // 9byte
  ConfidentialValue value("000000000005f5e100");
  EXPECT_STREQ(value.GetHex().c_str(), "");
  EXPECT_EQ(value.GetData().GetDataSize(), 0);
  EXPECT_EQ(value.HasBlinding(), false);
  int64_t satoshi = 0;
  EXPECT_NO_THROW((satoshi = value.GetAmount().GetSatoshiValue()));
  EXPECT_EQ(satoshi, 0);
}

TEST(ConfidentialValue, Constractor_hex33_version0) {
  // 33byte
  ConfidentialValue value(
      "00b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226");
  EXPECT_STREQ(value.GetHex().c_str(), "");
  EXPECT_EQ(value.GetData().GetDataSize(), 0);
  EXPECT_EQ(value.HasBlinding(), false);
  int64_t satoshi = 0;
  EXPECT_NO_THROW((satoshi = value.GetAmount().GetSatoshiValue()));
  EXPECT_EQ(satoshi, 0);
}

TEST(ConfidentialValue, Constractor_hex_err) {
  // error
  EXPECT_THROW(ConfidentialValue value("001122"), CfdException);
}

TEST(ConfidentialValue, Constractor_bytedata0) {
  // 0byte
  ConfidentialValue value(ByteData(""));
  EXPECT_STREQ(value.GetHex().c_str(), "");
  EXPECT_EQ(value.GetData().GetDataSize(), 0);
  EXPECT_EQ(value.HasBlinding(), false);
  int64_t satoshi = 0;
  EXPECT_NO_THROW((satoshi = value.GetAmount().GetSatoshiValue()));
  EXPECT_EQ(satoshi, 0);
}

TEST(ConfidentialValue, Constractor_bytedata8) {
  // 8byte
  ConfidentialValue value(ByteData("0000000005f5e100"));
  EXPECT_STREQ(value.GetHex().c_str(), "010000000005f5e100");
  EXPECT_EQ(value.GetData().GetDataSize(), 9);
  EXPECT_EQ(value.HasBlinding(), false);
  EXPECT_EQ(value.GetAmount().GetSatoshiValue(), 100000000);
}

TEST(ConfidentialValue, Constractor_bytedata9) {
  // 8byte
  ConfidentialValue value(ByteData("010000000005f5e100"));
  EXPECT_STREQ(value.GetHex().c_str(), "010000000005f5e100");
  EXPECT_EQ(value.GetData().GetDataSize(), 9);
  EXPECT_EQ(value.HasBlinding(), false);
  EXPECT_EQ(value.GetAmount().GetSatoshiValue(), 100000000);
}

TEST(ConfidentialValue, Constractor_bytedata33) {
  // 33byte
  ConfidentialValue value(
      "09b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226");
  EXPECT_STREQ(
      value.GetHex().c_str(),
      "09b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226");
  EXPECT_EQ(value.GetData().GetDataSize(), 33);
  EXPECT_EQ(value.HasBlinding(), true);
  EXPECT_EQ(value.GetAmount().GetSatoshiValue(), 0);
}

TEST(ConfidentialValue, Constractor_bytedata_err) {
  // error
  EXPECT_THROW(ConfidentialValue value(ByteData("001122")), CfdException);
}

TEST(ConfidentialValue, ConvertToConfidentialValue) {
  Amount amount = Amount::CreateBySatoshiAmount(100000000);
  ByteData bytedata = ConfidentialValue::ConvertToConfidentialValue(amount);
  EXPECT_STREQ(bytedata.GetHex().c_str(), "010000000005f5e100");
}

TEST(ConfidentialValue, ConvertFromConfidentialValue) {
  ByteData value("010000000005f5e100");
  Amount amount = ConfidentialValue::ConvertFromConfidentialValue(value);
  EXPECT_EQ(amount.GetSatoshiValue(), 100000000);

  EXPECT_THROW(
      ConfidentialValue::ConvertFromConfidentialValue(ByteData("001122")),
      CfdException);
}

#endif  // CFD_DISABLE_ELEMENTS
