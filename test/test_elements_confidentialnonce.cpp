#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ConfidentialNonce;

TEST(ConfidentialNonce, Constractor) {
  ConfidentialNonce nonce;

  EXPECT_STREQ(nonce.GetHex().c_str(), "");
  EXPECT_EQ(nonce.GetData().GetDataSize(), 0);
  EXPECT_EQ(nonce.HasBlinding(), false);
}

TEST(ConfidentialNonce, Constractor_hex0) {
  // 0byte
  ConfidentialNonce nonce("");
  EXPECT_STREQ(nonce.GetHex().c_str(), "");
  EXPECT_EQ(nonce.GetData().GetDataSize(), 0);
  EXPECT_EQ(nonce.HasBlinding(), false);
}

TEST(ConfidentialNonce, Constractor_hex32) {
  // 32byte
  ConfidentialNonce nonce(
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_STREQ(
      nonce.GetHex().c_str(),
      "01186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_EQ(nonce.GetData().GetDataSize(), 33);
  EXPECT_EQ(nonce.HasBlinding(), false);
}

TEST(ConfidentialNonce, Constractor_hex33) {
  // 33byte
  ConfidentialNonce nonce(
      "02c384a78ae89b9600a8d2b4ddb3090ba5dad224ff4b85e6868f2916ca64314ad9");
  EXPECT_STREQ(
      nonce.GetHex().c_str(),
      "02c384a78ae89b9600a8d2b4ddb3090ba5dad224ff4b85e6868f2916ca64314ad9");
  EXPECT_EQ(nonce.GetData().GetDataSize(), 33);
  EXPECT_EQ(nonce.HasBlinding(), true);
}

TEST(ConfidentialNonce, Constractor_sizeerr) {
  // error
  EXPECT_THROW(ConfidentialNonce nonce("001122"), CfdException);
}

TEST(ConfidentialNonce, Constractor_bytedata0) {
  // 0byte
  ByteData bytedata;
  ConfidentialNonce nonce(bytedata);
  EXPECT_STREQ(nonce.GetHex().c_str(), "");
  EXPECT_EQ(nonce.GetData().GetDataSize(), 0);
  EXPECT_EQ(nonce.HasBlinding(), false);
}

TEST(ConfidentialNonce, Constractor_bytedata32) {
  ByteData bytedata(
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  ConfidentialNonce nonce(bytedata);
  EXPECT_STREQ(
      nonce.GetHex().c_str(),
      "01186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_EQ(nonce.GetData().GetDataSize(), 33);
  EXPECT_EQ(nonce.HasBlinding(), false);
}

TEST(ConfidentialNonce, Constractor_bytedata33) {
  // 33byte
  ByteData bytedata(
      "02c384a78ae89b9600a8d2b4ddb3090ba5dad224ff4b85e6868f2916ca64314ad9");
  ConfidentialNonce nonce(bytedata);
  EXPECT_STREQ(
      nonce.GetHex().c_str(),
      "02c384a78ae89b9600a8d2b4ddb3090ba5dad224ff4b85e6868f2916ca64314ad9");
  EXPECT_EQ(nonce.GetData().GetDataSize(), 33);
  EXPECT_EQ(nonce.HasBlinding(), true);
}

TEST(ConfidentialNonce, Constractor_bytedata_err) {
  // error
  EXPECT_THROW(ConfidentialNonce nonce(ByteData("001122")), CfdException);
}

#endif  // CFD_DISABLE_ELEMENTS
