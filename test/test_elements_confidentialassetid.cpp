#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ConfidentialAssetId;

TEST(ConfidentialAssetId, Constractor) {
  ConfidentialAssetId assetid;

  EXPECT_STREQ(assetid.GetHex().c_str(), "");
  EXPECT_EQ(assetid.GetData().GetDataSize(), 0);
  EXPECT_EQ(assetid.HasBlinding(), false);
  EXPECT_STREQ(assetid.GetUnblindedData().GetHex().c_str(), "");
}

TEST(ConfidentialAssetId, Constractor_hex0) {
  // 0byte
  EXPECT_THROW(ConfidentialAssetId assetid(""), CfdException);
}

TEST(ConfidentialAssetId, Constractor_hex32) {
  // 32byte
  ConfidentialAssetId assetid(
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f");
  EXPECT_STREQ(
      assetid.GetHex().c_str(),
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f");
  EXPECT_EQ(assetid.GetData().GetDataSize(), 33);
  EXPECT_EQ(assetid.HasBlinding(), false);
  EXPECT_STREQ(
      assetid.GetUnblindedData().GetHex().c_str(),
      "1fbbbaa0d90b70e5738cd11cdc03c69dd9cbfa453389632cb96f4e0a8d0c7f0a");
}

TEST(ConfidentialAssetId, Constractor_hex33) {
  // 33byte
  ConfidentialAssetId assetid(
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
  EXPECT_STREQ(
      assetid.GetHex().c_str(),
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
  EXPECT_EQ(assetid.GetData().GetDataSize(), 33);
  EXPECT_EQ(assetid.HasBlinding(), true);
  EXPECT_STREQ(
      assetid.GetUnblindedData().GetHex().c_str(),
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
}

TEST(ConfidentialAssetId, Constractor_hex_err) {
  // error
  EXPECT_THROW(ConfidentialAssetId assetid("001122"), CfdException);
}

TEST(ConfidentialAssetId, Constractor_bytedata0) {
  // 0byte
  EXPECT_THROW(ConfidentialAssetId assetid(ByteData("")), CfdException);
}

TEST(ConfidentialAssetId, Constractor_bytedata32) {
  // 32byte
  ByteData bytedata(
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f");
  ConfidentialAssetId assetid(bytedata);
  EXPECT_STREQ(
      assetid.GetHex().c_str(),
      "1fbbbaa0d90b70e5738cd11cdc03c69dd9cbfa453389632cb96f4e0a8d0c7f0a");
  EXPECT_EQ(assetid.GetData().GetDataSize(), 33);
  EXPECT_EQ(assetid.HasBlinding(), false);
  EXPECT_STREQ(
      assetid.GetUnblindedData().GetHex().c_str(),
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f");
}

TEST(ConfidentialAssetId, Constractor_bytedata33) {
  // 33byte
  ConfidentialAssetId assetid(
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
  EXPECT_STREQ(
      assetid.GetHex().c_str(),
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
  EXPECT_EQ(assetid.GetData().GetDataSize(), 33);
  EXPECT_EQ(assetid.HasBlinding(), true);
  EXPECT_STREQ(
      assetid.GetUnblindedData().GetHex().c_str(),
      "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
}

TEST(ConfidentialAssetId, Constractor_bytedata_err) {
  // error
  EXPECT_THROW(ConfidentialAssetId assetid(ByteData("001122")), CfdException);
}

#endif  // CFD_DISABLE_ELEMENTS
