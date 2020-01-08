#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::NetType;

TEST(Privkey, Privkey) {
  Privkey privkey;
  EXPECT_STREQ(privkey.GetData().GetHex().c_str(), "");
}

TEST(Privkey, Privkey_ByteData) {
  ByteData bytedata(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Privkey privkey(bytedata);
  EXPECT_STREQ(
      privkey.GetData().GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
}

TEST(Privkey, Privkey_ByteData256) {
  ByteData256 bytedata(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Privkey privkey(bytedata);
  EXPECT_STREQ(
      privkey.GetData().GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
}

TEST(Privkey, Privkey_ByteData_Error) {
  try {
    ByteData bytedata(
        "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f2701");
    Privkey privkey(bytedata);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "Invalid Privkey data.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Privkey, Privkey_HexString) {
  std::string hex =
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27";
  Privkey privkey(hex);
  EXPECT_STREQ(
      privkey.GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
}

TEST(Privkey, Privkey_HexString_Error) {
  try {
    std::string hex =
        "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f2701";
    Privkey privkey(hex);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "Invalid Privkey data.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Privkey, ConvertWif_mainnnet_compressed) {
  std::string hex =
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27";
  Privkey privkey(hex);
  std::string wif = privkey.ConvertWif(NetType::kMainnet, true);
  EXPECT_STREQ(wif.c_str(),
               "KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG");
}

TEST(Privkey, ConvertWif_testnet_compressed) {
  std::string hex =
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27";
  Privkey privkey(hex);
  std::string wif = privkey.ConvertWif(NetType::kTestnet, true);
  EXPECT_STREQ(wif.c_str(),
               "cPCirFtGH3KUJ4ZusGdRUiW5iL3Y2PEM9gxSMRM3YSG6Eon9heJj");
}

TEST(Privkey, ConvertWif_mainnnet_uncompressed) {
  std::string hex =
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27";
  Privkey privkey(hex);
  std::string wif = privkey.ConvertWif(NetType::kMainnet, false);
  EXPECT_STREQ(wif.c_str(),
               "5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23");
}

TEST(Privkey, ConvertWif_testnet_uncompressed) {
  std::string hex =
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27";
  Privkey privkey(hex);
  std::string wif = privkey.ConvertWif(NetType::kTestnet, false);
  EXPECT_STREQ(wif.c_str(),
               "91xDetrgFxon9rHyPGKg5U5Kjttn6JGiGZcfpg3jGH9QPd4tmrm");
}

TEST(Privkey, ConvertWif_error) {
  try {
    Privkey privkey;
    std::string wif = privkey.ConvertWif(NetType::kMainnet, false);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "Error Private key to WIF.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Privkey, FromWif_mainnet_compressed) {
  std::string wif = "KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG";
  Privkey privkey = Privkey::FromWif(wif, NetType::kMainnet, true);
  EXPECT_STREQ(
      privkey.GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
}

TEST(Privkey, FromWif_testnet_compressed) {
  std::string wif = "cPCirFtGH3KUJ4ZusGdRUiW5iL3Y2PEM9gxSMRM3YSG6Eon9heJj";
  Privkey privkey = Privkey::FromWif(wif, NetType::kTestnet, true);
  EXPECT_STREQ(
      privkey.GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
}

TEST(Privkey, FromWif_mainnet_uncompressed) {
  std::string wif = "5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23";
  Privkey privkey = Privkey::FromWif(wif, NetType::kMainnet, false);
  EXPECT_STREQ(
      privkey.GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
}

TEST(Privkey, FromWif_wif_error) {
  try {
    std::string wif = "91xDetrgFxon9rHyPGKg5U5Kjttn6JGiGZc";
    Privkey privkey = Privkey::FromWif(wif, NetType::kTestnet);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "Error WIF to Private key.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Privkey, GeneratePubkey_compressed) {
  std::string wif = "cQNmd1D8MqzijUuXHb2yS5oRSm2F3TSTTMvcHC3V7CiKxArpg1bg";
  Privkey privkey = Privkey::FromWif(wif, NetType::kRegtest, true);
  Pubkey pubkey = privkey.GeneratePubkey(true);
  EXPECT_STREQ(
      pubkey.GetHex().c_str(),
      "02e3cf2c4dca39b502a6f8ba37e5d63a9757492c2155bf99418d9532728cd23d93");
}

TEST(Privkey, GeneratePubkey_uncompressed) {
  std::string wif = "5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23";
  Privkey privkey = Privkey::FromWif(wif, NetType::kMainnet, false);
  Pubkey pubkey = privkey.GeneratePubkey(false);
  EXPECT_STREQ(
      pubkey.GetHex().c_str(),
      "041777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb78885d348051c6fbd31ac749eb5646481f6d8d9c36f8d157712ca054046a9b8b");
}

TEST(Privkey, IsValid_true) {
  Privkey privkey(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  EXPECT_TRUE(privkey.IsValid());
}

TEST(Privkey, IsValid_false) {
  Privkey privkey;
  EXPECT_FALSE(privkey.IsValid());
}

TEST(Privkey, GenerageRandomKeyTest) {
  Privkey privkey = Privkey::GenerageRandomKey();
  bool isValid = privkey.IsValid();
  EXPECT_TRUE(isValid);
}
