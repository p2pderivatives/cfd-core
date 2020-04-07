#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::RandomNumberUtil;
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

  Privkey from_hex("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  EXPECT_TRUE(privkey.Equals(from_hex));
}

TEST(Privkey, FromWif_testnet_compressed) {
  std::string wif = "cPCirFtGH3KUJ4ZusGdRUiW5iL3Y2PEM9gxSMRM3YSG6Eon9heJj";
  Privkey privkey = Privkey::FromWif(wif, NetType::kTestnet, true);
  EXPECT_STREQ(
      privkey.GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");

  Privkey from_hex("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  EXPECT_TRUE(privkey.Equals(from_hex));
}

TEST(Privkey, FromWif_mainnet_uncompressed) {
  std::string wif = "5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23";
  Privkey privkey = Privkey::FromWif(wif, NetType::kMainnet, false);
  EXPECT_STREQ(
      privkey.GetHex().c_str(),
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");

  Privkey from_hex("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  EXPECT_TRUE(privkey.Equals(from_hex));
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

TEST(Privkey, IsValid_false) {
  Privkey privkey;
  bool is_valid = privkey.IsValid();
  EXPECT_FALSE(is_valid);
  EXPECT_TRUE(privkey.IsInvalid());
}

TEST(Privkey, IsValid_true) {
  Privkey privkey(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  bool is_valid = privkey.IsValid();
  EXPECT_TRUE(is_valid);
}

TEST(Privkey, GenerageRandomKeyTest) {
  Privkey privkey = Privkey::GenerageRandomKey();
  bool is_valid = privkey.IsValid();
  EXPECT_TRUE(is_valid);
}

TEST(Privkey, TweakConversionTest) {
  Privkey privkey("036b13c5a0dd9935fe175b2b9ff86585c231e734b2148149d788a941f1f4f566");
  ByteData256 tweak("98430d10471cf697e2661e31ceb8720750b59a85374290e175799ba5dd06508e");

  // test for adding tweak
  {
    Privkey priv_tweak_added;
    EXPECT_NO_THROW(priv_tweak_added = privkey.CreateTweakAdd(tweak));
    EXPECT_STREQ(priv_tweak_added.GetHex().c_str(), "9bae20d5e7fa8fcde07d795d6eb0d78d12e781b9e957122b4d0244e7cefb45f4");

    Pubkey expect_pubkey = privkey.GeneratePubkey().CreateTweakAdd(tweak);
    EXPECT_TRUE(expect_pubkey.Equals(priv_tweak_added.GeneratePubkey()));
  }

  // test for multiplying tweak
  {
    Privkey priv_tweak_mul;
    EXPECT_NO_THROW(priv_tweak_mul = privkey.CreateTweakMul(tweak));
    EXPECT_STREQ(priv_tweak_mul.GetHex().c_str(), "aa71b12accba23b49761a7521e661f07a7e5742ac48cf708b8f9497b3a72a957");

    Pubkey expect_pubkey = privkey.GeneratePubkey().CreateTweakMul(tweak);
    EXPECT_TRUE(expect_pubkey.Equals(priv_tweak_mul.GeneratePubkey()));
  }
}

TEST(Privkey, NegateTest) {
  Privkey privkey = Privkey("6a3f76d20a24aba37d97ad07bcb090499a64a76bb9d30e156d7e97285926cb89");
  Privkey negate = privkey.CreateNegate();
  EXPECT_FALSE(privkey.Equals(negate));
  EXPECT_TRUE(privkey.Equals(negate.CreateNegate()));
}

TEST(Privkey, CalculateEcSignature) {
  ByteData256 sighash(
      "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e");
  Privkey privkey(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");

  // has_grind_r true
  ByteData sig;
  EXPECT_NO_THROW(
      sig = privkey.CalculateEcSignature(sighash, true));
  EXPECT_STREQ(
      sig.GetHex().c_str(),
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");

  // has_grind_r false
  EXPECT_NO_THROW(
      sig = privkey.CalculateEcSignature(sighash, false));
  EXPECT_STREQ(
      sig.GetHex().c_str(),
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");

  ByteData err_sig;
  Privkey emptyPrivkey;
  EXPECT_THROW(
      (err_sig = emptyPrivkey.CalculateEcSignature(sighash, true)),
      CfdException);
  EXPECT_STREQ(err_sig.GetHex().c_str(), "");
}
