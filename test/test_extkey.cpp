#include "gtest/gtest.h"
#include <iostream>
#include <string>

#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::ExtKey;

TEST(ExtKey, DefaultConstructorTest) {
  ExtKey extkey = ExtKey();

  EXPECT_STREQ("", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("", extkey.GetPrefix().GetHex().c_str());
  EXPECT_FALSE(extkey.IsPrivkey());
  EXPECT_TRUE(extkey.IsInvalid());
}

TEST(ExtKey, SerializeConstructorTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtKey extkey = ExtKey(ByteData(ext_serial));

  EXPECT_STREQ(ext_serial.c_str(), extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", extkey.GetPrefix().GetHex().c_str());
  EXPECT_FALSE(extkey.IsPrivkey());
  EXPECT_FALSE(extkey.IsInvalid());
  EXPECT_STREQ("tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz", extkey.GetBase58String().c_str());
  EXPECT_EQ(2, extkey.GetDepth());
  EXPECT_STREQ("030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetPubkey().GetHex().c_str());
}

TEST(ExtKey, SeedConstructorTest_Privkey) {
  std::string ext_seed = "012345678913579246801472583690FF";
  ExtKey extkey = ExtKey(ByteData(ext_seed), ExtKey::kPrefixTestnetPrivkey);

  EXPECT_STREQ("04358394000000000000000000ef1d96024c1f0b9fd35356984cb6e347e901035f924f8af731fc2924b0ff72130059f40c9ff35a534bf02817c4c9b2a0eff6acc9b2e1e0c822dbbead73e4f69747", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("04358394", extkey.GetPrefix().GetHex().c_str());
  EXPECT_TRUE(extkey.IsPrivkey());
  EXPECT_FALSE(extkey.IsInvalid());
  EXPECT_STREQ("tprv8ZgxMBicQKsPfFfgL33JxxEMtuXMCaUxXqetSSSVcsFcbsYzrDAw5SUG8UStm8G86cxBUANpv2kpEsB4GMEG6NfLVRZGzZCRLQrr8deFcfZ", extkey.GetBase58String().c_str());
  EXPECT_EQ(0, extkey.GetDepth());
  EXPECT_STREQ("034bfc79a7f5b0666d50812ed4d4dec7cbff6d5092d762f50b91ed9261d9c201f7", extkey.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("59f40c9ff35a534bf02817c4c9b2a0eff6acc9b2e1e0c822dbbead73e4f69747", extkey.GetPrivkey().GetHex().c_str());
  EXPECT_STREQ(extkey.GetPubkey().GetHex().c_str(), extkey.GetPrivkey().GeneratePubkey().GetHex().c_str());
}

TEST(ExtKey, SeedConstructorTest_Pubkey) {
  std::string ext_seed = "012345678913579246801472583690FF";
  ExtKey extkey;
  EXPECT_THROW((extkey = ExtKey(ByteData(ext_seed), ExtKey::kPrefixMainnetPubkey)), CfdException);
}

TEST(ExtKey, Base58ConstructorTest) {
  
  std::string ext_base58 = "tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz";
  ExtKey extkey = ExtKey(ext_base58);

  EXPECT_STREQ("043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", extkey.GetPrefix().GetHex().c_str());
  EXPECT_FALSE(extkey.IsPrivkey());
  EXPECT_FALSE(extkey.IsInvalid());
  EXPECT_STREQ(ext_base58.c_str(), extkey.GetBase58String().c_str());
  EXPECT_EQ(2, extkey.GetDepth());
  EXPECT_STREQ("030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetPubkey().GetHex().c_str());
}

TEST(ExtKey, DerivePubkeyTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtKey extkey = ExtKey(ByteData(ext_serial));
  ExtKey child;

  EXPECT_NO_THROW((child = extkey.DerivePubkey(0)));
  EXPECT_STREQ("043587cf03b76659780000000087ced156b5641d416892046bbd1257c492c030967868aa8dc7a7067490fa08d502ca30dbb25a2cf96344a04ae2144fb28a17f006c34cfb973b9f21623db27c5cd3", child.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", child.GetPrefix().GetHex().c_str());
  EXPECT_FALSE(child.IsPrivkey());
  EXPECT_FALSE(child.IsInvalid());
  EXPECT_STREQ("tpubDDNapBCUaChXpE91grWNGp8xWg84GcS1iRSR7iynAFTv6JAGnKTEUB3vkHtsV4NbkZf6SfjYM6PvW3kZ77KLUZ2GTYNBN4PJRWCKN1ERjJe", child.GetBase58String().c_str());
  EXPECT_EQ(3, child.GetDepth());
  EXPECT_STREQ("02ca30dbb25a2cf96344a04ae2144fb28a17f006c34cfb973b9f21623db27c5cd3", child.GetPubkey().GetHex().c_str());
}

TEST(ExtKey, DerivePubTweakTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtKey extkey = ExtKey(ByteData(ext_serial));

  std::vector<uint32_t> key_paths = {0, 5};
  ByteData256 tweak_sum;
  EXPECT_NO_THROW((tweak_sum = extkey.DerivePubTweak(key_paths)));
  EXPECT_STREQ("2f0b491d070c810a9779a8398063ba6e20302604dc36cf6bf6f935e34c68fa22", tweak_sum.GetHex().c_str());
}

