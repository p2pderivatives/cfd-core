#include "gtest/gtest.h"
#include <iostream>
#include <string>

#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::ExtPubkey;
using cfd::core::ExtPrivkey;
using cfd::core::NetType;
using cfd::core::Privkey;

static const uint32_t extprivkey_kVersionMainnetPrivkey = ExtPrivkey::kVersionMainnetPrivkey;
static const uint32_t extprivkey_kVersionTestnetPrivkey = ExtPrivkey::kVersionTestnetPrivkey;
static const uint32_t extprivkey_kVersionMainnetPubkey = ExtPubkey::kVersionMainnetPubkey;
// static const uint32_t extprivkey_kVersionTestnetPubkey = ExtPubkey::kVersionTestnetPubkey;

TEST(ExtPrivkey, DefaultConstructorTest) {
  ExtPrivkey extkey = ExtPrivkey();

  EXPECT_STREQ("", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("00000000", extkey.GetVersionData().GetHex().c_str());
  EXPECT_FALSE(extkey.IsValid());
}

TEST(ExtPrivkey, SeedConstructorTest_Privkey) {
  std::string ext_seed = "012345678913579246801472583690FF";
  ExtPrivkey extkey = ExtPrivkey(ByteData(ext_seed), NetType::kMainnet);

  EXPECT_STREQ("0488ade4000000000000000000ef1d96024c1f0b9fd35356984cb6e347e901035f924f8af731fc2924b0ff72130059f40c9ff35a534bf02817c4c9b2a0eff6acc9b2e1e0c822dbbead73e4f69747", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("0488ade4", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, extkey.GetVersion());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ("xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7", extkey.ToString().c_str());
  EXPECT_EQ(0, extkey.GetDepth());
  EXPECT_STREQ("59f40c9ff35a534bf02817c4c9b2a0eff6acc9b2e1e0c822dbbead73e4f69747", extkey.GetPrivkey().GetHex().c_str());

  extkey = ExtPrivkey(ByteData(ext_seed), NetType::kTestnet);
  EXPECT_STREQ("04358394000000000000000000ef1d96024c1f0b9fd35356984cb6e347e901035f924f8af731fc2924b0ff72130059f40c9ff35a534bf02817c4c9b2a0eff6acc9b2e1e0c822dbbead73e4f69747", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("04358394", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extprivkey_kVersionTestnetPrivkey, extkey.GetVersion());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ("tprv8ZgxMBicQKsPfFfgL33JxxEMtuXMCaUxXqetSSSVcsFcbsYzrDAw5SUG8UStm8G86cxBUANpv2kpEsB4GMEG6NfLVRZGzZCRLQrr8deFcfZ", extkey.ToString().c_str());
  EXPECT_EQ(0, extkey.GetDepth());
  EXPECT_STREQ("59f40c9ff35a534bf02817c4c9b2a0eff6acc9b2e1e0c822dbbead73e4f69747", extkey.GetPrivkey().GetHex().c_str());
}

TEST(ExtPrivkey, SerializeConstructorTest) {
  std::string ext_serial = "0488ade4042da711a50000000028009126a24557d32ff2c5da21850dd06529f34faed53b4a3552b5ed4bda35d50073a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c";
  ExtPrivkey extkey = ExtPrivkey(ByteData(ext_serial));

  EXPECT_STREQ(ext_serial.c_str(), extkey.GetData().GetHex().c_str());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, extkey.GetVersion());
  EXPECT_STREQ("0488ade4", extkey.GetVersionData().GetHex().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV", extkey.ToString().c_str());
  EXPECT_EQ(4, extkey.GetDepth());
  EXPECT_STREQ("73a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c", extkey.GetPrivkey().GetHex().c_str());

  std::string pubkey_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  EXPECT_THROW((extkey = ExtPrivkey(ByteData(pubkey_serial))), CfdException);
}

TEST(ExtPrivkey, Base58ConstructorTest) {
  std::string ext_base58 = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  ExtPrivkey extkey = ExtPrivkey(ext_base58);

  EXPECT_STREQ("0488ade4042da711a50000000028009126a24557d32ff2c5da21850dd06529f34faed53b4a3552b5ed4bda35d50073a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_EQ(2769397549, extkey.GetFingerprint());
  EXPECT_STREQ("2da711a5", extkey.GetFingerprintData().GetHex().c_str());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, extkey.GetVersion());
  EXPECT_STREQ("0488ade4", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(4, extkey.GetDepth());
  EXPECT_EQ(0, extkey.GetChildNum());
  EXPECT_STREQ("28009126a24557d32ff2c5da21850dd06529f34faed53b4a3552b5ed4bda35d5", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("73a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c", extkey.GetPrivkey().GetHex().c_str());
  EXPECT_EQ(NetType::kMainnet, extkey.GetNetworkType());

  ext_base58 = "tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J";
  extkey = ExtPrivkey(ext_base58);
  EXPECT_STREQ("04358394000000000000000000a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c100cbedc75b0d6412c85c79bc13875112ef912fd1e756631b5a00330866f22ff184", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_EQ(0, extkey.GetFingerprint());
  EXPECT_STREQ("00000000", extkey.GetFingerprintData().GetHex().c_str());
  EXPECT_EQ(extprivkey_kVersionTestnetPrivkey, extkey.GetVersion());
  EXPECT_STREQ("04358394", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(0, extkey.GetDepth());
  EXPECT_EQ(0, extkey.GetChildNum());
  EXPECT_STREQ("a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c1", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("cbedc75b0d6412c85c79bc13875112ef912fd1e756631b5a00330866f22ff184", extkey.GetPrivkey().GetHex().c_str());

  std::string pubkey_xpub = "tpubD6NzVbkrYhZ4XyJymmEgYC3uVhyj4YtPFX6yRTbW6RvfRC7Ag3sVhKSz7MNzFWW5MJ7aVBKXCAX7En296EYdpo43M4a4LaeaHuhhgHToSJF";
  EXPECT_THROW((extkey = ExtPrivkey(pubkey_xpub)), CfdException);
}

TEST(ExtPrivkey, FromParentKeyTest) {
  // base: xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV
  // path: 4
  std::string ext_base58 = "xprvA3hskUkqh1sEsTnVmA1WTv74keit2RHGeCvG77peTHgtHjYu5xFAe3tmVosXLyn3DyS2S7duUkPjYihSULBwWgR51pX1ShuyDW3oJZD36YX";
  ExtPrivkey extkey = ExtPrivkey(NetType::kMainnet,
      Privkey("73a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c"),
      ByteData256("28009126a24557d32ff2c5da21850dd06529f34faed53b4a3552b5ed4bda35d5"),
      uint8_t{4},
      uint32_t{8});

  EXPECT_STREQ("0488ade405ae05dbb7000000088fa9c804362c158cb0a6a4e9573390b9fcb0c1625f1f33fae5fa3b949082293c0047131fdbfe2d1f53cd5c404199e243197cea058da8edcc47f0055b019afc102a", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_EQ(3084584366, extkey.GetFingerprint());
  EXPECT_STREQ("ae05dbb7", extkey.GetFingerprintData().GetHex().c_str());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, extkey.GetVersion());
  EXPECT_STREQ("0488ade4", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(5, extkey.GetDepth());
  EXPECT_EQ(8, extkey.GetChildNum());
  EXPECT_STREQ("8fa9c804362c158cb0a6a4e9573390b9fcb0c1625f1f33fae5fa3b949082293c", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("47131fdbfe2d1f53cd5c404199e243197cea058da8edcc47f0055b019afc102a", extkey.GetPrivkey().GetHex().c_str());
}

TEST(ExtPrivkey, FromKeyDataTest) {
  // base: xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV
  // path: 4
  std::string ext_base58 = "xprvA3hskUkqh1sEsTnVmA1WTv74keit2RHGeCvG77peTHgtHjYu5xFAe3tmVosXLyn3DyS2S7duUkPjYihSULBwWgR51pX1ShuyDW3oJZD36YX";
  ExtPrivkey extkey = ExtPrivkey(NetType::kMainnet,
      Privkey("73a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c"),
      Privkey("47131fdbfe2d1f53cd5c404199e243197cea058da8edcc47f0055b019afc102a"),
      ByteData256("8fa9c804362c158cb0a6a4e9573390b9fcb0c1625f1f33fae5fa3b949082293c"),
      uint8_t{5},
      uint32_t{8});

  EXPECT_STREQ("0488ade405ae05dbb7000000088fa9c804362c158cb0a6a4e9573390b9fcb0c1625f1f33fae5fa3b949082293c0047131fdbfe2d1f53cd5c404199e243197cea058da8edcc47f0055b019afc102a", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_EQ(3084584366, extkey.GetFingerprint());
  EXPECT_STREQ("ae05dbb7", extkey.GetFingerprintData().GetHex().c_str());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, extkey.GetVersion());
  EXPECT_STREQ("0488ade4", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(5, extkey.GetDepth());
  EXPECT_EQ(8, extkey.GetChildNum());
  EXPECT_STREQ("8fa9c804362c158cb0a6a4e9573390b9fcb0c1625f1f33fae5fa3b949082293c", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("47131fdbfe2d1f53cd5c404199e243197cea058da8edcc47f0055b019afc102a", extkey.GetPrivkey().GetHex().c_str());
}

TEST(ExtPrivkey, DerivePrivkeyTest) {
  std::string ext_base58 = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  ExtPrivkey extkey = ExtPrivkey(ext_base58);
  ExtPrivkey child;
  ExtPrivkey child1;
  ExtPrivkey child2;
  std::vector<uint32_t> path = {0, 44};

  child = extkey.DerivePrivkey(path);
  EXPECT_STREQ("0488ade40691fe4d290000002c368a8a370cc1f3e76cba08f13542e0dfb4e77dd08e8c70353f357a32b90be9d00005c52ec06dee7aa3249d9f8f3b930709967a43001fc8b9889eb22a850438ecc9", child.GetData().GetHex().c_str());
  EXPECT_STREQ("xprvA5P4YtgFjzqM4QpXJZ8Zr7Wkhng7ugTybA3KWMAqDfAamqu5nqJ3zKRhB29cxuqCc8hPagZcN5BsuoXx4Xn7iYHnQvEdyMwZRFgoJXs8CDN", child.ToString().c_str());
  EXPECT_TRUE(child.IsValid());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, child.GetVersion());
  EXPECT_EQ(6, child.GetDepth());
  EXPECT_EQ(44, child.GetChildNum());

  child1 = extkey.DerivePrivkey(0);
  EXPECT_STREQ("0488ade405ae05dbb7000000006abdc0ea6ae90c728659358371f9e576271ab7c2f0113e9128fa8b64b05a5a3f00d77115d2a8d35623ed755a2dd7c5cfd95256f7266dd3e55e3d8790d9758fe77a", child1.GetData().GetHex().c_str());
  EXPECT_STREQ("xprvA3hskUkqh1sEWhr726RLmGX7CwQ4jBHtY8ebnDijPhKNTiaCdBCdQe5UfvNFTZXwMm3vGktGpBWKZWCFbhQn5xYdHRPeaLpjCtVHSgoxS6E", child1.ToString().c_str());
  EXPECT_TRUE(child1.IsValid());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, child1.GetVersion());
  EXPECT_EQ(5, child1.GetDepth());
  EXPECT_EQ(0, child1.GetChildNum());

  child2 = child1.DerivePrivkey(44);
  EXPECT_STREQ(child2.GetData().GetHex().c_str(), child.GetData().GetHex().c_str());
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_TRUE(child2.IsValid());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());
  EXPECT_EQ(child2.GetDepth(), child.GetDepth());
  EXPECT_EQ(child2.GetChildNum(), child.GetChildNum());

  child2 = extkey.DerivePrivkey("0/44");
  EXPECT_STREQ(child2.GetData().GetHex().c_str(), child.GetData().GetHex().c_str());
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_TRUE(child2.IsValid());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());
  EXPECT_EQ(child2.GetDepth(), child.GetDepth());
  EXPECT_EQ(child2.GetChildNum(), child.GetChildNum());

  EXPECT_THROW((child2 = extkey.DerivePrivkey("m/0/44")), CfdException);
}

TEST(ExtPrivkey, GetExtPubkeyTest) {
  std::string ext_base58 = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  ExtPrivkey extkey = ExtPrivkey(ext_base58);

  ExtPubkey pubkey = extkey.GetExtPubkey();
  EXPECT_STREQ("xpub6DsNDJWpxZBXsbWsCy1VeBY8xf6hZBgznDTXSnp3FregxWoWfGsvtQ9j5wBJNPebZXD5YmhpQBV7nVjhUsUgkG9R7yE31mh6sVh2w854a1o", pubkey.ToString().c_str());

  ext_base58 = "tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J";
  extkey = ExtPrivkey(ext_base58);
  pubkey = extkey.GetExtPubkey();
  EXPECT_STREQ("tpubD6NzVbkrYhZ4XyJymmEgYC3uVhyj4YtPFX6yRTbW6RvfRC7Ag3sVhKSz7MNzFWW5MJ7aVBKXCAX7En296EYdpo43M4a4LaeaHuhhgHToSJF", pubkey.ToString().c_str());
}

TEST(ExtPrivkey, DerivePubkeyTest) {
  std::string ext_base58 = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  ExtPrivkey extkey = ExtPrivkey(ext_base58);
  ExtPubkey child;
  ExtPrivkey child1;
  ExtPubkey child2;
  std::vector<uint32_t> path = {0, 0x8000002c};  // 0/44h

  child = extkey.DerivePubkey(path);
  EXPECT_STREQ("xpub6JNQxQDHv2vcUQiXjggbaGYZg3nmxX6ojMcJPSs4KfLSLnMBCg8VbJUh5n4to2SwLWXdSXnHBkUQx1fVnJ9oKYjPPYAQehjWRpx6ErQyykX", child.ToString().c_str());
  EXPECT_EQ(extprivkey_kVersionMainnetPubkey, child.GetVersion());

  child1 = extkey.DerivePrivkey(0);
  EXPECT_STREQ("xprvA3hskUkqh1sEWhr726RLmGX7CwQ4jBHtY8ebnDijPhKNTiaCdBCdQe5UfvNFTZXwMm3vGktGpBWKZWCFbhQn5xYdHRPeaLpjCtVHSgoxS6E", child1.ToString().c_str());
  EXPECT_EQ(extprivkey_kVersionMainnetPrivkey, child1.GetVersion());

  child2 = child1.DerivePubkey(0x8000002c);
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());

  child2 = extkey.DerivePubkey("0/44h");
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());
}

