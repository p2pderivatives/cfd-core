#include "gtest/gtest.h"
#include <iostream>
#include <string>

#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::ExtPubkey;
using cfd::core::Pubkey;

static const uint32_t extpubkey_kVersionMainnetPubkey = ExtPubkey::kVersionMainnetPubkey;
static const uint32_t extpubkey_kVersionTestnetPubkey = ExtPubkey::kVersionTestnetPubkey;

TEST(ExtPubkey, DefaultConstructorTest) {
  ExtPubkey extkey = ExtPubkey();

  EXPECT_STREQ("", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("00000000", extkey.GetVersionData().GetHex().c_str());
  EXPECT_FALSE(extkey.IsValid());
}

TEST(ExtPubkey, SerializeConstructorTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtPubkey extkey = ExtPubkey(ByteData(ext_serial));

  EXPECT_STREQ(ext_serial.c_str(), extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", extkey.GetVersionData().GetHex().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ("tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz", extkey.ToString().c_str());
  EXPECT_EQ(2, extkey.GetDepth());
  EXPECT_STREQ("030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetPubkey().GetHex().c_str());
}

TEST(ExtPubkey, Base58ConstructorTest) {
  std::string ext_base58 = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  ExtPubkey extkey = ExtPubkey(ext_base58);

  EXPECT_STREQ("0488b21e000000000000000000a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c102f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("0488b21e", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionMainnetPubkey, extkey.GetVersion());
  EXPECT_EQ(0, extkey.GetFingerprint());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_EQ(0, extkey.GetDepth());
  EXPECT_EQ(0, extkey.GetChildNum());
  EXPECT_STREQ("a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c1", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd", extkey.GetPubkey().GetHex().c_str());

  ext_base58 = "tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz";
  extkey = ExtPubkey(ext_base58);
  EXPECT_STREQ("043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, extkey.GetVersion());
  EXPECT_EQ(2721163508, extkey.GetFingerprint());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_EQ(2, extkey.GetDepth());
  EXPECT_EQ(0, extkey.GetChildNum());
  EXPECT_STREQ("bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetPubkey().GetHex().c_str());

  std::string privkey_xpriv = "tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J";
  EXPECT_THROW((extkey = ExtPubkey(privkey_xpriv)), CfdException);
}

TEST(ExtPubkey, DerivePubkeyTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtPubkey extkey = ExtPubkey(ByteData(ext_serial));
  ExtPubkey child;
  ExtPubkey child1;
  ExtPubkey child2;
  std::vector<uint32_t> path = {0, 44};

  EXPECT_NO_THROW((child = extkey.DerivePubkey(path)));
  EXPECT_STREQ("043587cf04a53a8ff30000002c839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", child.GetData().GetHex().c_str());
  EXPECT_STREQ("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", child.ToString().c_str());
  EXPECT_STREQ("043587cf", child.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, child.GetVersion());
  EXPECT_TRUE(child.IsValid());
  EXPECT_EQ(4, child.GetDepth());
  EXPECT_STREQ("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", child.GetPubkey().GetHex().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_STREQ("68a454a64c91bd4086e5008e843dbe1c583d193afd9bdbbcdd8afcb1bdd3cafe", child.GetPubTweakSum().GetHex().c_str());
#endif  // CFD_DISABLE_ELEMENTS

  EXPECT_NO_THROW((child1 = extkey.DerivePubkey(0)));
  EXPECT_NO_THROW((child2 = child1.DerivePubkey(44)));
  EXPECT_STREQ(child2.GetData().GetHex().c_str(), child.GetData().GetHex().c_str());
  EXPECT_STREQ(child2.GetVersionData().GetHex().c_str(), child.GetVersionData().GetHex().c_str());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());
  EXPECT_TRUE(child2.IsValid());
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_EQ(child2.GetDepth(), child.GetDepth());
  EXPECT_STREQ(child2.GetPubkey().GetHex().c_str(), child.GetPubkey().GetHex().c_str());

  try {
    child2 = extkey.DerivePubkey("m/0/44");
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  EXPECT_NO_THROW((child2 = extkey.DerivePubkey("m/0/44")));
  EXPECT_STREQ(child2.GetData().GetHex().c_str(), child.GetData().GetHex().c_str());
  EXPECT_STREQ(child2.GetVersionData().GetHex().c_str(), child.GetVersionData().GetHex().c_str());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());
  EXPECT_TRUE(child2.IsValid());
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_EQ(child2.GetDepth(), child.GetDepth());
  EXPECT_STREQ(child2.GetPubkey().GetHex().c_str(), child.GetPubkey().GetHex().c_str());
}

TEST(ExtPubkey, DerivePubTweakTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtPubkey extkey = ExtPubkey(ByteData(ext_serial));

  std::vector<uint32_t> key_paths = {0, 5};
  ByteData256 tweak_sum;
  EXPECT_NO_THROW((tweak_sum = extkey.DerivePubTweak(key_paths)));
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_STREQ("2f0b491d070c810a9779a8398063ba6e20302604dc36cf6bf6f935e34c68fa22", tweak_sum.GetHex().c_str());
#endif  // CFD_DISABLE_ELEMENTS
}
