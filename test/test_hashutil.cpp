#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::HashUtil;
using cfd::core::Pubkey;
using cfd::core::Script;

// Hash tool
// https://bc-2.jp/tools/txeditor2.html
// https://hogehoge.tk/tool/

// Ripemd160 -----------------------------------------------------------------
TEST(HashUtil, Ripemd160String) {
  ByteData160 byte_data = HashUtil::Ripemd160("The quick brown fox jumps over the lazy dog");
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "37f332f68db77bd9d7edd4969571ad671cf9dd3b");

  byte_data = HashUtil::Ripemd160("The quick brown fox jumps over the lazy cog");
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "132072df690933835eb8b6ad0b77e7b6f14acad7");

  byte_data = HashUtil::Ripemd160("");
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "9c1185a5c5e9fc54612808977ee8f548b2258d31");
}

TEST(HashUtil, Ripemd160) {
  ByteData160 byte_data;
  byte_data = HashUtil::Ripemd160(ByteData("0123456789abcdef"));
  EXPECT_STREQ(byte_data.GetHex().c_str(), "cea1b21f1a739fba68d1d4290437d2c5609be1d3");

  byte_data = HashUtil::Ripemd160(ByteData160("0123456789abcdef0123456789abcdef01234567"));
  EXPECT_STREQ(byte_data.GetHex().c_str(), "49ec9207a365f6f330d529ca2a79e23a7ea2b526");

  byte_data = HashUtil::Ripemd160(ByteData256("1234567890123456789012345678901234567890123456789012345678901234"));
  EXPECT_STREQ(byte_data.GetHex().c_str(), "a5b1c86f10c81c3c543304e9891815d8de036296");

  byte_data = HashUtil::Ripemd160(Pubkey("032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db"));
  EXPECT_STREQ(byte_data.GetHex().c_str(), "1c8eae98d10ae2eb0ce0a99d446f0156c6f596ca");

  byte_data = HashUtil::Ripemd160(Script("21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"));
  EXPECT_STREQ(byte_data.GetHex().c_str(), "6be854f95bade5490a020c3841c50d08339a5c89");
}

TEST(HashUtil, Ripemd160ByOperator) {
  ByteData byte_data = (HashUtil(HashUtil::kRipemd160)
      << "The quick brown fox jumps over the lazy dog").Output();
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "37f332f68db77bd9d7edd4969571ad671cf9dd3b");

  byte_data = (HashUtil(HashUtil::kRipemd160)
      << ByteData("0123456789abcdef")).Output();
  EXPECT_STREQ(byte_data.GetHex().c_str(), "cea1b21f1a739fba68d1d4290437d2c5609be1d3");

  byte_data = (HashUtil(HashUtil::kRipemd160)
      << ByteData160("0123456789abcdef0123456789abcdef01234567")).Output();
  EXPECT_STREQ(byte_data.GetHex().c_str(), "49ec9207a365f6f330d529ca2a79e23a7ea2b526");

  auto bytedata160 = (HashUtil(HashUtil::kRipemd160)
      << ByteData160("0123456789abcdef0123456789abcdef01234567")).Output160();
  EXPECT_STREQ(bytedata160.GetHex().c_str(), "49ec9207a365f6f330d529ca2a79e23a7ea2b526");

  byte_data = (HashUtil(HashUtil::kRipemd160)
      << ByteData256("1234567890123456789012345678901234567890123456789012345678901234")).Output();
  EXPECT_STREQ(byte_data.GetHex().c_str(), "a5b1c86f10c81c3c543304e9891815d8de036296");

  byte_data = (HashUtil(HashUtil::kRipemd160)
      << Pubkey("032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db")).Output();
  EXPECT_STREQ(byte_data.GetHex().c_str(), "1c8eae98d10ae2eb0ce0a99d446f0156c6f596ca");

  byte_data = (HashUtil(HashUtil::kRipemd160)
      << Script("21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac")).Output();
  EXPECT_STREQ(byte_data.GetHex().c_str(), "6be854f95bade5490a020c3841c50d08339a5c89");
}

// Hash160 -----------------------------------------------------------------
TEST(HashUtil, Hash160String) {
  ByteData160 byte_data = HashUtil::Hash160("test Hash160 OK");
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "bad6268d95924542c33d094863ef68e2ccf92876");
}

//TEST(HashUtil, Hash160StringException) {
//}

TEST(HashUtil, Hash160Bytes) {
  std::vector<uint8_t> target;
  target.push_back(0x01);
  target.push_back(0x02);
  target.push_back(0x03);
  ByteData160 byte_data = HashUtil::Hash160(target);
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "9bc4860bb936abf262d7a51f74b4304833fee3b2");
}

TEST(HashUtil, Hash160ByteData) {
  ByteData target("0123456789abcdef");
  ByteData160 byte_data = HashUtil::Hash160(target);
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "a956ed79819901b1b2c7b3ec045081f749c588ed");
}

TEST(HashUtil, Hash160ByteData160) {
  ByteData160 target("0123456789abcdef0123456789abcdef01234567");
  ByteData160 byte_data = HashUtil::Hash160(target);
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "d318d0f06ff6f17e873db19f57cf983f570a7be4");
}

TEST(HashUtil, Hash160ByteData256) {
  ByteData256 target(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData160 byte_data = HashUtil::Hash160(target);
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "a499a67a0e497bd375ef8ff6509dd853732248b3");
}

TEST(HashUtil, Hash160BytePubkey) {
  Pubkey target(
      "032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db");
  ByteData160 byte_data = HashUtil::Hash160(target);
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "d856f6effbdef003119edf5b602ceb4a5947648f");
}

TEST(HashUtil, Hash160ByteScript) {
  Script target(
      "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
  ByteData160 byte_data = HashUtil::Hash160(target);
  EXPECT_STREQ(byte_data.GetHex().c_str(),
               "942bc0a5409862f5414d2e8e5514135cd0453ef7");
}

// Sha256 -----------------------------------------------------------------
TEST(HashUtil, Sha256String) {
  ByteData256 byte_data = HashUtil::Sha256("test Sha256 OK");
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "98478d92e5005d232ad06c805eccf5381f47f6f51ee7803e5206dc04e2639a62");

  ByteData byte_data2 = (HashUtil("Sha256") << "test Sha256 OK").Output();
  EXPECT_STREQ(
      byte_data2.GetHex().c_str(),
      "98478d92e5005d232ad06c805eccf5381f47f6f51ee7803e5206dc04e2639a62");
}

TEST(HashUtil, Sha256Bytes) {
  std::vector<uint8_t> target;
  target.push_back(0x01);
  target.push_back(0x02);
  target.push_back(0x03);
  ByteData256 byte_data = HashUtil::Sha256(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
}

TEST(HashUtil, Sha256ByteData) {
  ByteData target("0123456789abcdef");
  ByteData256 byte_data = HashUtil::Sha256(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "55c53f5d490297900cefa825d0c8e8e9532ee8a118abe7d8570762cd38be9818");
}

TEST(HashUtil, Sha256ByteData160) {
  ByteData160 target("0123456789abcdef0123456789abcdef01234567");
  ByteData256 byte_data = HashUtil::Sha256(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "7e74ce75b5f2f89240b33afff241e209f98f7b8920af1b572957c8b030430d7a");
}

TEST(HashUtil, Sha256ByteData256) {
  ByteData256 target(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData256 byte_data = HashUtil::Sha256(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "ca1194a558362b5fa6e7887da7b41ec6faeb01c9477a0afd46dfc0692be33482");

  ByteData byte_data2 = (HashUtil("Sha256") << target).Output();
  EXPECT_STREQ(
      byte_data2.GetHex().c_str(),
      "ca1194a558362b5fa6e7887da7b41ec6faeb01c9477a0afd46dfc0692be33482");
}

TEST(HashUtil, Sha256BytePubkey) {
  Pubkey target(
      "032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db");
  ByteData256 byte_data = HashUtil::Sha256(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "2213d0c45bf1ece1a9b0c2d5a21d603601e88e22ae2786fe3f0060ee4aad321d");
}

TEST(HashUtil, Sha256ByteScript) {
  Script target(
      "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
  ByteData256 byte_data = HashUtil::Sha256(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0");
}

// Sha256D -----------------------------------------------------------------
TEST(HashUtil, Sha256DString) {
  ByteData256 byte_data = HashUtil::Sha256D("test Sha256D OK");
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "635c9e5d79bd3d16450884da9fc0a62939d768369853a2ae577ce162790c07d1");
}

TEST(HashUtil, Sha256DBytes) {
  std::vector<uint8_t> target;
  target.push_back(0x01);
  target.push_back(0x02);
  target.push_back(0x03);
  ByteData256 byte_data = HashUtil::Sha256D(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "19c6197e2140b9d034fb20b9ac7bb753a41233caf1e1dafda7316a99cef41416");
}

TEST(HashUtil, Sha256DByteData) {
  ByteData target("0123456789abcdef");
  ByteData256 byte_data = HashUtil::Sha256D(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "137ad663f79da06e282ed0abbec4d70523ced5ff8e39d5c2e5641d978c5925aa");
}

TEST(HashUtil, Sha256DByteData160) {
  ByteData160 target("0123456789abcdef0123456789abcdef01234567");
  ByteData256 byte_data = HashUtil::Sha256D(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "ee6ba2aa505be17522e936ebac2c31c108d58ebfc8d483ed75a6b298506cb949");
}

TEST(HashUtil, Sha256DByteData256) {
  ByteData256 target(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData256 byte_data = HashUtil::Sha256D(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "62e5fa013750097309ebcb838db33d1a9fe2e3083231fd87ce735ce4c0ca1e4c");
}

TEST(HashUtil, Sha256DBytePubkey) {
  Pubkey target(
      "032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db");
  ByteData256 byte_data = HashUtil::Sha256D(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "80b32bdf77034a9b152bac4ce3f8755ba72217c297c03b6ed150b544f0f2948c");
}

TEST(HashUtil, Sha256DByteScript) {
  Script target(
      "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
  ByteData256 byte_data = HashUtil::Sha256D(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "f90db0faee6addeb5cb4f66fa11590d5a21475fcbad58f3e847f0d27a2d18668");
}

// Sha512 -----------------------------------------------------------------
TEST(HashUtil, Sha512String) {
  ByteData byte_data = HashUtil::Sha512("test Sha512 OK");
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "f9ed57116c6b62a8b5b030eb655bb7c6833289666d219648abacbe52bce5df883267251cc1ec9c5bda2156f6a8212ebeb46e64360035d079f1eb2aed0ce4dccb");
}

TEST(HashUtil, Sha512Bytes) {
  std::vector<uint8_t> target;
  target.push_back(0x01);
  target.push_back(0x02);
  target.push_back(0x03);
  ByteData byte_data = HashUtil::Sha512(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "27864cc5219a951a7a6e52b8c8dddf6981d098da1658d96258c870b2c88dfbcb51841aea172a28bafa6a79731165584677066045c959ed0f9929688d04defc29");
}

TEST(HashUtil, Sha512ByteData) {
  ByteData target("0123456789abcdef");
  ByteData byte_data = HashUtil::Sha512(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "650161856da7d9f818e6047cf6b2092bc7aa3767d3495cfbefe2b710ed684a43ba933ea8286ef67d975e64e0482e5ebe0701788989396545b6badb3b0a136f19");
}

TEST(HashUtil, Sha512ByteData160) {
  ByteData160 target("0123456789abcdef0123456789abcdef01234567");
  ByteData byte_data = HashUtil::Sha512(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "a0328b2336a761329ef0ce5bd23743173cad5528bfc21cc7b493ea6a1f4cd7ef888e6fb7ca8f294e8e5f2d2459bc72880522bd43d64e5068bc2a8ea21d27ea70");
}

TEST(HashUtil, Sha512ByteData256) {
  ByteData256 target(
      "1234567890123456789012345678901234567890123456789012345678901234");
  ByteData byte_data = HashUtil::Sha512(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "f7487034525bc244358a1dc44f1a91a3abb475585b138d775a1d5d77c7279dff00a315cb32fbecea448baf6d471bac6b26427b0c0c53cf3d88a3a284a382b5f1");
}

TEST(HashUtil, Sha512BytePubkey) {
  Pubkey target(
      "032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db");
  ByteData byte_data = HashUtil::Sha512(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "3f7a5ecb744920c058e56759f853698ab2cbb62fa511f2211cc50f72152967d5545e67e13bcc19aeb4e699e417ac0c878342e3775d36a8e0b4cd75b1bd924b68");
}

TEST(HashUtil, Sha512ByteScript) {
  Script target(
      "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
  ByteData byte_data = HashUtil::Sha512(target);
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "7ad6132c2611fd0496ad42c758edc1bc2a23c3a4c463e139e144e25c35a53765c4c4c99d68d821a1bdd71b10e88afebdba72bfa0ae3877f628f1e2eab5320229");
}

TEST(HashUtil, operator) {
  ByteData target(
      "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
  HashUtil hash_util(HashUtil::kSha512);
  hash_util << target.GetBytes();
  HashUtil hash_util2(HashUtil::kSha512);
  hash_util2 = hash_util;
  EXPECT_EQ(
      hash_util2.Output().GetHex(),
      "7ad6132c2611fd0496ad42c758edc1bc2a23c3a4c463e139e144e25c35a53765c4c4c99d68d821a1bdd71b10e88afebdba72bfa0ae3877f628f1e2eab5320229");
}
