#include "gtest/gtest.h"

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_script.h"

using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::Script;
using cfd::core::ScriptElement;
using cfd::core::ScriptHash;
using cfd::core::ScriptType;

TEST(ScriptHash, ScriptHash_hex) {
  ScriptHash script_hash(
      "002016a2aa44989dab00f6c54dfc682ec482a0a061d289fd5ac39354c8dffed59ddf");
  EXPECT_STREQ(
      script_hash.GetHex().c_str(),
      "002016a2aa44989dab00f6c54dfc682ec482a0a061d289fd5ac39354c8dffed59ddf");
}

TEST(ScriptHash, ScriptHash_hex_empty) {
  ScriptHash script_hash("");
  size_t size = 0;
  EXPECT_STREQ(script_hash.GetHex().c_str(), "");
  EXPECT_EQ(script_hash.GetData().GetDataSize(), size);
}

TEST(ScriptHash, ScriptHash_hex_exception) {
  try {
    std::string hex("xxxx");
    ScriptHash script_hash(hex);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "hex to byte convert error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(ScriptHash, ScriptHash_script_witness) {
  Script script("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  ScriptHash script_hash(script, true);
  // OP_0 SHA256(script)
  EXPECT_STREQ(
      script_hash.GetHex().c_str(),
      "002016a2aa44989dab00f6c54dfc682ec482a0a061d289fd5ac39354c8dffed59ddf");
}

TEST(ScriptHash, ScriptHash_script_legacy) {
  Script script("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  ScriptHash script_hash(script, false);
  // OP_HASH160 Hash160(script) OP_EQUAL
  EXPECT_STREQ(script_hash.GetHex().c_str(),
               "a9140e83a9df2e7937d27e90a26a06857407e39eb47487");
}

TEST(ScriptHash, GetHex) {
  std::string hex("1234");
  ScriptHash script_hash(hex);
  EXPECT_STREQ(script_hash.GetHex().c_str(), "1234");
}

TEST(ScriptHash, GetData) {
  ByteData bytes("1234");
  ScriptHash script_hash(bytes.GetHex());
  EXPECT_TRUE(script_hash.GetData().GetBytes() == bytes.GetBytes());
}
