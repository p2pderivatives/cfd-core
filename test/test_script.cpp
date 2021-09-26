#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::ScriptHash;
using cfd::core::ScriptElement;
using cfd::core::ByteData;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::NetType;
using cfd::core::WitnessVersion;

TEST(Script, Script) {
  size_t size = 0;
  Script script;
  EXPECT_STREQ(script.GetHex().c_str(), "");
  EXPECT_EQ(script.IsEmpty(), true);
  EXPECT_EQ(script.GetData().GetDataSize(), size);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, Script_hex) {
  size_t size = 5;
  std::string hex("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  Script script(hex);
  EXPECT_STREQ(script.GetHex().c_str(),
               "76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetWitnessVersion(), WitnessVersion::kVersionNone);
}

TEST(Script, Script_hex_exception) {
  try {
    std::string hex("xxxx");
    Script script(hex);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "hex to byte convert error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, Script_bytedata) {
  size_t size = 5;
  ByteData bytedata("76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  Script script(bytedata);
  EXPECT_STREQ(script.GetHex().c_str(),
               "76a91498e977b2259a85278aa51188bd863a3df0ad31ba88ac");
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
}

TEST(Script, SetStackData_OP0) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(
      "96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  Script script = builder.Build();

  // OP_0 <hash160(pubkey)>
  size_t size = 2;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(
      script.GetHex().c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_STREQ(
      script.ToString().c_str(),
      "0 96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_EQ(script.GetWitnessVersion(), WitnessVersion::kVersion0);
}

TEST(Script, SetStackData_kUseScriptNum1) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_IF);
  builder.AppendData(
      "0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f");
  builder.AppendOperator(ScriptOperator::OP_ELSE);
  builder.AppendData(144);
  builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
  builder.AppendOperator(ScriptOperator::OP_DROP);
  builder.AppendData(
      "03f7cfe9da8101afb6a6894cac696c7e1ba74fba3ed4caab5eb66c7df4c9558621");
  builder.AppendOperator(ScriptOperator::OP_ENDIF);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  // OP_IF pubkeyA OP_ELSE delay OP_CHECKSEQUENCEVERIFY OP_DROP pubkeyB OP_ENDIF OP_CHECKSIG
  size_t size = 9;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(
      script.ToString().c_str(),
      "OP_IF 0211dcbf6768e8eff85d7b294776f046a5294a64158586cd2bc6da4b0740eacd2f OP_ELSE 144 OP_CHECKSEQUENCEVERIFY OP_DROP 03f7cfe9da8101afb6a6894cac696c7e1ba74fba3ed4caab5eb66c7df4c9558621 OP_ENDIF OP_CHECKSIG");
}

TEST(Script, SetStackData_kUseScriptNum2) {
  // script作成
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();

  // OP_5 OP_2 OP_ADD OP_7 OP_EQUALVERIFY
  size_t size = 5;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(script.GetHex().c_str(), "5552935788");
  EXPECT_STREQ(script.ToString().c_str(), "5 2 OP_ADD 7 OP_EQUALVERIFY");
}

TEST(Script, SetStackData_kUseScriptNum3) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_SIZE);
  builder.AppendOperator(ScriptOperator::OP_TUCK);
  builder.AppendData(0x20);
  builder.AppendData(0x23);
  builder.AppendOperator(ScriptOperator::OP_WITHIN);
  builder.AppendOperator(ScriptOperator::OP_VERIFY);
  Script script = builder.Build();

  // OP_SIZE OP_TUCK 20 23 OP_WITHIN OP_VERIFY
  size_t size = 6;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_STREQ(script.GetHex().c_str(), "827d01200123a569");
  EXPECT_STREQ(script.ToString().c_str(),
               "OP_SIZE OP_TUCK 32 35 OP_WITHIN OP_VERIFY");
}

TEST(Script, SetStackData_kOpPushData1) {
  // script作成
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(255, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4c);
}

TEST(Script, SetStackData_kOpPushData2) {
  // script作成
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(256, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4d);
}

TEST(Script, SetStackData_kOpPushData4) {
  // script作成
  // Builderではサイズエラーになるので、bytedataを自作
  std::vector<uint8_t> bytes(65541, 1);
  bytes[0] = 0x4e;
  bytes[1] = 0x00;
  bytes[2] = 0x00;
  bytes[3] = 0x01;
  bytes[4] = 0x00;
  Script script(bytes);

  size_t size = 1;
  EXPECT_EQ(script.IsEmpty(), false);
  EXPECT_EQ(script.GetElementList().size(), size);
  EXPECT_EQ(script.GetData().GetBytes()[0], 0x4e);
}

TEST(Script, SetStackData_kOpPushData1_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4c;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA1 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_kOpPushData2_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4d;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA2 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_kOpPushData4_error) {
  try {
    std::vector<uint8_t> bytes(2, 0xff);
    bytes[0] = 0x4e;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "OP_PUSHDATA4 is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, SetStackData_size_error) {
  try {
    std::vector<uint8_t> bytes(10, 0x1);
    bytes[0] = 0x4e;
    Script script(bytes);
  } catch (const cfd::core::CfdException &cfd_except) {
    EXPECT_STREQ(cfd_except.what(), "buffer is incorrect size.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(Script, GetScript) {
  ScriptBuilder builder;
  std::vector<uint8_t> bytes(255, 1);
  builder.AppendData(ByteData(bytes));
  Script script = builder.Build();

  Script script2 = script.GetScript();
  EXPECT_STREQ(script.GetHex().c_str(), script2.GetHex().c_str());
  EXPECT_STREQ(script.ToString().c_str(), script2.ToString().c_str());
}

TEST(Script, GetScriptHash) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ScriptHash script_hash = script.GetScriptHash();
  EXPECT_STREQ(script_hash.GetHex().c_str(),
               "a9145528d5065b3f370375a651128077eaf3258531d887");
}

TEST(Script, GetWitnessScriptHash) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ScriptHash script_hash = script.GetWitnessScriptHash();
  EXPECT_STREQ(
      script_hash.GetHex().c_str(),
      "00206bb5cc76cdbd684cb6f7c43a98c61c5aa789368d5e319e6c8258de3fec796562");
}

TEST(Script, GetData) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  ByteData byte_data = script.GetData();
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, GetHex) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  std::string hex = script.GetHex();
  EXPECT_STREQ(
      hex.c_str(),
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, IsEmpty_true) {
  Script script;
  EXPECT_EQ(script.IsEmpty(), true);
}

TEST(Script, IsEmpty_false) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_EQ(script.IsEmpty(), false);
}

TEST(Script, GetElementList) {
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();

  size_t size = 5;
  std::vector<ScriptElement> list = script.GetElementList();
  EXPECT_EQ(list.size(), size);
}

TEST(Script, ToString) {
  Script script(
      "002096376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
  EXPECT_STREQ(
      script.ToString().c_str(),
      "0 96376230fbeec4d1e703c3a2d1efe975ccf650a40f6ca2ec2d6cce44fc6bb2b3");
}

TEST(Script, ToString_empty) {
  Script script;
  EXPECT_STREQ(script.ToString().c_str(), "");
}

TEST(Script, IsPushOnly_true) {
  ScriptBuilder builder;
  builder.AppendData(5);
  Script script = builder.Build();
  EXPECT_EQ(script.IsPushOnly(), true);
}

TEST(Script, IsPushOnly_false) {
  ScriptBuilder builder;
  builder.AppendData(5);
  builder.AppendData(2);
  builder.AppendOperator(ScriptOperator::OP_ADD);
  builder.AppendData(7);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  Script script = builder.Build();
  EXPECT_EQ(script.IsPushOnly(), false);
}

TEST(Script, IsPushOnly_empty) {
  Script script;
  EXPECT_EQ(script.IsPushOnly(), true);
}

TEST(Script, IsP2pkScriptTest) {
  ScriptBuilder builder;
  builder.AppendData(Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81"));
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  EXPECT_TRUE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsP2pkhScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(ByteData("18763afd24a108d323f53ebcea974e7f7d309503"));
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_TRUE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsP2shScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(ByteData("776f6d27bac2dabca92ac82d3ec353ec6f0550c4"));
  builder.AppendOperator(ScriptOperator::OP_EQUAL);
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_TRUE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsMultisigScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_2);
  builder.AppendData(Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81"));
  builder.AppendData(Pubkey("03af2df16372b687457c4e522141ca5a600d64c61f3d7a19a465c051d060bdd727"));
  builder.AppendData(Pubkey("02582b60250c5f99ab33faaec09c047f68e81bc267e4da7f136dc7b72afdaf0183"));
  builder.AppendOperator(ScriptOperator::OP_3);
  builder.AppendOperator(ScriptOperator::OP_CHECKMULTISIG);
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_TRUE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());

  // 17-of-20
  builder = ScriptBuilder();
  builder << 17;
  builder << Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0");
  builder << Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c");
  builder << Pubkey("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82");
  builder << Pubkey("03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38");
  builder << Pubkey("020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1");
  builder << Pubkey("0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147");
  builder << Pubkey("0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c");
  builder << Pubkey("020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9");
  builder << Pubkey("0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37");
  builder << Pubkey("0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e");
  builder << Pubkey("03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b");
  builder << Pubkey("02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd");
  builder << Pubkey("0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d");
  builder << Pubkey("0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2");
  builder << Pubkey("025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db");
  builder << Pubkey("030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55");
  builder << Pubkey("0267a49281bd9d6d366c39c62f2e95a2aab37638f2a4718891c542d0961962644e");
  builder << Pubkey("02f48e8e2bcaeb16a6d781bb7a72f6250607bf21e32f08c48e37a9e4706e6d48b8");
  builder << Pubkey("03968ac57888ddaa3b57caa39efd5d5382c24f3deed602775cd4895f7c7adb5950");
  builder << Pubkey("024b64115bff6cc3718867114f7594fad535344f27ebe17ffa0e66288eb7bd2561");
  builder << 20;
  builder << ScriptOperator::OP_CHECKMULTISIG;
  script = builder.Build();
  EXPECT_TRUE(script.IsMultisigScript());

  // invalid multisig1
  builder = ScriptBuilder();
  builder.AppendData(ByteData("02"));  // binary value
  builder.AppendData(Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81"));
  builder.AppendData(Pubkey("03af2df16372b687457c4e522141ca5a600d64c61f3d7a19a465c051d060bdd727"));
  builder.AppendData(Pubkey("02582b60250c5f99ab33faaec09c047f68e81bc267e4da7f136dc7b72afdaf0183"));
  builder.AppendData(ByteData("03"));  // binary value
  builder.AppendOperator(ScriptOperator::OP_CHECKMULTISIG);
  script = builder.Build();
  EXPECT_EQ("0102210288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b812103af2df16372b687457c4e522141ca5a600d64c61f3d7a19a465c051d060bdd7272102582b60250c5f99ab33faaec09c047f68e81bc267e4da7f136dc7b72afdaf01830103ae", script.GetHex());
  EXPECT_FALSE(script.IsMultisigScript());

  // invalid multisig2
  builder = ScriptBuilder();
  builder << 2;
  builder << Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81");
  builder << 1 << ScriptOperator::OP_CHECKMULTISIG;
  script = builder.Build();
  EXPECT_EQ("52210288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b8151ae", script.GetHex());
  EXPECT_FALSE(script.IsMultisigScript());

  // invalid multisig3
  builder = ScriptBuilder();
  builder << 0;
  builder << Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81");
  builder << 1 << ScriptOperator::OP_CHECKMULTISIG;
  script = builder.Build();
  EXPECT_EQ("00210288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b8151ae", script.GetHex());
  EXPECT_FALSE(script.IsMultisigScript());

  // invalid multisig4
  builder = ScriptBuilder();
  builder << 1;
  builder << Pubkey("0288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b81");
  builder << 2 << ScriptOperator::OP_CHECKMULTISIG;
  script = builder.Build();
  EXPECT_EQ("51210288b03ce954e6eccfd9bdfd8cea71f80957e20d37d020b1b99973ea9f897f2b8152ae", script.GetHex());
  EXPECT_FALSE(script.IsMultisigScript());
}

TEST(Script, IsP2wpkhScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(ByteData("18763afd24a108d323f53ebcea974e7f7d309503"));
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_TRUE(script.IsWitnessProgram());
  EXPECT_TRUE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsP2wshScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(ByteData("0225718cefb8c26fdc0343681d116f5bdf6d6cd9dcf6a28067c76c9385e89fe3"));
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_TRUE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_TRUE(script.IsP2wshScript());
  EXPECT_FALSE(script.IsPegoutScript());
}

TEST(Script, IsPegoutScriptTest) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_RETURN);
  builder.AppendData(ByteData("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
  builder.AppendData(ByteData("a91453c252a6a1379642adea35d055329ea04528eab787"));
  Script script = builder.Build();

  EXPECT_FALSE(script.IsP2pkScript());
  EXPECT_FALSE(script.IsP2pkhScript());
  EXPECT_FALSE(script.IsP2shScript());
  EXPECT_FALSE(script.IsMultisigScript());
  EXPECT_FALSE(script.IsWitnessProgram());
  EXPECT_FALSE(script.IsP2wpkhScript());
  EXPECT_FALSE(script.IsP2wshScript());
  EXPECT_TRUE(script.IsPegoutScript());
}

TEST(Script, ParseCoinbaseScriptsigTest) {
  const std::string script = "03632b1e045352b260425443506f6f6cfabe6d6d4b081c2a3c7cb234c159b8e198294dfa79c04b54803e0e54c4a37d239445eb42020000007296cd100100000e8338000000000000";
  Script obj(script);
  EXPECT_EQ(script, obj.GetHex());
  auto list = obj.GetElementList();
  EXPECT_EQ(3, list.size());
  if (list.size() == 3) {
    EXPECT_EQ("03632b1e", list[0].GetData().GetHex());
    EXPECT_EQ("045352b260", list[1].GetData().GetHex());
    EXPECT_TRUE(list[2].IsBinary());
    // buffer size is low from length.
    EXPECT_EQ(
      "5443506f6f6cfabe6d6d4b081c2a3c7cb234c159b8e198294dfa79c04b54803e0e54c4a37d239445eb42020000007296cd100100000e8338000000000000",
      list[2].GetBinaryData().GetHex());
  }
}
