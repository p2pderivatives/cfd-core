#include "gtest/gtest.h"

#include <vector>
#include <limits>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"

using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::Pubkey;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptElement;
using cfd::core::ScriptOperator;
using cfd::core::ScriptType;

typedef struct {
  std::vector<ScriptElement> inputs;
  std::string expect_hex;
  std::string expect_asm;
} ScriptBuilderTestVector;

// @formatter:off
static const std::vector<ScriptBuilderTestVector> sb_test_vectors = {
  // empty data
  {
    {},
    "",
    ""
  },
  // various data type
  {
    {
      ScriptElement(ScriptType::kOp_5),
      ScriptElement(ScriptType::kOp_2),
      ScriptElement(ScriptType::kOpAdd),
      ScriptElement(ScriptType::kOpCheckSig),
    },
    "555293ac",
    "5 2 OP_ADD OP_CHECKSIG"
  },
  {
    {
      ScriptElement(-1),
      ScriptElement(0),
      ScriptElement(1),
      ScriptElement(2),
      ScriptElement(15),
      ScriptElement(16),
      ScriptElement(17),
      ScriptElement(static_cast<int64_t>(
                  std::numeric_limits<int32_t>::max()) - 1),
      ScriptElement(static_cast<int64_t>(
                  std::numeric_limits<int32_t>::max())),
      ScriptElement(static_cast<int64_t>(
                  std::numeric_limits<int32_t>::max()) + 1),
      ScriptElement(std::numeric_limits<int64_t>::max() - 1),
      ScriptElement(std::numeric_limits<int64_t>::max()),
    },
    "4f0051525f60011104feffff7f04ffffff7f05000000800008feffffffffffff7f08ffffffffffffff7f",
    "-1 0 1 2 15 16 17 2147483646 2147483647 0000008000 feffffffffffff7f ffffffffffffff7f"
  },
  {
    {
      ScriptElement(ByteData("00")),
      ScriptElement(ByteData("11")),
      ScriptElement(ByteData("2222")),
      ScriptElement(ByteData("333333")),
      ScriptElement(ByteData("4444")),
      ScriptElement(ByteData("55")),
      ScriptElement(ByteData("6666")),
      ScriptElement(ByteData("777777")),
      ScriptElement(ByteData("8888")),
      ScriptElement(ByteData("99")),
    },
    "01000111022222033333330244440155026666037777770288880199",
    "0 17 8738 3355443 17476 85 26214 7829367 -2184 -25"
  },
};
// @formatter:on

TEST(ScriptBuilder, DefaultConstructorTest) {
  ScriptBuilder sb = ScriptBuilder();
  Script actual = sb.Build();

  EXPECT_STREQ("", actual.GetHex().c_str());
  EXPECT_STREQ("", actual.ToString().c_str());
//  EXPECT_EQ(0, actual.GetElementList().size());
}

TEST(ScriptBuilder, AppendFunctionTest1) {
  ScriptBuilder sb = ScriptBuilder();
  std::string sig =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e";  // NOLINT
  std::string pubkey =
  "042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0";// NOLINT
  std::string pubkey_hash = "aea58b2d64af22fe06b95c46af4e471e6280226c";

  // ref: https://en.bitcoin.it/wiki/Script#Script_examples
  // Freezing funds until a time in the future
  sb.AppendData(sig);
  sb.AppendData(Pubkey(pubkey));
  sb.AppendData(144);
  sb.AppendOperator(ScriptType::kOpCheckLockTimeVerify);
  sb.AppendOperator(ScriptOperator::OP_DROP);
  sb.AppendOperator(ScriptOperator::OP_DUP);
  sb.AppendOperator(ScriptOperator::OP_HASH160);
  sb.AppendData(ByteData160(pubkey_hash));
  sb.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  sb.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script actual = sb.Build();

  std::string expect_hex =
  "46304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e41042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0029000b17576a914aea58b2d64af22fe06b95c46af4e471e6280226c88ac";// NOLINT
  std::string expect_asm =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e 042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0 144 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 aea58b2d64af22fe06b95c46af4e471e6280226c OP_EQUALVERIFY OP_CHECKSIG";// NOLINT
  size_t expect_size = 10;

  EXPECT_STREQ(expect_hex.c_str(), actual.GetHex().c_str());
  EXPECT_STREQ(expect_asm.c_str(), actual.ToString().c_str());
  EXPECT_EQ(expect_size, actual.GetElementList().size());
}

TEST(ScriptBuilder, AppendFunctionTest1ByOperator) {
  std::string sig =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e";  // NOLINT
  std::string pubkey =
  "042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0";// NOLINT
  std::string pubkey_hash = "aea58b2d64af22fe06b95c46af4e471e6280226c";

  // ref: https://en.bitcoin.it/wiki/Script#Script_examples
  // Freezing funds until a time in the future
  Script actual = (ScriptBuilder() << sig << Pubkey(pubkey) << 144
      << ScriptType::kOpCheckLockTimeVerify
      << ScriptOperator::OP_DROP << ScriptOperator::OP_DUP
      << ScriptOperator::OP_HASH160 << ByteData160(pubkey_hash)
      << ScriptOperator::OP_EQUALVERIFY << ScriptOperator::OP_CHECKSIG).Build();

  std::string expect_hex =
  "46304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e41042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0029000b17576a914aea58b2d64af22fe06b95c46af4e471e6280226c88ac";// NOLINT
  std::string expect_asm =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e 042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0 144 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 aea58b2d64af22fe06b95c46af4e471e6280226c OP_EQUALVERIFY OP_CHECKSIG";// NOLINT
  size_t expect_size = 10;

  EXPECT_STREQ(expect_hex.c_str(), actual.GetHex().c_str());
  EXPECT_STREQ(expect_asm.c_str(), actual.ToString().c_str());
  EXPECT_EQ(expect_size, actual.GetElementList().size());
}

TEST(ScriptBuilder, AppendFunctionTest2) {
  ScriptBuilder sb = ScriptBuilder();
  std::string sig =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e";  // NOLINT
  std::string pubkey =
  "042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0";// NOLINT
  // OP_5 OP_2 OP_ADD OP_7 OP_EQUALVERIFY
  std::string redeem_script = "55529357";
  std::string script_hash =
  "f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c4";// NOLINT

  // ref: https://en.bitcoin.it/wiki/Script#Script_examples
  // Freezing funds until a time in the future
  sb.AppendElement(ScriptElement(ByteData(sig)));
  sb.AppendData(ByteData(pubkey));
  sb.AppendData(144);
  sb.AppendOperator(ScriptType::kOpCheckLockTimeVerify);
  sb.AppendOperator(ScriptOperator::OP_DROP);
  sb.AppendData(Script(redeem_script));
  sb.AppendOperator(ScriptOperator::OP_SHA256);
  sb.AppendData(ByteData256(script_hash));
  sb.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  sb.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script actual = sb.Build();

  std::string expect_hex =
  "46304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e41042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0029000b1750455529357a820f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c488ac";// NOLINT
  std::string expect_asm =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e 042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0 144 OP_CHECKLOCKTIMEVERIFY OP_DROP 1469272661 OP_SHA256 f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c4 OP_EQUALVERIFY OP_CHECKSIG";// NOLINT
  size_t expect_size = 10;

  EXPECT_STREQ(expect_hex.c_str(), actual.GetHex().c_str());
  EXPECT_STREQ(expect_asm.c_str(), actual.ToString().c_str());
  EXPECT_EQ(expect_size, actual.GetElementList().size());
}

TEST(ScriptBilder, TestVectorNormalCase) {
  ScriptBuilder sb;
  for (const ScriptBuilderTestVector& test_vector : sb_test_vectors) {
    sb = ScriptBuilder();
    for (const ScriptElement& input_elem : test_vector.inputs) {
      sb.AppendElement(input_elem);
    }
    Script actual = sb.Build();

    EXPECT_STREQ(test_vector.expect_hex.c_str(), actual.GetHex().c_str());
    EXPECT_STREQ(test_vector.expect_asm.c_str(), actual.ToString().c_str());
    EXPECT_EQ(test_vector.inputs.size(), actual.GetElementList().size());
  }
}

TEST(ScriptBuilder, MaxScriptSizeOverErrorTest) {
  ScriptBuilder sb = ScriptBuilder();
  // dummy_data = sha256("0000")
  ByteData256 dummy_data = ByteData256(
      "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7");
  int64_t loop_num = (Script::kMaxScriptSize / 32) + 1;
  for (int64_t i = 0; i < loop_num; ++i) {
    sb.AppendData(dummy_data);
  }

  EXPECT_THROW(sb.Build(), CfdException);
}

TEST(ScriptBuilder, StringBuildTest) {
  Script script;
  ScriptBuilder sb = ScriptBuilder();
  sb.AppendString("5");
  sb.AppendString("2");
  sb.AppendString("OP_ADD");
  sb.AppendString("OP_CHECKSIG");

  EXPECT_NO_THROW(script = sb.Build());
  EXPECT_STREQ(script.GetHex().c_str(), "555293ac");
  EXPECT_STREQ(script.ToString().c_str(), "5 2 OP_ADD OP_CHECKSIG");

  sb = ScriptBuilder();
  sb.AppendString("0");
  sb.AppendString("17");
  sb.AppendString("8738");
  sb.AppendString("3355443");
  sb.AppendString("17476");
  sb.AppendString("85");
  sb.AppendString("26214");
  sb.AppendString("7829367");
  sb.AppendString("-2184");
  sb.AppendString("-25");

  EXPECT_NO_THROW(script = sb.Build());
  EXPECT_STREQ(script.GetHex().c_str(),
    "000111022222033333330244440155026666037777770288880199");
  EXPECT_STREQ(script.ToString().c_str(),
    "0 17 8738 3355443 17476 85 26214 7829367 -2184 -25");

  std::string expect_hex =
  "46304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e41042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0029000b1750455529357a820f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c488ac";// NOLINT
  std::string expect_asm =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e 042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0 144 OP_CHECKLOCKTIMEVERIFY OP_DROP 1469272661 OP_SHA256 f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c4 OP_EQUALVERIFY OP_CHECKSIG";// NOLINT
  sb = ScriptBuilder();
  sb.AppendString("304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e");
  sb.AppendString("042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0");
  sb.AppendString("144");
  sb.AppendString("OP_CHECKLOCKTIMEVERIFY");
  sb.AppendString("OP_DROP");
  sb.AppendString("1469272661");
  sb.AppendString("OP_SHA256");
  sb.AppendString("f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c4");
  sb.AppendString("OP_EQUALVERIFY");
  sb.AppendString("OP_CHECKSIG");

  EXPECT_NO_THROW(script = sb.Build());
  EXPECT_STREQ(script.GetHex().c_str(), expect_hex.c_str());
  EXPECT_STREQ(script.ToString().c_str(), expect_asm.c_str());

  // hex test
  sb = ScriptBuilder();
  sb.AppendString("0x00");
  sb.AppendString("0x11");
  sb.AppendString("0x2222");
  sb.AppendString("0x333333");

  EXPECT_NO_THROW(script = sb.Build());
  EXPECT_STREQ(script.GetHex().c_str(),
    "0100011102222203333333");
  EXPECT_STREQ(script.ToString().c_str(),
    "0 17 8738 3355443");
}

TEST(ScriptBuilder, StringBuildByOperator) {
  Script script = (ScriptBuilder() << "5" << "2" << "OP_ADD" << "OP_CHECKSIG").Build();
  EXPECT_STREQ(script.GetHex().c_str(), "555293ac");
  EXPECT_STREQ(script.ToString().c_str(), "5 2 OP_ADD OP_CHECKSIG");

  script = (ScriptBuilder() << "0" << "17" << "8738"
     << "3355443" << "17476" << "85" << "26214" << "7829367"
     << "-2184" << "-25").Build();
  EXPECT_STREQ(script.GetHex().c_str(),
    "000111022222033333330244440155026666037777770288880199");
  EXPECT_STREQ(script.ToString().c_str(),
    "0 17 8738 3355443 17476 85 26214 7829367 -2184 -25");

  std::string expect_hex =
  "46304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e41042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0029000b1750455529357a820f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c488ac";// NOLINT
  std::string expect_asm =
  "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e 042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0 144 OP_CHECKLOCKTIMEVERIFY OP_DROP 1469272661 OP_SHA256 f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c4 OP_EQUALVERIFY OP_CHECKSIG";// NOLINT

  script = (ScriptBuilder()
     << "304402203dd0c408e173d6b7252eabc7e3f6a0c632d930a7b343eaf60e7ebee9eb01adcc02204a567cb6a941c88f24f4c4201633468d53810fae9cdb90f35571e6b52bed005e"
     << "042322ed12f2779cae32ca89f15d61d10e3bd725d74d45269b05a34abb91b45a2ca19cc8734300deaf74d006871b5cd0730f2384037d16843663a0327fce24aef0"
     << "144"
     << "OP_CHECKLOCKTIMEVERIFY" << "OP_DROP" << "1469272661"
     << "OP_SHA256"
     << "f6116d61351c05df34e116f1cc63fcacbd4f1a3882d2f629e7a0986ac03005c4"
     << "OP_EQUALVERIFY" << "OP_CHECKSIG").Build();
  EXPECT_STREQ(script.GetHex().c_str(), expect_hex.c_str());
  EXPECT_STREQ(script.ToString().c_str(), expect_asm.c_str());

  // hex test
  script = (ScriptBuilder()
     << "0x00"
     << "0x11"
     << "0x2222"
     << "0x333333").Build();
  EXPECT_STREQ(script.GetHex().c_str(),
    "0100011102222203333333");
  EXPECT_STREQ(script.ToString().c_str(),
    "0 17 8738 3355443");
}
