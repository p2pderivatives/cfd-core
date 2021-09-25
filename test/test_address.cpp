#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_taproot.h"

using cfd::core::Address;
using cfd::core::NetType;
using cfd::core::WitnessVersion;
using cfd::core::AddressType;
using cfd::core::Pubkey;
using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::HashUtil;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::SchnorrPubkey;
using cfd::core::TaprootScriptTree;
using cfd::core::CfdException;
using cfd::core::AddressFormatData;
using cfd::core::GetBitcoinAddressFormatList;
#ifndef CFD_DISABLE_ELEMENTS
using cfd::core::GetElementsAddressFormatList;
using cfd::core::ElementsConfidentialAddress;
using cfd::core::ElementsNetType;
using cfd::core::ElementsAddressType;
#endif  // CFD_DISABLE_ELEMENTS

TEST(Address, GetBitcoinAddressFormatList) {
  std::vector<AddressFormatData> list = GetBitcoinAddressFormatList();
  EXPECT_STREQ("bc", list[NetType::kMainnet].GetBech32Hrp().c_str());
}

TEST(Address, EmptyAddressTest) {
  Address empty_address;
  EXPECT_STREQ("", empty_address.GetAddress().c_str());

  EXPECT_THROW((empty_address = Address("")), CfdException);
}

TEST(Address, P2pkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet, pubkey)));
  EXPECT_STREQ("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn", address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet, pubkey)));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest, pubkey)));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, P2shAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet, script)));
  EXPECT_STREQ("3K4cCA6U45jhvBcgc8qEdjHGDGyUMuVRpG",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet, script)));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest, script)));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, P2wpkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0, pubkey)));
  EXPECT_STREQ("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   WitnessVersion::kVersion0, pubkey)));
  EXPECT_STREQ("tb1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uhq9l7n",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0, pubkey)));
  EXPECT_STREQ("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, P2wshAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0, script)));
  EXPECT_STREQ("bc1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqszafymy",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   WitnessVersion::kVersion0, script)));
  EXPECT_STREQ("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0, script)));
  EXPECT_STREQ("bcrt1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqscv4d53",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
}

TEST(Address, TaprootAddressTest) {
  try {
    const SchnorrPubkey pubkey = SchnorrPubkey(
        "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb");
    Address address;
    address = Address(NetType::kMainnet,
                    WitnessVersion::kVersion1, pubkey);
    EXPECT_STREQ("bc1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naspp3kr4",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kMainnet, address.GetNetType());
    EXPECT_EQ(AddressType::kTaprootAddress, address.GetAddressType());
    EXPECT_EQ(WitnessVersion::kVersion1, address.GetWitnessVersion());
    EXPECT_STREQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
                address.GetHash().GetHex().c_str());
    EXPECT_STREQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
                address.GetSchnorrPubkey().GetHex().c_str());
    EXPECT_STREQ("", address.GetScript().GetHex().c_str());
    EXPECT_STREQ("51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        address.GetLockingScript().GetHex().c_str());

    auto formats = cfd::core::GetBitcoinAddressFormatList();
    EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                    WitnessVersion::kVersion1, pubkey, formats[1])));
    EXPECT_STREQ("tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kTestnet, address.GetNetType());

    EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                    WitnessVersion::kVersion1, pubkey, formats)));
    EXPECT_STREQ("bcrt1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8nasmsdlvq",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }
}

TEST(Address, TaprootScriptAddressTest) {
  try {
    const SchnorrPubkey pubkey(
        "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb");
    ScriptBuilder build;
    build.AppendOperator(ScriptOperator::OP_TRUE);
    TaprootScriptTree tree(build.Build());
    Address address;
    address = Address(NetType::kMainnet,
                    WitnessVersion::kVersion1, tree, pubkey);
    EXPECT_STREQ("bc1p3r0p5kdn3yultra5lrzlls74vwgdg057j8rmr4nlj8s8pucss7vsftyvah",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kMainnet, address.GetNetType());
    EXPECT_EQ(AddressType::kTaprootAddress, address.GetAddressType());
    EXPECT_EQ(WitnessVersion::kVersion1, address.GetWitnessVersion());
    EXPECT_STREQ("88de1a59b38939f58fb4f8c5ffc3d56390d43e9e91c7b1d67f91e070f3108799",
                address.GetHash().GetHex().c_str());
    EXPECT_EQ("tl(51)",
              address.GetScriptTree().ToString());
    EXPECT_STREQ("", address.GetScript().GetHex().c_str());
    EXPECT_STREQ("512088de1a59b38939f58fb4f8c5ffc3d56390d43e9e91c7b1d67f91e070f3108799",
        address.GetLockingScript().GetHex().c_str());

    auto formats = cfd::core::GetBitcoinAddressFormatList();
    EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                    WitnessVersion::kVersion1, tree, pubkey, formats[1])));
    EXPECT_STREQ("tb1p3r0p5kdn3yultra5lrzlls74vwgdg057j8rmr4nlj8s8pucss7vs7rjr8c",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kTestnet, address.GetNetType());

    EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                    WitnessVersion::kVersion1, tree, pubkey, formats)));
    EXPECT_STREQ("bcrt1p3r0p5kdn3yultra5lrzlls74vwgdg057j8rmr4nlj8s8pucss7vsn6c9jz",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }
}

TEST(Address, NoSegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData160 script_hash = HashUtil::Hash160(script);

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   AddressType::kP2pkhAddress, pubkey_hash)));
  EXPECT_STREQ("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   AddressType::kP2shAddress, script_hash)));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   AddressType::kP2pkhAddress, pubkey_hash)));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());

  // Illegal data
  EXPECT_THROW((address = Address(NetType::kTestnet,
                   AddressType::kP2wshAddress, script_hash)),
               CfdException);
}

TEST(Address, SegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData256 script_hash = HashUtil::Sha256(script);

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kMainnet,
                   WitnessVersion::kVersion0,
                   ByteData(pubkey_hash.GetBytes()))));
  EXPECT_STREQ("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kTestnet,
                   WitnessVersion::kVersion0,
                   ByteData(script_hash.GetBytes()))));
  EXPECT_STREQ("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());

  EXPECT_NO_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0,
                   ByteData(pubkey_hash.GetBytes()))));
  EXPECT_STREQ("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());

  // Illegal data
  EXPECT_THROW((address = Address(NetType::kRegtest,
                   WitnessVersion::kVersion0, ByteData())),
               CfdException);
}

TEST(Address, TaprootAddressFromHashTest) {
  try {
    const ByteData pubkey = ByteData(
        "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb");
    Address address;
    address = Address(NetType::kMainnet, WitnessVersion::kVersion1, pubkey);
    EXPECT_STREQ("bc1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naspp3kr4",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kMainnet, address.GetNetType());
    EXPECT_EQ(AddressType::kTaprootAddress, address.GetAddressType());
    EXPECT_EQ(WitnessVersion::kVersion1, address.GetWitnessVersion());
    EXPECT_STREQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
                address.GetHash().GetHex().c_str());
    EXPECT_STREQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
                address.GetSchnorrPubkey().GetHex().c_str());
    EXPECT_STREQ("", address.GetScript().GetHex().c_str());
    EXPECT_STREQ("51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
        address.GetLockingScript().GetHex().c_str());

    address = Address(NetType::kTestnet, WitnessVersion::kVersion1, pubkey);
    EXPECT_STREQ("tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kTestnet, address.GetNetType());

    address = Address(NetType::kRegtest, WitnessVersion::kVersion1, pubkey);
    EXPECT_STREQ("bcrt1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8nasmsdlvq",
                address.GetAddress().c_str());
    EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }
}

TEST(Address, NoSegwitAddressFromStringTest) {
  Address address;
  // P2PKH
  EXPECT_NO_THROW((address = Address("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn")));
  EXPECT_STREQ("1ELuNB5fLNUcrLzb93oJDPmjxjnsVwhNHn",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc")));
  EXPECT_STREQ("mtrrfEAe9PusdTUCrcmg3Jz4pjPaSnTiCc",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());

  // regtest prefix is equals testnet prefix

  // P2SH
  EXPECT_NO_THROW((address = Address("3K4cCA6U45jhvBcgc8qEdjHGDGyUMuVRpG")));
  EXPECT_STREQ("3K4cCA6U45jhvBcgc8qEdjHGDGyUMuVRpG",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW((address = Address("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU")));
  EXPECT_STREQ("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHNfHU",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  // Illegal data
  EXPECT_THROW((address = Address("2NAcpFu2VfYF47yFEHGT7FgGXRdBeBHXfHU")),
               CfdException);
}

TEST(Address, SegwitAddressFromStringTest) {
  Address address;
  EXPECT_NO_THROW((address = Address("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q")));
  EXPECT_STREQ("bc1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uax7v9q",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kMainnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt")));
  EXPECT_STREQ("tb1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqs44ltpt",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kTestnet, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());

  EXPECT_NO_THROW((address = Address("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6")));
  EXPECT_STREQ("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujf6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());

  EXPECT_NO_THROW((address = Address("bcrt1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8nasmsdlvq")));
  EXPECT_STREQ("bcrt1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8nasmsdlvq",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kRegtest, address.GetNetType());
  EXPECT_EQ(AddressType::kTaprootAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion1, address.GetWitnessVersion());
  EXPECT_STREQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
              address.GetHash().GetHex().c_str());
  EXPECT_STREQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
              address.GetSchnorrPubkey().GetHex().c_str());

  // Illegal data
  EXPECT_THROW((address = Address("bcrt1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5u4fujx6")),
               CfdException);
}

TEST(Address, ElementsP2wpkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  AddressFormatData net_param = AddressFormatData::ConvertFromJson(
      "{\"nettype\":\"custom\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"}");
  Address address;

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0, pubkey, net_param.GetBech32Hrp())));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0, pubkey, net_param)));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsP2wshAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  AddressFormatData net_param = AddressFormatData::ConvertFromJson(
      "{\"nettype\":\"custom\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"}");

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0, script, net_param.GetBech32Hrp())));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0, script, net_param)));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsP2pkhAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  AddressFormatData net_param = AddressFormatData::ConvertFromJson(
      "{\"nettype\":\"custom\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"}");

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kCustomChain, pubkey, net_param.GetP2pkhPrefix())));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3", address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain, pubkey, net_param)));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3", address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
               address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsP2shAddressTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  AddressFormatData net_param = AddressFormatData::ConvertFromJson(
      "{\"nettype\":\"custom\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"}");

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kCustomChain, script, net_param.GetP2shPrefix())));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain, script, net_param)));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetScript().GetHex().c_str());
}

TEST(Address, ElementsNoSegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData160 script_hash = HashUtil::Hash160(script);
  AddressFormatData net_param = AddressFormatData::ConvertFromJson(
      "{\"nettype\":\"custom\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"}");

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   AddressType::kP2pkhAddress, pubkey_hash, net_param)));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetLockingScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   AddressType::kP2shAddress, script_hash, net_param)));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());
  EXPECT_STREQ("a914be8f7ae2233fc122be82f2cf9fe3cc2c6196218a87",
               address.GetLockingScript().GetHex().c_str());
}

TEST(Address, ElementsSegwitAddressFromHashTest) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &script = builder.Build();
  ByteData256 script_hash = HashUtil::Sha256(script);
  AddressFormatData net_param = AddressFormatData::ConvertFromJson(
      "{\"nettype\":\"custom\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"}");

  Address address;
  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0,
                   ByteData(pubkey_hash.GetBytes()), net_param)));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());
  EXPECT_STREQ("0014925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetLockingScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address(NetType::kCustomChain,
                   WitnessVersion::kVersion0,
                   ByteData(script_hash.GetBytes()), net_param)));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
  EXPECT_EQ(NetType::kCustomChain, address.GetNetType());
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_STREQ("0020c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201",
               address.GetLockingScript().GetHex().c_str());
}

TEST(Address, ElementsNoSegwitAddressFromStringTest) {
  Address address;
  std::vector<AddressFormatData> params = AddressFormatData::ConvertListFromJson(
      "[{\"nettype\":\"Test\",\"p2pkh\":\"ff\",\"p2sh\":\"ff\",\"bech32\":\"dmy\"},"
      "{\"nettype\":\"elementsregtest\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"},]");

  // P2PKH
  EXPECT_NO_THROW((address = Address("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3", params)));
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetAddress().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_EQ(NetType::kElementsRegtest, address.GetNetType());
#else
  EXPECT_EQ(NetType::kNetTypeNum, address.GetNetType());
#endif  // CFD_DISABLE_ELEMENTS
  EXPECT_EQ(AddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersionNone, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA", params)));
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetAddress().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_EQ(NetType::kElementsRegtest, address.GetNetType());
#else
  EXPECT_EQ(NetType::kNetTypeNum, address.GetNetType());
#endif  // CFD_DISABLE_ELEMENTS
  EXPECT_EQ(AddressType::kP2shAddress, address.GetAddressType());

  // analyze fail data
  EXPECT_THROW((address = Address("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA")),
               CfdException);
}

TEST(Address, ElementsSegwitAddressFromStringTest) {
  Address address;
  std::vector<AddressFormatData> params = AddressFormatData::ConvertListFromJson(
      "[{\"nettype\":\"Test\",\"p2pkh\":\"ff\",\"p2sh\":\"ff\",\"bech32\":\"dmy\"},"
      "{\"nettype\":\"elementsregtest\",\"p2pkh\":\"eb\",\"p2sh\":\"4b\",\"bech32\":\"ert\"},]");

  EXPECT_NO_THROW((address = Address("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6", params)));
  EXPECT_STREQ("ert1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5udafvh6",
               address.GetAddress().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_EQ(NetType::kElementsRegtest, address.GetNetType());
#else
  EXPECT_EQ(NetType::kNetTypeNum, address.GetNetType());
#endif  // CFD_DISABLE_ELEMENTS
  EXPECT_EQ(AddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("", address.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("", address.GetScript().GetHex().c_str());

  EXPECT_NO_THROW((address = Address("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4", params)));
  EXPECT_STREQ("ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4",
               address.GetAddress().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_EQ(NetType::kElementsRegtest, address.GetNetType());
#else
  EXPECT_EQ(NetType::kNetTypeNum, address.GetNetType());
#endif  // CFD_DISABLE_ELEMENTS
  EXPECT_EQ(AddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_EQ(WitnessVersion::kVersion0, address.GetWitnessVersion());
}

#ifndef CFD_DISABLE_ELEMENTS
typedef struct {
  std::string address;
  ElementsNetType net_type;
  ElementsAddressType addr_type;
  Pubkey pubkey;
  Script script;
} ElementsUnblindedAddressTestVector;

// @formatter:off
static const std::vector<ElementsUnblindedAddressTestVector> test_vectors = {
  // mainnet p2pkh address
  {
    "QBF1353wcFYkri4efzX9HLjsoc2Tx6Lxfd",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kP2pkhAddress,
    Pubkey("02d21c625759280111907a06df050cccbc875b11a50bdafa71dae5d1e8695ba82e"),
    Script(),
  },
  {
    "Q58YfnS7p1NVZDTp9wTcrB5pveMbVae3Lh",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kP2pkhAddress,
    Pubkey("0345a0bab3022003ed107cd91b6fb6e3479d5ebdd2da8af6ddc29ab39f51a04d97"),
    Script(),
  },
  // mainnet p2sh address
  // p2sh-segwit
  {
    "GzYc1b58torxLcWAnSDGhzqiJZAv29eFVS",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kP2shAddress,
    Pubkey(),
    Script("0014994ee81a59f1ada3f4c3997c54f0401b5f539df0"),
  },
  // multisig
  {
    "GjGb5o2GnTisuL8aiWkwdsRvKh7bPQS4Tv",
    ElementsNetType::kLiquidV1,
    ElementsAddressType::kP2shAddress,
    Pubkey(),
    Script("522103a7bd50beb3aff9238336285c0a790169eca90b7ad807abc4b64897ca1f6dedb621039cbaf938d050dd2582e4c2f56d1f75cfc9d165f2f3270532363d9871fb7be14252ae"),
  },
  // regtest p2pkh address
  {
    "2dwGUKGZVKiRRN9TG5NeEgCqHT5PGjMqKTW",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kP2pkhAddress,
    Pubkey("03b301154568626491d4a698aa01768d7a273415646512edb5757c5c6cf5fb9f89"),
    Script(),
  },
  {
    "2dZq5CkTo2S6ejf9XSuuHSY8JsJDnaja542",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kP2pkhAddress,
    Pubkey("02d1337e4c15717a32a199cd4502d7c6b55f1b2534df21859363e4f24780974981"),
    Script(),
  },
  // regtest p2sh address
  // p2sh-segwit
  {
    "XBvES4D9QH2dXjcoe5KQFT8kG6d3n7zcJ2",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kP2shP2wpkhAddress,
    Pubkey(),
    Script("0014ef919b362c325291d3f24a3aff28ec811964f078"),
  },
  // p2sh multisig
  {
    "XTfKFxkeC83awc3HnPFbZxgMRdBAjDpDbc",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kP2shAddress,
    Pubkey(),
    Script("522102723d9fb5ad0c7f7d70c897731bcf6a58a4dee8113d7d848bff9f6f7bc01ff36621023bf567600a7972e22ac50eef693f05935cbcf48fb7bb550d7ab7e050f98567e352ae"),
  },
  // p2sh-segwit multisig
  {
    "XGpSNPYXP2h5FnDXiv5fGKdp4u2HjuexMu",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kP2shP2wshAddress,
    Pubkey(),
    // Script("522102723d9fb5ad0c7f7d70c897731bcf6a58a4dee8113d7d848bff9f6f7bc01ff36621023bf567600a7972e22ac50eef693f05935cbcf48fb7bb550d7ab7e050f98567e352ae"),
    Script("0020f41c58db6607eb43a43554cd45787df1d9ee89a2f001bff8ae9ce427d2d8cad4"),
  },
  // regtest bech32 address
  // bech32 pubkey
  {
    "ert1qa7gekd3vxfffr5ljfga0728vsyvkfurca37kgm",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kP2wpkhAddress,
    Pubkey("03b301154568626491d4a698aa01768d7a273415646512edb5757c5c6cf5fb9f89"),
    Script(),
  },
  // bech32 multisig
  {
    "ert1q7sw93kmxql458fp42nx527ra78v7azdz7qqml79wnnjz05kcet2q8xjucl",
    ElementsNetType::kElementsRegtest,
    ElementsAddressType::kP2wshAddress,
    Pubkey(),
    Script("522102723d9fb5ad0c7f7d70c897731bcf6a58a4dee8113d7d848bff9f6f7bc01ff36621023bf567600a7972e22ac50eef693f05935cbcf48fb7bb550d7ab7e050f98567e352ae"),
  },
};
// @formatter:on

TEST(Address, ElementsStringConstructorTest) {
  for (ElementsUnblindedAddressTestVector test : test_vectors) {
    // string constructor
    {
      Address addr = Address(test.address, GetElementsAddressFormatList());

      EXPECT_FALSE(ElementsConfidentialAddress::IsConfidentialAddress(test.address, GetElementsAddressFormatList()));
      EXPECT_STREQ(test.address.c_str(), addr.GetAddress().c_str());
      switch (test.addr_type) {
        case AddressType::kP2shP2wshAddress:
        case AddressType::kP2shP2wpkhAddress:
          EXPECT_EQ(AddressType::kP2shAddress, addr.GetAddressType());
          break;
        default:
          EXPECT_EQ(test.addr_type, addr.GetAddressType());
          break;
      }
      ByteData hash;
      switch (addr.GetAddressType()) {
        case AddressType::kP2wshAddress:
          hash = ByteData(HashUtil::Sha256(test.script).GetBytes());
          break;
        case AddressType::kP2pkhAddress:
        case AddressType::kP2wpkhAddress:
          hash = ByteData(HashUtil::Hash160(test.pubkey).GetBytes());
          break;
        default:
          hash = ByteData(HashUtil::Hash160(test.script).GetBytes());
          break;
      }
      EXPECT_EQ(test.net_type, addr.GetNetType());
      EXPECT_STREQ(hash.GetHex().c_str(), addr.GetHash().GetHex().c_str());
    }
  }
}

TEST(Address, ElementsSourceDataConstructorTest) {
  Address addr;
  for (ElementsUnblindedAddressTestVector test : test_vectors) {
    // pubkey/script constructor
    {
      ByteData hash;
      if ((test.addr_type == AddressType::kP2wpkhAddress)
          || (test.addr_type == AddressType::kP2wshAddress)) {
        // p2pkh constructor
        if (!test.pubkey.GetHex().empty()) {
          EXPECT_NO_THROW((addr = Address(test.net_type,
              WitnessVersion::kVersion0, test.pubkey,
              GetElementsAddressFormatList())));
          hash = ByteData(HashUtil::Hash160(test.pubkey).GetBytes());
        }
        // p2sh constructor
        else if (!test.script.GetHex().empty()) {
          EXPECT_NO_THROW((addr = Address(test.net_type,
              WitnessVersion::kVersion0, test.script,
              GetElementsAddressFormatList())));
          hash = ByteData(HashUtil::Sha256(test.script).GetBytes());
        }
        else {
          EXPECT_FALSE(true);
        }
      } else {
        // p2pkh constructor
        if (!test.pubkey.GetHex().empty()) {
          EXPECT_NO_THROW((addr = Address(test.net_type, test.pubkey, GetElementsAddressFormatList())));
          hash = ByteData(HashUtil::Hash160(test.pubkey).GetBytes());
        }
        // p2sh constructor
        else if (!test.script.GetHex().empty()) {
          EXPECT_NO_THROW((addr = Address(test.net_type, test.script, GetElementsAddressFormatList())));
          hash = ByteData(HashUtil::Hash160(test.script).GetBytes());
        }
        else {
          EXPECT_FALSE(true);
        }
      }

      EXPECT_FALSE(ElementsConfidentialAddress::IsConfidentialAddress(test.address, GetElementsAddressFormatList()));
      EXPECT_STREQ(test.address.c_str(), addr.GetAddress().c_str());
      switch (test.addr_type) {
        case AddressType::kP2shP2wshAddress:
        case AddressType::kP2shP2wpkhAddress:
          EXPECT_EQ(AddressType::kP2shAddress, addr.GetAddressType());
          break;
        default:
          EXPECT_EQ(test.addr_type, addr.GetAddressType());
          break;
      }
      EXPECT_EQ(test.net_type, addr.GetNetType());
      EXPECT_STREQ(hash.GetHex().c_str(), addr.GetHash().GetHex().c_str());
    }
  }
}

TEST(Address, ElementsHashDataConstructorTest) {
  Address addr;
  for (ElementsUnblindedAddressTestVector test : test_vectors) {
    // hash data constructor
    {
      ByteData hash;
      if ((test.addr_type == AddressType::kP2wpkhAddress)
          || (test.addr_type == AddressType::kP2wshAddress)) {
        // p2pkh constructor
        if (!test.pubkey.GetHex().empty()) {
          hash = ByteData(HashUtil::Hash160(test.pubkey).GetBytes());
        }
        // p2sh constructor
        else if (!test.script.GetHex().empty()) {
          hash = ByteData(HashUtil::Sha256(test.script).GetBytes());
        }
        else {
          EXPECT_FALSE(true);
        }
        EXPECT_NO_THROW((addr = Address(test.net_type, WitnessVersion::kVersion0,
            hash, GetElementsAddressFormatList())));
      } else {
        // p2pkh constructor
        ByteData160 hash160;
        if (!test.pubkey.GetHex().empty()) {
          hash160 = HashUtil::Hash160(test.pubkey);
        }
        // p2sh constructor
        else if (!test.script.GetHex().empty()) {
          hash160 = HashUtil::Hash160(test.script);
        }
        else {
          EXPECT_FALSE(true);
        }
        EXPECT_NO_THROW((addr = Address(test.net_type, test.addr_type, hash160,
            GetElementsAddressFormatList())));
        hash = ByteData(hash160.GetBytes());
      }
      EXPECT_FALSE(ElementsConfidentialAddress::IsConfidentialAddress(test.address, GetElementsAddressFormatList()));
      EXPECT_STREQ(test.address.c_str(), addr.GetAddress().c_str());
      EXPECT_EQ(test.net_type, addr.GetNetType());
      EXPECT_EQ(test.addr_type, addr.GetAddressType());
      EXPECT_STREQ(hash.GetHex().c_str(), addr.GetHash().GetHex().c_str());
    }
  }
}

TEST(Address, ElementsInvalidAddressTest) {
  // invalid address prefix [base58(01 + pubkey hash)]
  EXPECT_THROW(Address("C76uVp7JJqeUKht3wQXajaaGvUJAfEDnPx", GetElementsAddressFormatList()),
      CfdException)<< "pref";
  // invalid data (decode error)
  EXPECT_THROW(Address("DbJDuZXuDVSiYB6QXb5fn", GetElementsAddressFormatList()), CfdException)<< "len";

  ByteData160 hash =
      HashUtil::Hash160(
          Pubkey(
              "02d21c625759280111907a06df050cccbc875b11a50bdafa71dae5d1e8695ba82e"));
  // invalid net type
  EXPECT_THROW(Address(ElementsNetType::kNetTypeNum, ElementsAddressType::kP2pkhAddress, hash, GetElementsAddressFormatList()), CfdException)<< "net";
}

TEST(Address, PegoutAddressTest) {
  Script pegout_script("6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f17a914a722b257cabc3b8e7d46f8fb293f893f368219da872103700dcb030588ed828d85f645b48971de0d31e8c0244da46710d18681627f5a4a4101044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d0066");
  Address addr1 = Address::GetPegoutAddress(NetType::kRegtest, pegout_script);
  EXPECT_EQ("2N8UxQ5u9YXYFn6Ukj5KGXCMDUZTixKTXHo", addr1.GetAddress());

  Address addr2 = Address::GetPegoutAddress(NetType::kMainnet, pegout_script,
      GetBitcoinAddressFormatList()[0]);
  EXPECT_EQ("3GvkLLy7w52uaJrD3whPuFMxGDFZDDWg13", addr2.GetAddress());
}

#endif  // CFD_DISABLE_ELEMENTS
