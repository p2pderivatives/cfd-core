#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"

using cfd::core::CfdException;
using cfd::core::ElementsConfidentialAddress;
using cfd::core::Address;
using cfd::core::ConfidentialKey;
using cfd::core::ElementsNetType;
using cfd::core::ElementsAddressType;
using cfd::core::Pubkey;
using cfd::core::Privkey;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::ByteData;
using cfd::core::Script;
using cfd::core::ScriptOperator;
using cfd::core::ScriptBuilder;
using cfd::core::HashUtil;
using cfd::core::AddressFormatData;
using cfd::core::GetElementsAddressFormatList;
using cfd::core::ElementsConfidentialAddress;
using cfd::core::ElementsNetType;
using cfd::core::ElementsAddressType;
using cfd::core::WitnessVersion;

TEST(ElementsConfidentialAddress, EmptyAddressTest) {
  ElementsConfidentialAddress empty_address;
  EXPECT_STREQ("",
               empty_address.GetUnblindedAddress().GetHash().GetHex().c_str());
  EXPECT_STREQ("", empty_address.GetConfidentialKey().GetHex().c_str());

  Address unblind_addr;
  ConfidentialKey key;
  EXPECT_THROW((empty_address = ElementsConfidentialAddress("")), CfdException);
  EXPECT_THROW((empty_address = ElementsConfidentialAddress(unblind_addr, key)),
               CfdException);
}

TEST(ElementsConfidentialAddress, P2pkhAddress) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  Address unblind_addr;

  unblind_addr = Address(ElementsNetType::kLiquidV1, pubkey, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VTpyoufXeg8LByRmUeHt1zyzFm1RjEP7PvWYHsjGtj9Ef1ibxgVoGkPsUPDNvkKog17K7Qn5eQ3B7g9w",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("QAcHVN55oetZU3wXXxnTrYHaqVUe35UhwJ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetLockingScript().GetHex().c_str());

  unblind_addr = Address(ElementsNetType::kElementsRegtest, pubkey, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "CTEqTvCZtF8yBn4JeRxJKDjsVWk7m9mMuzThGzwTgn9G8cLBqjmqc5YkyheitzBooX7XBVNmAS34Be8o",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2pkhAddress, address.GetAddressType());
  EXPECT_STREQ("76a914925d4028880bd0c9d68fbc7fc7dfee976698629c88ac",
               address.GetLockingScript().GetHex().c_str());

  // uncompress pubkey
  ConfidentialKey uc_key =
      ConfidentialKey(
          "04d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16e50cd61e20eb14e59a0c763d9cda790becb868ceeb00e5f74da0d15ff8381534");
  EXPECT_THROW((address = ElementsConfidentialAddress(unblind_addr, uc_key)),
               CfdException);

  // copy check
  ElementsConfidentialAddress ca(address);
  EXPECT_EQ(address.GetAddress(), ca.GetAddress());
}

TEST(ElementsConfidentialAddress, P2shAddress) {
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
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  Address unblind_addr;

  unblind_addr = Address(ElementsNetType::kLiquidV1, script, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnoKqrKf3qi2c9KJdah9d62ovTckv5uzzZC",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GzZ7frEGCDVVivMdSQA57zY1cRjYVu1g2r",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());

  unblind_addr = Address(ElementsNetType::kElementsRegtest, script, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBprXEMfscpFfYRqjkT2CjY7QAxtAv5PHkX",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wpkhAddress) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  // locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(pubkey_hash);
  const Script &script = builder.Build();
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  Address unblind_addr;

  unblind_addr = Address(ElementsNetType::kLiquidV1, script, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnYHZSM3ydLeZvFxSQ1MK8cXrXdQYVwx3i1",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GjWqFsdByr7TVs1SFiMmAaFwgSPAz5xzQm",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());

  unblind_addr = Address(ElementsNetType::kElementsRegtest, script, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBZpEpP4oQSsdKNVYZmDtn7qLEyXoK7qUrY",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XDgYhnMZYLnzwU2Z8pMEd64GLbf8W9A5vA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wshAddress) {
  const Pubkey pubkey = Pubkey(
      "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af");
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  const Script &redeem_script = builder.Build();
  // locking_script = ScriptUtil::CreateP2wshLockingScript(pubkey);
  ByteData256 script_hash = HashUtil::Sha256(redeem_script);
  builder = ScriptBuilder();
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(script_hash);
  const Script &script = builder.Build();
  ConfidentialKey key = ConfidentialKey(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16");
  ElementsConfidentialAddress address;
  Address unblind_addr;

  unblind_addr = Address(ElementsNetType::kLiquidV1, script, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnZNmgEuyWyLvABqzeNyjtqWNNx3NTXMxXp",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("Gkc3VmVBsUoojntzW5zBvoETXm1zv6Bibz",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());

  unblind_addr = Address(ElementsNetType::kElementsRegtest, script, GetElementsAddressFormatList());
  EXPECT_NO_THROW((address = ElementsConfidentialAddress(unblind_addr, key)));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBauT4GvoJ5ZyZJP6p8rKYLor6JAdFoaoYJ",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XEmkwgDZRyVMBPv7PByfPK2nBvHxWJXpBQ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2pkhAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VTpyoufXeg8LByRmUeHt1zyzFm1RjEP7PvWYHsjGtj9Ef1ibxgVoGkPsUPDNvkKog17K7Qn5eQ3B7g9w")));
  EXPECT_STREQ(
      "VTpyoufXeg8LByRmUeHt1zyzFm1RjEP7PvWYHsjGtj9Ef1ibxgVoGkPsUPDNvkKog17K7Qn5eQ3B7g9w",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("QAcHVN55oetZU3wXXxnTrYHaqVUe35UhwJ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2pkhAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "CTEqTvCZtF8yBn4JeRxJKDjsVWk7m9mMuzThGzwTgn9G8cLBqjmqc5YkyheitzBooX7XBVNmAS34Be8o")));
  EXPECT_STREQ(
      "CTEqTvCZtF8yBn4JeRxJKDjsVWk7m9mMuzThGzwTgn9G8cLBqjmqc5YkyheitzBooX7XBVNmAS34Be8o",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("925d4028880bd0c9d68fbc7fc7dfee976698629c",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("2dnmekh8NBmNX3Ckwte5CArjcsHLYdthCg3",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2pkhAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnoKqrKf3qi2c9KJdah9d62ovTckv5uzzZC")));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnoKqrKf3qi2c9KJdah9d62ovTckv5uzzZC",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GzZ7frEGCDVVivMdSQA57zY1cRjYVu1g2r",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBprXEMfscpFfYRqjkT2CjY7QAxtAv5PHkX")));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBprXEMfscpFfYRqjkT2CjY7QAxtAv5PHkX",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("be8f7ae2233fc122be82f2cf9fe3cc2c6196218a",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XUiq7kxdkiB3AXNkKW9YaWLLGb1WBo9xcA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wpkhAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnYHZSM3ydLeZvFxSQ1MK8cXrXdQYVwx3i1")));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnYHZSM3ydLeZvFxSQ1MK8cXrXdQYVwx3i1",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("GjWqFsdByr7TVs1SFiMmAaFwgSPAz5xzQm",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBZpEpP4oQSsdKNVYZmDtn7qLEyXoK7qUrY")));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBZpEpP4oQSsdKNVYZmDtn7qLEyXoK7qUrY",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("19970f64fb36fe3b7b21eca335ff70dde51eb8c8",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XDgYhnMZYLnzwU2Z8pMEd64GLbf8W9A5vA",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2shWrappedP2wshAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnZNmgEuyWyLvABqzeNyjtqWNNx3NTXMxXp")));
  EXPECT_STREQ(
      "VJLBL3rkCh19CDi889GPXkn1BYqUih5DF2p8ViS2J4Tr2cnZNmgEuyWyLvABqzeNyjtqWNNx3NTXMxXp",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("Gkc3VmVBsUoojntzW5zBvoETXm1zv6Bibz",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kLiquidV1, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBauT4GvoJ5ZyZJP6p8rKYLor6JAdFoaoYJ")));
  EXPECT_STREQ(
      "AzppkWN3gNvcnBu2Pm4Nsi8EdCmugMU2zjbpsMQZGBfMDmBauT4GvoJ5ZyZJP6p8rKYLor6JAdFoaoYJ",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02d570f84ffe5bdf7583400af2e6b9e219210ecf29a333757481cbca826ada8e16",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("258b7b985398033523194e96d9509bc04d011645",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("XEmkwgDZRyVMBPv7PByfPK2nBvHxWJXpBQ",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2shAddress, address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2wpkhAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "el1qqtrrepq74crfxf3xzx8804qq9w4pgkf2a2l9gwwtughqv4p3nk8gepg0y9q39qhjgmnyfwfz5z5c5ek0llwtc3jfqw5zvqx5q")));
  EXPECT_STREQ(
      "el1qqtrrepq74crfxf3xzx8804qq9w4pgkf2a2l9gwwtughqv4p3nk8gepg0y9q39qhjgmnyfwfz5z5c5ek0llwtc3jfqw5zvqx5q",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "02c63c841eae06932626118e77d4002baa14592aeabe5439cbe22e0654319d8e8c",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("850f21411282f246e644b922a0a98a66cfffdcbc",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("ert1qs58jzsgjsteydejyhy32p2v2vm8llh9uns6d93",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2wpkhAddress, address.GetAddressType());
  EXPECT_STREQ("0014850f21411282f246e644b922a0a98a66cfffdcbc",
               address.GetLockingScript().GetHex().c_str());
}

TEST(ElementsConfidentialAddress, P2wshAddressFromString) {
  ElementsConfidentialAddress address;

  EXPECT_NO_THROW(
      (address =
          ElementsConfidentialAddress(
              "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz")));
  EXPECT_STREQ(
      "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz",
      address.GetAddress().c_str());
  EXPECT_STREQ(
      "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
      address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6",
               address.GetHash().GetHex().c_str());
  EXPECT_STREQ("ert1qxv4rpw9jw5lxfvwsa0y4rszh7rvu9xvj6yg3s72vp7sud5340jnquagp6g",
               address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2wshAddress, address.GetAddressType());
  EXPECT_STREQ("0020332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6",
               address.GetLockingScript().GetHex().c_str());
}

TEST(ElementsConfidentialAddress, P2wpkhAddressToConfidential) {
  Address address;
  ElementsConfidentialAddress confidential_address;
  ConfidentialKey confidential_key(
      "02c63c841eae06932626118e77d4002baa14592aeabe5439cbe22e0654319d8e8c");

  EXPECT_NO_THROW(
      (address =
          Address(ElementsNetType::kElementsRegtest, WitnessVersion::kVersion0,
                  Pubkey("02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995"),
                  GetElementsAddressFormatList())));
  EXPECT_NO_THROW(
      (confidential_address =
          ElementsConfidentialAddress(address, confidential_key)));
  EXPECT_STREQ(
      "el1qqtrrepq74crfxf3xzx8804qq9w4pgkf2a2l9gwwtughqv4p3nk8gepg0y9q39qhjgmnyfwfz5z5c5ek0llwtc3jfqw5zvqx5q",
      confidential_address.GetAddress().c_str());
  EXPECT_STREQ(
      "02c63c841eae06932626118e77d4002baa14592aeabe5439cbe22e0654319d8e8c",
      confidential_address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("850f21411282f246e644b922a0a98a66cfffdcbc",
               confidential_address.GetHash().GetHex().c_str());
  EXPECT_STREQ("ert1qs58jzsgjsteydejyhy32p2v2vm8llh9uns6d93",
               confidential_address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(confidential_address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, confidential_address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2wpkhAddress, confidential_address.GetAddressType());
}

TEST(ElementsConfidentialAddress, P2wshAddressToConfidential) {
  Address address;
  ElementsConfidentialAddress confidential_address;
  ConfidentialKey confidential_key(
      "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800");

  EXPECT_NO_THROW(
      (address =
          Address(ElementsNetType::kElementsRegtest, WitnessVersion::kVersion0,
                  Script("a91429b1ec079a9c6a45a4e9ab38c3aa3e0ad3dc61f088"),
                  GetElementsAddressFormatList())));
  EXPECT_NO_THROW(
      (confidential_address =
          ElementsConfidentialAddress(address, confidential_key)));
  EXPECT_STREQ(
      "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz",
      confidential_address.GetAddress().c_str());
  EXPECT_STREQ(
      "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800",
      confidential_address.GetConfidentialKey().GetHex().c_str());
  EXPECT_STREQ("332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6",
               confidential_address.GetHash().GetHex().c_str());
  EXPECT_STREQ("ert1qxv4rpw9jw5lxfvwsa0y4rszh7rvu9xvj6yg3s72vp7sud5340jnquagp6g",
               confidential_address.GetUnblindedAddress().GetAddress().c_str());
  EXPECT_TRUE(
      ElementsConfidentialAddress::IsConfidentialAddress(confidential_address.GetAddress()));
  EXPECT_EQ(ElementsNetType::kElementsRegtest, confidential_address.GetNetType());
  EXPECT_EQ(ElementsAddressType::kP2wshAddress, confidential_address.GetAddressType());
}

TEST(ElementsConfidentialAddress, GetBlindingKey) {
  const Privkey master_blinding_key(
      "881a1ab07e99ab0626b4d93b3dddfd16cbc04342ee71aab4da7093e7b853fd80");
  Address unblind_addr("ert1q0zln07l8vgm5qf4jhzz00668lfs7xssdlxlysh",
      GetElementsAddressFormatList());

  Privkey blinding_key;
  EXPECT_NO_THROW(
      (blinding_key =
          ElementsConfidentialAddress::GetBlindingKey(
                  master_blinding_key,
                  unblind_addr.GetLockingScript())));
  EXPECT_STREQ("95af1be4f929e182442c9f3aa55a3cacde69d1182677f3afd618cdfb4a588742",
               blinding_key.GetHex().c_str());
  Pubkey confidential_key = blinding_key.GeneratePubkey();
  EXPECT_STREQ(
      "0273f33808de34256679f932410fca27721ce3b287083c903d6c10dfabb600336e",
      confidential_key.GetHex().c_str());
  ElementsConfidentialAddress confidential_address;
  EXPECT_NO_THROW(
      (confidential_address =
          ElementsConfidentialAddress(unblind_addr, confidential_key)));
  EXPECT_STREQ(
      "el1qqfelxwqgmc6z2enelyeyzr72yaepecajsuyreypadsgdl2akqqeku79lxla7wc3hgqnt9wyy7l4507npudpq6typz2y9he7wu",
      confidential_address.GetAddress().c_str());
}

#endif  // CFD_DISABLE_ELEMENTS
