#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::SignatureUtil;
using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Pubkey;
using cfd::core::Script;
using cfd::core::Privkey;

TEST(SignatureUtil, CreateWitnessProgramWPKH) {
  Pubkey pubkey(
      "026e3ab12d8a898ac99e71bbca0843cf749009025381a2a109cf0d1c2bfd5f86b3");
  ByteData witness;
  EXPECT_NO_THROW(witness = SignatureUtil::CreateWitnessProgramWPKH(pubkey));
  EXPECT_STREQ(witness.GetHex().c_str(),
               "76a914ea4efcff6e8e16c21ba7fe9b4fd936bf286d095588ac");

  ByteData err_witness;
  EXPECT_THROW(err_witness = SignatureUtil::CreateWitnessProgramWPKH(Pubkey()),
               CfdException);
  EXPECT_STREQ(err_witness.GetHex().c_str(), "");
}

TEST(SignatureUtil, CreateWitnessProgramWSH) {
  Script script("00143a9caef76595ff9a610f40c568b5623531520c39");
  ByteData witness;
  EXPECT_NO_THROW(witness = SignatureUtil::CreateWitnessProgramWSH(script));
  EXPECT_STREQ(witness.GetHex().c_str(),
               "00143a9caef76595ff9a610f40c568b5623531520c39");

  ByteData err_witness;
  EXPECT_NO_THROW(
      err_witness = SignatureUtil::CreateWitnessProgramWSH(Script()));
  EXPECT_STREQ(err_witness.GetHex().c_str(), "");
}

TEST(SignatureUtil, CalculateEcSignature) {
  ByteData256 sighash(
      "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e");
  Privkey privkey(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");

  // has_grind_r true
  ByteData sig;
  EXPECT_NO_THROW(
      sig = SignatureUtil::CalculateEcSignature(sighash, privkey, true));
  EXPECT_STREQ(
      sig.GetHex().c_str(),
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");

  // has_grind_r false
  EXPECT_NO_THROW(
      sig = SignatureUtil::CalculateEcSignature(sighash, privkey, false));
  EXPECT_STREQ(
      sig.GetHex().c_str(),
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");

  ByteData err_sig;
  EXPECT_THROW(
      (err_sig = SignatureUtil::CalculateEcSignature(sighash, Privkey(), true)),
      CfdException);
  EXPECT_STREQ(err_sig.GetHex().c_str(), "");
}

TEST(SignatureUtil, VerifyEcSignature) {
  ByteData256 sighash(
      "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e");
  Pubkey pubkey(
      "031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb");
  ByteData signature(
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb"
      "12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");
  ByteData bad_signature1(
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb"
      "12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f");
  ByteData bad_signature2(
      "0e68b55347fe37338ceb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb"
      "12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");

  EXPECT_TRUE(SignatureUtil::VerifyEcSignature(sighash, pubkey, signature));

  EXPECT_FALSE(
      SignatureUtil::VerifyEcSignature(sighash, pubkey, bad_signature1));

  EXPECT_FALSE(
      SignatureUtil::VerifyEcSignature(sighash, pubkey, bad_signature2));
}
#endif  // CFD_DISABLE_ELEMENTS
