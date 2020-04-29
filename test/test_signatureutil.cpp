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

TEST(SignatureUtil, SchnorrSignVerify) {
  // Arrange
  ByteData256 data(
      "0000000000000000000000000000000000000000000000000000000000000000");
  Privkey privkey(
      "0000000000000000000000000000000000000000000000000000000000000001");
  Pubkey pubkey(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  Privkey nonce(
      "0000000000000000000000000000000000000000000000000000000000000002");
  Privkey bipSchnorrNonce(
      "58e8f2a1f78f0a591feb75aebecaaa81076e4290894b1c445cc32953604db089");

  // Act
  auto sig1 = SignatureUtil::CalculateSchnorrSignatureWithNonce(
      privkey, nonce, data);
  auto sig2 = SignatureUtil::CalculateSchnorrSignatureWithNonce(
      privkey, nonce, data);
  auto sig3 = SignatureUtil::CalculateSchnorrSignatureWithNonce(
      privkey, bipSchnorrNonce, data);

  bool is_valid = SignatureUtil::VerifySchnorrSignatureWithNonce(
      pubkey, bipSchnorrNonce.GeneratePubkey(), sig3, data);

  // Assert
  EXPECT_EQ(sig1.GetHex(), sig2.GetHex());
  EXPECT_NE(sig1.GetHex(), sig3.GetHex());
  EXPECT_EQ("7031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05",
            sig3.GetHex());
  EXPECT_TRUE(is_valid);
}
