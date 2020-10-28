#include "cfdcore/cfdcore_ecdsa_adaptor.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"
#include "gtest/gtest.h"

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CryptoUtil;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SigHashType;

using cfd::core::AdaptorPair;
using cfd::core::AdaptorProof;
using cfd::core::AdaptorSignature;
using cfd::core::AdaptorUtil;

const ByteData256 msg(
    "024bdd11f2144e825db05759bdd9041367a420fad14b665fd08af5b42056e5e2");
const Pubkey adaptor(
    "038d48057fc4ce150482114d43201b333bf3706f3cd527e8767ceb4b443ab5d349");
const Privkey sk(
    "90ac0d5dc0a1a9ab352afb02005a5cc6c4df0da61d8149d729ff50db9b5a5215");
const Pubkey pubkey = sk.GeneratePubkey();
const std::string adaptor_sig_str =
    "00cbe0859638c3600ea1872ed7a55b8182a251969f59d7d2da6bd4afedf25f5021a49956"
    "234cbbbbede8ca72e0113319c84921bf1224897a6abd89dc96b9c5b208";
const std::string adaptor_proof_str =
    "00b02472be1ba09f5675488e841a10878b38c798ca63eff3650c8e311e3e2ebe2e3b6fee"
    "5654580a91cc5149a71bf25bcbeae63dea3ac5ad157a0ab7373c3011d0fc2592a07f719c"
    "5fc1323f935569ecd010db62f045e965cc1d564eb42cce8d6d";

const AdaptorSignature adaptor_sig2(
    "01099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f47bb90e2a"
    "d"
    "6630900b69f55674c8ad74a419e6ce113c10a21a79345a6e47bc74c1");
const ByteData sig_der(
    "30440220099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f47"
    "02204d13456e98d8989043fd4674302ce90c432e2f8bb0269f02c72aafec60b72de101");
const Privkey secret(
    "475697a71a74ff3f2a8f150534e9b67d4b0b6561fab86fcaa51f8c9d6c9db8c6");

TEST(ECDSAAdaptor, Sign) {
  auto adaptor_pair = AdaptorUtil::Sign(msg, sk, adaptor);

  EXPECT_EQ(adaptor_sig_str, adaptor_pair.signature.GetData().GetHex());
  EXPECT_EQ(adaptor_proof_str, adaptor_pair.proof.GetData().GetHex());
}

TEST(ECDSAAdaptor, Verify) {
  AdaptorSignature adaptor_sig(adaptor_sig_str);
  AdaptorProof adaptor_proof(adaptor_proof_str);
  EXPECT_TRUE(
      AdaptorUtil::Verify(adaptor_sig, adaptor_proof, adaptor, msg, pubkey));
}

TEST(ECDSAAdaptor, Adapt) {
  SigHashType sig_hash;
  auto raw_sig = CryptoUtil::ConvertSignatureFromDer(sig_der, &sig_hash);
  auto sig = AdaptorUtil::Adapt(adaptor_sig2, secret);

  EXPECT_EQ(raw_sig.GetHex(), sig.GetHex());
}

TEST(ECDSAAdaptor, ExtractSecret) {
  SigHashType sig_hash;
  auto raw_sig = CryptoUtil::ConvertSignatureFromDer(sig_der, &sig_hash);

  auto sec = AdaptorUtil::ExtractSecret(adaptor_sig2, raw_sig, adaptor);

  EXPECT_EQ(secret.GetHex(), sec.GetHex());
}