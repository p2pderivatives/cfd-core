// Copyright 2020 CryptoGarage

#include "cfdcore/cfdcore_ecdsa_adaptor.h"

#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "secp256k1.h"                // NOLINT
#include "secp256k1_ecdsa_adaptor.h"  // NOLINT
#include "secp256k1_util.h"           // NOLINT
#include "wally_core.h"               // NOLINT

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;

AdaptorSignature::AdaptorSignature(const ByteData &data) : data_(data) {
  if ((data_.GetDataSize()) != AdaptorSignature::kAdaptorSignatureSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid adaptor signature data.");
  }
}

AdaptorSignature::AdaptorSignature(const std::string &data)
    : AdaptorSignature(ByteData(data)) {}

ByteData AdaptorSignature::GetData() const { return data_; }

AdaptorProof::AdaptorProof(const ByteData &data) : data_(data) {
  if ((data_.GetDataSize()) != AdaptorProof::kAdaptorProofSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid adaptor proof data.");
  }
}

ByteData AdaptorProof::GetData() const { return data_; }

AdaptorProof::AdaptorProof(const std::string &data)
    : AdaptorProof(ByteData(data)) {}

AdaptorPair AdaptorUtil::Sign(
    const ByteData256 &msg, const Privkey &sk, const Pubkey &adaptor) {
  auto ctx = wally_get_secp_context();
  std::vector<uint8_t> adaptor_sig_raw(
      AdaptorSignature::kAdaptorSignatureSize);
  std::vector<uint8_t> adaptor_proof_raw(AdaptorProof::kAdaptorProofSize);
  auto adaptor_key = ParsePubkey(adaptor);
  auto ret = secp256k1_ecdsa_adaptor_sign(
      ctx, adaptor_sig_raw.data(), adaptor_proof_raw.data(),
      sk.GetData().GetBytes().data(), &adaptor_key,
      msg.GetData().GetBytes().data());
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not create adaptor signature.");
  }
  AdaptorSignature adaptor_sig(adaptor_sig_raw);
  AdaptorProof adaptor_proof(adaptor_proof_raw);

  return AdaptorPair{adaptor_sig, adaptor_proof};
}

ByteData AdaptorUtil::Adapt(
    const AdaptorSignature &adaptor_signature, const Privkey &sk) {
  auto ctx = wally_get_secp_context();
  secp256k1_ecdsa_signature secp_signature;
  auto ret = secp256k1_ecdsa_adaptor_adapt(
      ctx, &secp_signature, sk.GetData().GetBytes().data(),
      adaptor_signature.GetData().GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not adapt signature.");
  }

  std::vector<uint8_t> signature(64);
  secp256k1_ecdsa_signature_serialize_compact(
      ctx, signature.data(), &secp_signature);

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not serialize signature.");
  }

  return ByteData(signature);
}

Privkey AdaptorUtil::ExtractSecret(
    const AdaptorSignature &adaptor_sig, const ByteData &signature,
    const Pubkey &adaptor) {
  auto ctx = wally_get_secp_context();
  std::vector<uint8_t> secret(Privkey::kPrivkeySize);
  auto secp_sig = ParseSignature(signature);
  auto secp_adaptor = ParsePubkey(adaptor);
  auto ret = secp256k1_ecdsa_adaptor_extract_secret(
      ctx, secret.data(), &secp_sig, adaptor_sig.GetData().GetBytes().data(),
      &secp_adaptor);

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not extract secret.");
  }

  return Privkey(ByteData(secret));
}

bool AdaptorUtil::Verify(
    const AdaptorSignature &adaptor_sig, const AdaptorProof &proof,
    const Pubkey &adaptor, const ByteData256 &msg, const Pubkey &pubkey) {
  auto ctx = wally_get_secp_context();
  auto secp_pubkey = ParsePubkey(pubkey);
  auto secp_adaptor = ParsePubkey(adaptor);
  return secp256k1_ecdsa_adaptor_sig_verify(
             ctx, adaptor_sig.GetData().GetBytes().data(), &secp_pubkey,
             msg.GetBytes().data(), &secp_adaptor,
             proof.GetData().GetBytes().data()) == 1;
}

}  // namespace core
}  // namespace cfd
