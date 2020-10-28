// Copyright 2020 CryptoGarage

#include "secp256k1_util.h"  // NOLINT

#include <string.h>

#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "secp256k1.h"            // NOLINT
#include "secp256k1_extrakeys.h"  // NOLINT
#include "wally_core.h"           // NOLINT

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;

secp256k1_pubkey ParsePubkey(const Pubkey& pubkey) {
  auto pubkey_bytes = pubkey.GetData().GetBytes();
  auto ctx = wally_get_secp_context();
  secp256k1_pubkey result;
  int ret = secp256k1_ec_pubkey_parse(
      ctx, &result, pubkey_bytes.data(), pubkey_bytes.size());
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Secp256k1 pubkey parse error");
  }

  return result;
}

secp256k1_xonly_pubkey ParseXOnlyPubkey(const SchnorrPubkey& pubkey) {
  auto ctx = wally_get_secp_context();
  secp256k1_xonly_pubkey xonly_pubkey;

  auto ret = secp256k1_xonly_pubkey_parse(
      ctx, &xonly_pubkey, pubkey.GetData().GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not parse xonly pubkey");
  }

  return xonly_pubkey;
}

secp256k1_ecdsa_signature ParseSignature(const ByteData& signature) {
  auto ctx = wally_get_secp_context();
  secp256k1_ecdsa_signature result;
  auto ret = secp256k1_ecdsa_signature_parse_compact(
      ctx, &result, signature.GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Could not parse ECDSA signature.");
  }

  return result;
}

secp256k1_xonly_pubkey GetXOnlyPubkeyFromPubkey(
    const secp256k1_pubkey& pubkey, bool* parity) {
  auto ctx = wally_get_secp_context();
  secp256k1_xonly_pubkey xonly_pubkey;
  int pk_parity = 0;

  auto ret = secp256k1_xonly_pubkey_from_pubkey(
      ctx, &xonly_pubkey, &pk_parity, &pubkey);
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not get xonly pubkey from pubkey");
  }
  if (parity != nullptr) *parity = (pk_parity != 0);

  return xonly_pubkey;
}

ByteData256 TweakAddXonlyPubkey(
    const SchnorrPubkey& pubkey, const ByteData256& tweak, bool* parity) {
  auto ctx = wally_get_secp_context();
  auto base_xonly_key = ParseXOnlyPubkey(pubkey);
  std::vector<uint8_t> tweak_bytes = tweak.GetBytes();
  secp256k1_pubkey tweak_pubkey;
  memset(&tweak_pubkey, 0, sizeof(tweak_pubkey));

  int ret = secp256k1_xonly_pubkey_tweak_add(
      ctx, &tweak_pubkey, &base_xonly_key, tweak_bytes.data());
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not tweak add xonly pubkey");
  }

  auto tweak_key = GetXOnlyPubkeyFromPubkey(tweak_pubkey, parity);
  return ConvertSchnorrPubkey(tweak_key);
}

bool CheckTweakAddXonlyPubkey(
    const SchnorrPubkey& tweaked_pubkey, const SchnorrPubkey& base_pubkey,
    const ByteData256& tweak, bool parity) {
  auto ctx = wally_get_secp_context();
  std::vector<uint8_t> tweak_xonly_key = tweaked_pubkey.GetData().GetBytes();
  auto base_xonly_key = ParseXOnlyPubkey(base_pubkey);
  std::vector<uint8_t> tweak_bytes = tweak.GetBytes();
  int tweaked_pk_parity = (parity) ? 1 : 0;

  int ret = secp256k1_xonly_pubkey_tweak_add_check(
      ctx, tweak_xonly_key.data(), tweaked_pk_parity, &base_xonly_key,
      tweak_bytes.data());

  return (ret == 1);
}

Pubkey ConvertSecpPubkey(const secp256k1_pubkey& pubkey) {
  auto ctx = wally_get_secp_context();
  std::vector<uint8_t> result_bytes(Pubkey::kCompressedPubkeySize);
  size_t result_bytes_size = result_bytes.size();
  int ret = secp256k1_ec_pubkey_serialize(
      ctx, result_bytes.data(), &result_bytes_size, &pubkey,
      SECP256K1_EC_COMPRESSED);
  if (ret != 1 || (result_bytes_size != Pubkey::kCompressedPubkeySize)) {
    throw CfdException(
        CfdError::kCfdInternalError, "Secp256k1 serialize exception");
  }

  return Pubkey(result_bytes);
}

ByteData256 ConvertSchnorrPubkey(const secp256k1_xonly_pubkey& pubkey) {
  auto ctx = wally_get_secp_context();
  std::vector<uint8_t> result_bytes(SchnorrPubkey::kSchnorrPubkeySize);
  int ret =
      secp256k1_xonly_pubkey_serialize(ctx, result_bytes.data(), &pubkey);
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Secp256k1 serialize exception");
  }

  return ByteData256(result_bytes);
}

}  // namespace core
}  // namespace cfd
