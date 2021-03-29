// Copyright 2020 CryptoGarage

#include "cfdcore/cfdcore_schnorrsig.h"

#include <cstring>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_util.h"
#include "secp256k1.h"             // NOLINT
#include "secp256k1_schnorrsig.h"  // NOLINT
#include "secp256k1_util.h"        // NOLINT
#include "wally_core.h"            // NOLINT

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::HashUtil;

// ----------------------------------------------------------------------------
// SchnorrSignature
// ----------------------------------------------------------------------------
SchnorrSignature::SchnorrSignature()
    : data_(), sighash_type_(SigHashAlgorithm::kSigHashDefault) {}

SchnorrSignature::SchnorrSignature(const ByteData &data)
    : data_(data), sighash_type_(SigHashAlgorithm::kSigHashDefault) {
  if (data_.GetDataSize() == SchnorrSignature::kSchnorrSignatureSize + 1) {
    auto bytes = data.GetBytes();
    uint8_t sighash_type = bytes[SchnorrSignature::kSchnorrSignatureSize];
    if ((sighash_type == 0) || (!IsValidSigHashType(sighash_type))) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Invalid Schnorr signature hash type.");
    }
    sighash_type_.SetFromSigHashFlag(sighash_type);
    data_ = ByteData(bytes.data(), SchnorrSignature::kSchnorrSignatureSize);
  } else if (data_.GetDataSize() != SchnorrSignature::kSchnorrSignatureSize) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Schnorr signature data.");
  }
}

SchnorrSignature::SchnorrSignature(const std::string &data)
    : SchnorrSignature(ByteData(data)) {}

SchnorrSignature::SchnorrSignature(const SchnorrSignature &object) {
  data_ = object.data_;
  sighash_type_ = object.sighash_type_;
}

SchnorrSignature &SchnorrSignature::operator=(const SchnorrSignature &object) {
  if (this != &object) {
    data_ = object.data_;
    sighash_type_ = object.sighash_type_;
  }
  return *this;
}

ByteData SchnorrSignature::GetData(bool append_sighash_type) const {
  if ((!append_sighash_type) || (sighash_type_.GetSigHashFlag() == 0) ||
      (data_.GetDataSize() != SchnorrSignature::kSchnorrSignatureSize)) {
    return data_;
  }

  uint8_t sighash_type = static_cast<uint8_t>(sighash_type_.GetSigHashFlag());
  return data_.Concat(ByteData(sighash_type));
}

std::string SchnorrSignature::GetHex(bool append_sighash_type) const {
  if (sighash_type_.GetSigHashFlag() == 0) return data_.GetHex();
  return GetData(append_sighash_type).GetHex();
}

SigHashType SchnorrSignature::GetSigHashType() const { return sighash_type_; }

SchnorrPubkey SchnorrSignature::GetNonce() const {
  auto bytes = data_.GetBytes();
  return SchnorrPubkey(ByteData(std::vector<uint8_t>(
      bytes.begin(), bytes.begin() + SchnorrPubkey::kSchnorrPubkeySize)));
}

Privkey SchnorrSignature::GetPrivkey() const {
  auto bytes = data_.GetBytes();
  auto start = bytes.begin() + SchnorrPubkey::kSchnorrPubkeySize;
  auto end = start + Privkey::kPrivkeySize;
  return Privkey(ByteData(std::vector<uint8_t>(start, end)));
}

void SchnorrSignature::SetSigHashType(const SigHashType &sighash_type) {
  if (!IsValidSigHashType(
          static_cast<uint8_t>(sighash_type.GetSigHashFlag()))) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid sighash type for schnorr signature.");
  }
  sighash_type_ = sighash_type;
}

bool SchnorrSignature::IsValidSigHashType(uint8_t sighash_type_value) {
  bool is_anyone_can_pay = (sighash_type_value & 0x80) ? true : false;
  if ((is_anyone_can_pay &&
       ((sighash_type_value <= 0x80) || (sighash_type_value > 0x83))) ||
      ((!is_anyone_can_pay) && (sighash_type_value > 0x03))) {
    return false;
  }
  return true;
}

// ----------------------------------------------------------------------------
// SchnorrPubkey
// ----------------------------------------------------------------------------
SchnorrPubkey::SchnorrPubkey() : data_() {}

SchnorrPubkey::SchnorrPubkey(const ByteData &data) : data_() {
  if (Pubkey::IsValid(data)) {
    auto pk = SchnorrPubkey::FromPubkey(Pubkey(data));
    data_ = pk.data_;
  } else {
    if (data.GetDataSize() != SchnorrPubkey::kSchnorrPubkeySize) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Invalid Schnorr pubkey length.");
    }
    data_ = ByteData256(data);
    if (data_.IsEmpty()) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Invalid Schnorr pubkey data.");
    }
  }
}

SchnorrPubkey::SchnorrPubkey(const ByteData256 &data) : data_(data) {
  if (data.IsEmpty()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Schnorr pubkey data.");
  }
}

SchnorrPubkey::SchnorrPubkey(const std::string &data)
    : SchnorrPubkey(ByteData(data)) {}

SchnorrPubkey SchnorrPubkey::FromPrivkey(
    const Privkey &privkey, bool *parity) {
  auto ctx = wally_get_secp_context();
  secp256k1_keypair keypair;
  auto ret = secp256k1_keypair_create(
      ctx, &keypair, privkey.GetData().GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid private key");
  }

  secp256k1_xonly_pubkey x_only_pubkey;
  int pk_parity = 0;
  ret = secp256k1_keypair_xonly_pub(ctx, &x_only_pubkey, &pk_parity, &keypair);

  if (ret != 1) {
    throw CfdException(CfdError::kCfdInternalError);
  }

  if (parity != nullptr) *parity = (pk_parity != 0);
  return SchnorrPubkey(ConvertSchnorrPubkey(x_only_pubkey));
}

SchnorrPubkey SchnorrPubkey::FromPubkey(const Pubkey &pubkey, bool *parity) {
  auto xpk = GetXOnlyPubkeyFromPubkey(ParsePubkey(pubkey), parity);
  return SchnorrPubkey(ConvertSchnorrPubkey(xpk));
}

SchnorrPubkey SchnorrPubkey::CreateTweakAddFromPrivkey(
    const Privkey &privkey, const ByteData256 &tweak, Privkey *tweaked_privkey,
    bool *parity) {
  std::vector<uint8_t> tweak_bytes = tweak.GetBytes();
  auto ctx = wally_get_secp_context();

  secp256k1_keypair keypair;
  auto ret = secp256k1_keypair_create(
      ctx, &keypair, privkey.GetData().GetBytes().data());
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid private key");
  }

  ret = secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak_bytes.data());
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not tweak add key pair");
  }

  secp256k1_xonly_pubkey x_only_pubkey;
  int pk_parity = 0;
  ret = secp256k1_keypair_xonly_pub(ctx, &x_only_pubkey, &pk_parity, &keypair);
  if (ret != 1) {
    throw CfdException(CfdError::kCfdInternalError);
  }

  if (tweaked_privkey != nullptr) {
    *tweaked_privkey = Privkey(ByteData(keypair.data, Privkey::kPrivkeySize));
  }
  if (parity != nullptr) *parity = (pk_parity != 0);
  return SchnorrPubkey(ConvertSchnorrPubkey(x_only_pubkey));
}

ByteData SchnorrPubkey::GetData() const { return data_.GetData(); }

ByteData256 SchnorrPubkey::GetByteData256() const {
  return ByteData256(data_);
}

std::string SchnorrPubkey::GetHex() const { return data_.GetHex(); }

bool SchnorrPubkey::Equals(const SchnorrPubkey &pubkey) const {
  return data_.Equals(pubkey.data_);
}

bool SchnorrPubkey::IsValid() const { return !data_.IsEmpty(); }

SchnorrPubkey SchnorrPubkey::CreateTweakAdd(
    const ByteData256 &tweak, bool *parity) const {
  return SchnorrPubkey(TweakAddXonlyPubkey(*this, tweak, parity));
}

SchnorrPubkey SchnorrPubkey::CreateTweakAdd(
    const SchnorrPubkey &tweak, bool *parity) const {
  return CreateTweakAdd(tweak.data_, parity);
}

bool SchnorrPubkey::IsTweaked(
    const SchnorrPubkey &base_pubkey, const ByteData256 &tweak,
    bool parity) const {
  return CheckTweakAddXonlyPubkey(*this, base_pubkey, tweak, parity);
}

bool SchnorrPubkey::Verify(
    const SchnorrSignature &signature, const ByteData256 &msg) const {
  return SchnorrUtil::Verify(signature, msg, *this);
}

Pubkey SchnorrPubkey::CreatePubkey(bool parity) const {
  uint8_t head = (parity) ? 3 : 2;
  ByteData data = ByteData(head).Concat(data_);
  return Pubkey(data);
}

SchnorrPubkey SchnorrPubkey::operator+=(const ByteData256 &right) {
  SchnorrPubkey key = CreateTweakAdd(right);
  *this = key;
  return *this;
}

SchnorrPubkey SchnorrPubkey::operator-=(const ByteData256 &right) {
  Privkey sk(right);
  auto neg = sk.CreateNegate();
  SchnorrPubkey key = CreateTweakAdd(ByteData256(neg.GetData()));
  *this = key;
  return *this;
}

SchnorrPubkey operator+(const SchnorrPubkey &left, const ByteData256 &right) {
  return left.CreateTweakAdd(right);
}

SchnorrPubkey operator-(const SchnorrPubkey &left, const ByteData256 &right) {
  SchnorrPubkey key = left;
  key -= right;
  return key;
}

// ----------------------------------------------------------------------------
// SchnorrUtil
// ----------------------------------------------------------------------------
/**
 * @brief A function that simply copies the data into the nonce.
 *
 * @param nonce32 the nonce
 * @param msg32 unused
 * @param key32 unused
 * @param algo16 unused
 * @param xonly_pk32 unused
 * @param data the data (actually the nonce to use)
 * @return int always returns 1
 */
int ConstantNonceFunction(
    unsigned char *nonce32, const unsigned char *msg32,
    const unsigned char *key32, const unsigned char *algo16,
    const unsigned char *xonly_pk32, void *data) {
  (void)msg32;
  (void)key32;
  (void)algo16;
  (void)xonly_pk32;
  std::memcpy(nonce32, (const unsigned char *)data, 32);
  return 1;
}

/**
 * @brief Constant nonce function instance to be passed to secp256k1.
 * 
 */
const secp256k1_nonce_function_hardened ConstantNonce = ConstantNonceFunction;

/**
 * @brief Private function to both create a schnorr signature using the default
 * bip340 nonce function (and passing aux_rand as ndata) or using the constant
 * nonce function (and passing the nonce as ndata)
 *
 * @param msg the message to sign
 * @param sk the private key to use
 * @param nonce_fn the nonce function to use (if null uses bip 340 nonce function)
 * @param ndata the ndata to pass
 * @return SchnorrSignature the generated signature
 */
SchnorrSignature SignCommon(
    const ByteData256 &msg, const Privkey &sk,
    const secp256k1_nonce_function_hardened *nonce_fn, const ByteData ndata) {
  auto ctx = wally_get_secp_context();
  secp256k1_keypair keypair;
  auto ret =
      secp256k1_keypair_create(ctx, &keypair, sk.GetData().GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not create keypair.");
  }

  secp256k1_nonce_function_hardened nfn =
      nonce_fn == nullptr ? nullptr : *nonce_fn;

  std::vector<uint8_t> raw_sig(SchnorrSignature::kSchnorrSignatureSize);

  ret = secp256k1_schnorrsig_sign(
      ctx, raw_sig.data(), msg.GetBytes().data(), &keypair, nfn,
      (ndata.IsEmpty()) ? nullptr : ndata.GetBytes().data());

  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not create Schnorr signature.");
  }

  return SchnorrSignature(raw_sig);
}

SchnorrSignature SchnorrUtil::Sign(const ByteData256 &msg, const Privkey &sk) {
  return SignCommon(msg, sk, nullptr, ByteData());
}

SchnorrSignature SchnorrUtil::Sign(
    const ByteData256 &msg, const Privkey &sk, const ByteData256 &aux_rand) {
  return SignCommon(msg, sk, nullptr, aux_rand.GetData());
}

SchnorrSignature SchnorrUtil::SignWithNonce(
    const ByteData256 &msg, const Privkey &sk, const Privkey &nonce) {
  return SignCommon(msg, sk, &ConstantNonce, nonce.GetData());
}

Pubkey SchnorrUtil::ComputeSigPoint(
    const ByteData256 &msg, const SchnorrPubkey &nonce,
    const SchnorrPubkey &pubkey) {
  auto ctx = wally_get_secp_context();
  secp256k1_xonly_pubkey xonly_pubkey = ParseXOnlyPubkey(pubkey);

  secp256k1_xonly_pubkey secp_nonce = ParseXOnlyPubkey(nonce);

  secp256k1_pubkey secp_sigpoint;

  auto ret = secp256k1_schnorrsig_compute_sigpoint(
      ctx, &secp_sigpoint, msg.GetBytes().data(), &secp_nonce, &xonly_pubkey);
  if (ret != 1) {
    throw CfdException(
        CfdError::kCfdInternalError, "Could not compute sigpoint");
  }

  return ConvertSecpPubkey(secp_sigpoint);
}

Pubkey SchnorrUtil::ComputeSigPointBatch(
    const std::vector<ByteData256> &msgs,
    const std::vector<SchnorrPubkey> &nonces, const SchnorrPubkey &pubkey) {
  if (msgs.size() != nonces.size() || msgs.empty()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Expected same number of messages or nonces, and at least one "
        "message.");
  }

  Pubkey rs;

  if (msgs.size() == 1) {
    rs = Pubkey(ByteData("02").Concat(nonces[0].GetData()));
  } else {
    std::vector<Pubkey> pub_nonces;
    for (const auto &nonce : nonces) {
      pub_nonces.push_back(Pubkey(ByteData("02").Concat(nonce.GetData())));
    }
    rs = Pubkey::CombinePubkey(pub_nonces);
  }

  auto bip340_challenge = ByteData(
      "7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c7bb52d7"
      "a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c");
  Privkey res;
  for (size_t i = 0; i < msgs.size(); i++) {
    auto m_tagged_hash =
        HashUtil::Sha256(bip340_challenge.Concat(nonces[i].GetData())
                             .Concat(pubkey.GetData())
                             .Concat(msgs[i]));
    if (i == 0) {
      res = Privkey(m_tagged_hash);
    } else {
      res = res.CreateTweakAdd(m_tagged_hash);
    }
  }

  auto xe = Pubkey(ByteData("02").Concat(pubkey.GetData()))
                .CreateTweakMul(ByteData256(res.GetData()));

  return Pubkey::CombinePubkey({rs, xe});
}

bool SchnorrUtil::Verify(
    const SchnorrSignature &signature, const ByteData256 &msg,
    const SchnorrPubkey &pubkey) {
  auto ctx = wally_get_secp_context();
  secp256k1_xonly_pubkey xonly_pubkey = ParseXOnlyPubkey(pubkey);
  return 1 == secp256k1_schnorrsig_verify(
                  ctx, signature.GetData().GetBytes().data(),
                  msg.GetBytes().data(), &xonly_pubkey);
}

}  // namespace core
}  // namespace cfd
