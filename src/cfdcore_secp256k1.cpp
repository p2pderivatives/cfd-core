// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_secp256k1.cpp
 *
 * @brief \~english definition for secp256k1 related classes
 *   \~japanese secp256k1関連クラス定義
 */

#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore_secp256k1.h"          // NOLINT
#include "secp256k1.h"                  // NOLINT
#include "secp256k1_generator.h"        // NOLINT
#include "secp256k1_rangeproof.h"       // NOLINT
#include "secp256k1_surjectionproof.h"  // NOLINT
#include "secp256k1_whitelist.h"        // NOLINT

namespace cfd {
namespace core {

using logger::warn;

//////////////////////////////////
/// inner definitions
//////////////////////////////////
static constexpr uint8_t kTweakByteSize = 32;    //!< ByteSize of tweak data
static constexpr uint8_t kPrivkeyByteSize = 32;  //!< ByteSize of privkey
static constexpr uint8_t kCompressedPubkeyByteSize =
    33;  //!< ByteSize of compressed pubkey
static constexpr uint8_t kFullPubkeyByteSize =
    65;  //!< ByteSize of full pubkey
//! Maximum of surjectionproof input
static constexpr uint32_t kSurjectionproofMaxInputs =
    SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS;

//////////////////////////////////
/// Secp256k1
//////////////////////////////////
Secp256k1::Secp256k1(void* context) : secp256k1_context_(context) {
  // do nothing
}

uint32_t Secp256k1::GetSurjectionproofInputLimit() {
  return kSurjectionproofMaxInputs;
}

ByteData Secp256k1::CombinePubkeySecp256k1Ec(
    const std::vector<ByteData>& pubkey_list) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }

  if (pubkey_list.size() < 2) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey list.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey List data.");
  }

  std::vector<secp256k1_pubkey> key_array(pubkey_list.size());
  std::vector<secp256k1_pubkey*> ptr_array(pubkey_list.size());
  int ret;

  for (size_t i = 0; i < pubkey_list.size(); ++i) {
    // Change ByteData to secp256k1_pubkey format
    ret = secp256k1_ec_pubkey_parse(
        context, &key_array[i], pubkey_list[i].GetBytes().data(),
        pubkey_list[i].GetBytes().size());

    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "Secp256k1 pubkey parse Error.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
    }
    ptr_array[i] = &key_array[i];
  }

  // Join Pubkey
  secp256k1_pubkey combine_key;
  ret = secp256k1_ec_pubkey_combine(
      context, &combine_key, ptr_array.data(), key_array.size());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "Secp256k1 pubkey combine Error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey combine Error.");
  }

  std::vector<uint8_t> byte_data(65);
  size_t byte_size = byte_data.size();
  // Format ByteData
  ret = secp256k1_ec_pubkey_serialize(
      context, byte_data.data(), &byte_size, &combine_key,
      SECP256K1_EC_COMPRESSED);

  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "Secp256k1 pubkey serialize Error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 pubkey serialize Error.");
  }

  byte_data.resize(byte_size);
  return ByteData(byte_data);
}

ByteData Secp256k1::CompressPubkeySecp256k1Ec(
    const ByteData& uncompressed_pubkey) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }

  if (uncompressed_pubkey.GetDataSize() != 65) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey size.");
  }

  secp256k1_pubkey pubkey;
  int ret = secp256k1_ec_pubkey_parse(
      context, &pubkey, uncompressed_pubkey.GetBytes().data(),
      uncompressed_pubkey.GetDataSize());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "Secp256k1 pubkey parse Error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
  }

  std::vector<uint8_t> byte_data(33);
  size_t byte_size = byte_data.size();
  // Format ByteData
  ret = secp256k1_ec_pubkey_serialize(
      context, byte_data.data(), &byte_size, &pubkey, SECP256K1_EC_COMPRESSED);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "Secp256k1 pubkey serialize Error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 pubkey serialize Error.");
  }

  byte_data.resize(byte_size);
  return ByteData(byte_data);
}

ByteData Secp256k1::AddTweakPrivkeySecp256k1Ec(
    const ByteData& privkey, const ByteData& tweak) {
  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (privkey.GetDataSize() != kPrivkeyByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument privkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid privkey size.");
  }
  if (tweak.GetDataSize() != kTweakByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument tweak size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid tweak size.");
  }

  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  std::vector<uint8_t> privkey_work = privkey.GetBytes();
  std::vector<uint8_t> tweak_byte = tweak.GetBytes();
  int ret = secp256k1_ec_privkey_tweak_add(
      context, privkey_work.data(), tweak_byte.data());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_privkey_tweak_add Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 privkey tweak add Error.");
  }

  return ByteData(privkey_work);
}

ByteData Secp256k1::MulTweakPrivkeySecp256k1Ec(
    const ByteData& privkey, const ByteData& tweak) {
  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (privkey.GetDataSize() != kPrivkeyByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument privkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid privkey size.");
  }
  if (tweak.GetDataSize() != kTweakByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument tweak size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid tweak size.");
  }

  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  std::vector<uint8_t> privkey_work = privkey.GetBytes();
  const std::vector<uint8_t>& tweak_byte = tweak.GetBytes();
  int ret = secp256k1_ec_privkey_tweak_mul(
      context, privkey_work.data(), tweak_byte.data());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_privkey_tweak_mul Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 privkey tweak mul Error.");
  }

  return ByteData(privkey_work);
}

ByteData Secp256k1::AddTweakPubkeySecp256k1Ec(
    const ByteData& pubkey, const ByteData& tweak, bool is_tweak_check) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (pubkey.GetDataSize() != kCompressedPubkeyByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey size.");
  }
  if (tweak.GetDataSize() != kTweakByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument tweak size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid tweak size.");
  }

  int ret;
  std::vector<uint8_t> pubkey_data = pubkey.GetBytes();
  std::vector<uint8_t> tweak_data = tweak.GetBytes();
  secp256k1_pubkey tweaked;
  secp256k1_pubkey watchman;
  ret = secp256k1_ec_pubkey_parse(
      context, &tweaked, pubkey_data.data(), pubkey_data.size());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
  }
  memcpy(&watchman, &tweaked, sizeof(watchman));

  ret = secp256k1_ec_pubkey_tweak_add(context, &tweaked, tweak_data.data());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_tweak_add Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey tweak Error.");
  }

  std::vector<uint8_t> byte_data(kFullPubkeyByteSize);
  size_t byte_size = byte_data.size();
  ret = secp256k1_ec_pubkey_serialize(
      context, byte_data.data(), &byte_size, &tweaked,
      SECP256K1_EC_COMPRESSED);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_serialize Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 pubkey serialize Error.");
  }

  if (byte_size != kCompressedPubkeyByteSize) {
    warn(
        CFD_LOG_SOURCE,
        "secp256k1_ec_pubkey_serialize pubkey length Error.({})", byte_size);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey length Error.");
  }
  byte_data.resize(byte_size);

  if (is_tweak_check) {
    // check: `tweaked - watchman = tweak`
    secp256k1_pubkey tweaked2;
    ret = secp256k1_ec_pubkey_create(context, &tweaked2, tweak_data.data());
    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse Error.({})", ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
    }
    ret = secp256k1_ec_pubkey_negate(context, &watchman);
    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_negate Error.({})", ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Secp256k1 pubkey negate Error.");
    }

    secp256k1_pubkey* pubkey_combined[2];
    pubkey_combined[0] = &watchman;
    pubkey_combined[1] = &tweaked;
    secp256k1_pubkey maybe_tweaked2;
    ret = secp256k1_ec_pubkey_combine(
        context, &maybe_tweaked2, pubkey_combined, 2);
    if (ret != 1) {
      warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_combine Error.({})", ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Secp256k1 pubkey combine Error.");
    }
    if (memcmp(&maybe_tweaked2, &tweaked2, 64) != 0) {
      warn(CFD_LOG_SOURCE, "tweak check Error.");
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Secp256k1 tweak check Error.");
    }
  }
  return ByteData(byte_data);
}

ByteData Secp256k1::MulTweakPubkeySecp256k1Ec(
    const ByteData& pubkey, const ByteData& tweak) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (pubkey.GetDataSize() != kCompressedPubkeyByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey size.");
  }
  if (tweak.GetDataSize() != kTweakByteSize) {
    warn(CFD_LOG_SOURCE, "Invalid Argument tweak size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid tweak size.");
  }

  int ret;
  std::vector<uint8_t> pubkey_data = pubkey.GetBytes();
  std::vector<uint8_t> tweak_data = tweak.GetBytes();
  secp256k1_pubkey tweaked;
  secp256k1_pubkey watchman;
  ret = secp256k1_ec_pubkey_parse(
      context, &tweaked, pubkey_data.data(), pubkey_data.size());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
  }
  memcpy(&watchman, &tweaked, sizeof(watchman));

  ret = secp256k1_ec_pubkey_tweak_mul(context, &tweaked, tweak_data.data());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_tweak_add Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey tweak Error.");
  }

  std::vector<uint8_t> byte_data(kFullPubkeyByteSize);
  size_t byte_size = byte_data.size();
  ret = secp256k1_ec_pubkey_serialize(
      context, byte_data.data(), &byte_size, &tweaked,
      SECP256K1_EC_COMPRESSED);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_serialize Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 pubkey serialize Error.");
  }

  if (byte_size != kCompressedPubkeyByteSize) {
    warn(
        CFD_LOG_SOURCE,
        "secp256k1_ec_pubkey_serialize pubkey length Error.({})", byte_size);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey length Error.");
  }
  byte_data.resize(byte_size);
  return ByteData(byte_data);
}

ByteData Secp256k1::NegatePrivkeySecp256k1Ec(const ByteData& privkey) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (privkey.GetDataSize() != 32) {
    warn(CFD_LOG_SOURCE, "Invalid Argument privkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid privkey size.");
  }

  int ret;
  std::vector<uint8_t> privkey_work = privkey.GetBytes();
  ret = secp256k1_ec_privkey_negate(context, privkey_work.data());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_negate Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey negate Error.");
  }
  return ByteData(privkey_work);
}

ByteData Secp256k1::NegatePubkeySecp256k1Ec(const ByteData& pubkey) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (pubkey.GetDataSize() != 33) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey size.");
  }

  int ret;
  const std::vector<uint8_t>& pubkey_data = pubkey.GetBytes();
  secp256k1_pubkey pubkey_secp;

  ret = secp256k1_ec_pubkey_parse(
      context, &pubkey_secp, pubkey_data.data(), pubkey_data.size());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey parse Error.");
  }

  ret = secp256k1_ec_pubkey_negate(context, &pubkey_secp);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_negate Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 pubkey negate Error.");
  }

  std::vector<uint8_t> byte_data(65);
  size_t byte_size = byte_data.size();
  ret = secp256k1_ec_pubkey_serialize(
      context, byte_data.data(), &byte_size, &pubkey_secp,
      SECP256K1_EC_COMPRESSED);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_ec_pubkey_serialize Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 pubkey serialize Error.");
  }
  byte_data.resize(byte_size);
  return ByteData(byte_data);
}

void Secp256k1::RangeProofInfoSecp256k1(
    const ByteData& range_proof, int* exponent, int* mantissa,
    uint64_t* min_value, uint64_t* max_value) {
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);
  if (secp256k1_context_ == nullptr) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (!range_proof.GetDataSize()) {
    warn(CFD_LOG_SOURCE, "Secp256k1 range proof is empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 empty range proof Error.");
  }

  std::vector<uint8_t> range_proof_bytes = range_proof.GetBytes();
  int ret = secp256k1_rangeproof_info(
      context, exponent, mantissa, min_value, max_value,
      range_proof_bytes.data(), range_proof_bytes.size());
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_rangeproof_info Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 decode range proof info Error.");
  }
}

ByteData Secp256k1::SignWhitelistSecp256k1Ec(
    const ByteData& offline_pubkey, const ByteData256& online_privkey,
    const ByteData256& tweak_sum, const std::vector<ByteData>& online_keys,
    const std::vector<ByteData>& offline_keys, uint32_t whitelist_index) {
  static constexpr uint32_t kWhitelistCountMaximum = 256;
  static constexpr uint32_t kPrivkeySize = 32;
  static constexpr uint32_t kOutputMaxSize =
      1 + (kPrivkeySize * (1 + kWhitelistCountMaximum));
  secp256k1_context* context =
      static_cast<secp256k1_context*>(secp256k1_context_);

  if (secp256k1_context_ == NULL) {
    warn(CFD_LOG_SOURCE, "Secp256k1 context is NULL.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 context is NULL.");
  }
  if (offline_pubkey.GetDataSize() != 33) {
    warn(CFD_LOG_SOURCE, "Invalid Argument pubkey size.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey size.");
  }
  if (online_keys.empty()) {
    warn(CFD_LOG_SOURCE, "Invalid Argument online_keys empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Empty online_keys.");
  }
  if (online_keys.size() > kWhitelistCountMaximum) {
    warn(CFD_LOG_SOURCE, "Invalid Argument online_keys maximum over.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid online_keys size over.");
  }
  if (online_keys.size() != offline_keys.size()) {
    warn(CFD_LOG_SOURCE, "Invalid Argument online_keys length.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unmatch keylist length.");
  }

  int ret;
  const std::vector<uint8_t>& offline_pubkey_data = offline_pubkey.GetBytes();
  secp256k1_pubkey offline_pubkey_secp;
  ret = secp256k1_ec_pubkey_parse(
      context, &offline_pubkey_secp, offline_pubkey_data.data(),
      offline_pubkey_data.size());
  if (ret != 1) {
    warn(
        CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse offline_pubkey Error.({})",
        ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 offline_pubkey parse Error.");
  }

  std::vector<secp256k1_pubkey> online_pubkeys(online_keys.size());
  std::vector<secp256k1_pubkey> offline_pubkeys(offline_keys.size());
  for (size_t index = 0; index < online_pubkeys.size(); ++index) {
    const std::vector<uint8_t>& online_data = online_keys[index].GetBytes();
    ret = secp256k1_ec_pubkey_parse(
        context, &online_pubkeys[index], online_data.data(),
        online_data.size());
    if (ret != 1) {
      warn(
          CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse onlines[{}] Error.({})",
          index, ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Secp256k1 onlines pubkey parse Error.");
    }

    const std::vector<uint8_t>& offline_data = offline_keys[index].GetBytes();
    ret = secp256k1_ec_pubkey_parse(
        context, &offline_pubkeys[index], offline_data.data(),
        offline_data.size());
    if (ret != 1) {
      warn(
          CFD_LOG_SOURCE, "secp256k1_ec_pubkey_parse offlines[{}] Error.({})",
          index, ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Secp256k1 offlines pubkey parse Error.");
    }
  }

  secp256k1_whitelist_signature signature;
  ret = secp256k1_whitelist_sign(
      context, &signature, online_pubkeys.data(), offline_pubkeys.data(),
      online_pubkeys.size(), &offline_pubkey_secp,
      online_privkey.GetBytes().data(), tweak_sum.GetBytes().data(),
      whitelist_index, nullptr, nullptr);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_whitelist_sign Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Secp256k1 whitelist sign Error.");
  }

  ret = secp256k1_whitelist_verify(
      context, &signature, online_pubkeys.data(), offline_pubkeys.data(),
      online_pubkeys.size(), &offline_pubkey_secp);
  if (ret != 1) {
    warn(CFD_LOG_SOURCE, "secp256k1_whitelist_verify Error.({})", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 whitelist verify Error.");
  }

  std::vector<uint8_t> output(kOutputMaxSize);
  size_t output_size = 1 + (kPrivkeySize * (1 + online_pubkeys.size()));
  size_t outlen = output_size;
  ret = secp256k1_whitelist_signature_serialize(
      context, output.data(), &outlen, &signature);
  if (ret != 1) {
    warn(
        CFD_LOG_SOURCE, "secp256k1_whitelist_signature_serialize Error.({})",
        ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 whitelist signature serialize Error.");
  }
  if (outlen != output_size) {
    warn(
        CFD_LOG_SOURCE,
        "secp256k1_whitelist_signature_serialize size Error.({})", outlen);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Secp256k1 whitelist signature serialize size Error.");
  }
  output.resize(output_size);
  return ByteData(output);
}

}  // namespace core
}  // namespace cfd
