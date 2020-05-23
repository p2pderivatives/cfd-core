// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_transaction.cpp
 *
 * @brief \~japanese Confidential Transaction関連クラスの実装ファイルです。
 *   \~english implementation of Confidential Transaction classes
 */
#ifndef CFD_DISABLE_ELEMENTS

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_secp256k1.h"   // NOLINT
#include "cfdcore_wally_util.h"  // NOLINT
#include "wally_elements.h"      // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::warn;

// -----------------------------------------------------------------------------
// File constants
// -----------------------------------------------------------------------------
/// Definition of ConfidentialCommitment Version1(unblind)
static constexpr uint8_t kConfidentialVersion_1 = 1;
/// Definition of No Witness Transaction version
static constexpr uint32_t kTransactionVersionNoWitness = 0x40000000;
/// Size of asset at unblind
static constexpr size_t kAssetSize = ASSET_TAG_LEN;
/// Size of asset at Nonce
static constexpr size_t kNonceSize = 32;
/// Size of blind factor
static constexpr size_t kBlindFactorSize = 32;
/// Size of ConfidentialData
static constexpr size_t kConfidentialDataSize = WALLY_TX_ASSET_CT_LEN;
/// Size of issuance entropy
static constexpr size_t kEntropySize = 32;
// @formatter:off
/// Size of value at unblind
static constexpr size_t kConfidentialValueSize =
    WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN;  // NOLINT
/// Size of value at ubline (no version byte)
static constexpr size_t kAssetValueSize =
    WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN - 1;  // NOLINT
/// Vount index value mask
static constexpr uint32_t kTxInVoutMask = WALLY_TX_INDEX_MASK;
/// Issuance flag for txin::feature
static constexpr uint8_t kTxInFeatureIssuance = WALLY_TX_IS_ISSUANCE;
/// Pegin flag for txin::feature
static constexpr uint8_t kTxInFeaturePegin = WALLY_TX_IS_PEGIN;
/// Empty data of ByteData256
static const ByteData256 kEmptyByteData256;
// @formatter:on

/**
 * @brief rangeProofなどを生成する。
 * @param[in] value             amount
 * @param[in] pubkey            public key
 * @param[in] privkey           private key
 * @param[in] asset             confidential asset
 * @param[in] abf               asset blind factor
 * @param[in] vbf               value(amount) blind factor
 * @param[in] script            script
 * @param[in] minimum_range_value       rangeproof minimum value.
 *   0 to max(int64_t)
 * @param[in] exponent                  rangeproof exponent value.
 *   -1 to 18. -1 is public value. 0 is most private.
 * @param[in] minimum_bits              rangeproof blinding bits.
 *   0 to 64. Number of bits of the value to keep private. 0 is auto.
 * @param[out] commitment        amount commitment
 * @param[out] range_proof       amount range proof
 * @return asset generator
 */
static ByteData CalculateRangeProof(
    const uint64_t value, const Pubkey *pubkey, const Privkey &privkey,
    const ConfidentialAssetId &asset, const std::vector<uint8_t> &abf,
    const std::vector<uint8_t> &vbf, const Script &script,
    int64_t minimum_range_value, int exponent, int minimum_bits,
    std::vector<uint8_t> *commitment, std::vector<uint8_t> *range_proof) {
  std::vector<uint8_t> generator(ASSET_GENERATOR_LEN);
  const std::vector<uint8_t> &asset_bytes =
      asset.GetUnblindedData().GetBytes();
  int ret = wally_asset_generator_from_bytes(
      asset_bytes.data(), asset_bytes.size(), abf.data(), abf.size(),
      generator.data(), generator.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "output asset generator error.");
  }

  commitment->resize(ASSET_COMMITMENT_LEN);
  ret = wally_asset_value_commitment(
      value, vbf.data(), vbf.size(), generator.data(), generator.size(),
      commitment->data(), commitment->size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_value_commitment NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "calc asset commitment error.");
  }
  // info(
  //    CFD_LOG_SOURCE, "generator=[{}] commitment=[{}]",
  //    ByteData(generator).GetHex(), ByteData(commitment).GetHex());

  range_proof->resize(ASSET_RANGEPROOF_MAX_LEN);
  size_t size = 0;
  const std::vector<uint8_t> &privkey_byte = privkey.GetData().GetBytes();
  const std::vector<uint8_t> &script_byte = script.GetData().GetBytes();
  const std::vector<ScriptElement> &script_item = script.GetElementList();
  int64_t min_range_value = minimum_range_value;
  if (script_item.empty() ||
      (script_item[0].GetOpCode() == ScriptOperator::OP_RETURN) ||
      (script_byte.size() > Script::kMaxScriptSize)) {
    min_range_value = 0;
  }

  if (pubkey == nullptr) {
    ret = wally_asset_rangeproof_with_nonce(
        value, privkey_byte.data(), privkey_byte.size(), asset_bytes.data(),
        asset_bytes.size(), abf.data(), abf.size(), vbf.data(), vbf.size(),
        commitment->data(), commitment->size(), script_byte.data(),
        script_byte.size(), generator.data(), generator.size(),
        static_cast<uint64_t>(min_range_value), exponent, minimum_bits,
        range_proof->data(), range_proof->size(), &size);
  } else {
    const std::vector<uint8_t> &pubkey_byte = pubkey->GetData().GetBytes();
    ret = wally_asset_rangeproof(
        value, pubkey_byte.data(), pubkey_byte.size(), privkey_byte.data(),
        privkey_byte.size(), asset_bytes.data(), asset_bytes.size(),
        abf.data(), abf.size(), vbf.data(), vbf.size(), commitment->data(),
        commitment->size(), script_byte.data(), script_byte.size(),
        generator.data(), generator.size(),
        static_cast<uint64_t>(min_range_value), exponent, minimum_bits,
        range_proof->data(), range_proof->size(), &size);
  }
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_rangeproof NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "calc asset rangeproof error.");
  }
  range_proof->resize(size);
  return ByteData(generator);
}

/**
 * @brief calculate rangeproof size.
 * @param[in] exponent        blinding exponent
 * @param[in] minimum_bits    blinding minimum bits
 * @return rangeproof size.
 */
static uint32_t CalculateRangeProofSize(int exponent, int minimum_bits) {
  ByteData vbf_data(
      "e863b2791be1be9659a940123143f210b9760a3b85862bf0833ef27c80c83816");
  ByteData256 key_data(
      "7df80e5705518368f2e1598e177f4929ba5ab54ab8177582dcc7504fc333c84e");
  ConfidentialAssetId asset(
      "3668f9bdc8f1cc9c1a0247613fffa17b18e3141898e011386b831709c518d805");
  std::vector<uint8_t> empty_factor(kBlindFactorSize);
  std::vector<uint8_t> vbf = vbf_data.GetBytes();
  Privkey privkey(key_data);
  std::vector<uint8_t> commitment;
  std::vector<uint8_t> range_proof;
  CalculateRangeProof(
      uint64_t{10000000}, nullptr, privkey, asset, empty_factor, vbf, Script(),
      1, exponent, minimum_bits, &commitment, &range_proof);
  uint32_t rangeproof_size =
      static_cast<uint32_t>(ByteData(range_proof).GetSerializeSize());
  info(
      CFD_LOG_SOURCE, "[{},{}] rangeproof_size[{}]", exponent, minimum_bits,
      rangeproof_size);
  return rangeproof_size;
}

// -----------------------------------------------------------------------------
// ConfidentialNonce
// -----------------------------------------------------------------------------
ConfidentialNonce::ConfidentialNonce() : data_(), version_(0) {
  // do nothing
}

ConfidentialNonce::ConfidentialNonce(const std::string &hex_string)
    : data_(hex_string), version_(0) {
  switch (data_.GetDataSize()) {
    case 0:
      break;
    case kNonceSize: {
      std::vector<uint8_t> bytes;
      version_ = kConfidentialVersion_1;
      const std::vector<uint8_t> &data = data_.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = data_.GetBytes();
      version_ = data[0];
      if (version_ == 0) {
        data_ = ByteData();
      }
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Nonce size Invalid. size={}.", data_.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Nonce size Invalid.");
  }
  CheckVersion(version_);
}

ConfidentialNonce::ConfidentialNonce(const ByteData &byte_data)
    : data_(), version_(0) {
  switch (byte_data.GetDataSize()) {
    case 0:
      // do nothing
      break;
    case kNonceSize: {
      version_ = kConfidentialVersion_1;
      std::vector<uint8_t> bytes;
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      version_ = data[0];
      if (version_ == 0) {
        data_ = ByteData();
      } else {
        data_ = byte_data;
      }
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Nonce size Invalid. size={}.",
          byte_data.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Nonce size Invalid.");
  }
  CheckVersion(version_);
}

ConfidentialNonce::ConfidentialNonce(const Pubkey &pubkey)
    : ConfidentialNonce(pubkey.GetData()) {
  // do nothing
}

void ConfidentialNonce::CheckVersion(uint8_t version) {
  if ((version != 0) && (version != 1) && (version != 2) && (version != 3)) {
    warn(CFD_LOG_SOURCE, "Nonce version Invalid. version={}.", version);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Nonce version Invalid.");
  }
}

ByteData ConfidentialNonce::GetData() const { return data_; }

std::string ConfidentialNonce::GetHex() const { return data_.GetHex(); }

bool ConfidentialNonce::HasBlinding() const {
  return (version_ != 0) && (version_ != kConfidentialVersion_1);
}

bool ConfidentialNonce::IsEmpty() const { return (version_ == 0); }

// -----------------------------------------------------------------------------
// ConfidentialAssetId
// -----------------------------------------------------------------------------
ConfidentialAssetId::ConfidentialAssetId() : data_(), version_(0) {
  // do nothing
}

ConfidentialAssetId::ConfidentialAssetId(const std::string &hex_string)
    : data_(hex_string), version_(kConfidentialVersion_1) {
  switch (data_.GetDataSize()) {
    case 0:
      warn(
          CFD_LOG_SOURCE, "Empty ConfidentialAssetId. hex_string={}.",
          hex_string);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Empty AssetId is invalid.");
      break;
    case kAssetSize: {
      // reverse
      const std::vector<uint8_t> &data = data_.GetBytes();
      std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
      data_ = ByteData(reverse_buffer);
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = data_.GetBytes();
      std::vector<uint8_t> buffer(data.cbegin() + 1, data.cend());
      version_ = data[0];
      if (version_ == 0) {
        data_ = ByteData();
      } else {
        data_ = ByteData(buffer);
      }
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "AssetId size Invalid. size={}.",
          data_.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "AssetId size Invalid.");
  }
  CheckVersion(version_);
}

ConfidentialAssetId::ConfidentialAssetId(const ByteData &byte_data)
    : data_(), version_(0) {
  switch (byte_data.GetDataSize()) {
    case 0:
      warn(
          CFD_LOG_SOURCE, "Empty ConfidentialAssetId. byte_data={}.",
          StringUtil::ByteToString(byte_data.GetBytes()));
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Empty AssetId is invalid.");
      break;
    case kAssetSize: {
      data_ = byte_data;
      version_ = kConfidentialVersion_1;
      break;
    }
    case kConfidentialDataSize: {
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      std::vector<uint8_t> buffer(data.cbegin() + 1, data.cend());
      version_ = data[0];
      if (version_ != 0) {
        data_ = ByteData(buffer);
      }
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "AssetId size Invalid. size={}.",
          byte_data.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "AssetId size Invalid.");
  }
  CheckVersion(version_);
}

void ConfidentialAssetId::CheckVersion(uint8_t version) {
  if ((version != 0) && (version != 1) && (version != 0x0a) &&
      (version != 0x0b)) {
    warn(CFD_LOG_SOURCE, "Asset version Invalid. version={}.", version);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Asset version Invalid.");
  }
}

ByteData ConfidentialAssetId::GetData() const {
  std::vector<uint8_t> byte_data;
  if (data_.GetDataSize() != 0) {
    const std::vector<uint8_t> &data = data_.GetBytes();
    byte_data.push_back(version_);
    std::copy(data.begin(), data.end(), std::back_inserter(byte_data));
  }
  return ByteData(byte_data);
}

std::string ConfidentialAssetId::GetHex() const {
  if (HasBlinding()) {
    return GetData().GetHex();
  } else {
    const std::vector<uint8_t> &data = data_.GetBytes();
    std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
    return StringUtil::ByteToString(reverse_buffer);
  }
}

bool ConfidentialAssetId::HasBlinding() const {
  return (version_ != 0) && (version_ != kConfidentialVersion_1);
}

ByteData ConfidentialAssetId::GetUnblindedData() const {
  if (!HasBlinding()) {
    return data_;
  }
  return GetData();
}

bool ConfidentialAssetId::IsEmpty() const { return (version_ == 0); }

ConfidentialAssetId ConfidentialAssetId::GetCommitment(
    const ConfidentialAssetId &unblind_asset,
    const BlindFactor &asset_blind_factor) {
  if (unblind_asset.HasBlinding()) {
    warn(CFD_LOG_SOURCE, "asset is commitment.");
    throw CfdException(kCfdIllegalStateError, "asset is commitment.");
  }
  std::vector<uint8_t> generator(ASSET_COMMITMENT_LEN);
  std::vector<uint8_t> asset_id = unblind_asset.GetUnblindedData().GetBytes();
  std::vector<uint8_t> abf = asset_blind_factor.GetData().GetBytes();
  int ret = wally_asset_generator_from_bytes(
      asset_id.data(), asset_id.size(), abf.data(), abf.size(),
      generator.data(), generator.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "calc asset commitment error.");
  }
  return ConfidentialAssetId(ByteData(generator));
}

// -----------------------------------------------------------------------------
// ConfidentialValue
// -----------------------------------------------------------------------------
ConfidentialValue::ConfidentialValue() : data_(), version_(0) {
  // do nothing
}

ConfidentialValue::ConfidentialValue(const std::string &hex_string)
    : data_(hex_string), version_(0) {
  switch (data_.GetDataSize()) {
    case 0:
      // do nothing
      break;
    case kAssetValueSize: {
      std::vector<uint8_t> bytes;
      version_ = kConfidentialVersion_1;
      const std::vector<uint8_t> &data = data_.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize:
    case kConfidentialValueSize: {
      const std::vector<uint8_t> &data = data_.GetBytes();
      version_ = data[0];
      if (version_ == 0) {
        data_ = ByteData();
      }
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Value size Invalid. size={}.", data_.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Value size Invalid.");
  }
  CheckVersion(version_);
}

ConfidentialValue::ConfidentialValue(const ByteData &byte_data)
    : data_(), version_(0) {
  switch (byte_data.GetDataSize()) {
    case 0:
      // do nothing
      break;
    case kAssetValueSize: {
      version_ = kConfidentialVersion_1;
      std::vector<uint8_t> bytes;
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      bytes.push_back(version_);
      std::copy(data.begin(), data.end(), std::back_inserter(bytes));
      data_ = ByteData(bytes);
      break;
    }
    case kConfidentialDataSize:
    case kConfidentialValueSize: {
      const std::vector<uint8_t> &data = byte_data.GetBytes();
      version_ = data[0];
      if (version_ == 0) {
        data_ = ByteData();
      } else {
        data_ = byte_data;
      }
      break;
    }
    default:
      warn(
          CFD_LOG_SOURCE, "Value size Invalid. size={}.",
          byte_data.GetDataSize());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Value size Invalid.");
  }
  CheckVersion(version_);
}

ConfidentialValue::ConfidentialValue(const Amount &amount)
    : ConfidentialValue(ConvertToConfidentialValue(amount)) {
  // do nothing
}

void ConfidentialValue::CheckVersion(uint8_t version) {
  if ((version != 0) && (version != 1) && (version != 0x08) &&
      (version != 0x09)) {
    warn(CFD_LOG_SOURCE, "Value version Invalid. version={}.", version);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Value version Invalid.");
  }
}

ByteData ConfidentialValue::GetData() const { return data_; }

std::string ConfidentialValue::GetHex() const { return data_.GetHex(); }

Amount ConfidentialValue::GetAmount() const {
  Amount amount = Amount::CreateBySatoshiAmount(0);
  if (version_ == 1) {
    amount = ConvertFromConfidentialValue(GetData());
  }
  return amount;
}

bool ConfidentialValue::HasBlinding() const {
  return (version_ != 0) && (version_ != kConfidentialVersion_1);
}

bool ConfidentialValue::IsEmpty() const { return (version_ == 0); }

ByteData ConfidentialValue::ConvertToConfidentialValue(  // force LF
    const Amount &value) {
  std::vector<uint8_t> buffer(kConfidentialValueSize);
  uint64_t satoshi = static_cast<uint64_t>(value.GetSatoshiValue());
  int ret = wally_tx_confidential_value_from_satoshi(
      satoshi, buffer.data(), buffer.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_confidential_value_from_satoshi NG[{}].",
        ret);
    throw CfdException(
        kCfdIllegalStateError, "generate confidential value error.");
  }
  return ByteData(buffer);
}

Amount ConfidentialValue::ConvertFromConfidentialValue(  // force LF
    const ByteData &value) {
  const std::vector<uint8_t> &buffer = value.GetBytes();
  uint64_t satoshi = 0;
  int ret = wally_tx_confidential_value_to_satoshi(
      buffer.data(), buffer.size(), &satoshi);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_confidential_value_to_satoshi NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "convert from confidential value error.");
  }
  return Amount::CreateBySatoshiAmount(static_cast<int64_t>(satoshi));
}

ConfidentialValue ConfidentialValue::GetCommitment(
    const Amount &amount, const ConfidentialAssetId &asset_commitment,
    const BlindFactor &amount_blind_factor) {
  if (!asset_commitment.HasBlinding()) {
    warn(CFD_LOG_SOURCE, "asset is not commitment.");
    throw CfdException(kCfdIllegalStateError, "asset is not commitment.");
  }
  std::vector<uint8_t> commitment(ASSET_COMMITMENT_LEN);
  std::vector<uint8_t> generator = asset_commitment.GetData().GetBytes();
  std::vector<uint8_t> vbf = amount_blind_factor.GetData().GetBytes();
  uint64_t value = static_cast<uint64_t>(amount.GetSatoshiValue());
  int ret = wally_asset_value_commitment(
      value, vbf.data(), vbf.size(), generator.data(), generator.size(),
      commitment.data(), commitment.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_value_commitment NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "calc amount commitment error.");
  }
  return ConfidentialValue(ByteData(commitment));
}

// -----------------------------------------------------------------------------
// BlindFactor
// -----------------------------------------------------------------------------
BlindFactor::BlindFactor() : data_() {
  // do nothing
}
BlindFactor::BlindFactor(const std::string &hex_string) : data_() {
  if (hex_string.size() != (kByteData256Length * 2)) {
    warn(
        CFD_LOG_SOURCE, "Value hex-string-length Invalid. length={}.",
        hex_string.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Value hex string length Invalid.");
  }
  const std::vector<uint8_t> &data = StringUtil::StringToByte(hex_string);
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  data_ = ByteData256(reverse_buffer);
}

BlindFactor::BlindFactor(const ByteData &byte_data)
    : BlindFactor(ByteData256(byte_data)) {
  // do nothing
}

BlindFactor::BlindFactor(const ByteData256 &byte_data) : data_(byte_data) {
  // do nothing
}

ByteData256 BlindFactor::GetData() const { return data_; }

std::string BlindFactor::GetHex() const {
  const std::vector<uint8_t> &data = data_.GetBytes();
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  return StringUtil::ByteToString(reverse_buffer);
}

bool BlindFactor::IsEmpty() const { return data_.IsEmpty(); }

// -----------------------------------------------------------------------------
// ConfidentialTxIn
// -----------------------------------------------------------------------------
ConfidentialTxIn::ConfidentialTxIn()
    : AbstractTxIn(Txid(), 0, 0),
      blinding_nonce_(),
      asset_entropy_(),
      issuance_amount_(),
      inflation_keys_(),
      issuance_amount_rangeproof_(),
      inflation_keys_rangeproof_(),
      pegin_witness_() {
  // do nothing
}

ConfidentialTxIn::ConfidentialTxIn(const Txid &txid, uint32_t index)
    : AbstractTxIn(txid, index, 0),
      blinding_nonce_(),
      asset_entropy_(),
      issuance_amount_(),
      inflation_keys_(),
      issuance_amount_rangeproof_(),
      inflation_keys_rangeproof_(),
      pegin_witness_() {
  // do nothing
}

ConfidentialTxIn::ConfidentialTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence)
    : AbstractTxIn(txid, index, sequence),
      blinding_nonce_(),
      asset_entropy_(),
      issuance_amount_(),
      inflation_keys_(),
      issuance_amount_rangeproof_(),
      inflation_keys_rangeproof_(),
      pegin_witness_() {
  // do nothing
}

ConfidentialTxIn::ConfidentialTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script)
    : AbstractTxIn(txid, index, sequence, unlocking_script),
      blinding_nonce_(),
      asset_entropy_(),
      issuance_amount_(),
      inflation_keys_(),
      issuance_amount_rangeproof_(),
      inflation_keys_rangeproof_(),
      pegin_witness_() {
  // do nothing
}

ConfidentialTxIn::ConfidentialTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script, const ScriptWitness &witness_stack,
    const ByteData256 &blinding_nonce, const ByteData256 &asset_entropy,
    const ConfidentialValue &issuance_amount,
    const ConfidentialValue &inflation_keys,
    const ByteData &issuance_amount_rangeproof,
    const ByteData &inflation_keys_rangeproof,
    const ScriptWitness &pegin_witness)
    : AbstractTxIn(txid, index, sequence, unlocking_script),
      blinding_nonce_(blinding_nonce),
      asset_entropy_(asset_entropy),
      issuance_amount_(issuance_amount),
      inflation_keys_(inflation_keys),
      issuance_amount_rangeproof_(issuance_amount_rangeproof),
      inflation_keys_rangeproof_(inflation_keys_rangeproof),
      pegin_witness_(pegin_witness) {
  script_witness_ = witness_stack;
}

void ConfidentialTxIn::SetIssuance(
    const ByteData256 &blinding_nonce, const ByteData256 &asset_entropy,
    const ConfidentialValue &issuance_amount,
    const ConfidentialValue &inflation_keys,
    const ByteData &issuance_amount_rangeproof,
    const ByteData &inflation_keys_rangeproof) {
  blinding_nonce_ = blinding_nonce;
  asset_entropy_ = asset_entropy;
  issuance_amount_ = issuance_amount;
  inflation_keys_ = inflation_keys;
  issuance_amount_rangeproof_ = issuance_amount_rangeproof;
  inflation_keys_rangeproof_ = inflation_keys_rangeproof;
}

ScriptWitness ConfidentialTxIn::AddPeginWitnessStack(const ByteData &data) {
  pegin_witness_.AddWitnessStack(data);
  return pegin_witness_;
}

ScriptWitness ConfidentialTxIn::SetPeginWitnessStack(
    uint32_t index, const ByteData &data) {
  pegin_witness_.SetWitnessStack(index, data);
  return pegin_witness_;
}

void ConfidentialTxIn::RemovePeginWitnessStackAll() {
  pegin_witness_ = ScriptWitness();
}

ByteData256 ConfidentialTxIn::GetWitnessHash() const {
  std::vector<ByteData256> leaves;
  if (IsCoinBase()) {
    ByteData256 empty_data = HashUtil::Sha256D(ByteData().Serialize());
    leaves.push_back(empty_data);
    leaves.push_back(empty_data);
    leaves.push_back(empty_data);
    leaves.push_back(empty_data);
  } else {
    leaves.push_back(
        HashUtil::Sha256D(issuance_amount_rangeproof_.Serialize()));
    leaves.push_back(
        HashUtil::Sha256D(inflation_keys_rangeproof_.Serialize()));
    leaves.push_back(HashUtil::Sha256D(script_witness_.Serialize()));
    leaves.push_back(HashUtil::Sha256D(pegin_witness_.Serialize()));
  }
  ByteData256 result = CryptoUtil::ComputeFastMerkleRoot(leaves);
  return result;
}

uint32_t ConfidentialTxIn::EstimateTxInSize(
    AddressType addr_type, Script redeem_script, uint32_t pegin_btc_tx_size,
    Script fedpeg_script, bool is_issuance, bool is_blind,
    uint32_t *witness_area_size, uint32_t *no_witness_area_size,
    bool is_reissuance, const Script *scriptsig_template, int exponent,
    int minimum_bits, uint32_t *rangeproof_size) {
  // issuance時の追加サイズ: entity(32),hash(32),amount(8+1),key(8+1)
  static constexpr const uint32_t kIssuanceAppendSize = 82;
  // blind issuance時の追加サイズ: entity,hash,amount(33),key(33)
  static constexpr const uint32_t kIssuanceBlindSize = 130;
  // issuance rangeproof size
  // static constexpr const uint32_t kTxInRangeproof = 2893 + 3;
  // pegin size:
  // btc(9),asset(33),block(33),fedpegSize(-),txSize(3),txoutproof(152)
  static constexpr const uint32_t kPeginWitnessSize = 230;
  uint32_t witness_size = 0;
  uint32_t size = 0;
  TxIn::EstimateTxInSize(
      addr_type, redeem_script, &witness_size, &size, scriptsig_template);

  if (is_issuance || is_reissuance) {
    if (is_blind) {
      size += kIssuanceBlindSize;
    } else {
      size += kIssuanceAppendSize;
    }
  }

  if ((pegin_btc_tx_size != 0) || is_issuance || is_reissuance ||
      (witness_size != 0)) {
    if (witness_size == 0) {
      witness_size += 1;  // witness size
    }

    if (pegin_btc_tx_size != 0) {
      witness_size += pegin_btc_tx_size + kPeginWitnessSize;
      if (!fedpeg_script.IsEmpty()) {
        witness_size +=
            static_cast<uint32_t>(fedpeg_script.GetData().GetSerializeSize());
      }
    }
    witness_size += 1;  // pegin witness num

    if ((!is_issuance && !is_reissuance) || !is_blind) {
      witness_size += 2;  // issuance rangeproof size
    } else {
      uint32_t work_proof_size = 0;
      if ((rangeproof_size != nullptr) && (*rangeproof_size != 0)) {
        work_proof_size = *rangeproof_size;
      } else {
        work_proof_size = 4 + CalculateRangeProofSize(exponent, minimum_bits);
        if (rangeproof_size != nullptr) *rangeproof_size = work_proof_size;
      }
      if (is_reissuance) {
        work_proof_size += 1;
      } else {
        work_proof_size *= 2;
      }
      witness_size += work_proof_size;
    }
  }

  if (witness_area_size != nullptr) {
    *witness_area_size = witness_size;
  }
  if (no_witness_area_size != nullptr) {
    *no_witness_area_size = size;
  }
  return size + witness_size;
}

uint32_t ConfidentialTxIn::EstimateTxInVsize(
    AddressType addr_type, Script redeem_script, uint32_t pegin_btc_tx_size,
    Script fedpeg_script, bool is_issuance, bool is_blind, bool is_reissuance,
    const Script *scriptsig_template, int exponent, int minimum_bits,
    uint32_t *rangeproof_size) {
  uint32_t witness_size = 0;
  uint32_t no_witness_size = 0;
  ConfidentialTxIn::EstimateTxInSize(
      addr_type, redeem_script, pegin_btc_tx_size, fedpeg_script, is_issuance,
      is_blind, &witness_size, &no_witness_size, is_reissuance,
      scriptsig_template, exponent, minimum_bits, rangeproof_size);
  return AbstractTransaction::GetVsizeFromSize(no_witness_size, witness_size);
}

// -----------------------------------------------------------------------------
// ConfidentialTxInReference
// -----------------------------------------------------------------------------
ConfidentialTxInReference::ConfidentialTxInReference(
    const ConfidentialTxIn &tx_in)
    : AbstractTxInReference(tx_in),
      blinding_nonce_(tx_in.GetBlindingNonce()),
      asset_entropy_(tx_in.GetAssetEntropy()),
      issuance_amount_(tx_in.GetIssuanceAmount()),
      inflation_keys_(tx_in.GetInflationKeys()),
      issuance_amount_rangeproof_(tx_in.GetIssuanceAmountRangeproof()),
      inflation_keys_rangeproof_(tx_in.GetInflationKeysRangeproof()),
      pegin_witness_(tx_in.GetPeginWitness()) {
  // do nothing
}

ConfidentialTxInReference::ConfidentialTxInReference()
    : ConfidentialTxInReference(ConfidentialTxIn(Txid(), 0, 0)) {
  // do nothing
}

// -----------------------------------------------------------------------------
// ConfidentialTxOut
// -----------------------------------------------------------------------------
ConfidentialTxOut::ConfidentialTxOut()
    : AbstractTxOut(),
      asset_(),
      confidential_value_(),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const Script &locking_script, const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value)
    : AbstractTxOut(Amount::CreateBySatoshiAmount(0), locking_script),
      asset_(asset),
      confidential_value_(confidential_value),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const Script &locking_script, const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value,
    const ConfidentialNonce &nonce, const ByteData &surjection_proof,
    const ByteData &range_proof)
    : AbstractTxOut(Amount::CreateBySatoshiAmount(0), locking_script),
      asset_(asset),
      confidential_value_(confidential_value),
      nonce_(nonce),
      surjection_proof_(surjection_proof),
      range_proof_(range_proof) {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value)
    : AbstractTxOut(),
      asset_(asset),
      confidential_value_(confidential_value),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const ConfidentialAssetId &asset, const Amount &amount)
    : AbstractTxOut(),
      asset_(asset),
      confidential_value_(ConfidentialValue(amount)),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const Address &address, const ConfidentialAssetId &asset,
    const Amount &amount)
    : AbstractTxOut(address.GetLockingScript()),
      asset_(asset),
      confidential_value_(ConfidentialValue(amount)),
      nonce_(),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

ConfidentialTxOut::ConfidentialTxOut(
    const ElementsConfidentialAddress &confidential_address,
    const ConfidentialAssetId &asset, const Amount &amount)
    : AbstractTxOut(confidential_address.GetLockingScript()),
      asset_(asset),
      confidential_value_(ConfidentialValue(amount)),
      nonce_(confidential_address.GetConfidentialKey()),
      surjection_proof_(),
      range_proof_() {
  // do nothing
}

void ConfidentialTxOut::SetCommitment(
    const ConfidentialAssetId &asset,
    const ConfidentialValue &confidential_value,
    const ConfidentialNonce &nonce, const ByteData &surjection_proof,
    const ByteData &range_proof) {
  asset_ = asset;
  confidential_value_ = confidential_value;
  nonce_ = nonce;
  surjection_proof_ = surjection_proof;
  range_proof_ = range_proof;
}

void ConfidentialTxOut::SetValue(const Amount &value) { value_ = value; }

ByteData256 ConfidentialTxOut::GetWitnessHash() const {
  ByteData256 result;
  std::vector<ByteData256> leaves;
  leaves.push_back(HashUtil::Sha256D(surjection_proof_.Serialize()));
  leaves.push_back(HashUtil::Sha256D(range_proof_.Serialize()));
  result = CryptoUtil::ComputeFastMerkleRoot(leaves);
  return result;
}

ConfidentialTxOut ConfidentialTxOut::CreateDestroyAmountTxOut(
    const ConfidentialAssetId &asset, const Amount &amount) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_RETURN);
  return ConfidentialTxOut(builder.Build(), asset, ConfidentialValue(amount));
}

const RangeProofInfo ConfidentialTxOut::DecodeRangeProofInfo(
    const ByteData &range_proof) {
  RangeProofInfo range_proof_info;
  WallyUtil::RangeProofInfo(
      range_proof, &range_proof_info.exponent, &range_proof_info.mantissa,
      &range_proof_info.min_value, &range_proof_info.max_value);
  return range_proof_info;
}

// -----------------------------------------------------------------------------
// ConfidentialTxOutReference
// -----------------------------------------------------------------------------
ConfidentialTxOutReference::ConfidentialTxOutReference(
    const ConfidentialTxOut &tx_out)
    : AbstractTxOutReference(tx_out),
      asset_(tx_out.GetAsset()),
      confidential_value_(tx_out.GetConfidentialValue()),
      nonce_(tx_out.GetNonce()),
      surjection_proof_(tx_out.GetSurjectionProof()),
      range_proof_(tx_out.GetRangeProof()) {
  // do nothing
}

uint32_t ConfidentialTxOutReference::GetSerializeSize(
    bool is_blinded, uint32_t *witness_area_size,
    uint32_t *no_witness_area_size, int exponent, int minimum_bits,
    uint32_t *rangeproof_size) const {
  static constexpr const uint32_t kTxOutSurjection = 162 + 1;
  // SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(256, 3) = 162
  // static constexpr const uint32_t kTxOutRangeproof = 2893 + 3;
  uint32_t result = 0;
  uint32_t witness_size = 0;
  bool is_blind = is_blinded || (!nonce_.IsEmpty());
  if (is_blind && (!locking_script_.IsEmpty()) &&
      (!locking_script_.IsPegoutScript())) {
    result += kConfidentialDataSize;  // asset
    result += kConfidentialDataSize;  // value
    result += kConfidentialDataSize;  // nonce
    result +=
        static_cast<uint32_t>(locking_script_.GetData().GetSerializeSize());
    witness_size += kTxOutSurjection;  // surjection proof
    // witness_size += kTxOutRangeproof;  // range proof
    uint32_t work_proof_size = 0;
    if ((rangeproof_size != nullptr) && (*rangeproof_size != 0)) {
      work_proof_size = *rangeproof_size;
    } else {
      work_proof_size = 4 + CalculateRangeProofSize(exponent, minimum_bits);
      if (rangeproof_size != nullptr) *rangeproof_size = work_proof_size;
    }
    witness_size += work_proof_size;
  } else {
    result += kConfidentialDataSize;   // asset
    result += kConfidentialValueSize;  // value
    if (locking_script_.IsEmpty()) {
      result += 2;  // fee (nonce & lockingScript empty.)
    } else {
      result += 1;  // nonce
      result +=
          static_cast<uint32_t>(locking_script_.GetData().GetSerializeSize());
    }
    witness_size += 1;  // surjection proof
    witness_size += 1;  // range proof
  }

  if (witness_area_size != nullptr) {
    *witness_area_size = witness_size;
  }
  if (no_witness_area_size != nullptr) {
    *no_witness_area_size = result;
  }
  result += witness_size;
  return result;
}

uint32_t ConfidentialTxOutReference::GetSerializeVsize(
    bool is_blinded, int exponent, int minimum_bits,
    uint32_t *rangeproof_size) const {
  uint32_t witness_size = 0;
  uint32_t no_witness_size = 0;
  GetSerializeSize(
      is_blinded, &witness_size, &no_witness_size, exponent, minimum_bits,
      rangeproof_size);
  return AbstractTransaction::GetVsizeFromSize(no_witness_size, witness_size);
}

// -----------------------------------------------------------------------------
// ConfidentialTransaction
// -----------------------------------------------------------------------------

ConfidentialTransaction::ConfidentialTransaction()
    : ConfidentialTransaction(2, static_cast<uint32_t>(0)) {
  // do nothing
}

ConfidentialTransaction::ConfidentialTransaction(
    int32_t version, uint32_t lock_time)
    : vin_(), vout_() {
  struct wally_tx *tx_pointer = NULL;
  int ret = wally_tx_init_alloc(version, lock_time, 0, 0, &tx_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_init_alloc NG[{}] ", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "transaction data generate error.");
  }
  wally_tx_pointer_ = tx_pointer;
}

ConfidentialTransaction::ConfidentialTransaction(const std::string &hex_string)
    : vin_(), vout_() {
  SetFromHex(hex_string);
}

ConfidentialTransaction::ConfidentialTransaction(const ByteData &byte_data)
    : ConfidentialTransaction(byte_data.GetHex()) {}

ConfidentialTransaction::ConfidentialTransaction(
    const ConfidentialTransaction &transaction)
    : ConfidentialTransaction(transaction.GetHex()) {
  // copy constructor
}

void ConfidentialTransaction::SetFromHex(const std::string &hex_string) {
  void *original_address = wally_tx_pointer_;
  std::vector<ConfidentialTxIn> vin_work;
  std::vector<ConfidentialTxOut> vout_work;

  // It is assumed that tx information has been created.
  // (If it is not created, it will cause inconsistency)
  struct wally_tx *tx_pointer = NULL;
  uint32_t flag = WALLY_TX_FLAG_USE_ELEMENTS;
  int ret = wally_tx_from_hex(hex_string.c_str(), flag, &tx_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }
  wally_tx_pointer_ = tx_pointer;

  try {
    // create ConfidentialTxIn and ConfidentialTxOut
    for (size_t index = 0; index < tx_pointer->num_inputs; ++index) {
      struct wally_tx_input *txin_item = &tx_pointer->inputs[index];
      std::vector<uint8_t> txid_buf(
          txin_item->txhash, txin_item->txhash + sizeof(txin_item->txhash));
      std::vector<uint8_t> script_buf(
          txin_item->script, txin_item->script + txin_item->script_len);
      Script unlocking_script = Script(ByteData(script_buf));
      /* Temporarily comment out
      if (!unlocking_script.IsPushOnly()) {
        warn(CFD_LOG_SOURCE, "IsPushOnly() false.");
        throw CfdException(
            kCfdIllegalArgumentError,
            "unlocking script error. "
            "The script needs to be push operator only.");
      } */
      std::vector<uint8_t> blinding_buf(
          txin_item->blinding_nonce,
          txin_item->blinding_nonce + sizeof(txin_item->blinding_nonce));
      std::vector<uint8_t> entropy(
          txin_item->entropy, txin_item->entropy + sizeof(txin_item->entropy));
      ConfidentialTxIn txin(
          Txid(ByteData256(txid_buf)), txin_item->index, txin_item->sequence,
          unlocking_script, ScriptWitness(), ByteData256(blinding_buf),
          ByteData256(entropy),
          ConfidentialValue(ConvertToByteData(
              txin_item->issuance_amount, txin_item->issuance_amount_len)),
          ConfidentialValue(ConvertToByteData(
              txin_item->inflation_keys, txin_item->inflation_keys_len)),
          ConvertToByteData(
              txin_item->issuance_amount_rangeproof,
              txin_item->issuance_amount_rangeproof_len),
          ConvertToByteData(
              txin_item->inflation_keys_rangeproof,
              txin_item->inflation_keys_rangeproof_len),
          ScriptWitness());
      if ((txin_item->witness != NULL) &&
          (txin_item->witness->num_items != 0)) {
        struct wally_tx_witness_item *witness_stack;
        for (size_t w_index = 0; w_index < txin_item->witness->num_items;
             ++w_index) {
          witness_stack = &txin_item->witness->items[w_index];
          const std::vector<uint8_t> witness_buf(
              witness_stack->witness,
              witness_stack->witness + witness_stack->witness_len);
          txin.AddScriptWitnessStack(ByteData(witness_buf));
        }
      }
      if ((txin_item->pegin_witness != NULL) &&
          (txin_item->pegin_witness->num_items != 0)) {
        for (size_t w_index = 0; w_index < txin_item->pegin_witness->num_items;
             ++w_index) {
          struct wally_tx_witness_item *witness_stack;
          witness_stack = &txin_item->pegin_witness->items[w_index];
          const std::vector<uint8_t> witness_buf(
              witness_stack->witness,
              witness_stack->witness + witness_stack->witness_len);
          txin.AddPeginWitnessStack(ByteData(witness_buf));
        }
      }
      vin_work.push_back(txin);
    }

    info(CFD_LOG_SOURCE, "num_outputs={} ", tx_pointer->num_outputs);
    for (size_t index = 0; index < tx_pointer->num_outputs; ++index) {
      struct wally_tx_output *txout_item = &tx_pointer->outputs[index];
      ConfidentialTxOut txout(
          Script(
              ConvertToByteData(txout_item->script, txout_item->script_len)),
          ConfidentialAssetId(
              ConvertToByteData(txout_item->asset, txout_item->asset_len)),
          ConfidentialValue(
              ConvertToByteData(txout_item->value, txout_item->value_len)),
          ConfidentialNonce(
              ConvertToByteData(txout_item->nonce, txout_item->nonce_len)),
          ConvertToByteData(
              txout_item->surjectionproof, txout_item->surjectionproof_len),
          ConvertToByteData(
              txout_item->rangeproof, txout_item->rangeproof_len));
      vout_work.push_back(txout);
    }

    // If the copy process is successful, release the old buffer
    if (original_address != NULL) {
      wally_tx_free(static_cast<struct wally_tx *>(original_address));
      vin_.clear();
      vout_.clear();
    }
    vin_ = vin_work;
    vout_ = vout_work;
  } catch (const CfdException &exception) {
    // free on error
    wally_tx_free(tx_pointer);
    wally_tx_pointer_ = original_address;
    throw exception;
  } catch (...) {
    // free on error
    wally_tx_free(tx_pointer);
    wally_tx_pointer_ = original_address;
    throw CfdException(kCfdUnknownError);
  }
}

ConfidentialTransaction &ConfidentialTransaction::operator=(
    const ConfidentialTransaction &transaction) & {
  SetFromHex(transaction.GetHex());
  return *this;
}

const ConfidentialTxInReference ConfidentialTransaction::GetTxIn(
    uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  return ConfidentialTxInReference(vin_[index]);
}

uint32_t ConfidentialTransaction::GetTxInIndex(
    const Txid &txid, uint32_t vout) const {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  size_t is_coinbase = 0;
  wally_tx_is_coinbase(tx_pointer, &is_coinbase);

  uint32_t index = (is_coinbase == 0) ? vout & kTxInVoutMask : vout;
  for (size_t i = 0; i < vin_.size(); ++i) {
    if (vin_[i].GetTxid().Equals(txid) && vin_[i].GetVout() == index) {
      return static_cast<uint32_t>(i);
    }
  }
  warn(CFD_LOG_SOURCE, "Txid is not found.");
  throw CfdException(kCfdIllegalArgumentError, "Txid is not found.");
}

uint32_t ConfidentialTransaction::GetTxOutIndex(
    const Script &locking_script) const {
  std::string search_str = locking_script.GetHex();
  uint32_t index = 0;
  for (; index < static_cast<uint32_t>(vout_.size()); ++index) {
    std::string script = vout_[index].GetLockingScript().GetHex();
    if (script == search_str) {
      return index;
    }
  }
  warn(CFD_LOG_SOURCE, "locking script is not found.");
  throw CfdException(kCfdIllegalArgumentError, "locking script is not found.");
}

std::vector<uint32_t> ConfidentialTransaction::GetTxOutIndexList(
    const Script &locking_script) const {
  std::vector<uint32_t> result;
  std::string search_str = locking_script.GetHex();
  uint32_t index = 0;
  for (; index < static_cast<uint32_t>(vout_.size()); ++index) {
    if (search_str == vout_[index].GetLockingScript().GetHex()) {
      result.push_back(index);
    }
  }
  if (result.empty()) {
    warn(CFD_LOG_SOURCE, "locking script is not found.");
    throw CfdException(
        kCfdIllegalArgumentError, "locking script is not found.");
  }
  return result;
}

uint32_t ConfidentialTransaction::GetTxInCount() const {
  return static_cast<uint32_t>(vin_.size());
}

const std::vector<ConfidentialTxInReference>  // force LF
ConfidentialTransaction::GetTxInList() const {
  std::vector<ConfidentialTxInReference> refs;
  for (ConfidentialTxIn tx_in : vin_) {
    refs.push_back(ConfidentialTxInReference(tx_in));
  }
  return refs;
}

uint32_t ConfidentialTransaction::AddTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script) {
  if (vin_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vin maximum.");
    throw CfdException(kCfdIllegalStateError, "txin maximum.");
  }

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  const std::vector<uint8_t> &txid_buf = txid.GetData().GetBytes();
  std::vector<uint8_t> empty_data;
  const std::vector<uint8_t> &script_data =
      (unlocking_script.IsEmpty()) ? empty_data
                                   : unlocking_script.GetData().GetBytes();
  int ret = wally_tx_add_elements_raw_input(
      tx_pointer, txid_buf.data(), txid_buf.size(), index, sequence,
      script_data.data(), script_data.size(), NULL, NULL, 0, NULL, 0, NULL, 0,
      NULL, 0, NULL, 0, NULL, 0, NULL, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_elements_raw_input NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "txin add error.");
  }

  size_t is_coinbase = 0;
  wally_tx_is_coinbase(tx_pointer, &is_coinbase);
  uint32_t set_index = (is_coinbase == 0) ? index & kTxInVoutMask : index;
  ConfidentialTxIn txin(txid, set_index, sequence);
  if (!unlocking_script.IsEmpty()) {
    txin = ConfidentialTxIn(txid, set_index, sequence, unlocking_script);
  }
  vin_.push_back(txin);
  return static_cast<uint32_t>(vin_.size() - 1);
}

void ConfidentialTransaction::RemoveTxIn(uint32_t index) {
  AbstractTransaction::RemoveTxIn(index);

  std::vector<ConfidentialTxIn>::const_iterator ite = vin_.cbegin();
  if (index != 0) {
    ite += index;
  }
  vin_.erase(ite);
}

void ConfidentialTransaction::SetUnlockingScript(
    uint32_t tx_in_index, const Script &unlocking_script) {
  AbstractTransaction::SetUnlockingScript(tx_in_index, unlocking_script);
  vin_[tx_in_index].SetUnlockingScript(unlocking_script);
}

void ConfidentialTransaction::SetUnlockingScript(
    uint32_t tx_in_index, const std::vector<ByteData> &unlocking_script) {
  Script generate_unlocking_script =
      AbstractTransaction::SetUnlockingScript(tx_in_index, unlocking_script);
  vin_[tx_in_index].SetUnlockingScript(generate_unlocking_script);
}

uint32_t ConfidentialTransaction::GetScriptWitnessStackNum(
    uint32_t tx_in_index) const {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);
  return vin_[tx_in_index].GetScriptWitnessStackNum();
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData &data) {
  return AddScriptWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData160 &data) {
  return AddScriptWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData256 &data) {
  return AddScriptWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const std::vector<uint8_t> &data) {
  AbstractTransaction::AddScriptWitnessStack(tx_in_index, data);

  const ScriptWitness &witness =
      vin_[tx_in_index].AddScriptWitnessStack(ByteData(data));
  return witness;
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData &data) {
  return SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData160 &data) {
  return SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData256 &data) {
  return SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index,
    const std::vector<uint8_t> &data) {
  AbstractTransaction::SetScriptWitnessStack(tx_in_index, witness_index, data);

  const ScriptWitness &witness =
      vin_[tx_in_index].SetScriptWitnessStack(witness_index, ByteData(data));
  return witness;
}

void ConfidentialTransaction::RemoveScriptWitnessStackAll(
    uint32_t tx_in_index) {
  AbstractTransaction::RemoveScriptWitnessStackAll(tx_in_index);

  vin_[tx_in_index].RemoveScriptWitnessStackAll();
}

void ConfidentialTransaction::SetIssuance(
    // force LF
    uint32_t tx_in_index, const ByteData256 blinding_nonce,
    const ByteData256 asset_entropy, const ConfidentialValue issuance_amount,
    const ConfidentialValue inflation_keys,
    const ByteData issuance_amount_rangeproof,
    const ByteData inflation_keys_rangeproof) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  const std::vector<uint8_t> &nonce = blinding_nonce.GetBytes();
  const std::vector<uint8_t> &entropy = asset_entropy.GetBytes();
  const std::vector<uint8_t> &issuance_amount_bytes =
      issuance_amount.GetData().GetBytes();
  const std::vector<uint8_t> &inflation_keys_bytes =
      inflation_keys.GetData().GetBytes();
  const std::vector<uint8_t> &issuance_amount_rangeproof_bytes =
      issuance_amount_rangeproof.GetBytes();
  const std::vector<uint8_t> &inflation_keys_rangeproof_bytes =
      inflation_keys_rangeproof.GetBytes();

  int ret = wally_tx_elements_input_issuance_set(
      &tx_pointer->inputs[tx_in_index], nonce.data(), nonce.size(),
      entropy.data(), entropy.size(), issuance_amount_bytes.data(),
      issuance_amount_bytes.size(), inflation_keys_bytes.data(),
      inflation_keys_bytes.size(), issuance_amount_rangeproof_bytes.data(),
      issuance_amount_rangeproof_bytes.size(),
      inflation_keys_rangeproof_bytes.data(),
      inflation_keys_rangeproof_bytes.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_elements_input_issuance_set NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "txin add error.");
  }
  SetElementsTxState();

  vin_[tx_in_index].SetIssuance(
      blinding_nonce, asset_entropy, issuance_amount, inflation_keys,
      issuance_amount_rangeproof, inflation_keys_rangeproof);
}

uint32_t ConfidentialTransaction::GetPeginWitnessStackNum(
    uint32_t tx_in_index) const {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);
  return vin_[tx_in_index].GetPeginWitnessStackNum();
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const ByteData &data) {
  return AddPeginWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const ByteData160 &data) {
  return AddPeginWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const ByteData256 &data) {
  return AddPeginWitnessStack(tx_in_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::AddPeginWitnessStack(
    uint32_t tx_in_index, const std::vector<uint8_t> &data) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    int ret = WALLY_OK;
    bool is_alloc = false;
    struct wally_tx_witness_stack *stack_pointer = NULL;

    std::string function_name = "wally_tx_witness_stack_init_alloc";
    if (tx_pointer->inputs[tx_in_index].pegin_witness == NULL) {
      is_alloc = true;
      ret = wally_tx_witness_stack_init_alloc(1, &stack_pointer);
    } else {
      stack_pointer = tx_pointer->inputs[tx_in_index].pegin_witness;
    }

    if (ret == WALLY_OK) {
      try {
        // append witness stack
        function_name = "wally_tx_witness_stack_add";
        if (data.empty()) {
          ret = wally_tx_witness_stack_add(stack_pointer, NULL, 0);
        } else {
          ret = wally_tx_witness_stack_add(
              stack_pointer, data.data(), data.size());
        }

        // append tx input
        if (is_alloc && (ret == WALLY_OK)) {
          tx_pointer->inputs[tx_in_index].pegin_witness = stack_pointer;
          stack_pointer = nullptr;
        }
      } catch (...) {
        // internal error.
        warn(CFD_LOG_SOURCE, "system error.");
        ret = WALLY_ERROR;
      }

      if (is_alloc && stack_pointer) {
        wally_tx_witness_stack_free(stack_pointer);
      }
    }

    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "{} NG[{}].", function_name, ret);
      throw CfdException(kCfdIllegalStateError, "witness stack error.");
    }
  }
  SetElementsTxState();

  const ScriptWitness &witness =
      vin_[tx_in_index].AddPeginWitnessStack(ByteData(data));
  return witness;
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData &data) {
  return SetPeginWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData160 &data) {
  return SetPeginWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData256 &data) {
  return SetPeginWitnessStack(tx_in_index, witness_index, data.GetBytes());
}

const ScriptWitness ConfidentialTransaction::SetPeginWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index,
    const std::vector<uint8_t> &data) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    int ret = WALLY_EINVAL;
    struct wally_tx_witness_stack *stack_pointer = NULL;

    std::string function_name = "wally witness is NULL.";
    if (tx_pointer->inputs[tx_in_index].pegin_witness != NULL) {
      stack_pointer = tx_pointer->inputs[tx_in_index].pegin_witness;

      // append witness stack
      function_name = "wally_tx_witness_stack_set";
      if (data.empty()) {
        ret =
            wally_tx_witness_stack_set(stack_pointer, witness_index, NULL, 0);
      } else {
        ret = wally_tx_witness_stack_set(
            stack_pointer, witness_index, data.data(), data.size());
      }
    }

    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "{} NG[{}].", function_name, ret);
      throw CfdException(kCfdIllegalStateError, "witness stack set error.");
    }
  }
  SetElementsTxState();

  const ScriptWitness &witness =
      vin_[tx_in_index].SetPeginWitnessStack(witness_index, ByteData(data));
  return witness;
}

void ConfidentialTransaction::RemovePeginWitnessStackAll(
    uint32_t tx_in_index) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    if (tx_pointer->inputs[tx_in_index].pegin_witness != NULL) {
      struct wally_tx_witness_stack *stack_pointer;
      stack_pointer = tx_pointer->inputs[tx_in_index].pegin_witness;
      int ret = wally_tx_witness_stack_free(stack_pointer);
      tx_pointer->inputs[tx_in_index].pegin_witness = NULL;
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_free NG[{}].", ret);
        throw CfdException(
            kCfdIllegalStateError, "pegin witness stack error.");
      }
    }
  }
  SetElementsTxState();

  vin_[tx_in_index].RemovePeginWitnessStackAll();
}

IssuanceParameter ConfidentialTransaction::SetAssetIssuance(
    uint32_t tx_in_index, const Amount &asset_amount,
    const Script &asset_locking_script, const ConfidentialNonce &asset_nonce,
    const Amount &token_amount, const Script &token_locking_script,
    const ConfidentialNonce &token_nonce, bool is_blind,
    const ByteData256 &contract_hash) {
  std::vector<Amount> asset_output_amount_list;
  std::vector<Script> asset_locking_script_list;
  std::vector<ConfidentialNonce> asset_nonce_list;
  std::vector<Amount> token_output_amount_list;
  std::vector<Script> token_locking_script_list;
  std::vector<ConfidentialNonce> token_nonce_list;
  asset_output_amount_list.push_back(asset_amount);
  asset_locking_script_list.push_back(asset_locking_script);
  asset_nonce_list.push_back(asset_nonce);
  token_output_amount_list.push_back(token_amount);
  token_locking_script_list.push_back(token_locking_script);
  token_nonce_list.push_back(token_nonce);
  return SetAssetIssuance(
      tx_in_index, asset_amount, asset_output_amount_list,
      asset_locking_script_list, asset_nonce_list, token_amount,
      token_output_amount_list, token_locking_script_list, token_nonce_list,
      is_blind, contract_hash);
}

IssuanceParameter ConfidentialTransaction::SetAssetIssuance(
    uint32_t tx_in_index, const Amount &asset_amount,
    const std::vector<Amount> &asset_output_amount_list,
    const std::vector<Script> &asset_locking_script_list,
    const std::vector<ConfidentialNonce> &asset_nonce_list,
    const Amount &token_amount,
    const std::vector<Amount> &token_output_amount_list,
    const std::vector<Script> &token_locking_script_list,
    const std::vector<ConfidentialNonce> &token_nonce_list, bool is_blind,
    const ByteData256 &contract_hash) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  if ((vin_[tx_in_index].GetInflationKeys().GetData().GetDataSize() > 0) ||
      (vin_[tx_in_index].GetIssuanceAmount().GetData().GetDataSize() > 0)) {
    warn(CFD_LOG_SOURCE, "already set to issue parameter");
    throw CfdException(
        kCfdIllegalArgumentError, "already set to issue parameter");
  }
  if ((asset_amount.GetSatoshiValue() <= 0) &&
      (token_amount.GetSatoshiValue() <= 0)) {
    warn(CFD_LOG_SOURCE, "Issuance must have one non-zero amount.");
    throw CfdException(
        kCfdIllegalArgumentError, "Issuance must have one non-zero amount.");
  }
  if (asset_output_amount_list.empty() != asset_locking_script_list.empty()) {
    warn(
        CFD_LOG_SOURCE,
        "Unmatch count. asset amount list and locking script list.");
    throw CfdException(
        kCfdIllegalArgumentError,
        "Unmatch count. asset amount list and locking script list.");
  }
  if (!asset_output_amount_list.empty()) {
    Amount total;
    for (const auto &amount : asset_output_amount_list) {
      total += amount;
    }
    if (total != asset_amount) {
      warn(CFD_LOG_SOURCE, "Unmatch asset amount.");
      throw CfdException(kCfdIllegalArgumentError, "Unmatch asset amount.");
    }
    for (const auto &script : asset_locking_script_list) {
      if (script.IsEmpty()) {
        warn(CFD_LOG_SOURCE, "Empty locking script from asset.");
        throw CfdException(
            kCfdIllegalArgumentError, "Empty locking script from asset.");
      }
    }
  }
  if (token_output_amount_list.empty() != token_locking_script_list.empty()) {
    warn(
        CFD_LOG_SOURCE,
        "Unmatch count. token amount list and locking script list.");
    throw CfdException(
        kCfdIllegalArgumentError,
        "Unmatch count. token amount list and locking script list.");
  }
  if (!token_output_amount_list.empty()) {
    Amount total;
    for (const auto &amount : token_output_amount_list) {
      total += amount;
    }
    if (total != token_amount) {
      warn(CFD_LOG_SOURCE, "Unmatch token amount.");
      throw CfdException(kCfdIllegalArgumentError, "Unmatch token amount.");
    }
    for (const auto &script : token_locking_script_list) {
      if (script.IsEmpty()) {
        warn(CFD_LOG_SOURCE, "Empty locking script from token.");
        throw CfdException(
            kCfdIllegalArgumentError, "Empty locking script from token.");
      }
    }
  }

  IssuanceParameter param = CalculateIssuanceValue(
      vin_[tx_in_index].GetTxid(), vin_[tx_in_index].GetVout(), is_blind,
      contract_hash, ByteData256());
  SetIssuance(
      tx_in_index, ByteData256(), contract_hash,
      ConfidentialValue(asset_amount), ConfidentialValue(token_amount),
      ByteData(), ByteData());

  if ((!asset_output_amount_list.empty()) &&
      (asset_amount.GetSatoshiValue() > 0)) {
    for (size_t index = 0; index < asset_output_amount_list.size(); ++index) {
      ConfidentialNonce nonce;
      if (index < asset_nonce_list.size()) nonce = asset_nonce_list[index];
      AddTxOut(
          asset_output_amount_list[index], param.asset,
          asset_locking_script_list[index], nonce);
    }
  }
  if ((!token_output_amount_list.empty()) &&
      (token_amount.GetSatoshiValue() > 0)) {
    for (size_t index = 0; index < token_output_amount_list.size(); ++index) {
      ConfidentialNonce nonce;
      if (index < token_nonce_list.size()) nonce = token_nonce_list[index];
      AddTxOut(
          token_output_amount_list[index], param.token,
          token_locking_script_list[index], nonce);
    }
  }

  return param;
}

IssuanceParameter ConfidentialTransaction::SetAssetReissuance(
    uint32_t tx_in_index, const Amount &asset_amount,
    const Script &asset_locking_script,
    const ConfidentialNonce &asset_blind_nonce,
    const BlindFactor &asset_blind_factor, const BlindFactor &entropy) {
  std::vector<Amount> asset_output_amount_list;
  std::vector<Script> asset_locking_script_list;
  std::vector<ConfidentialNonce> asset_blind_nonce_list;
  asset_output_amount_list.push_back(asset_amount);
  asset_locking_script_list.push_back(asset_locking_script);
  asset_blind_nonce_list.push_back(asset_blind_nonce);
  return SetAssetReissuance(
      tx_in_index, asset_amount, asset_output_amount_list,
      asset_locking_script_list, asset_blind_nonce_list, asset_blind_factor,
      entropy);
}

IssuanceParameter ConfidentialTransaction::SetAssetReissuance(
    uint32_t tx_in_index, const Amount &asset_amount,
    const std::vector<Amount> &asset_output_amount_list,
    const std::vector<Script> &asset_locking_script_list,
    const std::vector<ConfidentialNonce> &asset_blind_nonce_list,
    const BlindFactor &asset_blind_factor, const BlindFactor &entropy) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  if ((vin_[tx_in_index].GetInflationKeys().GetData().GetDataSize() > 0) ||
      (vin_[tx_in_index].GetIssuanceAmount().GetData().GetDataSize() > 0)) {
    warn(CFD_LOG_SOURCE, "already set to reissue parameter");
    throw CfdException(
        kCfdIllegalArgumentError, "already set to reissue parameter");
  }

  if (asset_amount.GetSatoshiValue() <= 0) {
    warn(CFD_LOG_SOURCE, "ReIssuance must have one non-zero amount.");
    throw CfdException(
        kCfdIllegalArgumentError, "ReIssuance must have one non-zero amount.");
  }
  if (asset_output_amount_list.empty() != asset_locking_script_list.empty()) {
    warn(
        CFD_LOG_SOURCE,
        "Unmatch count. asset amount list and locking script list.");
    throw CfdException(
        kCfdIllegalArgumentError,
        "Unmatch count. asset amount list and locking script list.");
  }
  if (!asset_output_amount_list.empty()) {
    Amount total;
    for (const auto &amount : asset_output_amount_list) {
      total += amount;
    }
    if (total != asset_amount) {
      warn(CFD_LOG_SOURCE, "Unmatch asset amount.");
      throw CfdException(kCfdIllegalArgumentError, "Unmatch asset amount.");
    }
    for (const auto &script : asset_locking_script_list) {
      if (script.IsEmpty()) {
        warn(CFD_LOG_SOURCE, "Empty locking script from asset.");
        throw CfdException(
            kCfdIllegalArgumentError, "Empty locking script from asset.");
      }
    }
  }

  std::vector<uint8_t> asset(kAssetSize);
  int ret = wally_tx_elements_issuance_calculate_asset(
      entropy.GetData().GetBytes().data(), entropy.GetData().GetBytes().size(),
      asset.data(), asset.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_elements_issuance_calculate_asset NG[{}].",
        ret);
    throw CfdException(kCfdIllegalStateError, "asset calculate error.");
  }

  IssuanceParameter param;
  param.entropy = entropy;
  param.asset = ConfidentialAssetId(ByteData(asset));
  SetIssuance(
      tx_in_index, asset_blind_factor.GetData(), entropy.GetData(),
      ConfidentialValue(asset_amount), ConfidentialValue(), ByteData(),
      ByteData());

  if ((!asset_output_amount_list.empty()) &&
      (asset_amount.GetSatoshiValue() > 0)) {
    for (size_t index = 0; index < asset_output_amount_list.size(); ++index) {
      ConfidentialNonce nonce;
      if (index < asset_blind_nonce_list.size()) {
        nonce = asset_blind_nonce_list[index];
      }
      AddTxOut(
          asset_output_amount_list[index], param.asset,
          asset_locking_script_list[index], nonce);
    }
  }
  return param;
}

BlindFactor ConfidentialTransaction::CalculateAssetEntropy(
    const Txid &txid, const uint32_t vout, const ByteData256 &contract_hash) {
  const std::vector<uint8_t> &txid_byte = txid.GetData().GetBytes();
  const std::vector<uint8_t> &contract_hash_byte = contract_hash.GetBytes();
  std::vector<uint8_t> entropy(kEntropySize);

  int ret = wally_tx_elements_issuance_generate_entropy(
      txid_byte.data(), txid_byte.size(), vout, contract_hash_byte.data(),
      contract_hash_byte.size(), entropy.data(), entropy.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_elements_issuance_generate_entropy NG[{}].",
        ret);
    throw CfdException(kCfdIllegalStateError, "entropy generate error.");
  }

  return BlindFactor(ByteData256(entropy));
}

ConfidentialAssetId ConfidentialTransaction::CalculateAsset(
    const BlindFactor &entropy) {
  const std::vector<uint8_t> &entropy_byte = entropy.GetData().GetBytes();

  std::vector<uint8_t> asset(kAssetSize);
  int ret = wally_tx_elements_issuance_calculate_asset(
      entropy_byte.data(), entropy_byte.size(), asset.data(), asset.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_elements_issuance_calculate_asset NG[{}].",
        ret);
    throw CfdException(kCfdIllegalStateError, "asset calculate error.");
  }

  return ConfidentialAssetId(ByteData(asset));
}

ConfidentialAssetId ConfidentialTransaction::CalculateReissuanceToken(
    const BlindFactor &entropy, bool is_blind) {
  const std::vector<uint8_t> &entropy_byte = entropy.GetData().GetBytes();

  std::vector<uint8_t> token(kAssetSize);
  uint32_t flag = (is_blind) ? WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE : 0;
  int ret = wally_tx_elements_issuance_calculate_reissuance_token(
      entropy_byte.data(), entropy_byte.size(), flag, token.data(),
      token.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "wally_tx_elements_issuance_calculate_reissuance_token NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "token calculate error.");
  }

  return ConfidentialAssetId(ByteData(token));
}

IssuanceParameter ConfidentialTransaction::CalculateIssuanceValue(
    const Txid &txid, uint32_t vout, bool is_blind,
    const ByteData256 &contract_hash, const ByteData256 &asset_entropy) {
  IssuanceParameter result;

  if (!asset_entropy.Equals(kEmptyByteData256)) {
    // reissue
    result.entropy = BlindFactor(contract_hash);
    result.asset = CalculateAsset(
        result.entropy);  // ConfidentialAssetId(ByteData(asset));
    return result;
  }

  // calculate issue value
  const BlindFactor entropy = CalculateAssetEntropy(txid, vout, contract_hash);
  result.entropy = entropy;

  // calculate asset value
  const ConfidentialAssetId asset = CalculateAsset(entropy);
  result.asset = asset;

  // calculate token
  const ConfidentialAssetId token =
      CalculateReissuanceToken(entropy, is_blind);
  result.token = token;

  info(
      CFD_LOG_SOURCE, "asset[{}] token[{}] is_blind[{}]",
      result.asset.GetHex(), result.token.GetHex(), is_blind);
  return result;
}

const ConfidentialTxOutReference ConfidentialTransaction::GetTxOut(
    uint32_t index) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  return ConfidentialTxOutReference(vout_[index]);
}

uint32_t ConfidentialTransaction::GetTxOutCount() const {
  return static_cast<uint32_t>(vout_.size());
}

const std::vector<ConfidentialTxOutReference>  // force LF
ConfidentialTransaction::GetTxOutList() const {
  std::vector<ConfidentialTxOutReference> refs;
  for (ConfidentialTxOut tx_out : vout_) {
    refs.push_back(ConfidentialTxOutReference(tx_out));
  }
  return refs;
}

uint32_t ConfidentialTransaction::AddTxOut(
    const Amount &value, const ConfidentialAssetId &asset,
    const Script &locking_script) {
  return AddTxOut(
      value, asset, locking_script, ConfidentialNonce(), ByteData(),
      ByteData());
}

uint32_t ConfidentialTransaction::AddTxOut(
    const Amount &value, const ConfidentialAssetId &asset,
    const Script &locking_script, const ConfidentialNonce &nonce) {
  return AddTxOut(value, asset, locking_script, nonce, ByteData(), ByteData());
}

uint32_t ConfidentialTransaction::AddTxOut(
    const Amount &value, const ConfidentialAssetId &asset,
    const Script &locking_script, const ConfidentialNonce &nonce,
    const ByteData &surjection_proof, const ByteData &range_proof) {
  if (vout_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vout maximum.");
    throw CfdException(kCfdIllegalStateError, "vout maximum.");
  }

  ConfidentialValue confidential_value = ConfidentialValue(value);
  const std::vector<uint8_t> &script_data =
      locking_script.GetData().GetBytes();
  const std::vector<uint8_t> &asset_data = asset.GetData().GetBytes();
  const std::vector<uint8_t> &value_data =
      confidential_value.GetData().GetBytes();
  const std::vector<uint8_t> &nonce_data = nonce.GetData().GetBytes();
  const std::vector<uint8_t> &surjection_data = surjection_proof.GetBytes();
  const std::vector<uint8_t> &range_data = range_proof.GetBytes();

  int ret = wally_tx_add_elements_raw_output(
      static_cast<struct wally_tx *>(wally_tx_pointer_), script_data.data(),
      script_data.size(), asset_data.data(), asset_data.size(),
      value_data.data(), value_data.size(),
      (nonce_data.size() == 0) ? nullptr : nonce_data.data(),
      nonce_data.size(),
      (surjection_data.size() == 0) ? nullptr : surjection_data.data(),
      surjection_data.size(),
      (range_data.size() == 0) ? nullptr : range_data.data(),
      range_data.size(), 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_elements_raw_output NG[{}].", ret);
    warn(CFD_LOG_SOURCE, "script_data.size[{}].", script_data.size());
    warn(CFD_LOG_SOURCE, "asset_data.size[{}].", asset_data.size());
    warn(CFD_LOG_SOURCE, "value_data.size[{}].", value_data.size());
    warn(CFD_LOG_SOURCE, "nonce_data.size[{}].", nonce_data.size());
    warn(CFD_LOG_SOURCE, "surjection_data.size[{}].", surjection_data.size());
    warn(CFD_LOG_SOURCE, "range_data.size[{}].", range_data.size());
    throw CfdException(kCfdIllegalStateError, "vout add error.");
  }

  ConfidentialTxOut out(
      locking_script, asset, confidential_value, nonce, surjection_proof,
      range_proof);
  out.SetValue(value);
  vout_.push_back(out);
  return static_cast<uint32_t>(vout_.size() - 1);
}

uint32_t ConfidentialTransaction::AddTxOutFee(
    const Amount &value, const ConfidentialAssetId &asset) {
  if (vout_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vout maximum.");
    throw CfdException(kCfdIllegalStateError, "vout maximum.");
  }

  ConfidentialValue confidential_value = ConfidentialValue(value);
  const std::vector<uint8_t> &asset_data = asset.GetData().GetBytes();
  const std::vector<uint8_t> &value_data =
      confidential_value.GetData().GetBytes();

  int ret = wally_tx_add_elements_raw_output(
      static_cast<struct wally_tx *>(wally_tx_pointer_), nullptr, 0,
      asset_data.data(), asset_data.size(), value_data.data(),
      value_data.size(), nullptr, 0, nullptr, 0, nullptr, 0, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_raw_output NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "vout fee add error.");
  }

  ConfidentialTxOut out(asset, confidential_value);
  vout_.push_back(out);
  return static_cast<uint32_t>(vout_.size() - 1);
}

void ConfidentialTransaction::SetTxOutCommitment(
    uint32_t index, const ConfidentialAssetId &asset,
    const ConfidentialValue &value, const ConfidentialNonce &nonce,
    const ByteData &surjection_proof, const ByteData &range_proof) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);

  const std::vector<uint8_t> &asset_data = asset.GetData().GetBytes();
  const std::vector<uint8_t> &value_data = value.GetData().GetBytes();
  const std::vector<uint8_t> &nonce_data = nonce.GetData().GetBytes();
  const std::vector<uint8_t> &surjection_data = surjection_proof.GetBytes();
  const std::vector<uint8_t> &range_data = range_proof.GetBytes();

  struct wally_tx *tx = static_cast<struct wally_tx *>(wally_tx_pointer_);
  int ret = wally_tx_elements_output_commitment_set(
      &tx->outputs[index], asset_data.data(), asset_data.size(),
      value_data.data(), value_data.size(), nonce_data.data(),
      nonce_data.size(), surjection_data.data(), surjection_data.size(),
      range_data.data(), range_data.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_elements_output_commitment_set NG[{}].",
        ret);
    throw CfdException(kCfdIllegalStateError, "set commitment error.");
  }

  vout_[index].SetCommitment(
      asset, value, nonce, surjection_proof, range_proof);
}

void ConfidentialTransaction::RemoveTxOut(uint32_t index) {
  AbstractTransaction::RemoveTxOut(index);

  std::vector<ConfidentialTxOut>::const_iterator ite = vout_.cbegin();
  if (index != 0) {
    ite += index;
  }
  vout_.erase(ite);
}

void ConfidentialTransaction::BlindTransaction(
    const std::vector<BlindParameter> &txin_info_list,
    const std::vector<IssuanceBlindingKeyPair> &issuance_blinding_keys,
    const std::vector<Pubkey> &txout_confidential_keys,
    int64_t minimum_range_value, int exponent, int minimum_bits) {
  std::vector<uint64_t> input_values;
  std::vector<uint8_t> input_generators;  // serialize
  std::vector<uint8_t> input_asset_ids;   // serialize
  std::vector<uint8_t> abfs;              // serialize
  std::vector<uint8_t> vbfs;              // serialize
  std::vector<uint8_t> input_abfs;        // serialize
  std::vector<uint8_t> empty_factor(kBlindFactorSize);
  uint32_t blinded_txin_count = 0;
  size_t blind_target_count = 0;
  std::vector<size_t> blind_issuance_indexes;
  std::vector<size_t> blind_txout_indexes;
  int ret;
  memset(empty_factor.data(), 0, empty_factor.size());

  if (vin_.size() > txin_info_list.size()) {
    warn(
        CFD_LOG_SOURCE, "txin_info_list few count. [{},{}].", vin_.size(),
        txin_info_list.size());
    throw CfdException(kCfdIllegalStateError, "txin_info_list few error.");
  }
  if (vout_.size() > txout_confidential_keys.size()) {
    warn(
        CFD_LOG_SOURCE, "txout_confidential_keys few count. [{},{}].",
        vout_.size(), txout_confidential_keys.size());
    throw CfdException(
        kCfdIllegalStateError, "txout_confidential_keys few error.");
  }

  for (size_t index = 0; index < txin_info_list.size(); ++index) {
    const BlindParameter &param = txin_info_list[index];
    const std::vector<uint8_t> &asset_id =
        param.asset.GetUnblindedData().GetBytes();
    const std::vector<uint8_t> &abf = param.abf.GetData().GetBytes();
    std::vector<uint8_t> generator(ASSET_GENERATOR_LEN);
    ret = wally_asset_generator_from_bytes(
        asset_id.data(), asset_id.size(), abf.data(), abf.size(),
        generator.data(), generator.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
      throw CfdException(kCfdIllegalStateError, "asset generator error.");
    }
    input_generators.insert(
        input_generators.end(), std::begin(generator), std::end(generator));
    input_asset_ids.insert(
        input_asset_ids.end(), std::begin(asset_id), std::end(asset_id));
    info(CFD_LOG_SOURCE, "input asset=[{}]", ByteData(asset_id).GetHex());
    input_abfs.insert(input_abfs.end(), std::begin(abf), std::end(abf));
    const std::vector<uint8_t> &vbf = param.vbf.GetData().GetBytes();

    const Amount &amount = param.value.GetAmount();
    if (amount.GetSatoshiValue() < 0) {
      warn(
          CFD_LOG_SOURCE, "satoshi under zero. [{}].",
          amount.GetSatoshiValue());
      throw CfdException(kCfdIllegalStateError, "satoshi under zero.");
    }
    if ((abf != empty_factor) || (vbf != empty_factor)) {
      ++blinded_txin_count;
      input_values.push_back(amount.GetSatoshiValue());
      abfs.insert(abfs.end(), std::begin(abf), std::end(abf));
      vbfs.insert(vbfs.end(), std::begin(vbf), std::end(vbf));
    }

    if (((!vin_[index].GetIssuanceAmount().IsEmpty()) ||
         (!vin_[index].GetInflationKeys().IsEmpty()))) {
      if (vin_[index].GetIssuanceAmount().HasBlinding() ||
          vin_[index].GetInflationKeys().HasBlinding()) {
        warn(CFD_LOG_SOURCE, "already txin blinded.");
        throw CfdException(kCfdIllegalStateError, "already txin blinded.");
      }

      bool asset_blind = false;
      bool token_blind = false;
      if ((!issuance_blinding_keys.empty()) &&
          (issuance_blinding_keys.size() > index)) {
        asset_blind = issuance_blinding_keys[index].asset_key.IsValid();
        token_blind = issuance_blinding_keys[index].token_key.IsValid();
      }
      IssuanceParameter issue = CalculateIssuanceValue(
          vin_[index].GetTxid(), vin_[index].GetVout(), token_blind,
          vin_[index].GetAssetEntropy(), vin_[index].GetBlindingNonce());
      info(
          CFD_LOG_SOURCE, "input issue asset=[{}] token=[{}] token_blind=[{}]",
          issue.asset.GetHex(), issue.token.GetHex(), token_blind);
      bool is_reissue =
          !vin_[index].GetBlindingNonce().Equals(kEmptyByteData256);

      if (!vin_[index].GetIssuanceAmount().IsEmpty()) {
        const std::vector<uint8_t> &asset_bytes =
            issue.asset.GetUnblindedData().GetBytes();
        input_asset_ids.insert(
            input_asset_ids.end(), std::begin(asset_bytes),
            std::end(asset_bytes));
        std::vector<uint8_t> asset_generator(ASSET_GENERATOR_LEN);
        ret = wally_asset_generator_from_bytes(
            asset_bytes.data(), asset_bytes.size(), empty_factor.data(),
            empty_factor.size(), asset_generator.data(),
            asset_generator.size());
        if (ret != WALLY_OK) {
          warn(
              CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
          throw CfdException(
              kCfdIllegalStateError, "issue asset generator error.");
        }
        ByteData generator_data(asset_generator);
        input_generators.insert(
            input_generators.end(), std::begin(asset_generator),
            std::end(asset_generator));
        // empty factor
        input_abfs.insert(
            input_abfs.end(), std::begin(empty_factor),
            std::end(empty_factor));
        info(
            CFD_LOG_SOURCE, "generator_data asset=[{}]",
            generator_data.GetHex());
      }
      if ((!is_reissue) && (!vin_[index].GetInflationKeys().IsEmpty())) {
        const std::vector<uint8_t> &token_bytes =
            issue.token.GetUnblindedData().GetBytes();
        input_asset_ids.insert(
            input_asset_ids.end(), std::begin(token_bytes),
            std::end(token_bytes));
        std::vector<uint8_t> token_generator(ASSET_GENERATOR_LEN);
        ret = wally_asset_generator_from_bytes(
            token_bytes.data(), token_bytes.size(), empty_factor.data(),
            empty_factor.size(), token_generator.data(),
            token_generator.size());
        if (ret != WALLY_OK) {
          warn(
              CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
          throw CfdException(
              kCfdIllegalStateError, "token asset generator error.");
        }
        ByteData generator_data(token_generator);
        input_generators.insert(
            input_generators.end(), std::begin(token_generator),
            std::end(token_generator));
        // empty factor
        input_abfs.insert(
            input_abfs.end(), std::begin(empty_factor),
            std::end(empty_factor));
        info(
            CFD_LOG_SOURCE, "generator_data token=[{}]",
            generator_data.GetHex());
      }
      // Marked for blinding
      if (asset_blind) {
        if (vin_[index].GetIssuanceAmount().HasBlinding() ||
            (vin_[index].GetIssuanceAmountRangeproof().GetDataSize() > 0)) {
          warn(CFD_LOG_SOURCE, "already txin asset blinded.");
          throw CfdException(
              kCfdIllegalStateError, "already txin asset blinded.");
        }
        ++blind_target_count;
      }
      if ((!is_reissue) && token_blind) {
        if (vin_[index].GetInflationKeys().HasBlinding() ||
            (vin_[index].GetInflationKeysRangeproof().GetDataSize() > 0)) {
          warn(CFD_LOG_SOURCE, "already txin token blinded.");
          throw CfdException(
              kCfdIllegalStateError, "already txin token blinded.");
        }
        ++blind_target_count;
      }
      if (asset_blind || token_blind) {
        blind_issuance_indexes.push_back(index);
      }
    }
  }
  info(
      CFD_LOG_SOURCE, "txin blind_target_count={} blinded_txin_count={}",
      blind_target_count, blinded_txin_count);

  // check of SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS
  size_t surjectionproofInputNum = input_asset_ids.size() / kAssetSize;
  if (Secp256k1::GetSurjectionproofInputLimit() < surjectionproofInputNum) {
    warn(
        CFD_LOG_SOURCE, "blind input count over. count[{}] limit[{}]",
        surjectionproofInputNum, Secp256k1::GetSurjectionproofInputLimit());
    throw CfdException(
        kCfdIllegalStateError,
        "blind input count over.(for SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS)");
  }

  for (const size_t index : blind_issuance_indexes) {
    bool asset_blind = false;
    bool token_blind = false;
    if ((!issuance_blinding_keys.empty()) &&
        (issuance_blinding_keys.size() > index)) {
      asset_blind = issuance_blinding_keys[index].asset_key.IsValid();
      token_blind = issuance_blinding_keys[index].token_key.IsValid();
    }
    IssuanceParameter issue = CalculateIssuanceValue(
        vin_[index].GetTxid(), vin_[index].GetVout(), token_blind,
        vin_[index].GetAssetEntropy(), vin_[index].GetBlindingNonce());
    bool is_reissue =
        !vin_[index].GetBlindingNonce().Equals(kEmptyByteData256);
    ConfidentialTxIn txin = vin_[index];
    std::vector<uint8_t> commitment(ASSET_COMMITMENT_LEN);
    std::vector<uint8_t> range_proof(ASSET_RANGEPROOF_MAX_LEN);

    if (asset_blind) {
      const Amount &amount = vin_[index].GetIssuanceAmount().GetAmount();
      int64_t value = amount.GetSatoshiValue();
      input_values.push_back(value);
      const std::vector<uint8_t> &vbf =
          RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
      vbfs.insert(vbfs.end(), std::begin(vbf), std::end(vbf));
      abfs.insert(
          abfs.end(), std::begin(empty_factor), std::end(empty_factor));

      GetRangeProof(
          static_cast<uint64_t>(value), nullptr,
          issuance_blinding_keys[index].asset_key, issue.asset, empty_factor,
          vbf, Script(), minimum_range_value, exponent, minimum_bits,
          &commitment, &range_proof);

      txin.SetIssuance(
          txin.GetBlindingNonce(), txin.GetAssetEntropy(),
          ConfidentialValue(ByteData(commitment)), txin.GetInflationKeys(),
          ByteData(range_proof), txin.GetInflationKeysRangeproof());
    }

    if (token_blind) {
      const Amount &amount = vin_[index].GetInflationKeys().GetAmount();
      int64_t value = amount.GetSatoshiValue();

      if (!is_reissue) {
        input_values.push_back(value);

        const std::vector<uint8_t> &vbf =
            RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
        vbfs.insert(vbfs.end(), std::begin(vbf), std::end(vbf));
        abfs.insert(
            abfs.end(), std::begin(empty_factor), std::end(empty_factor));

        GetRangeProof(
            static_cast<uint64_t>(value), nullptr,
            issuance_blinding_keys[index].token_key, issue.token, empty_factor,
            vbf, Script(), minimum_range_value, exponent, minimum_bits,
            &commitment, &range_proof);

        txin.SetIssuance(
            txin.GetBlindingNonce(), txin.GetAssetEntropy(),
            txin.GetIssuanceAmount(), ConfidentialValue(ByteData(commitment)),
            txin.GetIssuanceAmountRangeproof(), ByteData(range_proof));
      }
    }

    SetIssuance(
        static_cast<uint32_t>(index), txin.GetBlindingNonce(),
        txin.GetAssetEntropy(), txin.GetIssuanceAmount(),
        txin.GetInflationKeys(), txin.GetIssuanceAmountRangeproof(),
        txin.GetInflationKeysRangeproof());
  }
  size_t input_blind_amount_count = input_values.size();

  std::vector<Pubkey> input_confidential_keys(vout_.size());
  for (size_t index = 0; index < vout_.size(); ++index) {
    if (vout_[index].GetLockingScript().IsEmpty()) {
      // fee
    } else if (txout_confidential_keys[index].IsValid()) {
      const ConfidentialValue &value = vout_[index].GetConfidentialValue();
      if (value.HasBlinding() || vout_[index].GetAsset().HasBlinding()) {
        warn(CFD_LOG_SOURCE, "already blinded vout. index={}", index);
        throw CfdException(
            kCfdIllegalStateError, "already blinded vout error.");
      }
      Amount temp_amount = value.GetAmount();
      input_values.push_back(temp_amount.GetSatoshiValue());
      blind_txout_indexes.push_back(index);
      input_confidential_keys[index] =
          txout_confidential_keys[index].Compress();
    }
  }
  blind_target_count += blind_txout_indexes.size();
  if ((blinded_txin_count == 0) && (blind_target_count <= 1)) {
    // elements: if (num_blind_attempts == 1 && num_known_input_blinds == 0)
    warn(
        CFD_LOG_SOURCE, "blind target few({}). set over 2.",
        blind_target_count);
    throw CfdException(kCfdIllegalArgumentError, "blind target few error.");
  }
  info(CFD_LOG_SOURCE, "total blind_target_count=[{}]", blind_target_count);
  if (blind_txout_indexes.empty()) {
    // txout blind data nothing.
    return;
  }

  std::vector<ByteData> output_abfs(blind_txout_indexes.size());
  std::vector<ByteData> output_vbfs(blind_txout_indexes.size() - 1);

  for (size_t index = 0; index < output_abfs.size(); ++index) {
    const std::vector<uint8_t> &data =
        RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
    output_abfs[index] = ByteData(data);
    abfs.insert(abfs.end(), std::begin(data), std::end(data));
  }

  for (size_t index = 0; index < output_vbfs.size(); ++index) {
    const std::vector<uint8_t> &data =
        RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
    output_vbfs[index] = ByteData(data);
    vbfs.insert(vbfs.end(), std::begin(data), std::end(data));
  }

  info(
      CFD_LOG_SOURCE, "n_total[{}] n_inputs[{}]", input_values.size(),
      input_blind_amount_count);
  std::vector<uint8_t> asset_data(kAssetSize);
  ret = wally_asset_final_vbf(
      input_values.data(), input_values.size(), input_blind_amount_count,
      abfs.data(), abfs.size(), vbfs.data(), vbfs.size(), asset_data.data(),
      asset_data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_final_vbf NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "asset value blind factor error.");
  }
  output_vbfs.push_back(ByteData(asset_data));

  uint32_t count = 0;
  std::vector<uint8_t> commitment(ASSET_COMMITMENT_LEN);
  std::vector<uint8_t> range_proof(ASSET_RANGEPROOF_MAX_LEN);
  for (const size_t txout_index : blind_txout_indexes) {
    const auto &output = vout_[txout_index];
    Amount amount = output.GetConfidentialValue().GetAmount();
    uint64_t value = static_cast<uint64_t>(amount.GetSatoshiValue());
    ConfidentialAssetId output_asset_id(output.GetAsset());
    const std::vector<uint8_t> &abf = output_abfs[count].GetBytes();

    Privkey key = Privkey::GenerageRandomKey();
    ByteData gen = GetRangeProof(
        value, &input_confidential_keys[txout_index], key, output_asset_id,
        abf, output_vbfs[count].GetBytes(), output.GetLockingScript(),
        minimum_range_value, exponent, minimum_bits, &commitment,
        &range_proof);
    const std::vector<uint8_t> &generator = gen.GetBytes();

    size_t size = 0;
    ret = wally_asset_surjectionproof_size(
        input_asset_ids.size() / kAssetSize, &size);
    if (ret != WALLY_OK) {
      warn(
          CFD_LOG_SOURCE, "wally_asset_surjectionproof_size NG[{}] index={}",
          ret, txout_index);
      throw CfdException(
          kCfdIllegalStateError, "calc asset surjectionproof size error.");
    }
    std::vector<uint8_t> surjection_proof(size);

    std::vector<uint8_t> entropy;
    uint8_t retry_count = 0;
    const std::vector<uint8_t> &asset_bytes =
        output_asset_id.GetUnblindedData().GetBytes();
    do {
      entropy = RandomNumberUtil::GetRandomBytes(kBlindFactorSize);
      ret = wally_asset_surjectionproof(
          asset_bytes.data(), asset_bytes.size(), abf.data(), abf.size(),
          generator.data(), generator.size(), entropy.data(), entropy.size(),
          input_asset_ids.data(), input_asset_ids.size(), input_abfs.data(),
          input_abfs.size(), input_generators.data(), input_generators.size(),
          surjection_proof.data(), surjection_proof.size(), &size);
      ++retry_count;
    } while ((ret == WALLY_ERROR) && (retry_count < 20));
    if (ret != WALLY_OK) {
      warn(
          CFD_LOG_SOURCE, "wally_asset_surjectionproof NG[{}] index={}", ret,
          txout_index);
      throw CfdException(
          kCfdIllegalStateError, "calc asset surjectionproof error.");
    }
    surjection_proof.resize(size);

    SetTxOutCommitment(
        static_cast<uint32_t>(txout_index),
        ConfidentialAssetId(ByteData(generator)),
        ConfidentialValue(ByteData(commitment)),
        ConfidentialNonce(key.GeneratePubkey().GetData()),
        ByteData(surjection_proof), ByteData(range_proof));
    ++count;
  }
}

void ConfidentialTransaction::BlindTxOut(
    const std::vector<BlindParameter> &txin_info_list,
    const std::vector<Pubkey> &txout_confidential_keys,
    int64_t minimum_range_value, int exponent, int minimum_bits) {
  BlindTransaction(
      txin_info_list, std::vector<IssuanceBlindingKeyPair>(),
      txout_confidential_keys, minimum_range_value, exponent, minimum_bits);
}

ByteData ConfidentialTransaction::GetRangeProof(
    const uint64_t value, const Pubkey *pubkey, const Privkey &privkey,
    const ConfidentialAssetId &asset, const std::vector<uint8_t> &abf,
    const std::vector<uint8_t> &vbf, const Script &script,
    int64_t minimum_range_value, int exponent, int minimum_bits,
    std::vector<uint8_t> *commitment, std::vector<uint8_t> *range_proof) {
  return CalculateRangeProof(
      value, pubkey, privkey, asset, abf, vbf, script, minimum_range_value,
      exponent, minimum_bits, commitment, range_proof);
}

std::vector<UnblindParameter> ConfidentialTransaction::UnblindTxIn(
    uint32_t tx_in_index, const Privkey &blinding_key,
    const Privkey token_blinding_key) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  ConfidentialTxIn tx_in(vin_[tx_in_index]);
  if (((!tx_in.GetIssuanceAmount().HasBlinding()) &&
       (!tx_in.GetInflationKeys().HasBlinding())) ||
      ((tx_in.GetIssuanceAmountRangeproof().GetDataSize() == 0) &&
       (tx_in.GetInflationKeysRangeproof().GetDataSize() == 0))) {
    warn(
        CFD_LOG_SOURCE,
        "Failed to unblind TxIn. Target TxIn already unblinded.: "
        "tx_in_index=[{}]",
        tx_in_index);
    throw CfdException(
        kCfdIllegalStateError,
        "Failed to unblind TxIn. Target TxIn already unblinded.");
  }

  IssuanceParameter issue = CalculateIssuanceValue(
      tx_in.GetTxid(), tx_in.GetVout(), true, tx_in.GetAssetEntropy(),
      tx_in.GetBlindingNonce());

  ByteData amount_rangeproof = tx_in.GetIssuanceAmountRangeproof();
  ByteData token_rangeproof = tx_in.GetInflationKeysRangeproof();

  UnblindParameter asset_unblind;
  UnblindParameter token_unblind;

  if (tx_in.GetIssuanceAmount().HasBlinding()) {
    asset_unblind = CalculateUnblindIssueData(
        blinding_key, amount_rangeproof, tx_in.GetIssuanceAmount(), Script(),
        issue.asset);
    amount_rangeproof = ByteData();
  }

  if (tx_in.GetInflationKeysRangeproof().GetDataSize() != 0) {
    if (tx_in.GetInflationKeys().HasBlinding()) {
      token_unblind = CalculateUnblindIssueData(
          (token_blinding_key.IsValid()) ? token_blinding_key : blinding_key,
          token_rangeproof, tx_in.GetInflationKeys(), Script(), issue.token);
      token_rangeproof = ByteData();
    }
  }

  // clear and set unblind value to txin
  SetIssuance(
      tx_in_index, tx_in.GetBlindingNonce(), tx_in.GetAssetEntropy(),
      asset_unblind.value, token_unblind.value, amount_rangeproof,
      token_rangeproof);
  std::vector<UnblindParameter> result;
  result.push_back(asset_unblind);
  result.push_back(token_unblind);

  return result;
}

UnblindParameter ConfidentialTransaction::UnblindTxOut(
    uint32_t tx_out_index, const Privkey &blinding_key) {
  CheckTxOutIndex(tx_out_index, __LINE__, __FUNCTION__);

  ConfidentialTxOut tx_out(vout_[tx_out_index]);
  if (!tx_out.GetAsset().HasBlinding() || !tx_out.GetNonce().HasBlinding() ||
      !tx_out.GetConfidentialValue().HasBlinding() ||
      (tx_out.GetRangeProof().GetDataSize() == 0) ||
      (tx_out.GetSurjectionProof().GetDataSize() == 0)) {
    warn(
        CFD_LOG_SOURCE,
        "Failed to unblind TxOut. Target TxOut already unblinded.: "
        "tx_out_index=[{}]",
        tx_out_index);
    throw CfdException(
        kCfdIllegalStateError,
        "Failed to unblind TxOut. Target TxOut already unblinded.");
  }

  UnblindParameter result = CalculateUnblindData(
      tx_out.GetNonce(), blinding_key, tx_out.GetRangeProof(),
      tx_out.GetConfidentialValue(), tx_out.GetLockingScript(),
      tx_out.GetAsset());

  // clear and set unblind value to txout
  SetTxOutCommitment(
      tx_out_index, result.asset, result.value, ConfidentialNonce(),
      ByteData(), ByteData());

  return result;
}

std::vector<UnblindParameter> ConfidentialTransaction::UnblindTxOut(
    const std::vector<Privkey> &blinding_keys) {
  // validate input vector size
  if (vout_.size() != blinding_keys.size()) {
    warn(
        CFD_LOG_SOURCE,
        "Unmatch size blinding_keys and txouts.:"
        " txout num=[{}], blinding key num=[{}]",
        vout_.size(), blinding_keys.size());
    throw CfdException(
        kCfdIllegalArgumentError, "Unmatch size blinding_keys and txouts.");
  }

  std::vector<UnblindParameter> results;
  for (uint32_t index = 0; index < vout_.size(); index++) {
    // skip if vout is txout for fee
    if (vout_[index].GetLockingScript().IsEmpty()) {
      // fall-through
    } else if (!blinding_keys[index].IsValid()) {
      // fall-through
    } else {
      results.push_back(UnblindTxOut(index, blinding_keys[index]));
    }
  }

  return results;
}

UnblindParameter ConfidentialTransaction::CalculateUnblindData(
    const ConfidentialNonce &nonce, const Privkey &blinding_key,
    const ByteData &rangeproof, const ConfidentialValue &value_commitment,
    const Script &extra, const ConfidentialAssetId &asset) {
  const std::vector<uint8_t> nonce_bytes = nonce.GetData().GetBytes();
  const std::vector<uint8_t> blinding_key_bytes =
      blinding_key.GetData().GetBytes();
  const std::vector<uint8_t> rangeproof_bytes = rangeproof.GetBytes();
  const std::vector<uint8_t> commitment_bytes =
      value_commitment.GetData().GetBytes();
  const std::vector<uint8_t> extra_bytes = extra.GetData().GetBytes();
  const std::vector<uint8_t> entropy_bytes = asset.GetData().GetBytes();
  std::vector<uint8_t> abf_out(kBlindFactorSize);
  std::vector<uint8_t> vbf_out(kBlindFactorSize);
  std::vector<uint8_t> asset_out(kAssetSize);
  uint64_t value_out = 0;
  int ret = wally_asset_unblind(
      nonce_bytes.data(), nonce_bytes.size(), blinding_key_bytes.data(),
      blinding_key_bytes.size(), rangeproof_bytes.data(),
      rangeproof_bytes.size(), commitment_bytes.data(),
      commitment_bytes.size(), extra_bytes.data(), extra_bytes.size(),
      entropy_bytes.data(), entropy_bytes.size(), asset_out.data(),
      asset_out.size(), abf_out.data(), abf_out.size(), vbf_out.data(),
      vbf_out.size(), &value_out);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_unblind NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "unblind confidential data error.");
  }

  UnblindParameter result;
  result.asset = ConfidentialAssetId(asset_out);
  result.abf = BlindFactor(ByteData256(abf_out));
  result.vbf = BlindFactor(ByteData256(vbf_out));
  result.value = ConfidentialValue(Amount::CreateBySatoshiAmount(value_out));

  return result;
}

UnblindParameter ConfidentialTransaction::CalculateUnblindIssueData(
    const Privkey &blinding_key, const ByteData &rangeproof,
    const ConfidentialValue &value_commitment, const Script &extra,
    const ConfidentialAssetId &asset) {
  int ret;
  const std::vector<uint8_t> nonce_bytes = blinding_key.GetData().GetBytes();
  const std::vector<uint8_t> rangeproof_bytes = rangeproof.GetBytes();
  const std::vector<uint8_t> commitment_bytes =
      value_commitment.GetData().GetBytes();
  std::vector<uint8_t> extra_bytes;
  if (!extra.IsEmpty()) {
    extra_bytes = extra.GetData().GetBytes();
  }

  std::vector<uint8_t> empty_factor(kBlindFactorSize);
  memset(empty_factor.data(), 0, empty_factor.size());
  const std::vector<uint8_t> asset_bytes = asset.GetUnblindedData().GetBytes();
  std::vector<uint8_t> generator(ASSET_GENERATOR_LEN);
  ret = wally_asset_generator_from_bytes(
      asset_bytes.data(), asset_bytes.size(), empty_factor.data(),
      empty_factor.size(), generator.data(), generator.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_generator_from_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "asset generator error.");
  }

  std::vector<uint8_t> abf_out(kBlindFactorSize);
  std::vector<uint8_t> vbf_out(kBlindFactorSize);
  std::vector<uint8_t> asset_out(kAssetSize);
  uint64_t value_out = 0;
  ret = wally_asset_unblind_with_nonce(
      nonce_bytes.data(), nonce_bytes.size(), rangeproof_bytes.data(),
      rangeproof_bytes.size(), commitment_bytes.data(),
      commitment_bytes.size(), extra_bytes.data(), extra_bytes.size(),
      generator.data(), generator.size(), asset_out.data(), asset_out.size(),
      abf_out.data(), abf_out.size(), vbf_out.data(), vbf_out.size(),
      &value_out);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_asset_unblind_with_nonce NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "unblind confidential data error.");
  }

  UnblindParameter result;
  result.asset = ConfidentialAssetId(asset_out);
  result.abf = BlindFactor(ByteData256(abf_out));
  result.vbf = BlindFactor(ByteData256(vbf_out));
  result.value = ConfidentialValue(Amount::CreateBySatoshiAmount(value_out));
  return result;
}

Privkey ConfidentialTransaction::GetIssuanceBlindingKey(
    const Privkey &master_blinding_key, const Txid &txid, uint32_t vout) {
  // script: OP_RETURN <txid> <vout>
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_RETURN);
  builder.AppendData(txid.GetData());
  int64_t vout64 = vout;
  builder.AppendData(vout64);
  Script script = builder.Build();

  ByteData256 data = CryptoUtil::HmacSha256(
      master_blinding_key.GetData().GetBytes(), script.GetData());
  return Privkey(data);
}

ByteData256 ConfidentialTransaction::GetElementsSignatureHash(
    uint32_t txin_index, const ByteData &script_data, SigHashType sighash_type,
    const ConfidentialValue &value, WitnessVersion version) const {
  if (script_data.IsEmpty()) {
    warn(CFD_LOG_SOURCE, "empty script");
    throw CfdException(
        kCfdIllegalArgumentError, "Failed to GetSignatureHash. empty script.");
  }
  std::vector<uint8_t> buffer(SHA256_LEN);
  const std::vector<uint8_t> &bytes = script_data.GetBytes();
  struct wally_tx *tx_pointer = NULL;
  int ret;

  // Change AbstractTransaction to wally_tx
  const std::vector<uint8_t> &tx_bytedata =
      GetByteData(HasWitness()).GetBytes();
  ret = wally_tx_from_bytes(
      tx_bytedata.data(), tx_bytedata.size(), GetWallyFlag(), &tx_pointer);
  if (ret != WALLY_OK || tx_pointer == NULL) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_bytes NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }

  // Calculate signature hash
  try {
    const std::vector<uint8_t> &value_data = value.GetData().GetBytes();
    uint32_t tx_flag = 0;
    if (version != WitnessVersion::kVersionNone) {
      tx_flag = GetWallyFlag() & WALLY_TX_FLAG_USE_WITNESS;
    }
    ret = wally_tx_get_elements_signature_hash(
        tx_pointer, txin_index, bytes.data(), bytes.size(), value_data.data(),
        value_data.size(), sighash_type.GetSigHashFlag(), tx_flag,
        buffer.data(), buffer.size());
    wally_tx_free(tx_pointer);
  } catch (...) {
    wally_tx_free(tx_pointer);
    warn(
        CFD_LOG_SOURCE, "wally_tx_get_elements_signature_hash exception[{}] ",
        ret);
    throw CfdException(
        kCfdIllegalArgumentError, "SignatureHash generate error.");
  }

  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_elements_signature_hash NG[{}] ", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "SignatureHash generate error.");
  }
  return ByteData256(buffer);
}

void ConfidentialTransaction::RandomSortTxOut() {
  const std::vector<ConfidentialTxOutReference> &txout_list = GetTxOutList();
  // blind check
  for (size_t index = 0; index < txout_list.size(); ++index) {
    const ConfidentialValue &value = txout_list[index].GetConfidentialValue();
    if (value.HasBlinding()) {
      warn(CFD_LOG_SOURCE, "already blinded tx");
      throw CfdException(kCfdIllegalArgumentError, "already blinded tx");
    }
  }
  for (size_t index = txout_list.size(); index > 0; --index) {
    RemoveTxOut(static_cast<uint32_t>(index - 1));
  }

  std::vector<uint32_t> indexes = RandomNumberUtil::GetRandomIndexes(
      static_cast<uint32_t>(txout_list.size()));
  for (size_t index = 0; index < indexes.size(); ++index) {
    const ConfidentialTxOutReference &txout = txout_list[indexes[index]];
    AddTxOut(
        txout.GetConfidentialValue().GetAmount(), txout.GetAsset(),
        txout.GetLockingScript(), txout.GetNonce(), txout.GetSurjectionProof(),
        txout.GetRangeProof());
  }
}

PegoutKeyData ConfidentialTransaction::GetPegoutPubkeyData(
    const Pubkey &online_pubkey, const Privkey &master_online_key,
    const std::string &bitcoin_descriptor, uint32_t bip32_counter,
    const ByteData &whitelist, NetType net_type, const ByteData &pubkey_prefix,
    NetType elements_net_type, Address *descriptor_derive_address) {
  static constexpr uint32_t kPegoutBip32CountMaximum = 1000000000;
  static constexpr uint32_t kWhitelistCountMaximum = 256;
  static constexpr uint32_t kPubkeySize = Pubkey::kCompressedPubkeySize;
  static constexpr uint32_t kWhitelistSingleSize = kPubkeySize * 2;
  PegoutKeyData result;
  std::vector<ByteData> offline_keys;
  std::vector<ByteData> online_keys;
  std::vector<uint8_t> whitelist_bytes = whitelist.GetBytes();
  uint32_t whitelist_size = static_cast<uint32_t>(whitelist_bytes.size());

  if ((whitelist_size == 0) ||
      ((whitelist_size % kWhitelistSingleSize) != 0)) {
    throw CfdException(kCfdIllegalArgumentError, "whitelist length error.");
  }
  // parameter check
  if (bip32_counter > kPegoutBip32CountMaximum) {
    throw CfdException(kCfdIllegalArgumentError, "bip32_counter over error.");
  }
  if ((!online_pubkey.IsValid()) || (!master_online_key.IsValid()) ||
      (!master_online_key.GeneratePubkey().Equals(online_pubkey))) {
    throw CfdException(kCfdIllegalArgumentError, "Illegal online key error.");
  }

  // CreatePAKListFromExtensionSpace
  decltype(whitelist_bytes)::const_iterator ite = whitelist_bytes.begin();
  uint32_t whitelist_count = whitelist_size / kWhitelistSingleSize;
  if (whitelist_count > kWhitelistCountMaximum) {
    throw CfdException(
        kCfdIllegalArgumentError, "Illegal whitelist maximum error.");
  }

  try {
    for (uint32_t index = 0; index < whitelist_count; ++index) {
      uint32_t offline_key_start = index * kWhitelistSingleSize;
      uint32_t offline_key_end = offline_key_start + kPubkeySize;
      uint32_t online_key_start = offline_key_start + kPubkeySize;
      uint32_t online_key_end = (index + 1) * kWhitelistSingleSize;
      Pubkey offline_key(std::vector<uint8_t>(
          ite + offline_key_start, ite + offline_key_end));
      offline_keys.push_back(offline_key.GetData());
      Pubkey online_key(
          std::vector<uint8_t>(ite + online_key_start, ite + online_key_end));
      online_keys.push_back(online_key.GetData());
    }
  } catch (const CfdException &except) {
    throw CfdException(
        kCfdIllegalArgumentError,
        "Illegal whitelist key. (" + std::string(except.what()) + ")");
  }

  ByteData prefix = pubkey_prefix;
  if ((net_type == NetType::kTestnet) || ((net_type == NetType::kRegtest))) {
    prefix = ByteData("043587cf");
  } else if (net_type == NetType::kMainnet) {
    prefix = ByteData("0488b21e");
  } else if (prefix.GetDataSize() != 4) {
    throw CfdException(
        kCfdIllegalArgumentError, "Illegal prefix and nettype.");
  }

  // check descriptor
  ExtPubkey xpub;
  ExtPubkey child_xpub = GenerateExtPubkeyFromDescriptor(
      bitcoin_descriptor, bip32_counter, prefix, net_type, elements_net_type,
      &xpub, descriptor_derive_address);
  // FlatSigningProvider provider;
  // const auto descriptor = Parse(desc_str, provider);
  // if (!descriptor) desc_str = "pkh(" + xpub.GetBase58String() + "/0/*)";

  // check whitelist
  uint32_t whitelist_index = 0;
  bool is_find = false;
  const ByteData &online_pubkey_bytes = online_pubkey.GetData();
  for (uint32_t index = 0; index < online_keys.size(); ++index) {
    if (online_pubkey_bytes.Equals(online_keys[index])) {
      whitelist_index = index;
      is_find = true;
      break;
    }
  }
  if (!is_find) {
    warn(CFD_LOG_SOURCE, "online_pubkey not exists.");
    throw CfdException(kCfdIllegalArgumentError, "online_pubkey not exists.");
  }

  Pubkey offline_pubkey = xpub.GetPubkey();
  ByteData offline_pubkey_negate =
      WallyUtil::NegatePubkey(offline_pubkey.GetData());
  if (!offline_keys[whitelist_index].Equals(offline_pubkey_negate)) {
    warn(CFD_LOG_SOURCE, "offline_pubkey not exists.");
    throw CfdException(kCfdIllegalArgumentError, "offline_pubkey not exists.");
  }

  // calc tweak
  ByteData256 tweak_sum = child_xpub.GetPubTweakSum();
  ByteData btcpubkeybytes =
      WallyUtil::AddTweakPubkey(offline_pubkey.GetData(), tweak_sum);

  ByteData whitelist_proof = WallyUtil::SignWhitelist(
      btcpubkeybytes, ByteData256(master_online_key.GetData().GetBytes()),
      tweak_sum, online_keys, offline_keys, whitelist_index);

  result.btc_pubkey_bytes = Pubkey(btcpubkeybytes);
  result.whitelist_proof = whitelist_proof;
  return result;
}

ExtPubkey ConfidentialTransaction::GenerateExtPubkeyFromDescriptor(
    const std::string &bitcoin_descriptor, uint32_t bip32_counter,
    const ByteData &prefix, NetType net_type, NetType elements_net_type,
    ExtPubkey *base_ext_pubkey, Address *descriptor_derive_address) {
  bool is_liquidv1 = false;
  switch (elements_net_type) {
    case NetType::kMainnet:
    case NetType::kTestnet:
    case NetType::kRegtest:
      throw CfdException(
          kCfdIllegalArgumentError, "Illegal elements network type error.");
    case NetType::kLiquidV1:
      is_liquidv1 = true;
      break;
    case NetType::kElementsRegtest:
    case NetType::kCustomChain:
    default:
      break;
  }

  ExtPubkey child_xpub;
  ExtPubkey xpub;
  std::string desc_str = bitcoin_descriptor;
  try {
    // check extkey (not output descriptor)
    ExtPubkey check_key(bitcoin_descriptor);
    if (check_key.GetVersionData().Equals(prefix)) {
      desc_str = "pkh(" + bitcoin_descriptor + ")";  // create pkh descriptor
    }
  } catch (const CfdException &except) {
    info(
        CFD_LOG_SOURCE, "bitcoin_descriptor check fail. go on next check.({})",
        except.what());
    // other descriptor
  }

  std::vector<std::string> arg_list_base;
  arg_list_base.push_back(std::string(kArgumentBaseExtkey));
  std::vector<std::string> arg_list;
  arg_list.push_back(std::to_string(bip32_counter));
  Descriptor desc = Descriptor::Parse(desc_str);
  DescriptorScriptReference script_ref = desc.GetReference(&arg_list_base);
  switch (script_ref.GetAddressType()) {
    case AddressType::kP2pkhAddress:
      break;
    case AddressType::kP2wpkhAddress:
    case AddressType::kP2shP2wpkhAddress:
      if (is_liquidv1) {
        warn(
            CFD_LOG_SOURCE, "liquidv1 not supported address type[{}].",
            script_ref.GetAddressType());
        throw CfdException(
            kCfdIllegalArgumentError,
            "bitcoin_descriptor is not of any type supported: pkh(<xpub>)");
      }
      break;
    default:
      warn(CFD_LOG_SOURCE, "bitcoin_descriptor invalid type.");
      throw CfdException(
          kCfdIllegalArgumentError,
          "bitcoin_descriptor is not of any type supported: pkh(<xpub>), "
          "sh(wpkh(<xpub>)), wpkh(<xpub>), or <xpub>.");
  }

  if (script_ref.GetAddressType() == AddressType::kP2shP2wpkhAddress) {
    script_ref = script_ref.GetChild();
  }
  DescriptorKeyReference key_ref = script_ref.GetKeyList()[0];
  if (!key_ref.HasExtPubkey()) {
    warn(CFD_LOG_SOURCE, "bitcoin_descriptor invalid extkey format.");
    throw CfdException(
        kCfdIllegalArgumentError, "BitcoinDescriptor invalid extkey format.");
  }
  *base_ext_pubkey = key_ref.GetExtPubkey();
  if (!base_ext_pubkey->GetVersionData().Equals(prefix)) {
    warn(
        CFD_LOG_SOURCE, "bitcoin_descriptor illegal prefix[{}].",
        xpub.GetVersionData().GetHex());
    throw CfdException(
        kCfdIllegalArgumentError, "bitcoin_descriptor illegal prefix.");
  }

  // collect derive key
  DescriptorScriptReference derive_script;
  derive_script = desc.GetReference(&arg_list);
  script_ref = derive_script;
  if (script_ref.GetAddressType() == AddressType::kP2shP2wpkhAddress) {
    script_ref = script_ref.GetChild();
  }
  key_ref = script_ref.GetKeyList()[0];
  child_xpub = key_ref.GetExtPubkey();

  // If it is the same as base, add a default path.
  if (child_xpub.ToString() == base_ext_pubkey->ToString()) {
    std::string xpub_str = base_ext_pubkey->ToString() + "/0/*";
    if (script_ref.GetAddressType() == AddressType::kP2shP2wpkhAddress) {
      xpub_str = "sh(wpkh(" + xpub_str + "))";
    } else if (script_ref.GetAddressType() == AddressType::kP2wpkhAddress) {
      xpub_str = "wpkh(" + xpub_str + ")";
    } else {
      xpub_str = "pkh(" + xpub_str + ")";
    }
    desc = Descriptor::Parse(xpub_str);
    derive_script = desc.GetReference(&arg_list);
    script_ref = derive_script;
    if (script_ref.GetAddressType() == AddressType::kP2shP2wpkhAddress) {
      script_ref = script_ref.GetChild();
    }
    key_ref = script_ref.GetKeyList()[0];
    child_xpub = key_ref.GetExtPubkey();
  }

  if (descriptor_derive_address != nullptr) {
    *descriptor_derive_address = derive_script.GenerateAddress(net_type);
  }
  return child_xpub;
}

ByteData256 ConfidentialTransaction::GetWitnessOnlyHash() const {
  std::vector<ByteData256> leaves;
  leaves.reserve(std::max(vin_.size(), vout_.size()));
  for (const auto &vin : vin_) {
    leaves.push_back(vin.GetWitnessHash());
  }
  ByteData256 hash_in = CryptoUtil::ComputeFastMerkleRoot(leaves);
  leaves.clear();

  for (const auto &vout : vout_) {
    leaves.push_back(vout.GetWitnessHash());
  }
  ByteData256 hash_out = CryptoUtil::ComputeFastMerkleRoot(leaves);
  leaves.clear();

  leaves.push_back(hash_in);
  leaves.push_back(hash_out);
  return CryptoUtil::ComputeFastMerkleRoot(leaves);
}

ByteData ConfidentialTransaction::ConvertToByteData(
    const uint8_t *data, size_t size) {
  std::vector<uint8_t> buffer(size);
  if ((data != nullptr) && (size != 0)) {
    memcpy(buffer.data(), data, size);
  }
  return ByteData(buffer);
}

bool ConfidentialTransaction::HasWitness() const {
  size_t is_witness = 0;
  int ret = wally_tx_get_witness_count(
      static_cast<struct wally_tx *>(wally_tx_pointer_), &is_witness);
  if (ret == WALLY_OK) {
    return (is_witness != 0);
  }
  return false;
}

uint8_t *ConfidentialTransaction::CopyConfidentialCommitment(
    const void *buffer, size_t buffer_size, size_t explicit_size,
    uint8_t *address) {
  uint8_t *result = address;
  const uint8_t *buffer_addr = static_cast<const uint8_t *>(buffer);
  if ((!buffer_addr) || (buffer_size == 0) || (buffer_addr[0] == 0)) {
    *result = 0;  // version is 0
    ++result;
  } else {
    size_t max_size = kConfidentialDataSize;
    if (buffer_addr[0] == kConfidentialVersion_1) {
      max_size = explicit_size;
    }
    size_t copy_size = max_size;
    if (buffer_size <= copy_size) {
      copy_size = buffer_size;
    }
    // explicit value
    // confidential value
    uint8_t ct_buffer[kConfidentialDataSize];
    memset(ct_buffer, 0, sizeof(ct_buffer));
    memcpy(ct_buffer, buffer_addr, copy_size);
    memcpy(address, ct_buffer, max_size);
    result += max_size;
  }
  return result;
}

void ConfidentialTransaction::SetElementsTxState() {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer != nullptr) {
    size_t is_coinbase = 0;
    // coinbase priority when coinbase is set
    int ret = wally_tx_is_coinbase(tx_pointer, &is_coinbase);
    if ((ret == WALLY_OK) && (is_coinbase == 0)) {
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        struct wally_tx_input *input = tx_pointer->inputs + i;
        // pegin_witness
        if ((input->pegin_witness != nullptr) &&
            (input->pegin_witness->num_items != 0)) {
          input->features |= kTxInFeaturePegin;
        } else {
          input->features &= ~kTxInFeaturePegin;
        }

        // issuance
        if (((input->issuance_amount != nullptr) &&
             (input->issuance_amount_len != 0)) ||
            ((input->inflation_keys != nullptr) &&
             (input->inflation_keys_len != 0))) {
          input->features |= kTxInFeatureIssuance;
        } else {
          input->features &= ~kTxInFeatureIssuance;
        }
      }
    }
  }
}

ByteData ConfidentialTransaction::GetByteData(bool has_witness) const {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  size_t size = 0;
  uint32_t flag = 0;
  if (has_witness) {
    flag = WALLY_TX_FLAG_USE_WITNESS;
  }

  int ret = wally_tx_get_length(tx_pointer, flag, &size);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_tx_get_length NG[{}]. wit[{}]", ret,
        has_witness);
    throw CfdException(kCfdIllegalStateError, "tx length calc error.");
  }
  // info(CFD_LOG_SOURCE, "wally_tx_get_length size[{}]", size);
  if (size < kElementsTransactionMinimumSize) {
    ret = WALLY_EINVAL;
    warn(CFD_LOG_SOURCE, "tx size low.[{}]", size);
  }
  std::vector<uint8_t> buffer(size);
  if (ret != WALLY_EINVAL) {
    size_t txsize = size;
    // flag |= WALLY_TX_FLAG_USE_ELEMENTS;
    ret = wally_tx_to_bytes(
        tx_pointer, flag, buffer.data(), buffer.size(), &txsize);
  }
  if (ret == WALLY_EINVAL) {
    /* About conversion with object.
     * In libwally, txin / txout does not allow empty data.
     * Therefore, if txin / txout is empty, object to byte is an error.
     * Therefore, it performs its own processing under certain circumstances.
     */
    if ((tx_pointer->num_inputs == 0) || (tx_pointer->num_outputs == 0)) {
      info(CFD_LOG_SOURCE, "wally_tx_get_length size[{}]", size);
      bool has_txin_witness = false;
      bool has_txin_rangeproof = false;
      bool has_txout_witness = false;
      bool is_witness = false;
      // Necessary size calculation because wally_tx_get_length may be
      // an invalid value (reserved more)
      size_t need_size = sizeof(struct wally_tx);
      need_size += tx_pointer->num_inputs * sizeof(struct wally_tx_input);
      need_size += tx_pointer->num_outputs * sizeof(struct wally_tx_output);
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        need_size += sizeof(input->blinding_nonce);
        need_size += sizeof(input->entropy);
        if (input->issuance_amount) {
          need_size += input->issuance_amount_len + 10;
        }
        if (input->inflation_keys) {
          need_size += input->inflation_keys_len + 10;
        }
      }
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        if (output->asset) need_size += output->asset_len + 10;
        if (output->value) need_size += output->value_len + 10;
        if (output->nonce) need_size += output->nonce_len + 10;
        if (output->script) need_size += output->script_len + 10;
        need_size += 10;
      }
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        // issuance amount range proof
        if (input->issuance_amount_rangeproof) {
          need_size += input->issuance_amount_rangeproof_len + 10;
          has_txin_rangeproof = true;
        }
        // inflation keys range proof
        if (input->inflation_keys_rangeproof) {
          need_size += input->inflation_keys_rangeproof_len + 10;
          has_txin_rangeproof = true;
        }
        // witness
        size_t num_items = input->witness ? input->witness->num_items : 0;
        for (uint32_t j = 0; j < num_items; ++j) {
          const struct wally_tx_witness_item *stack;
          stack = input->witness->items + j;
          need_size += stack->witness_len + 10;
          has_txin_witness = true;
        }
        // pegin_witness
        num_items = input->pegin_witness ? input->pegin_witness->num_items : 0;
        for (uint32_t j = 0; j < num_items; ++j) {
          const struct wally_tx_witness_item *stack;
          stack = input->pegin_witness->items + j;
          need_size += stack->witness_len + 10;
          has_txin_witness = true;
        }
        need_size += 10;
      }
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        if (output->surjectionproof) {
          need_size += output->surjectionproof_len + 10;
          has_txout_witness = true;
        }
        if (output->rangeproof) {
          need_size += output->rangeproof_len + 10;
          has_txout_witness = true;
        }
        need_size += 10;
      }
      if (need_size > buffer.size()) {
        buffer.resize(need_size);
        info(CFD_LOG_SOURCE, "buffer.resize[{}]", need_size);
      }

      uint8_t *address_pointer = buffer.data();
      memcpy(
          address_pointer, &tx_pointer->version, sizeof(tx_pointer->version));
      address_pointer += sizeof(tx_pointer->version);
      uint8_t witness_flag = 0;
      if ((tx_pointer->version & kTransactionVersionNoWitness) == 0) {
        if (has_txin_witness || has_txin_rangeproof || has_txout_witness) {
          is_witness = true;
          witness_flag = 1;
        }
      }
      *address_pointer = witness_flag;
      ++address_pointer;

      // txin
      address_pointer =
          CopyVariableInt(tx_pointer->num_inputs, address_pointer);
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        memcpy(address_pointer, input->txhash, sizeof(input->txhash));
        address_pointer += sizeof(input->txhash);
        // Separate handling is required for pegin and issue
        memcpy(address_pointer, &input->index, sizeof(input->index));
        address_pointer += sizeof(input->index);
        address_pointer = CopyVariableBuffer(
            input->script, input->script_len, address_pointer);
        memcpy(address_pointer, &input->sequence, sizeof(input->sequence));
        address_pointer += sizeof(input->sequence);
        if (has_txin_rangeproof) {
          // blinding_nonce
          memcpy(
              address_pointer, &input->blinding_nonce,
              sizeof(input->blinding_nonce));
          address_pointer += sizeof(input->blinding_nonce);
          // entropy
          memcpy(address_pointer, &input->entropy, sizeof(input->entropy));
          address_pointer += sizeof(input->entropy);
          // issuance amount
          address_pointer = CopyConfidentialCommitment(
              input->issuance_amount, input->issuance_amount_len,
              kConfidentialValueSize, address_pointer);
          // inflation keys
          address_pointer = CopyConfidentialCommitment(
              input->inflation_keys, input->inflation_keys_len,
              kConfidentialValueSize, address_pointer);
        }
      }

      // txout
      address_pointer =
          CopyVariableInt(tx_pointer->num_outputs, address_pointer);
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        // asset (fix size)
        address_pointer = CopyConfidentialCommitment(
            output->asset, output->asset_len, kConfidentialDataSize,
            address_pointer);
        // value (fix size)
        address_pointer = CopyConfidentialCommitment(
            output->value, output->value_len, kConfidentialValueSize,
            address_pointer);
        // nonce (fix size)
        address_pointer = CopyConfidentialCommitment(
            output->nonce, output->nonce_len, kConfidentialDataSize,
            address_pointer);
        // script
        address_pointer = CopyVariableBuffer(
            output->script, output->script_len, address_pointer);
      }

      // locktime
      memcpy(
          address_pointer, &tx_pointer->locktime,
          sizeof(tx_pointer->locktime));
      address_pointer += sizeof(tx_pointer->locktime);

      // witness
      if (is_witness) {
        for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
          const struct wally_tx_input *input = tx_pointer->inputs + i;
          // issuance amount range proof
          address_pointer = CopyVariableBuffer(
              input->issuance_amount_rangeproof,
              input->issuance_amount_rangeproof_len, address_pointer);
          // inflation keys range proof
          address_pointer = CopyVariableBuffer(
              input->inflation_keys_rangeproof,
              input->inflation_keys_rangeproof_len, address_pointer);
          // witness
          size_t num_items = input->witness ? input->witness->num_items : 0;
          address_pointer = CopyVariableInt(num_items, address_pointer);
          for (uint32_t j = 0; j < num_items; ++j) {
            const struct wally_tx_witness_item *stack;
            stack = input->witness->items + j;
            address_pointer = CopyVariableBuffer(
                stack->witness, stack->witness_len, address_pointer);
          }
          // pegin_witness
          num_items = 0;
          if (input->pegin_witness)
            num_items = input->pegin_witness->num_items;
          address_pointer = CopyVariableInt(num_items, address_pointer);
          for (uint32_t j = 0; j < num_items; ++j) {
            const struct wally_tx_witness_item *stack;
            stack = input->pegin_witness->items + j;
            address_pointer = CopyVariableBuffer(
                stack->witness, stack->witness_len, address_pointer);
          }
        }

        for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
          const struct wally_tx_output *output = tx_pointer->outputs + i;
          // surjection proof
          address_pointer = CopyVariableBuffer(
              output->surjectionproof, output->surjectionproof_len,
              address_pointer);
          // range proof
          address_pointer = CopyVariableBuffer(
              output->rangeproof, output->rangeproof_len, address_pointer);
        }
      }

      unsigned char *start_address = buffer.data();
      size = address_pointer - start_address;
      if (buffer.size() > size) {
        buffer.resize(size);
        info(CFD_LOG_SOURCE, "set buffer size[{}]", size);
      }
    } else {
      warn(
          CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}]. in/out={}/{}", ret,
          tx_pointer->num_inputs, tx_pointer->num_outputs);
      throw CfdException(kCfdIllegalStateError, "tx hex convert error.");
    }
  } else if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "tx hex convert error.");
  }

  return ByteData(buffer);
}

uint32_t ConfidentialTransaction::GetWallyFlag() const {
  return WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS;
}

ByteData ConfidentialTransaction::GetBitcoinTransaction(
    const ByteData &bitcoin_tx_data, bool is_remove_witness) {
  const std::vector<uint8_t> &byte_data = bitcoin_tx_data.GetBytes();
  struct wally_tx *tx_pointer = NULL;
  int ret =
      wally_tx_from_bytes(byte_data.data(), byte_data.size(), 0, &tx_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_bytes NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }

  ByteData result;
  try {
    uint32_t flag = (is_remove_witness) ? 0 : WALLY_TX_FLAG_USE_WITNESS;
    size_t size = 0;
    size_t vsize = 0;
    ret = wally_tx_get_length(tx_pointer, flag, &size);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_get_length NG[{}].", ret);
      throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
    }
    if (flag != 0) {
      ret = wally_tx_get_vsize(tx_pointer, &vsize);
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_tx_get_vsize NG[{}].", ret);
        throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
      }
      if (size == vsize) {
        flag = 0;
      }
    }
    std::vector<uint8_t> buffer(size);
    ret = wally_tx_to_bytes(
        tx_pointer, flag, buffer.data(), buffer.size(), &size);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}].", ret);
      throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
    }
    if (buffer.size() != size) {
      buffer.resize(size);
    }
    result = ByteData(buffer);
    wally_tx_free(tx_pointer);
    tx_pointer = nullptr;
  } catch (const CfdException &cfd_except) {
    wally_tx_free(tx_pointer);
    throw cfd_except;
  } catch (...) {
    wally_tx_free(tx_pointer);
    warn(CFD_LOG_SOURCE, "unknown exception.");
    throw CfdException(kCfdIllegalStateError, "bitcoin tx convert error.");
  }
  return result;
}

void ConfidentialTransaction::CheckTxInIndex(
    uint32_t index, int line, const char *caller) const {
  if (vin_.size() <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "vin[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "vin out_of_range error.");
  }
}

void ConfidentialTransaction::CheckTxOutIndex(
    uint32_t index, int line, const char *caller) const {
  if (vout_.size() <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "vout[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "vout out_of_range error.");
  }
}

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
