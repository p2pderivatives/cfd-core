// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_transaction_common.cpp
 *
 * @brief \~japanese Transaction関連基底クラスの実装ファイルです。
 *   \~english implementation of Transaction related common classes
 */
#include "cfdcore/cfdcore_transaction_common.h"

#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::trace;
using logger::warn;

// -----------------------------------------------------------------------------
// Internal constants (ported from libwally. Varint_to_bytes, varbuff_to_bytes)
// -----------------------------------------------------------------------------
static constexpr uint8_t kViTag16 = 253;  //!< VarInt16
static constexpr uint8_t kViTag32 = 254;  //!< VarInt32
static constexpr uint8_t kViTag64 = 255;  //!< VarInt64
static constexpr uint8_t kViMax8 = 252;   //!< VarInt8

// -----------------------------------------------------------------------------
// ScriptWitness
// -----------------------------------------------------------------------------
const std::vector<ByteData> ScriptWitness::GetWitness() const {
  return witness_stack_;
}

uint32_t ScriptWitness::GetWitnessNum() const {
  return static_cast<uint32_t>(witness_stack_.size());
}

void ScriptWitness::AddWitnessStack(const ByteData &data) {
  witness_stack_.push_back(data);
}

void ScriptWitness::SetWitnessStack(uint32_t index, const ByteData &data) {
  if (witness_stack_.size() <= index) {
    warn(CFD_LOG_SOURCE, "WitnessStack[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "vin out_of_range error.");
  }
  witness_stack_[index] = data;
}

bool ScriptWitness::Empty() const { return IsEmpty(); }

bool ScriptWitness::IsEmpty() const { return (witness_stack_.size() == 0); }

ByteData ScriptWitness::Serialize() const {
  std::vector<ByteData> buffer_array;
  ByteData stack_count = ByteData::GetVariableInt(witness_stack_.size());
  buffer_array.push_back(stack_count);
  for (const ByteData &stack : witness_stack_) {
    buffer_array.push_back(stack.Serialize());
  }

  std::vector<uint8_t> result;
  for (const ByteData &buffer : buffer_array) {
    std::vector<uint8_t> work_buffer = buffer.GetBytes();
    result.insert(result.end(), work_buffer.begin(), work_buffer.end());
  }
  return ByteData(result);
}

// -----------------------------------------------------------------------------
// AbstractTxIn
// -----------------------------------------------------------------------------
AbstractTxIn::AbstractTxIn(const Txid &txid, uint32_t index, uint32_t sequence)
    : txid_(txid),
      vout_(index),
      unlocking_script_(),
      sequence_(sequence),
      script_witness_() {
  // do nothing
}

AbstractTxIn::AbstractTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script)
    : txid_(txid),
      vout_(index),
      unlocking_script_(unlocking_script),
      sequence_(sequence),
      script_witness_() {
  // do nothing
}

Txid AbstractTxIn::GetTxid() const { return txid_; }

uint32_t AbstractTxIn::GetVout() const { return vout_; }

OutPoint AbstractTxIn::GetOutPoint() const { return OutPoint(txid_, vout_); }

Script AbstractTxIn::GetUnlockingScript() const { return unlocking_script_; }

void AbstractTxIn::SetUnlockingScript(const Script &unlocking_script) {
  unlocking_script_ = unlocking_script;
}

uint32_t AbstractTxIn::GetSequence() const { return sequence_; }

ScriptWitness AbstractTxIn::GetScriptWitness() const {
  return script_witness_;
}

uint32_t AbstractTxIn::GetScriptWitnessStackNum() const {
  return script_witness_.GetWitnessNum();
}

ScriptWitness AbstractTxIn::AddScriptWitnessStack(const ByteData &data) {
  script_witness_.AddWitnessStack(data);
  return script_witness_;
}

ScriptWitness AbstractTxIn::SetScriptWitnessStack(
    uint32_t index, const ByteData &data) {
  script_witness_.SetWitnessStack(index, data);
  return script_witness_;
}

void AbstractTxIn::RemoveScriptWitnessStackAll() {
  script_witness_ = ScriptWitness();
}

bool AbstractTxIn::IsCoinBase() const {
  bool is_coinbase = false;
  std::vector<uint8_t> empty_txid(kByteData256Length);
  if ((vout_ == std::numeric_limits<uint32_t>::max()) &&
      (txid_.GetData().GetBytes() == empty_txid)) {
    is_coinbase = true;
  }
  return is_coinbase;
}

// -----------------------------------------------------------------------------
// AbstractTxInReference
// -----------------------------------------------------------------------------
AbstractTxInReference::AbstractTxInReference(const AbstractTxIn &tx_in)
    : txid_(tx_in.GetTxid()),
      vout_(tx_in.GetVout()),
      unlocking_script_(tx_in.GetUnlockingScript()),
      sequence_(tx_in.GetSequence()),
      script_witness_(tx_in.GetScriptWitness()) {
  // do nothing
}

// -----------------------------------------------------------------------------
// AbstractTxOut
// -----------------------------------------------------------------------------
AbstractTxOut::AbstractTxOut()
    : value_(Amount::CreateBySatoshiAmount(0)), locking_script_() {
  // do nothing
}

AbstractTxOut::AbstractTxOut(const Amount &value, const Script &locking_script)
    : value_(value), locking_script_(locking_script) {
  // do nothing
}

AbstractTxOut::AbstractTxOut(const Script &locking_script)
    : value_(Amount::CreateBySatoshiAmount(0)),
      locking_script_(locking_script) {
  // do nothing
}

const Amount AbstractTxOut::GetValue() const { return value_; }

const Script AbstractTxOut::GetLockingScript() const {
  return locking_script_;
}

void AbstractTxOut::SetValue(const Amount &value) { value_ = value; }

// -----------------------------------------------------------------------------
// AbstractTxOutReference
// -----------------------------------------------------------------------------
AbstractTxOutReference::AbstractTxOutReference(const AbstractTxOut &tx_out)
    : value_(tx_out.GetValue()), locking_script_(tx_out.GetLockingScript()) {
  // do nothing
}

uint32_t AbstractTxOutReference::GetSerializeSize() const {
  size_t result = 8;  // Amount分
  result += locking_script_.GetData().GetSerializeSize();
  return static_cast<uint32_t>(result);
}

uint32_t AbstractTxOutReference::GetSerializeVsize() const {
  return AbstractTransaction::GetVsizeFromSize(GetSerializeSize(), 0);
}

// -----------------------------------------------------------------------------
// SignatureUtil
// -----------------------------------------------------------------------------
ByteData SignatureUtil::CalculateEcSignature(
    const ByteData256 &signature_hash, const Privkey &private_key,
    bool has_grind_r) {
  std::vector<uint8_t> buffer(EC_SIGNATURE_LEN);
  std::vector<uint8_t> privkey_data = private_key.GetData().GetBytes();
  std::vector<uint8_t> sighash = signature_hash.GetBytes();
  uint32_t flag = EC_FLAG_ECDSA;
  if (has_grind_r) {
    flag |= EC_FLAG_GRIND_R;
  }
  int ret = wally_ec_sig_from_bytes(
      privkey_data.data(), privkey_data.size(), sighash.data(), sighash.size(),
      flag, buffer.data(), buffer.size());

  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_ec_sig_from_bytes NG[{}] ", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "ec signature calculation error.");
  }
  return ByteData(buffer);
}

bool SignatureUtil::VerifyEcSignature(
    const ByteData256 &signature_hash, const Pubkey &pubkey,
    const ByteData &signature) {
  std::vector<uint8_t> pubkey_data = pubkey.GetData().GetBytes();
  std::vector<uint8_t> sighash = signature_hash.GetBytes();
  std::vector<uint8_t> signature_data = signature.GetBytes();
  int flag = EC_FLAG_ECDSA;
  int ret = wally_ec_sig_verify(
      pubkey_data.data(), pubkey_data.size(), sighash.data(), sighash.size(),
      flag, signature_data.data(), signature_data.size());
  return ret == WALLY_OK;
}

ByteData256 SignatureUtil::CalculateSchnorrSignatureWithNonce(
    const Privkey &oracle_key, const Privkey &k_value,
    const ByteData256 &message) {
  ByteData signature = CalculateSchnorrSignature(oracle_key, k_value, message);
  std::vector<uint8_t> sig = signature.GetBytes();
  std::vector<uint8_t> result;
  result.assign(sig.data() + 32, sig.data() + 64);
  return ByteData256(result);
}

ByteData SignatureUtil::CalculateSchnorrSignature(
    const Privkey &oracle_key, const Privkey &k_value,
    const ByteData256 &message) {
  return WallyUtil::CalculateSchnorrsig(oracle_key, k_value, message);
}

bool SignatureUtil::VerifySchnorrSignatureWithNonce(
    const Pubkey &pubkey, const Pubkey &nonce, const ByteData256 &signature,
    const ByteData256 &message) {
  std::vector<uint8_t> nonce_signature(64);
  std::vector<uint8_t> nonce_bytes = nonce.GetData().GetBytes();
  std::vector<uint8_t> signature_bytes = signature.GetBytes();
  memcpy(nonce_signature.data(), nonce_bytes.data() + 1, 32);
  memcpy(nonce_signature.data() + 32, signature_bytes.data(), 32);
  return VerifySchnorrSignature(pubkey, ByteData(nonce_signature), message);
}

bool SignatureUtil::VerifySchnorrSignature(
    const Pubkey &pubkey, const ByteData &signature,
    const ByteData256 &message) {
  return WallyUtil::VerifySchnorrsig(pubkey, signature, message);
}

// -----------------------------------------------------------------------------
// OutPoint
// -----------------------------------------------------------------------------
OutPoint::OutPoint() : txid_(), vout_(0) {
  // do nothing
}

OutPoint::OutPoint(const Txid &txid, uint32_t vout)
    : txid_(txid), vout_(vout) {
  // do nothing
}

const Txid OutPoint::GetTxid() const { return txid_; }

uint32_t OutPoint::GetVout() const { return vout_; }

bool OutPoint::IsValid() const { return txid_.IsValid(); }

bool OutPoint::operator==(const OutPoint &object) const {
  if ((vout_ == object.vout_) && (txid_.Equals(object.txid_))) {
    return true;
  }
  return false;
}

bool OutPoint::operator!=(const OutPoint &object) const {
  return !(*this == object);
}

bool operator<(const OutPoint &source, const OutPoint &dest) {
  if (source.GetVout() < dest.GetVout()) {
    return true;
  }
  if (source.GetTxid().GetData().GetBytes() <
      dest.GetTxid().GetData().GetBytes()) {
    return true;
  }
  return false;
}

bool operator<=(const OutPoint &source, const OutPoint &dest) {
  if (source == dest) {
    return true;
  }
  return (source < dest);
}

bool operator>=(const OutPoint &source, const OutPoint &dest) {
  return !(source < dest);
}

bool operator>(const OutPoint &source, const OutPoint &dest) {
  if (source == dest) {
    return false;
  }
  return !(source < dest);
}

// -----------------------------------------------------------------------------
// AbstractTransaction
// -----------------------------------------------------------------------------
AbstractTransaction::AbstractTransaction() : wally_tx_pointer_(NULL) {
  // do nothing
}

void AbstractTransaction::FreeWallyAddress(const void *wally_tx_pointer) {
  if (wally_tx_pointer != NULL) {
    struct wally_tx *tx_pointer = nullptr;
    memcpy(&tx_pointer, &wally_tx_pointer, sizeof(void *));  // const外し
    wally_tx_free(tx_pointer);
  }
}

int32_t AbstractTransaction::GetVersion() const {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  // Type is matched to bitcoin-core
  // return reinterpret_cast<int32_t>(tx_pointer-> version);
  // VC ++ errors and warnings appear, so change to pointer cast
  int32_t *p_version = reinterpret_cast<int32_t *>(&tx_pointer->version);
  return *p_version;
}

uint32_t AbstractTransaction::GetLockTime() const {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  return tx_pointer->locktime;
}

void AbstractTransaction::CallbackStateChange(uint32_t type) {
  // please override this function
  trace(CFD_LOG_SOURCE, "type[%#x]", type);
}

void AbstractTransaction::AddTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script) {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  const std::vector<uint8_t> &txid_buf = txid.GetData().GetBytes();
  int ret;
  if (unlocking_script.IsEmpty()) {
    ret = wally_tx_add_raw_input(
        tx_pointer, txid_buf.data(), txid_buf.size(), index, sequence, NULL, 0,
        NULL, 0);
  } else {
    const std::vector<uint8_t> &script_data =
        unlocking_script.GetData().GetBytes();
    ret = wally_tx_add_raw_input(
        tx_pointer, txid_buf.data(), txid_buf.size(), index, sequence,
        script_data.data(), script_data.size(), NULL, 0);
  }
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_raw_input NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "txin add error.");
  }
}

void AbstractTransaction::RemoveTxIn(uint32_t index) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);

  int ret = wally_tx_remove_input(
      static_cast<struct wally_tx *>(wally_tx_pointer_), index);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_remove_input NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "txin remove error.");
  }
}

void AbstractTransaction::SetUnlockingScript(
    uint32_t tx_in_index, const Script &unlocking_script) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);
  if (!unlocking_script.IsPushOnly()) {
    warn(CFD_LOG_SOURCE, "IsPushOnly() false.");
    throw CfdException(
        kCfdIllegalArgumentError,
        "unlocking script error. "
        "The script needs to be push operator only.");
  }

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  const std::vector<uint8_t> &arrays = unlocking_script.GetData().GetBytes();
  int ret = wally_tx_set_input_script(
      tx_pointer, tx_in_index, arrays.data(), arrays.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_set_input_script NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "unlocking script setting error.");
  }
}

Script AbstractTransaction::SetUnlockingScript(
    uint32_t tx_in_index, const std::vector<ByteData> &unlocking_script) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  ScriptBuilder builder;
  for (ByteData script : unlocking_script) {
    builder.AppendData(script);
  }
  SetUnlockingScript(tx_in_index, builder.Build());
  return builder.Build();
}

void AbstractTransaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const std::vector<uint8_t> &data) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    int ret = WALLY_OK;
    bool is_alloc = false;
    struct wally_tx_witness_stack *stack_pointer = NULL;

    std::string function_name = "wally_tx_witness_stack_init_alloc";
    if (tx_pointer->inputs[tx_in_index].witness == NULL) {
      is_alloc = true;
      ret = wally_tx_witness_stack_init_alloc(1, &stack_pointer);
    } else {
      stack_pointer = tx_pointer->inputs[tx_in_index].witness;
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
          function_name = "wally_tx_set_input_witness";
          ret = wally_tx_set_input_witness(
              tx_pointer, tx_in_index, stack_pointer);
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
}

void AbstractTransaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index,
    const std::vector<uint8_t> &data) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    int ret = WALLY_EINVAL;
    struct wally_tx_witness_stack *stack_pointer = NULL;

    std::string function_name = "wally witness is NULL.";
    if (tx_pointer->inputs[tx_in_index].witness != NULL) {
      stack_pointer = tx_pointer->inputs[tx_in_index].witness;

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
}

void AbstractTransaction::RemoveScriptWitnessStackAll(uint32_t tx_in_index) {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);

  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx_pointer->num_inputs > tx_in_index) {
    struct wally_tx_witness_stack *stack_pointer = NULL;
    if (tx_pointer->inputs[tx_in_index].witness != NULL) {
      stack_pointer = tx_pointer->inputs[tx_in_index].witness;
      int ret = wally_tx_witness_stack_free(stack_pointer);
      tx_pointer->inputs[tx_in_index].witness = NULL;
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_free NG[{}].", ret);
        throw CfdException(kCfdIllegalStateError, "witness stack error.");
      }
    }
  }
}

void AbstractTransaction::AddTxOut(
    const Amount &value, const Script &locking_script) {
  const std::vector<uint8_t> &script_data =
      locking_script.GetData().GetBytes();
  int ret = wally_tx_add_raw_output(
      static_cast<struct wally_tx *>(wally_tx_pointer_),
      value.GetSatoshiValue(), script_data.data(), script_data.size(), 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_add_raw_output NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "vout add error.");
  }
}

void AbstractTransaction::RemoveTxOut(uint32_t index) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);

  int ret = wally_tx_remove_output(
      static_cast<struct wally_tx *>(wally_tx_pointer_), index);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_remove_output NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "vout remove error.");
  }
}

uint32_t AbstractTransaction::GetTotalSize() const {
  size_t length = 0;
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  uint32_t flag = 0;
  if (HasWitness()) {
    flag = GetWallyFlag() & WALLY_TX_FLAG_USE_WITNESS;
  }
  int ret = wally_tx_get_length(tx_pointer, flag, &length);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_length NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "transaction size calc error.");
  }
  return static_cast<uint32_t>(length);
}

uint32_t AbstractTransaction::GetVsize() const {
  size_t vsize = 0;
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  int ret = wally_tx_get_vsize(tx_pointer, &vsize);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_vsize NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "transaction vsize calc error.");
  }
  return static_cast<uint32_t>(vsize);
}

uint32_t AbstractTransaction::GetWeight() const {
  size_t weight = 0;
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  int ret = wally_tx_get_weight(tx_pointer, &weight);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_weight NG[{}].", ret);
    throw CfdException(
        kCfdIllegalStateError, "transaction weight calc error.");
  }
  return static_cast<uint32_t>(weight);
}

Amount AbstractTransaction::GetValueOut() const {
  uint64_t satoshi = 0;
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);

  int ret = wally_tx_get_total_output_satoshi(tx_pointer, &satoshi);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_total_output_satoshi NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "total output calc error.");
  }
  return Amount::CreateBySatoshiAmount(satoshi);
}

bool AbstractTransaction::HasWitness() const { return false; }

ByteData256 AbstractTransaction::GetHash() const { return GetHash(false); }

ByteData256 AbstractTransaction::GetWitnessHash() const {
  return GetHash(HasWitness());
}

ByteData256 AbstractTransaction::GetHash(bool has_witness) const {
  ByteData buffer = GetByteData(has_witness);
  // sha256d hash
  return HashUtil::Sha256D(buffer.GetBytes());
}

ByteData AbstractTransaction::GetData() const {
  return GetByteData(HasWitness());
}

std::string AbstractTransaction::GetHex() const { return GetData().GetHex(); }

Txid AbstractTransaction::GetTxid() const {
  ByteData256 bytedata = GetHash();
  return Txid(bytedata);
}

bool AbstractTransaction::IsCoinBase() const {
  bool is_coinbase = false;
  struct wally_tx *tx = static_cast<struct wally_tx *>(wally_tx_pointer_);
  if (tx != nullptr) {
    size_t coinbase = 0;
    int ret = wally_tx_is_coinbase(tx, &coinbase);
    if ((ret == WALLY_OK) && (coinbase != 0)) {
      is_coinbase = true;
    }
  }
  return is_coinbase;
}

uint32_t AbstractTransaction::GetVsizeFromSize(
    uint32_t no_witness_size, uint32_t witness_size) {
  uint32_t weight = (no_witness_size * 4) + witness_size;
  // 端数切り上げ
  uint32_t vsize = (weight + 3) / 4;
  return vsize;
}

bool AbstractTransaction::GetVariableInt(
    const uint8_t *p_byte_data, size_t data_size, uint64_t *p_result,
    size_t *p_size) {
  bool is_success = false;
  if ((p_byte_data == nullptr) || (p_size == nullptr) || (data_size < 1)) {
    // do nothing
  } else if (*p_byte_data <= kViMax8) {
    *p_size = 1;
    *p_result = *p_byte_data;
    is_success = true;
  } else if (*p_byte_data == kViTag16) {
    if (data_size >= (sizeof(uint16_t) + 1)) {
      uint16_t v16;
      memcpy(&v16, &p_byte_data[1], sizeof(v16));
      *p_result = v16;
      *p_size = sizeof(v16) + 1;
      is_success = true;
    }
  } else if (*p_byte_data == kViTag32) {
    if (data_size >= (sizeof(uint32_t) + 1)) {
      uint32_t v32;
      memcpy(&v32, &p_byte_data[1], sizeof(v32));
      *p_result = v32;
      *p_size = sizeof(v32) + 1;
      is_success = true;
    }
  } else {
    if (data_size >= (sizeof(uint64_t) + 1)) {
      uint64_t v64;
      memcpy(&v64, &p_byte_data[1], sizeof(v64));
      *p_result = v64;
      *p_size = sizeof(v64) + 1;
      is_success = true;
    }
  }
  return is_success;
}

uint8_t *AbstractTransaction::CopyVariableInt(uint64_t v, uint8_t *bytes_out) {
  if (v <= kViMax8) {
    uint8_t v8 = static_cast<uint8_t>(v);
    memcpy(bytes_out, &v8, sizeof(v8));
    bytes_out += sizeof(v8);
  } else if (v <= std::numeric_limits<uint16_t>::max()) {
    *bytes_out = kViTag16;
    ++bytes_out;
    uint16_t v16 = static_cast<uint16_t>(v);
    memcpy(bytes_out, &v16, sizeof(v16));
    bytes_out += sizeof(v16);
  } else if (v <= std::numeric_limits<uint32_t>::max()) {
    *bytes_out = kViTag32;
    ++bytes_out;
    uint32_t v32 = static_cast<uint32_t>(v);
    memcpy(bytes_out, &v32, sizeof(v32));
    bytes_out += sizeof(v32);
  } else {
    *bytes_out = kViTag64;
    ++bytes_out;
    uint64_t v64 = v;
    memcpy(bytes_out, &v64, sizeof(v64));
    bytes_out += sizeof(v64);
  }

  return bytes_out;
}

uint8_t *AbstractTransaction::CopyVariableBuffer(
    const uint8_t *bytes, size_t bytes_len, uint8_t *bytes_out) {
  bytes_out = CopyVariableInt(bytes_len, bytes_out);
  if (bytes_len) {
    memcpy(bytes_out, bytes, bytes_len);
    bytes_out += bytes_len;
  }
  return bytes_out;
}

}  // namespace core
}  // namespace cfd
