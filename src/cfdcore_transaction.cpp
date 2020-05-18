// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_transaction.cpp
 *
 * @brief \~japanese Transaction関連クラスの実装ファイルです。
 *   \~english implementation of Transaction related class
 */
#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::warn;

// -----------------------------------------------------------------------------
// File constants
// -----------------------------------------------------------------------------
/// Minimum Hex size of Transaction
static constexpr size_t kTransactionMinimumHexSize =
    AbstractTransaction::kTransactionMinimumSize * 2;

// -----------------------------------------------------------------------------
// TxOut
// -----------------------------------------------------------------------------
TxOut::TxOut() {
  // do nothing
}

TxOut::TxOut(const Amount &value, const Script &locking_script)
    : AbstractTxOut(value, locking_script) {
  // do nothing
}

TxOut::TxOut(const Amount &value, const Address &address)
    : AbstractTxOut(value, address.GetLockingScript()) {
  // do nothing
}
// -----------------------------------------------------------------------------
// TxOutReference
// -----------------------------------------------------------------------------
TxOutReference::TxOutReference(const TxOut &tx_out)
    : AbstractTxOutReference(tx_out) {
  // do nothing
}

// -----------------------------------------------------------------------------
// TxIn
// -----------------------------------------------------------------------------
TxIn::TxIn(const Txid &txid, uint32_t index, uint32_t sequence)
    : AbstractTxIn(txid, index, sequence) {
  // do nothing
}

TxIn::TxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script)
    : AbstractTxIn(txid, index, sequence, unlocking_script) {
  // do nothing
}

uint32_t TxIn::EstimateTxInSize(
    AddressType addr_type, Script redeem_script, uint32_t *witness_area_size,
    uint32_t *no_witness_area_size, const Script *scriptsig_template) {
  bool is_pubkey = false;
  bool is_witness = true;
  bool use_unlocking_script = true;
  uint32_t size = kMinimumTxInSize;
  uint32_t witness_size = 0;
  uint32_t script_size = 0;

  switch (addr_type) {
    case AddressType::kP2shAddress:
      is_witness = false;
      break;
    case AddressType::kP2pkhAddress:
      is_pubkey = true;
      is_witness = false;
      break;
    case AddressType::kP2wshAddress:
      use_unlocking_script = false;
      break;
    case AddressType::kP2wpkhAddress:
      is_pubkey = true;
      use_unlocking_script = false;
      break;
    case AddressType::kP2shP2wshAddress:
      break;
    case AddressType::kP2shP2wpkhAddress:
      is_pubkey = true;
      break;
    default:
      if (redeem_script.IsEmpty()) {
        warn(CFD_LOG_SOURCE, "unknown address type, and empty redeem script.");
        throw CfdException(
            kCfdIllegalArgumentError,
            "unknown address type, and empty redeem script.");
      }
      is_witness = false;
      break;
  }

  if (is_pubkey) {
    script_size = Pubkey::kCompressedPubkeySize + EC_SIGNATURE_DER_MAX_LEN + 3;
  } else if (
      (scriptsig_template != nullptr) && (!scriptsig_template->IsEmpty())) {
    script_size = static_cast<uint32_t>(
        scriptsig_template->GetData().GetSerializeSize());
  } else {
    // Forehead is a big size
    script_size = (EC_SIGNATURE_DER_MAX_LEN - 2) * 2;
    if (!redeem_script.IsEmpty()) {
      size_t redeem_script_size = redeem_script.GetData().GetSerializeSize();
      script_size += static_cast<uint32_t>(redeem_script_size);
      try {
        // OP_0 <sig1> <sig2> ... <unlocking script>
        uint32_t reqnum = 0;
        ScriptUtil::ExtractPubkeysFromMultisigScript(redeem_script, &reqnum);
        if (reqnum != 0) {
          // set multisig size
          script_size = static_cast<uint32_t>(redeem_script_size);
          script_size += (EC_SIGNATURE_DER_MAX_LEN + 2) * reqnum;
          script_size += 2;  // for top OP_0 size
        }
      } catch (const CfdException &except) {
        if (except.GetErrorCode() != CfdError::kCfdIllegalArgumentError) {
          // error occurs other than multisig confirmation
          throw except;
        }
      }
    }
  }

  if (is_witness) {
    if (is_pubkey) {
      witness_size = script_size;
      if (use_unlocking_script) {
        size += 22;  // wpkh locking script length
      }
    } else {
      witness_size = script_size;
      if (use_unlocking_script) {
        size += 34;  // wsh locking script length
      }
    }
  } else {
    size += script_size;
  }
  if (witness_area_size != nullptr) {
    *witness_area_size = static_cast<uint32_t>(witness_size);
  }
  if (no_witness_area_size != nullptr) {
    *no_witness_area_size = static_cast<uint32_t>(size);
  }
  size += witness_size;
  return static_cast<uint32_t>(size);
}

uint32_t TxIn::EstimateTxInVsize(
    AddressType addr_type, Script redeem_script,
    const Script *scriptsig_template) {
  uint32_t witness_size = 0;
  uint32_t no_witness_size = 0;
  TxIn::EstimateTxInSize(
      addr_type, redeem_script, &witness_size, &no_witness_size,
      scriptsig_template);
  return AbstractTransaction::GetVsizeFromSize(no_witness_size, witness_size);
}

// -----------------------------------------------------------------------------
// TxInReference
// -----------------------------------------------------------------------------
TxInReference::TxInReference(const TxIn &tx_in)
    : AbstractTxInReference(tx_in) {
  // do nothing
}

// -----------------------------------------------------------------------------
// Transaction
// -----------------------------------------------------------------------------
Transaction::Transaction() : Transaction(2, static_cast<uint32_t>(0)) {
  // do nothing
}

Transaction::Transaction(int32_t version, uint32_t lock_time)
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

Transaction::Transaction(const std::string &hex_string) : vin_(), vout_() {
  SetFromHex(hex_string);
}

Transaction::Transaction(const ByteData &byte_data) : vin_(), vout_() {
  SetFromHex(byte_data.GetHex());
}

Transaction::Transaction(const Transaction &transaction)
    : Transaction(transaction.GetHex()) {
  // copy constructor
}

bool Transaction::CheckTxOutBuffer(
    const uint8_t *buffer, size_t buf_size, uint64_t txout_num,
    size_t txout_num_size, void *tx_pointer, std::vector<TxOut> *txout_list) {
  bool is_success = false;
  if (buf_size > txout_num_size) {
    size_t data_size = buf_size - txout_num_size;
    size_t offset = 0;
    const uint8_t *address_pointer = buffer;
    address_pointer += txout_num_size;
    bool is_error = false;
    for (uint64_t index = 0; index < txout_num; ++index) {
      const uint8_t *work_address = &address_pointer[offset];
      size_t limit = data_size - offset;
      size_t total = 0;
      // check for value
      if (limit <= sizeof(int64_t)) {
        is_error = true;
        break;
      }
      uint64_t amount;
      memcpy(&amount, work_address, sizeof(amount));
      work_address += sizeof(uint64_t);
      limit -= sizeof(uint64_t);
      total += sizeof(uint64_t);
      // Check locking script
      uint64_t script_size = 0;
      size_t vnum_size = 0;
      if (!GetVariableInt(work_address, limit, &script_size, &vnum_size)) {
        is_error = true;
        break;
      } else if (limit < (vnum_size + script_size)) {
        is_error = true;
        break;
      }
      work_address += vnum_size;
      total += vnum_size + script_size;
      offset += total;

      // Copy of TxOut
      if (tx_pointer != NULL) {
        int ret = wally_tx_add_raw_output(
            static_cast<struct wally_tx *>(tx_pointer), amount, work_address,
            script_size, 0);
        if (ret != WALLY_OK) {
          warn(CFD_LOG_SOURCE, "wally_tx_add_raw_output NG[{}].", ret);
          throw CfdException(kCfdIllegalStateError, "vout add error.");
        }
      }
      if (txout_list != nullptr) {
        std::vector<uint8_t> byte_array(script_size);
        memcpy(byte_array.data(), work_address, byte_array.size());
        TxOut out(
            Amount::CreateBySatoshiAmount(amount),
            Script(ByteData(byte_array)));
        txout_list->push_back(out);
      }
    }

    if ((!is_error) && (data_size == offset)) {
      is_success = true;
    }
  }
  return is_success;
}

void Transaction::SetFromHex(const std::string &hex_string) {
  void *original_address = wally_tx_pointer_;
  bool append_txout = false;
  std::vector<TxIn> vin_work;
  std::vector<TxOut> vout_work;

  // It is assumed that tx information has been created.
  // (If it is not created, it will cause inconsistency)
  struct wally_tx *tx_pointer = NULL;
  int ret = wally_tx_from_hex(hex_string.c_str(), 0, &tx_pointer);
  if (ret == WALLY_OK) {
    if ((tx_pointer->num_inputs == 0) && (tx_pointer->num_outputs == 0) &&
        (hex_string.size() > kTransactionMinimumHexSize)) {
      // Judged as an invalid analysis condition when txin is 0 and txout is 1,
      // and enters the exception route
      // (libwally misidentifies as witness tx)
      wally_tx_free(tx_pointer);
      tx_pointer = NULL;
      ret = WALLY_EINVAL;
    }
  }

  if (ret == WALLY_EINVAL) {
    ByteData tx_byte = StringUtil::StringToByte(hex_string);
    const std::vector<uint8_t> &tx_buf = tx_byte.GetBytes();
    const uint8_t *address_pointer = tx_buf.data();

    // If the minimum size, perform analysis
    if (hex_string.size() >= kTransactionMinimumHexSize) {
      uint32_t version = 0;
      uint32_t lock_time = 0;
      memcpy(&version, address_pointer, sizeof(version));
      address_pointer += sizeof(version);
      if (*address_pointer != 0) {
        // marker is 1 or txin is greater than 1
        // Since type can be analyzed with libwally, treated as invalid data.
      } else {
        // txin is 0 or marker is 0
        ++address_pointer;
        if ((*address_pointer == 0) &&
            (hex_string.size() == kTransactionMinimumHexSize)) {
          // txout is 0
          ++address_pointer;
          memcpy(&lock_time, address_pointer, sizeof(lock_time));
          ret = wally_tx_init_alloc(version, lock_time, 0, 0, &tx_pointer);
          if (ret != WALLY_OK) {
            warn(CFD_LOG_SOURCE, "wally_tx_init_alloc NG[{}] ", ret);
            throw CfdException(
                kCfdIllegalArgumentError, "transaction data generate error.");
          }
          info(CFD_LOG_SOURCE, "call wally_tx_init_alloc");
        } else {
          // Check remaining size and check if txin is 0 and txout is 1 or more
          const uint8_t *start_address = tx_buf.data();
          size_t size = address_pointer - start_address;
          uint64_t txout_num = 0;
          size_t num_size = 0;
          // Subtract the size up to the txout area and the locktime
          // from the txbuf size.
          size_t buf_size = tx_buf.size() - size - sizeof(uint32_t);
          if (!GetVariableInt(
                  address_pointer, buf_size, &txout_num, &num_size)) {
            // Invalid
          } else if (!CheckTxOutBuffer(
                         address_pointer, buf_size, txout_num, num_size)) {
            // Invalid
          } else {
            // txout OK
            // locktime copy
            const uint8_t *work_address = address_pointer + buf_size;
            memcpy(&lock_time, work_address, sizeof(lock_time));
            ret = wally_tx_init_alloc(version, lock_time, 0, 0, &tx_pointer);
            if (ret != WALLY_OK) {
              warn(CFD_LOG_SOURCE, "wally_tx_init_alloc NG[{}] ", ret);
              throw CfdException(
                  kCfdIllegalArgumentError,
                  "transaction data generate error.");
            }
            info(CFD_LOG_SOURCE, "call wally_tx_init_alloc");
            append_txout = true;
            // Add data to TxOut again
            CheckTxOutBuffer(
                address_pointer, buf_size, txout_num, num_size, tx_pointer,
                &vout_work);
          }
        }
      }
    }
  }

  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }
  wally_tx_pointer_ = tx_pointer;

  try {
    // create TxIn and TxOut
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
      TxIn txin(
          Txid(ByteData256(txid_buf)), txin_item->index, txin_item->sequence,
          unlocking_script);
      if ((txin_item->witness != NULL) &&
          (txin_item->witness->num_items != 0)) {
        for (size_t w_index = 0; w_index < txin_item->witness->num_items;
             ++w_index) {
          struct wally_tx_witness_item *witness_stack;
          witness_stack = &txin_item->witness->items[w_index];
          const std::vector<uint8_t> witness_buf(
              witness_stack->witness,
              witness_stack->witness + witness_stack->witness_len);
          txin.AddScriptWitnessStack(ByteData(witness_buf));
        }
      }
      vin_work.push_back(txin);
    }

    info(CFD_LOG_SOURCE, "num_outputs={} ", tx_pointer->num_outputs);
    if (!append_txout) {
      for (size_t index = 0; index < tx_pointer->num_outputs; ++index) {
        struct wally_tx_output *txout_item = &tx_pointer->outputs[index];
        std::vector<uint8_t> script_buf(
            txout_item->script, txout_item->script + txout_item->script_len);
        TxOut txout(
            Amount::CreateBySatoshiAmount(txout_item->satoshi),
            Script(ByteData(script_buf)));
        vout_work.push_back(txout);
      }
    }
    // If the copy process is successful, free the old buffer
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

Transaction &Transaction::operator=(const Transaction &transaction) & {
  SetFromHex(transaction.GetHex());
  return *this;
}

uint32_t Transaction::GetTotalSize() const {
  size_t length = 0;
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  // If both input / output are 0, libwally misidentifies as ElementsTransaction
  if ((tx_pointer->num_inputs == 0) && (tx_pointer->num_outputs == 0)) {
    length = static_cast<size_t>(kTransactionMinimumSize);
  } else {
    length = AbstractTransaction::GetTotalSize();
  }
  return static_cast<uint32_t>(length);
}

uint32_t Transaction::GetVsize() const {
  size_t vsize = 0;
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  // If both input / output are 0, libwally misidentifies as ElementsTransaction
  if ((tx_pointer->num_inputs == 0) && (tx_pointer->num_outputs == 0)) {
    vsize = static_cast<size_t>(kTransactionMinimumSize);
  } else {
    vsize = AbstractTransaction::GetVsize();
  }
  return static_cast<uint32_t>(vsize);
}

uint32_t Transaction::GetWeight() const {
  size_t weight = 0;
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  // If both input / output are 0, libwally misidentifies as ElementsTransaction
  if ((tx_pointer->num_inputs == 0) && (tx_pointer->num_outputs == 0)) {
    weight = static_cast<size_t>(kTransactionMinimumSize) * 4;
  } else {
    weight = AbstractTransaction::GetWeight();
  }
  return static_cast<uint32_t>(weight);
}

const TxInReference Transaction::GetTxIn(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  return TxInReference(vin_[index]);
}

uint32_t Transaction::GetTxInIndex(const Txid &txid, uint32_t vout) const {
  for (size_t i = 0; i < vin_.size(); ++i) {
    if (vin_[i].GetTxid().Equals(txid) && vin_[i].GetVout() == vout) {
      return static_cast<uint32_t>(i);
    }
  }
  warn(CFD_LOG_SOURCE, "Txid is not found.");
  throw CfdException(kCfdIllegalArgumentError, "Txid is not found.");
}

uint32_t Transaction::GetTxOutIndex(const Script &locking_script) const {
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

std::vector<uint32_t> Transaction::GetTxOutIndexList(
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

uint32_t Transaction::GetTxInCount() const {
  return static_cast<uint32_t>(vin_.size());
}

const std::vector<TxInReference> Transaction::GetTxInList() const {
  std::vector<TxInReference> refs;
  for (TxIn tx_in : vin_) {
    refs.push_back(TxInReference(tx_in));
  }
  return refs;
}

uint32_t Transaction::AddTxIn(
    const Txid &txid, uint32_t index, uint32_t sequence,
    const Script &unlocking_script) {
  if (vin_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vin maximum.");
    throw CfdException(kCfdIllegalStateError, "txin maximum.");
  }

  AbstractTransaction::AddTxIn(txid, index, sequence, unlocking_script);
  TxIn txin(txid, index, sequence);
  if (!unlocking_script.IsEmpty()) {
    txin = TxIn(txid, index, sequence, unlocking_script);
  }

  vin_.push_back(txin);

  CallbackStateChange(kStateChangeAddTxIn);
  return static_cast<uint32_t>(vin_.size() - 1);
}

void Transaction::RemoveTxIn(uint32_t index) {
  AbstractTransaction::RemoveTxIn(index);

  std::vector<TxIn>::const_iterator ite = vin_.cbegin();
  if (index != 0) {
    ite += index;
  }
  vin_.erase(ite);
  CallbackStateChange(kStateChangeRemoveTxIn);
}

void Transaction::SetUnlockingScript(
    uint32_t tx_in_index, const Script &unlocking_script) {
  AbstractTransaction::SetUnlockingScript(tx_in_index, unlocking_script);
  vin_[tx_in_index].SetUnlockingScript(unlocking_script);
  CallbackStateChange(kStateChangeUpdateSignTxIn);
}

void Transaction::SetUnlockingScript(
    uint32_t tx_in_index, const std::vector<ByteData> &unlocking_script) {
  Script generate_unlocking_script =
      AbstractTransaction::SetUnlockingScript(tx_in_index, unlocking_script);
  vin_[tx_in_index].SetUnlockingScript(generate_unlocking_script);
  CallbackStateChange(kStateChangeUpdateSignTxIn);
}

uint32_t Transaction::GetScriptWitnessStackNum(uint32_t tx_in_index) const {
  CheckTxInIndex(tx_in_index, __LINE__, __FUNCTION__);
  return vin_[tx_in_index].GetScriptWitnessStackNum();
}

const ScriptWitness Transaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData &data) {
  const ScriptWitness &witness =
      AddScriptWitnessStack(tx_in_index, data.GetBytes());
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

const ScriptWitness Transaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData160 &data) {
  const ScriptWitness &witness =
      AddScriptWitnessStack(tx_in_index, data.GetBytes());
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

const ScriptWitness Transaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const ByteData256 &data) {
  const ScriptWitness &witness =
      AddScriptWitnessStack(tx_in_index, data.GetBytes());
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

const ScriptWitness Transaction::AddScriptWitnessStack(
    uint32_t tx_in_index, const std::vector<uint8_t> &data) {
  AbstractTransaction::AddScriptWitnessStack(tx_in_index, data);

  const ScriptWitness &witness =
      vin_[tx_in_index].AddScriptWitnessStack(ByteData(data));
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

const ScriptWitness Transaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData &data) {
  const ScriptWitness &witness =
      SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

const ScriptWitness Transaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData160 &data) {
  const ScriptWitness &witness =
      SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

const ScriptWitness Transaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index, const ByteData256 &data) {
  const ScriptWitness &witness =
      SetScriptWitnessStack(tx_in_index, witness_index, data.GetBytes());
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

const ScriptWitness Transaction::SetScriptWitnessStack(
    uint32_t tx_in_index, uint32_t witness_index,
    const std::vector<uint8_t> &data) {
  AbstractTransaction::SetScriptWitnessStack(tx_in_index, witness_index, data);

  const ScriptWitness &witness =
      vin_[tx_in_index].SetScriptWitnessStack(witness_index, ByteData(data));
  CallbackStateChange(kStateChangeUpdateSignTxIn);
  return witness;
}

void Transaction::RemoveScriptWitnessStackAll(uint32_t tx_in_index) {
  AbstractTransaction::RemoveScriptWitnessStackAll(tx_in_index);

  vin_[tx_in_index].RemoveScriptWitnessStackAll();
  CallbackStateChange(kStateChangeUpdateSignTxIn);
}

const TxOutReference Transaction::GetTxOut(uint32_t index) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  return TxOutReference(vout_[index]);
}

uint32_t Transaction::GetTxOutCount() const {
  return static_cast<uint32_t>(vout_.size());
}

const std::vector<TxOutReference> Transaction::GetTxOutList() const {
  std::vector<TxOutReference> refs;
  for (TxOut tx_out : vout_) {
    refs.push_back(TxOutReference(tx_out));
  }
  return refs;
}

uint32_t Transaction::AddTxOut(
    const Amount &value, const Script &locking_script) {
  if (vout_.size() == std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "vout maximum.");
    throw CfdException(kCfdIllegalStateError, "vout maximum.");
  }

  AbstractTransaction::AddTxOut(value, locking_script);

  TxOut out(value, locking_script);
  vout_.push_back(out);
  CallbackStateChange(kStateChangeAddTxOut);
  return static_cast<uint32_t>(vout_.size() - 1);
}

void Transaction::RemoveTxOut(uint32_t index) {
  AbstractTransaction::RemoveTxOut(index);

  std::vector<TxOut>::const_iterator ite = vout_.cbegin();
  if (index != 0) {
    ite += index;
  }
  vout_.erase(ite);
  CallbackStateChange(kStateChangeRemoveTxOut);
}

ByteData256 Transaction::GetSignatureHash(
    uint32_t txin_index, const ByteData &script_data, SigHashType sighash_type,
    const Amount &value, WitnessVersion version) const {
  if (script_data.IsEmpty()) {
    warn(CFD_LOG_SOURCE, "empty script");
    throw CfdException(
        kCfdIllegalArgumentError, "Failed to GetSignatureHash. empty script.");
  }
  std::vector<uint8_t> buffer(SHA256_LEN);
  const std::vector<uint8_t> &bytes = script_data.GetBytes();
  struct wally_tx *tx_pointer = NULL;
  int ret = WALLY_OK;

  // It is assumed that tx information has been created.
  // (If it is not created, it will cause inconsistency)
  const std::vector<uint8_t> &tx_bytedata =
      GetByteData(HasWitness()).GetBytes();
  ret = wally_tx_from_bytes(
      tx_bytedata.data(), tx_bytedata.size(), 0, &tx_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_bytes NG[{}] ", ret);
    throw CfdException(kCfdIllegalArgumentError, "transaction data invalid.");
  }

  ret = WALLY_ENOMEM;
  if (tx_pointer != NULL) {
    try {
      uint32_t tx_flag = 0;
      if (version != WitnessVersion::kVersionNone) {
        tx_flag = GetWallyFlag() & WALLY_TX_FLAG_USE_WITNESS;
      }
      ret = wally_tx_get_btc_signature_hash(
          tx_pointer, txin_index, bytes.data(), bytes.size(),
          value.GetSatoshiValue(), sighash_type.GetSigHashFlag(), tx_flag,
          buffer.data(), buffer.size());
      wally_tx_free(tx_pointer);
    } catch (...) {
      wally_tx_free(tx_pointer);  // Separately released in case of exception
                                  // (possibility of exception by warn ())
      warn(CFD_LOG_SOURCE, "wally_tx_get_btc_signature_hash cause exception.");
      ret = WALLY_ERROR;
    }
  }

  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_btc_signature_hash NG[{}] ", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "SignatureHash generate error.");
  }

  return ByteData256(buffer);
}

bool Transaction::HasWitness() const {
  for (const TxIn &txin : vin_) {
    if (!txin.GetScriptWitness().GetWitness().empty()) {
      return true;
    }
  }
  return false;
}

ByteData Transaction::GetByteData(bool has_witness) const {
  struct wally_tx *tx_pointer =
      static_cast<struct wally_tx *>(wally_tx_pointer_);
  size_t size = 0;
  uint32_t flag = 0;
  if (has_witness) {
    flag = WALLY_TX_FLAG_USE_WITNESS;
  }

  int ret = wally_tx_get_length(tx_pointer, flag, &size);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_length NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "tx length calc error.");
  }
  if (size < kTransactionMinimumHexSize) {
    ret = WALLY_EINVAL;
  }
  std::vector<uint8_t> buffer(size);
  if (ret != WALLY_EINVAL) {
    ret = wally_tx_to_bytes(
        tx_pointer, flag, buffer.data(), buffer.size(), &size);
  }
  if (ret == WALLY_EINVAL) {
    /* TODO: About conversion to the object.
     * In libwally, txin / txout does not allow empty data.
     * Therefore, if txin / txout is empty, object to byte is an error.
     * Therefore, it performs its own processing under certain circumstances.
     */
    if ((tx_pointer->num_inputs == 0) || (tx_pointer->num_outputs == 0)) {
      info(CFD_LOG_SOURCE, "wally_tx_get_length size[{}]", size);
      // Necessary size calculation because wally_tx_get_length may be
      // an invalid value (reserved more)
      size_t need_size = sizeof(struct wally_tx);
      need_size += tx_pointer->num_inputs * sizeof(struct wally_tx_input);
      need_size += tx_pointer->num_outputs * sizeof(struct wally_tx_output);
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        need_size += input->script_len + 10;
      }
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        need_size += output->script_len + 10;
      }
      if (flag) {
        for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
          const struct wally_tx_input *input = tx_pointer->inputs + i;
          size_t num_items = input->witness ? input->witness->num_items : 0;
          for (uint32_t j = 0; j < num_items; ++j) {
            const struct wally_tx_witness_item *stack;
            stack = input->witness->items + j;
            need_size += stack->witness_len + 10;
          }
          need_size += 10;
        }
      }
      if (need_size > buffer.size()) {
        buffer.resize(need_size);
        info(CFD_LOG_SOURCE, "buffer.resize[{}]", need_size);
      }

      uint8_t *address_pointer = buffer.data();
      memcpy(
          address_pointer, &tx_pointer->version, sizeof(tx_pointer->version));
      address_pointer += sizeof(tx_pointer->version);
      if (flag && (tx_pointer->num_inputs != 0)) {  // witness
        *address_pointer = 0;                       // marker is 0
        ++address_pointer;
        *address_pointer = 1;  // flag is 1(witness)
        ++address_pointer;
      }

      // txin
      address_pointer =
          CopyVariableInt(tx_pointer->num_inputs, address_pointer);
      for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
        const struct wally_tx_input *input = tx_pointer->inputs + i;
        memcpy(address_pointer, input->txhash, sizeof(input->txhash));
        address_pointer += sizeof(input->txhash);
        memcpy(address_pointer, &input->index, sizeof(input->index));
        address_pointer += sizeof(input->index);
        address_pointer = CopyVariableBuffer(
            input->script, input->script_len, address_pointer);
        memcpy(address_pointer, &input->sequence, sizeof(input->sequence));
        address_pointer += sizeof(input->sequence);
      }

      // txout
      address_pointer =
          CopyVariableInt(tx_pointer->num_outputs, address_pointer);
      for (uint32_t i = 0; i < tx_pointer->num_outputs; ++i) {
        const struct wally_tx_output *output = tx_pointer->outputs + i;
        memcpy(address_pointer, &output->satoshi, sizeof(output->satoshi));
        address_pointer += sizeof(output->satoshi);
        address_pointer = CopyVariableBuffer(
            output->script, output->script_len, address_pointer);
      }

      // witness
      if (flag) {
        for (uint32_t i = 0; i < tx_pointer->num_inputs; ++i) {
          const struct wally_tx_input *input = tx_pointer->inputs + i;
          size_t num_items = input->witness ? input->witness->num_items : 0;
          address_pointer = CopyVariableInt(num_items, address_pointer);
          for (uint32_t j = 0; j < num_items; ++j) {
            const struct wally_tx_witness_item *stack;
            stack = input->witness->items + j;
            address_pointer = CopyVariableBuffer(
                stack->witness, stack->witness_len, address_pointer);
          }
        }
      }

      // locktime
      memcpy(
          address_pointer, &tx_pointer->locktime,
          sizeof(tx_pointer->locktime));
      address_pointer += sizeof(tx_pointer->locktime);

      unsigned char *start_address = buffer.data();
      size = address_pointer - start_address;
      if (buffer.size() > size) {
        buffer.resize(size);
        info(CFD_LOG_SOURCE, "set buffer size[{}]", size);
      }
    } else {
      // Exception
      warn(CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}].", ret);
      throw CfdException(kCfdIllegalStateError, "tx hex convert error.");
    }
  } else if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_to_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "tx hex convert error.");
  }

  return ByteData(buffer);
}

uint32_t Transaction::GetWallyFlag() const {
  return WALLY_TX_FLAG_USE_WITNESS;
}

void Transaction::CheckTxInIndex(
    uint32_t index, int line, const char *caller) const {
  if (vin_.size() <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "vin[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "vin out_of_range error.");
  }
}

void Transaction::CheckTxOutIndex(
    uint32_t index, int line, const char *caller) const {
  if (vout_.size() <= index) {
    spdlog::source_loc location = {CFD_LOG_FILE, line, caller};
    warn(location, "vout[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "vin out_of_range error.");
  }
}

}  // namespace core
}  // namespace cfd
