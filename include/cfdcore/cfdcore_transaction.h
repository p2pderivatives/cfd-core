// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_transaction.h
 *
 * @brief This file that defines Transaction related classes.
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_H_

#include <cstddef>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

//! OP_CODESEPARATOR default position
constexpr const uint32_t kDefaultCodeSeparatorPosition = 0xffffffff;

/**
 * @brief Tapscript data struct.
 */
struct TapScriptData {
  ByteData256 tap_leaf_hash;  //!< tapleaf hash
  //! OP_CODESEPARATOR position
  uint32_t code_separator_position = kDefaultCodeSeparatorPosition;
};

//! transaction callback type: add txin
constexpr const uint32_t kStateChangeAddTxIn = 0x00000001;
//! transaction callback type: update txin
constexpr const uint32_t kStateChangeUpdateTxIn = 0x00000002;
//! transaction callback type: remove txout
constexpr const uint32_t kStateChangeRemoveTxIn = 0x00000004;
//! transaction callback type: update sign txin
constexpr const uint32_t kStateChangeUpdateSignTxIn = 0x00000008;
//! transaction callback type: add txout
constexpr const uint32_t kStateChangeAddTxOut = 0x00000100;
//! transaction callback type: update txout
constexpr const uint32_t kStateChangeUpdateTxOut = 0x00000200;
//! transaction callback type: remove txout
constexpr const uint32_t kStateChangeRemoveTxOut = 0x00000400;

/**
 * @brief Class that holds TxOut information
 */
class CFD_CORE_EXPORT TxOut : public AbstractTxOut {
 public:
  /**
   * @brief constructor
   */
  TxOut();
  /**
   * @brief constructor
   * @param[in] value             amount value.
   * @param[in] locking_script    locking script.
   */
  TxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief constructor
   * @param[in] value             amount value.
   * @param[in] address           out address.
   */
  TxOut(const Amount& value, const Address& address);
  /**
   * @brief destructor
   */
  virtual ~TxOut() {
    // do nothing
  }
};

/**
 * @brief Class for referencing TxOut information.
 */
class CFD_CORE_EXPORT TxOutReference : public AbstractTxOutReference {
 public:
  /**
   * @brief constructor
   * @param[in] tx_out  TxOut instance
   */
  explicit TxOutReference(const TxOut& tx_out);
  /**
   * @brief default constructor.
   */
  TxOutReference() : TxOutReference(TxOut()) {
    // do nothing
  }
  /**
   * @brief destructor
   */
  virtual ~TxOutReference() {
    // do nothing
  }
};

/**
 * @brief Class that holds TxIn information
 */
class CFD_CORE_EXPORT TxIn : public AbstractTxIn {
 public:
  /**
   * @brief Minimum TxIn size
   * @details txid(32), vout(4), sequence(4), scriptLength(1)
   */
  static constexpr const size_t kMinimumTxInSize = 41;

  /**
   * @brief estimate txin's size, and witness size.
   * @param[in] addr_type         address type
   * @param[in] redeem_script     redeem script
   * @param[out] witness_area_size     witness area size
   * @param[out] no_witness_area_size  no witness area size
   * @param[in] scriptsig_template     scriptsig template
   * @return TxIn size.
   */
  static uint32_t EstimateTxInSize(
      AddressType addr_type, Script redeem_script = Script(),
      uint32_t* witness_area_size = nullptr,
      uint32_t* no_witness_area_size = nullptr,
      const Script* scriptsig_template = nullptr);

  /**
   * @brief estimate txin's virtual size direct.
   * @param[in] addr_type           address type
   * @param[in] redeem_script       redeem script
   * @param[in] scriptsig_template  scriptsig template
   * @return TxIn virtual size.
   */
  static uint32_t EstimateTxInVsize(
      AddressType addr_type, Script redeem_script = Script(),
      const Script* scriptsig_template = nullptr);

  /**
   * @brief constructor.
   * @param[in] txid        txid
   * @param[in] index       tx output index(vout)
   * @param[in] sequence    sequence
   */
  TxIn(const Txid& txid, uint32_t index, uint32_t sequence);
  /**
   * @brief constructor.
   * @param[in] txid              txid
   * @param[in] index       tx output index(vout)
   * @param[in] sequence          sequence
   * @param[in] unlocking_script  unlocking script
   */
  TxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script);
  /**
   * @brief destructor
   */
  virtual ~TxIn() {
    // do nothing
  }
};

/**
 * @brief Class for referencing TxIn information
 */
class CFD_CORE_EXPORT TxInReference : public AbstractTxInReference {
 public:
  /**
   * @brief constructor.
   * @param[in] tx_in TxIn instance to reference
   */
  explicit TxInReference(const TxIn& tx_in);
  /**
   * @brief default constructor.
   */
  TxInReference() : TxInReference(TxIn(Txid(), 0, 0)) {
    // do nothing
  }

  /**
   * @brief destructor
   */
  virtual ~TxInReference() {
    // do nothing
  }
};

/**
 * @brief Transaction class
 */
class CFD_CORE_EXPORT Transaction : public AbstractTransaction {
 public:
  /**
   * @brief constructor.
   */
  Transaction();
  /**
   * @brief constructor
   * @param[in] version       version
   * @param[in] lock_time     lock time
   */
  explicit Transaction(int32_t version, uint32_t lock_time);
  /**
   * @brief constructor
   * @param[in] byte_data   tx byte data
   */
  explicit Transaction(const ByteData& byte_data);
  /**
   * @brief constructor
   * @param[in] hex_string    HEX string
   */
  explicit Transaction(const std::string& hex_string);
  /**
   * @brief copy constructor.
   * @param[in] transaction   transaction object.
   */
  Transaction(const Transaction& transaction);
  /**
   * @brief destructor.
   */
  virtual ~Transaction() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] transaction   transaction object.
   * @return transaction object.
   */
  Transaction& operator=(const Transaction& transaction) &;

  /**
   * @brief Get the total byte size of Transaction.
   * @return total byte size
   */
  virtual uint32_t GetTotalSize() const;
  /**
   * @brief Get vsize information of Transaction.
   * @return vsize
   */
  virtual uint32_t GetVsize() const;
  /**
   * @brief Get the Weight information of Transaction.
   * @return weight
   */
  virtual uint32_t GetWeight() const;

  /**
   * @brief Get TxIn.
   * @param[in] index   txin index.
   * @return TxIn object.
   */
  const TxInReference GetTxIn(uint32_t index) const;
  /**
   * @brief Get the index of TxIn.
   * @param[in] txid   txid
   * @param[in] vout   vout
   * @return TxIn index
   */
  virtual uint32_t GetTxInIndex(const Txid& txid, uint32_t vout) const;
  /**
   * @brief Get the count of TxIn.
   * @return TxIn count.
   */
  uint32_t GetTxInCount() const;
  /**
   * @brief Get the TxIn list.
   * @return TxInReference list
   */
  const std::vector<TxInReference> GetTxInList() const;
  /**
   * @brief Add TxIn.
   * @param[in] txid                txid
   * @param[in] index               vout
   * @param[in] sequence            sequence
   * @param[in] unlocking_script    unlocking script
   * @return Index position of added TxIn
   */
  uint32_t AddTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script = Script::Empty);
  /**
   * @brief Delete the TxIn information.
   * @param[in] index     index
   */
  void RemoveTxIn(uint32_t index);
  /**
   * @brief Set the sequence number.
   * @param[in] tx_in_index       TxIn index
   * @param[in] sequence          sequence
   */
  void SetTxInSequence(uint32_t tx_in_index, uint32_t sequence);
  /**
   * @brief Set the unlocking script.
   * @param[in] tx_in_index       TxIn index
   * @param[in] unlocking_script  unlocking script (Push Op Only)
   */
  void SetUnlockingScript(
      uint32_t tx_in_index, const Script& unlocking_script);
  /**
   * @brief Set the unlocking script.
   * @param[in] tx_in_index       TxIn index
   * @param[in] unlocking_script  Unlocking script component list
   */
  void SetUnlockingScript(
      uint32_t tx_in_index, const std::vector<ByteData>& unlocking_script);
  /**
   * @brief Get the count of witness stacks.
   * @param[in] tx_in_index       TxIn index
   * @return count of witness stacks.
   */
  uint32_t GetScriptWitnessStackNum(uint32_t tx_in_index) const;
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData& data);
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData160& data);
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData256& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData160& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData256& data);
  /**
   * @brief Remove all script witness.
   * @param[in] tx_in_index       TxIn index
   */
  void RemoveScriptWitnessStackAll(uint32_t tx_in_index);

  /**
   * @brief Get TxOut.
   * @param[in] index     txout index
   * @return TxOutReference
   */
  const TxOutReference GetTxOut(uint32_t index) const;
  /**
   * @brief Get the index of TxOut.
   * @param[in] locking_script  locking script
   * @return txout index
   */
  virtual uint32_t GetTxOutIndex(const Script& locking_script) const;
  /**
   * @brief Get the TxOut index all at once.
   * @param[in] locking_script  locking script
   * @return txout index list.
   */
  virtual std::vector<uint32_t> GetTxOutIndexList(
      const Script& locking_script) const;
  /**
   * @brief Get the count of TxOuts.
   * @return count of TxOuts
   */
  uint32_t GetTxOutCount() const;
  /**
   * @brief Get the TxOut list.
   * @return TxOutReference list
   */
  const std::vector<TxOutReference> GetTxOutList() const;
  /**
   * @brief Add TxOut information.
   * @param[in] value           amount
   * @param[in] locking_script  locking script
   * @return Index position of added TxOut
   */
  uint32_t AddTxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief set TxOut's value.
   * @param[in] index   target txout index
   * @param[in] value   amount
   */
  void SetTxOutValue(uint32_t index, const Amount& value);
  /**
   * @brief Delete the TxOut information.
   * @param[in] index     txout index
   */
  void RemoveTxOut(uint32_t index);
  /**
   * @brief Get the signature hash.
   * @param[in] txin_index    TxIn index
   * @param[in] script_data   unlocking script or witness program.
   * @param[in] sighash_type  SigHashType(@see cfdcore_util.h)
   * @param[in] value         TxIn Amount.
   * @param[in] version       Witness version
   * @return signature hash
   */
  ByteData256 GetSignatureHash(
      uint32_t txin_index, const ByteData& script_data,
      SigHashType sighash_type, const Amount& value = Amount(),
      WitnessVersion version = WitnessVersion::kVersionNone) const;
  /**
   * @brief Get signature hash by schnorr.
   * @param[in] txin_index    TxIn's index
   * @param[in] sighash_type  SigHashType(@see cfdcore_util.h)
   * @param[in] utxo_list     utxo list (for amount & scriptPubkey)
   * @param[in] script_data   tap script data
   * @param[in] annex         annex data
   * @return signature hash
   */
  ByteData256 GetSchnorrSignatureHash(
      uint32_t txin_index, SigHashType sighash_type,
      const std::vector<TxOut>& utxo_list,
      const TapScriptData* script_data = nullptr,
      const ByteData& annex = ByteData()) const;
  /**
   * @brief Whether it holds witness information.
   * @retval true   witness exist.
   * @retval false  witness not found.
   */
  virtual bool HasWitness() const;

  // internal
  /**
   * @brief libwally Get the processing flag.
   * @return Flag for libwally
   */
  virtual uint32_t GetWallyFlag() const;

 protected:
  std::vector<TxIn> vin_;    ///< TxIn array
  std::vector<TxOut> vout_;  ///< TxOut array

  /**
   * @brief Set Transaction information from HEX string.
   * @param[in] hex_string    HEX string of Transaction byte data
   */
  void SetFromHex(const std::string& hex_string);

 private:
  /**
   * @brief check TxIn array range.
   * @param[in] index     TxIn Index
   * @param[in] line      Number of lines
   * @param[in] caller    Calling function name
   */
  virtual void CheckTxInIndex(
      uint32_t index, int line, const char* caller) const;
  /**
   * @brief check TxOut array range.
   * @param[in] index     TxOut Index
   * @param[in] line      Number of lines
   * @param[in] caller    Calling function name
   */
  virtual void CheckTxOutIndex(
      uint32_t index, int line, const char* caller) const;
  /**
   * @brief Add information to the witness stack.
   * @param[in] tx_in_index   TxIn index
   * @param[in] data          data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const std::vector<uint8_t>& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief Get the byte data of Transaction.
   * @param[in] has_witness   Flag to include witness
   * @return ByteData
   */
  ByteData GetByteData(bool has_witness) const;
  /**
   * @brief Check the consistency of ByteData in the TxOut area and set to TxOut.
   *
   * Set to TxOut only if tx_pointer is not NULL.
   * If tx_pointer is NULL, only consistency check is performed.
   * @param[in] buffer         ByteData in the TxOut area
   * @param[in] buf_size       ByteData size in the TxOut area
   * @param[in] txout_num      Number of TxOut information in the TxOut area
   * @param[in] txout_num_size TxOut information area size
   * @param[out] tx_pointer    Transaction information buffer (nullable)
   * @param[out] txout_list    TxOut array (nullable)
   * @retval true   Consistency check OK, TxOut information copy OK
   * @retval false  Consistency check NG or TxOut information copy failure
   */
  static bool CheckTxOutBuffer(
      const uint8_t* buffer, size_t buf_size, uint64_t txout_num,
      size_t txout_num_size, void* tx_pointer = nullptr,
      std::vector<TxOut>* txout_list = nullptr);
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_H_
