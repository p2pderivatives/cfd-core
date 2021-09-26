// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_transaction_common.h
 *
 * @brief Define Transaction-related common class and base class.
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_COMMON_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_COMMON_H_

#include <cstddef>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

/**
 * @brief Hash type definition
 */
enum HashType {
  kP2pkh = 0,   //!< P2pkh
  kP2sh = 1,    //!< P2sh
  kP2wpkh = 2,  //!< P2wpkh
  kP2wsh = 3,   //!< P2wsh
  kTaproot = 6  //!< Taproot
};

/**
 * @brief witness information retention class
 */
class CFD_CORE_EXPORT ScriptWitness {
 public:
  /**
   * @brief constructor.
   */
  ScriptWitness() : witness_stack_() {
    // do nothing
  }
  /**
   * @brief destructor.
   */
  virtual ~ScriptWitness() {
    // do nothing
  }
  /**
   * @brief Get the witness stack.
   * @return witness stack
   */
  const std::vector<ByteData> GetWitness() const;
  /**
   * @brief Get the number of witness stacks.
   * @return number of witness stacks.
   */
  uint32_t GetWitnessNum() const;
  /**
   * @brief Add to witness stack.
   * @param[in] data      byte array.
   */
  void AddWitnessStack(const ByteData& data);
  /**
   * @brief Update the specified index of the witness stack.
   * @param[in] index     index
   * @param[in] data      byte array.
   */
  void SetWitnessStack(uint32_t index, const ByteData& data);
  /**
   * @brief Check if the data is empty.
   * @retval true   empty.
   * @retval false  exist.
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief Check if the data is empty.
   * @retval true   empty.
   * @retval false  exist.
   */
  bool IsEmpty() const;

  /**
   * @brief Serialize witness stack information.
   * @return serialize data
   */
  ByteData Serialize() const;

 private:
  std::vector<ByteData> witness_stack_;  ///< witness stack.
};

/**
 * @brief class for serialize txin data model.
 */
class CFD_CORE_EXPORT OutPoint {
 public:
  /**
   * @brief constructor (for vector)
   */
  OutPoint();
  /**
   * @brief constructor.
   * @param[in] txid            txid
   * @param[in] vout            vout
   */
  explicit OutPoint(const Txid& txid, uint32_t vout);

  /**
   * @brief get txid.
   * @return Txid
   */
  const Txid GetTxid() const;
  /**
   * @brief get vout.
   * @return vout
   */
  uint32_t GetVout() const;

  /**
   * @brief check valid object.
   * @retval true
   * @retval false
   */
  bool IsValid() const;

  /**
   * @brief Equals operator.
   * @param[in] object     compare target.
   * @retval true   equals
   * @retval false  not equals
   */
  bool operator==(const OutPoint& object) const;
  /**
   * @brief Not Equals operator.
   * @param[in] object     compare target.
   * @retval true   not equals
   * @retval false  equals
   */
  bool operator!=(const OutPoint& object) const;
  /**
   * @brief Compare object.
   * @param[in] object     compare target.
   * @return compare value (0 is match)
   */
  int Compare(const OutPoint& object) const;

 private:
  Txid txid_;      //!< txid
  uint32_t vout_;  //!< vout
};

/**
 * @brief Compare operator.
 * @param[in] source     source
 * @param[in] dest       destination
 * @retval true   match
 * @retval false  unmatch
 */
CFD_CORE_EXPORT bool operator<(const OutPoint& source, const OutPoint& dest);
/**
 * @brief Compare operator.
 * @param[in] source     source
 * @param[in] dest       destination
 * @retval true   match
 * @retval false  unmatch
 */
CFD_CORE_EXPORT bool operator<=(const OutPoint& source, const OutPoint& dest);
/**
 * @brief Compare operator.
 * @param[in] source     source
 * @param[in] dest       destination
 * @retval true   match
 * @retval false  unmatch
 */
CFD_CORE_EXPORT bool operator>(const OutPoint& source, const OutPoint& dest);
/**
 * @brief Compare operator.
 * @param[in] source     source
 * @param[in] dest       destination
 * @retval true   match
 * @retval false  unmatch
 */
CFD_CORE_EXPORT bool operator>=(const OutPoint& source, const OutPoint& dest);

/**
 * @brief Base class that holds basic information about TxIn.
 */
class CFD_CORE_EXPORT AbstractTxIn {
 public:
  /**
   * @brief constructor.
   * @param[in] txid        txid
   * @param[in] index       TxOut Index information for txid transactions(vout)
   * @param[in] sequence    sequence
   */
  AbstractTxIn(const Txid& txid, uint32_t index, uint32_t sequence);
  /**
   * @brief constructor.
   * @param[in] txid              txid
   * @param[in] index             TxOut Index information for txid transactions(vout)
   * @param[in] sequence          sequence
   * @param[in] unlocking_script  unlocking script
   */
  AbstractTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script);
  /**
   * @brief destructor
   */
  virtual ~AbstractTxIn() {
    // do nothing
  }
  /**
   * @brief Get a txid.
   * @return Txid
   */
  Txid GetTxid() const;
  /**
   * @brief Get a vout.
   * @return vout
   */
  uint32_t GetVout() const;
  /**
   * @brief Get an outpoint.
   * @return outpoint
   */
  OutPoint GetOutPoint() const;
  /**
   * @brief Get an unlocking script.
   * @return unlocking script
   */
  Script GetUnlockingScript() const;
  /**
   * @brief Set an unlocking script.
   * @param[in] unlocking_script    unlocking script
   */
  void SetUnlockingScript(const Script& unlocking_script);
  /**
   * @brief Get a sequence.
   * @return sequence番号
   */
  uint32_t GetSequence() const;
  /**
   * @brief Set a sequence number.
   * @param[in] sequence    sequence number
   */
  void SetSequence(uint32_t sequence);
  /**
   * @brief Get a script witness.
   * @return ScriptWitness
   */
  ScriptWitness GetScriptWitness() const;
  /**
   * @brief Get the current stack number of script witness.
   * @return number of script witness.
   */
  uint32_t GetScriptWitnessStackNum() const;
  /**
   * @brief Add byte data to script witness.
   * @param[in] data    witness stack
   * @return ScriptWitness object
   */
  ScriptWitness AddScriptWitnessStack(const ByteData& data);
  /**
   * @brief Set byte data in script witness.
   * @param[in] index   witness stack index
   * @param[in] data    witness stack data
   * @return ScriptWitness object
   */
  ScriptWitness SetScriptWitnessStack(uint32_t index, const ByteData& data);
  /**
   * @brief Remove all script witness.
   */
  void RemoveScriptWitnessStackAll();

  /**
   * @brief Determine coinbase by txid / vout.
   * @retval true  coinbase
   * @retval false other
   */
  bool IsCoinBase() const;

 protected:
  Txid txid_;                     ///< txid
  uint32_t vout_;                 ///< vout
  Script unlocking_script_;       ///< unlocking script
  uint32_t sequence_;             ///< sequence no
  ScriptWitness script_witness_;  ///< script witness.
};

/**
 * @brief Base class for referencing basic information on TxIn.
 */
class CFD_CORE_EXPORT AbstractTxInReference {
 public:
  /**
   * @brief constructor.
   * @param[in] tx_in   TxIn instance to reference
   */
  explicit AbstractTxInReference(const AbstractTxIn& tx_in);

  /**
   * @brief destructor.
   */
  virtual ~AbstractTxInReference() {
    // do nothing
  }
  /**
   * @brief Get a txid.
   * @return Txid object.
   */
  Txid GetTxid() const { return txid_; }
  /**
   * @brief Get a vout.
   * @return vout
   */
  uint32_t GetVout() const { return vout_; }
  /**
   * @brief Get an outpoint.
   * @return outpoint
   */
  OutPoint GetOutPoint() const { return OutPoint(txid_, vout_); }
  /**
   * @brief Get an unlocking script.
   * @return unlocking script
   */
  Script GetUnlockingScript() const { return unlocking_script_; }
  /**
   * @brief Get a sequence.
   * @return sequence
   */
  uint32_t GetSequence() const { return sequence_; }
  /**
   * @brief Get a script witness.
   * @return ScriptWitness
   */
  ScriptWitness GetScriptWitness() const { return script_witness_; }
  /**
   * @brief Get a stack number of script witness.
   * @return stack number of script witness.
   */
  uint32_t GetScriptWitnessStackNum() const {
    return script_witness_.GetWitnessNum();
  }

 private:
  Txid txid_;                     ///< txid
  uint32_t vout_;                 ///< vout
  Script unlocking_script_;       ///< unlocking script
  uint32_t sequence_;             ///< sequence no
  ScriptWitness script_witness_;  ///< script witness.
};

/**
 * @brief Base class that holds basic information about TxOut.
 */
class CFD_CORE_EXPORT AbstractTxOut {
 public:
  /**
   * @brief constructor
   */
  AbstractTxOut();
  /**
   * @brief constructor
   * @param[in] value             amount value.
   * @param[in] locking_script    locking script.
   */
  AbstractTxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief constructor
   * @param[in] locking_script    locking script.
   */
  explicit AbstractTxOut(const Script& locking_script);
  /**
   * @brief destructor
   */
  virtual ~AbstractTxOut() {
    // do nothing
  }
  /**
   * @brief Get the amount.
   * @return amount
   */
  const Amount GetValue() const;
  /**
   * @brief Get the locking script.
   * @return locking script
   */
  const Script GetLockingScript() const;
  /**
   * @brief get value amount.
   * @param[in] value    amount.
   */
  virtual void SetValue(const Amount& value);

 protected:
  Amount value_;           ///< amount
  Script locking_script_;  ///< locking script
};

/**
 * @brief Base class for referencing basic information on TxOut.
 */
class CFD_CORE_EXPORT AbstractTxOutReference {
 public:
  /**
   * @brief constructor.
   * @param[in] tx_out  TxOut instance to reference
   */
  explicit AbstractTxOutReference(const AbstractTxOut& tx_out);
  /**
   * @brief destructor
   */
  virtual ~AbstractTxOutReference() {
    // do nothing
  }

  /**
   * @brief Get an amount.
   * @return amount
   */
  const Amount GetValue() const { return value_; }

  /**
   * @brief Get a locking script.
   * @return locking script
   */
  const Script GetLockingScript() const { return locking_script_; }

  /**
   * @brief Get a serialized size.
   * @return serialized size
   */
  uint32_t GetSerializeSize() const;

  /**
   * @brief Get a serialized virtual size.
   * @return serialized virtual size.
   */
  uint32_t GetSerializeVsize() const;

 protected:
  Amount value_;           ///< amount
  Script locking_script_;  ///< locking script
};

/**
 * @brief Base class of transaction information.
 */
class CFD_CORE_EXPORT AbstractTransaction {
 public:
  /// Minimum size of Transaction
  static constexpr size_t kTransactionMinimumSize = 10;

  /**
   * @brief constructor.
   */
  AbstractTransaction();
  /**
   * @brief destructor.
   */
  virtual ~AbstractTransaction() {
    AbstractTransaction::FreeWallyAddress(wally_tx_pointer_);
  }

  /**
   * @brief Get a version information.
   * @return version
   */
  int32_t GetVersion() const;
  /**
   * @brief Get a lock time.
   * @return lock time
   */
  uint32_t GetLockTime() const;

  /**
   * @brief Get a TxIn index.
   * @param[in] txid   txid
   * @param[in] vout   vout
   * @return index
   */
  virtual uint32_t GetTxInIndex(const Txid& txid, uint32_t vout) const = 0;
  /**
   * @brief Get a TxOut index.
   * @param[in] locking_script  locking script
   * @return index
   */
  virtual uint32_t GetTxOutIndex(const Script& locking_script) const = 0;

  /**
   * @brief Get the total byte size of Transaction.
   * @return Total byte size
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
   * @brief Get the total TxOut amount of Transaction.
   * @return total TxOut amount
   */
  Amount GetValueOut() const;
  /**
   * @brief Get witness information.
   * @retval true   witness
   * @retval false  not witness
   */
  virtual bool HasWitness() const;
  /**
   * @brief Get the hash value of Transaction.
   *
   * In the Witness format, the Witness information is not included in the hash calculation.
   * @return Hash value
   */
  ByteData256 GetHash() const;
  /**
   * @brief Get the hash value of Transaction including Witness information.
   * @return Hash value
   */
  ByteData256 GetWitnessHash() const;
  /**
   * @brief Get the byte data of Transaction.
   * @return byte data
   */
  virtual ByteData GetData() const;
  /**
   * @brief Get the byte data of Transaction by converting to HEX character string.
   * @return hex string.
   */
  std::string GetHex() const;
  /**
   * @brief Get the txid.
   *
   * Equivalent to GetHash().
   * @return txid
   */
  Txid GetTxid() const;
  /**
   * @brief Determine if it is coinbase.
   * @retval true   coinbase transaction
   * @retval false  normaltransaction
   */
  bool IsCoinBase() const;

  /**
   * @brief libwally Get the processing flag.
   * @return Flag for libwally
   */
  virtual uint32_t GetWallyFlag() const = 0;

  /**
   * @brief Get vsize from size information.
   * @param[in] no_witness_size   Non-witness area size
   * @param[in] witness_size      witness area size
   * @return vsize
   */
  static uint32_t GetVsizeFromSize(
      uint32_t no_witness_size, uint32_t witness_size);

 protected:
  void* wally_tx_pointer_;  ///< libwally tx structure address

  /**
   * @brief This function is called by the state change.
   * @param[in] type    change type
   */
  virtual void CallbackStateChange(uint32_t type);
  /**
   * @brief Add TxIn.
   * @param[in] txid                txid
   * @param[in] index               vout
   * @param[in] sequence            sequence
   * @param[in] unlocking_script    unlocking script
   */
  void AddTxIn(
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
   * @param[in] tx_in_index       index
   * @param[in] unlocking_script  Unlocking script to set to TxIn (Push Op Only)
   */
  void SetUnlockingScript(
      uint32_t tx_in_index, const Script& unlocking_script);
  /**
   * @brief Set the unlocking script.
   * @param[in] tx_in_index       index
   * @param[in] unlocking_script  List of unlocking script components to set in TxIn
   * @return Generated Unlocking Script
   */
  Script SetUnlockingScript(
      uint32_t tx_in_index, const std::vector<ByteData>& unlocking_script);
  /**
   * @brief Remove all script witness.
   * @param[in] tx_in_index       index
   */
  void RemoveScriptWitnessStackAll(uint32_t tx_in_index);
  /**
   * @brief Add TxOut information.
   * @param[in] value           amount
   * @param[in] locking_script  locking script
   */
  void AddTxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief Delete the TxOut information.
   * @param[in] index     index
   */
  void RemoveTxOut(uint32_t index);

  /**
   * @brief Check the Index range of the TxIn array.
   * @param[in] index     index
   * @param[in] line      Number of lines
   * @param[in] caller    Calling function name
   */
  virtual void CheckTxInIndex(
      uint32_t index, int line, const char* caller) const = 0;
  /**
   * @brief check TxOut array range.
   * @param[in] index     index
   * @param[in] line      Number of lines
   * @param[in] caller    Calling function name
   */
  virtual void CheckTxOutIndex(
      uint32_t index, int line, const char* caller) const = 0;
  /**
   * @brief Add information to the witness stack.
   * @param[in] tx_in_index   index
   * @param[in] data          Byte data to add to the witness stack
   */
  void AddScriptWitnessStack(
      uint32_t tx_in_index, const std::vector<uint8_t>& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       index position of txin
   * @param[in] witness_index     index position of witness stack
   * @param[in] data              32byte information to add to the witness stack
   */
  void SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief Get the hash value of transaction.
   * @param[in] has_witness   Whether to include witness in the calculation (whether to perform wtxid calculation)
   * @return Hash value
   */
  ByteData256 GetHash(bool has_witness) const;
  /**
   * @brief Get the byte data of Transaction.
   * @param[in] has_witness   Flag to include witness
   * @return byte data
   */
  virtual ByteData GetByteData(bool has_witness) const = 0;
  /**
   * @brief Get VariableInt data.
   * @param[in] p_byte_data Byte array address
   * @param[in] data_size Byte array size
   * @param[out] p_result VariableInt data
   * @param[out] p_size VariableInt data size
   * @retval true   success
   * @retval false  fail
   */
  static bool GetVariableInt(
      const uint8_t* p_byte_data, size_t data_size, uint64_t* p_result,
      size_t* p_size);
  /**
   * @brief Copy VariableInt data.
   * @param[in] v VariableInt data
   * @param[out] bytes_out Copy destination address
   * @return Copy destination address
   */
  static uint8_t* CopyVariableInt(uint64_t v, uint8_t* bytes_out);
  /**
   * @brief Copy VariableBuffer data.
   * @param[in] bytes Byte array address
   * @param[in] bytes_len Byte array size
   * @param[out] bytes_out Copy destination address
   * @return Copy destination address
   */
  static uint8_t* CopyVariableBuffer(
      const uint8_t* bytes, size_t bytes_len, uint8_t* bytes_out);
  /**
   * @brief Free the libwally heap address.
   * @param[in] wally_tx_pointer  address
   */
  static void FreeWallyAddress(const void* wally_tx_pointer);
};

/**
 * @brief A class that performs signature calculations.
 */
class CFD_CORE_EXPORT SignatureUtil {
 public:
  /**
   * @brief Calculate the signature from the private key using elliptic curve cryptography.
   * @param[in] signature_hash  signature hash
   * @param[in] private_key     private key
   * @param[in] has_grind_r     EC_FLAG_GRIND_R flag
   * @return signature
   */
  static ByteData CalculateEcSignature(
      const ByteData256& signature_hash, const Privkey& private_key,
      bool has_grind_r = true);

  /**
   * @brief Verify if a signature with respect to a public key and a message.
   * @param[in] signature_hash  the message to verify the signature against.
   * @param[in] pubkey          the public key to verify the signature against.
   * @param[in] signature       the signature to verify.
   * @return true if the signature is valid, false if not.
   */
  static bool VerifyEcSignature(
      const ByteData256& signature_hash, const Pubkey& pubkey,
      const ByteData& signature);

 private:
  SignatureUtil();
  // constructor抑止
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_COMMON_H_
