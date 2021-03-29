// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_psbt.h
 *
 * @brief This file is defines Partially Signed Bitcoin Transaction.
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_PSBT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_PSBT_H_

#include <cstddef>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_transaction.h"

namespace cfd {
namespace core {

/**
 * @brief The class of Partially Signed Bitcoin Transaction.
 */
class CFD_CORE_EXPORT Psbt {
 public:
  //! PSBT_GLOBAL_UNSIGNED_TX
  static constexpr uint8_t kPsbtGlobalUnsignedTx = 0x00;
  //! PSBT_GLOBAL_XPUB
  static constexpr uint8_t kPsbtGlobalXpub = 0x01;
  //! PSBT_GLOBAL_VERSION
  static constexpr uint8_t kPsbtGlobalVersion = 0xfb;
  //! PSBT_GLOBAL_PROPRIETARY
  static constexpr uint8_t kPsbtGlobalProprietary = 0xfc;
  //! PSBT_IN_NON_WITNESS_UTXO
  static constexpr uint8_t kPsbtInputNonWitnessUtxo = 0x00;
  //! PSBT_IN_WITNESS_UTXO
  static constexpr uint8_t kPsbtInputWitnessUtxo = 0x01;
  //! PSBT_IN_PARTIAL_SIG
  static constexpr uint8_t kPsbtInputPartialSig = 0x02;
  //! PSBT_IN_SIGHASH_TYPE
  static constexpr uint8_t kPsbtInputSighashType = 0x03;
  //! PSBT_IN_REDEEM_SCRIPT
  static constexpr uint8_t kPsbtInputRedeemScript = 0x04;
  //! PSBT_IN_WITNESS_SCRIPT
  static constexpr uint8_t kPsbtInputWitnessScript = 0x05;
  //! PSBT_IN_BIP32_DERIVATION
  static constexpr uint8_t kPsbtInputBip32Derivation = 0x06;
  //! PSBT_IN_FINAL_SCRIPTSIG
  static constexpr uint8_t kPsbtInputFinalScriptsig = 0x07;
  //! PSBT_IN_FINAL_SCRIPTWITNESS
  static constexpr uint8_t kPsbtInputFinalScriptWitness = 0x08;
  //! PSBT_IN_POR_COMMITMENT
  static constexpr uint8_t kPsbtInputPorCommitment = 0x09;
  //! PSBT_IN_RIPEMD160
  static constexpr uint8_t kPsbtInputRipemd160 = 0x0a;
  //! PSBT_IN_SHA256
  static constexpr uint8_t kPsbtInputSha256 = 0x0b;
  //! PSBT_IN_HASH160
  static constexpr uint8_t kPsbtInputHash160 = 0x0c;
  //! PSBT_IN_HASH256
  static constexpr uint8_t kPsbtInputHash256 = 0x0d;
  //! PSBT_IN_PROPRIETARY
  static constexpr uint8_t kPsbtInputProprietary = 0xfc;
  //! PSBT_OUT_REDEEM_SCRIPT
  static constexpr uint8_t kPsbtOutputRedeemScript = 0x00;
  //! PSBT_OUT_WITNESS_SCRIPT
  static constexpr uint8_t kPsbtOutputWitnessScript = 0x01;
  //! PSBT_OUT_BIP32_DERIVATION
  static constexpr uint8_t kPsbtOutputBip32Derivation = 0x02;
  //! PSBT_OUT_PROPRIETARY
  static constexpr uint8_t kPsbtOutputProprietary = 0xfc;

  /**
   * @brief Get PSBT default version.
   * @return PSBT version.
   */
  static uint32_t GetDefaultVersion();
  /**
   * @brief Create psbt record key.
   * @param[in] type  key type.
   * @return key data.
   */
  static ByteData CreateRecordKey(uint8_t type);
  /**
   * @brief Create psbt fix size record key.
   * @param[in] type  key type.
   * @param[in] fixed_size_key  fixed size key value.
   * @return key data.
   */
  static ByteData CreateFixRecordKey(
      uint8_t type, const ByteData& fixed_size_key);
  /**
   * @brief Create psbt record key.
   * @param[in] type  key type.
   * @param[in] key_bytes  key value.
   * @return key data.
   */
  static ByteData CreateRecordKey(uint8_t type, const ByteData& key_bytes);
  /**
   * @brief Create psbt record key.
   * @param[in] type  key type.
   * @param[in] key  key value.
   * @return key data.
   */
  static ByteData CreateRecordKey(uint8_t type, const std::string& key);
  /**
   * @brief Create psbt record key.
   * @param[in] type  key type.
   * @param[in] prefix  key prefix.
   * @param[in] sub_type  sub field key type.
   * @return key data.
   */
  static ByteData CreateRecordKey(
      uint8_t type, const ByteData& prefix, uint8_t sub_type);
  /**
   * @brief Create psbt record key.
   * @param[in] type  key type.
   * @param[in] prefix  key prefix.
   * @param[in] sub_type  sub field key type.
   * @return key data.
   */
  static ByteData CreateRecordKey(
      uint8_t type, const std::string& prefix, uint8_t sub_type);
  /**
   * @brief Create psbt record key.
   * @param[in] type  key type.
   * @param[in] prefix  key prefix.
   * @param[in] sub_type  sub field key type.
   * @param[in] sub_key_bytes  sub field key value.
   * @return key data.
   */
  static ByteData CreateRecordKey(
      uint8_t type, const ByteData& prefix, uint8_t sub_type,
      const ByteData& sub_key_bytes);
  /**
   * @brief Create psbt record key.
   * @param[in] type  key type.
   * @param[in] prefix  key prefix.
   * @param[in] sub_type  sub field key type.
   * @param[in] sub_key   sub field key value.
   * @return key data.
   */
  static ByteData CreateRecordKey(
      uint8_t type, const std::string& prefix, uint8_t sub_type,
      const std::string& sub_key);
  /**
   * @brief Create psbt pubkey record key.
   * @param[in] type  key type.
   * @param[in] pubkey  pubkey value.
   * @return key data.
   */
  static ByteData CreatePubkeyRecordKey(uint8_t type, const Pubkey& pubkey);

  /**
   * @brief constructor.
   *
   * for List.
   */
  Psbt();
  /**
   * @brief constructor
   * @param[in] version       tx version
   * @param[in] lock_time     lock time
   */
  explicit Psbt(uint32_t version, uint32_t lock_time);
  /**
   * @brief constructor
   * @param[in] psbt_version  psbt version
   * @param[in] version       tx version
   * @param[in] lock_time     lock time
   */
  explicit Psbt(uint32_t psbt_version, uint32_t version, uint32_t lock_time);
  /**
   * @brief constructor
   * @param[in] base64    base64 string.
   */
  explicit Psbt(const std::string& base64);
  /**
   * @brief constructor
   * @param[in] byte_data   byte data
   */
  explicit Psbt(const ByteData& byte_data);
  /**
   * @brief constructor
   * @param[in] transaction   Transaction object.
   */
  explicit Psbt(const Transaction& transaction);
  /**
   * @brief constructor
   * @param[in] psbt_version  psbt version
   * @param[in] transaction   Transaction object.
   */
  explicit Psbt(uint32_t psbt_version, const Transaction& transaction);
  /**
   * @brief constructor
   * @param[in] psbt   Psbt object.
   */
  Psbt(const Psbt& psbt);
  /**
   * @brief destructor
   */
  virtual ~Psbt() { Psbt::FreeWallyPsbtAddress(wally_psbt_pointer_); }

  /**
   * @brief copy constructor.
   * @param[in] psbt   Psbt object.
   * @return Psbt object.
   */
  Psbt& operator=(const Psbt& psbt) &;

  /**
   * @brief Get base64 string.
   * @return base64 string.
   */
  std::string GetBase64() const;

  /**
   * @brief Get binary data.
   * @return binary data.
   */
  ByteData GetData() const;

  /**
   * @brief Get binary size.
   * @return binary size.
   */
  uint32_t GetDataSize() const;

  /**
   * @brief check finalized.
   * @retval true   already finalized.
   * @retval false  not finalized.
   */
  bool IsFinalized() const;

  /**
   * @brief check finalized input.
   * @param[in] index   txin index.
   * @retval true   already finalized input.
   * @retval false  not finalized input.
   */
  bool IsFinalizedInput(uint32_t index) const;

  /**
   * @brief finalize input all.
   * @details support hashtype is p2pkh, p2wpkh, p2sh-p2wpkh, multisig(p2sh, p2wsh, p2sh-p2wsh)
   */
  void Finalize();

  /**
   * @brief extract transaction.
   * @details need already finalized.
   * @return binary transaction data.
   */
  ByteData Extract() const;

  /**
   * @brief extract transaction.
   * @details need already finalized.
   * @return transactiona.
   */
  Transaction ExtractTransaction() const;

  /**
   * @brief Get currently base transaction.
   * @return base transaction.
   */
  Transaction GetTransaction() const;

  /**
   * @brief Join psbt transaction before sign.
   * @param[in] transaction     psbt transaction.
   * @param[in] ignore_duplicate_error  ignore duplicate parameter error.
   */
  void Join(const Psbt& transaction, bool ignore_duplicate_error = false);

  /**
   * @brief Sign psbt transaction.
   * @param[in] privkey      private key.
   * @param[in] has_grind_r  Grind-R option.
   */
  void Sign(const Privkey& privkey, bool has_grind_r = true);

  /**
   * @brief Combine signed psbt transaction.
   * @param[in] transaction signed psbt transaction.
   */
  void Combine(const Psbt& transaction);

  /**
   * @brief Get txin count.
   * @return txin count.
   */
  uint32_t GetTxInCount() const;

  /**
   * @brief Get txout count.
   * @return txout count.
   */
  uint32_t GetTxOutCount() const;

  /**
   * @brief add base transaction input.
   * @param[in] txin  transaction input.
   * @return added index.
   */
  uint32_t AddTxIn(const TxIn& txin);
  /**
   * @brief add base transaction input.
   * @param[in] txin  transaction input.
   * @return added index.
   */
  uint32_t AddTxIn(const TxInReference& txin);
  /**
   * @brief add base transaction input.
   * @param[in] txid  utxo txid.
   * @param[in] vout  utxo vout.
   * @param[in] sequence  sequence.
   * @return added index.
   */
  uint32_t AddTxIn(const Txid& txid, uint32_t vout, uint32_t sequence);

  /**
   * @brief set input utxo data.
   * @param[in] index   input index
   * @param[in] tx      utxo transaction
   * @param[in] key     utxo related pubkey
   */
  void SetTxInUtxo(uint32_t index, const Transaction& tx, const KeyData& key);
  /**
   * @brief set input utxo data.
   * @param[in] index   input index
   * @param[in] tx      utxo transaction
   * @param[in] redeem_script   utxo related script (only script hash)
   * @param[in] key     utxo related pubkey
   */
  void SetTxInUtxo(
      uint32_t index, const Transaction& tx, const Script& redeem_script,
      const KeyData& key);
  /**
   * @brief set input utxo data.
   * @param[in] index   input index
   * @param[in] tx      utxo transaction
   * @param[in] redeem_script   utxo related script (only script hash)
   * @param[in] key_list     utxo related pubkey list
   */
  void SetTxInUtxo(
      uint32_t index, const Transaction& tx, const Script& redeem_script,
      const std::vector<KeyData>& key_list);
  /**
   * @brief set input utxo data.
   * @param[in] index   input index
   * @param[in] txout   utxo witness transaction output
   * @param[in] key     utxo related pubkey
   */
  void SetTxInUtxo(
      uint32_t index, const TxOutReference& txout, const KeyData& key);
  /**
   * @brief set input utxo data.
   * @param[in] index   input index
   * @param[in] txout   utxo witness transaction output
   * @param[in] redeem_script   utxo related script (only script hash)
   * @param[in] key     utxo related pubkey
   */
  void SetTxInUtxo(
      uint32_t index, const TxOutReference& txout, const Script& redeem_script,
      const KeyData& key);
  /**
   * @brief set input utxo data.
   * @param[in] index   input index
   * @param[in] txout   utxo witness transaction output
   * @param[in] redeem_script   utxo related script (only script hash)
   * @param[in] key_list     utxo related pubkey list
   */
  void SetTxInUtxo(
      uint32_t index, const TxOutReference& txout, const Script& redeem_script,
      const std::vector<KeyData>& key_list);
  /**
   * @brief set input utxo data on direct.
   * @param[in] index   input index
   * @param[in] txout   utxo witness transaction output
   */
  void SetTxInWitnessUtxoDirect(uint32_t index, const TxOutReference& txout);
  /**
   * @brief set input bip32 key on direct.
   * @param[in] index       input index
   * @param[in] key_data    key data
   */
  void SetTxInBip32KeyDirect(uint32_t index, const KeyData& key_data);

  /**
   * @brief set input signature.
   * @param[in] index   input index
   * @param[in] key     utxo related pubkey
   * @param[in] signature   signature data
   */
  void SetTxInSignature(
      uint32_t index, const KeyData& key, const ByteData& signature);
  /**
   * @brief set input sighash type.
   * @param[in] index   input index
   * @param[in] sighash_type   sighash type
   */
  void SetTxInSighashType(uint32_t index, const SigHashType& sighash_type);
  /**
   * @brief set input final script.
   * @param[in] index   input index
   * @param[in] unlocking_script   unlocking script data list.
   */
  void SetTxInFinalScript(
      uint32_t index, const std::vector<ByteData>& unlocking_script);
  /**
   * @brief set input record.
   * @param[in] index  input index
   * @param[in] key    key
   * @param[in] value  value
   */
  void SetTxInRecord(
      uint32_t index, const ByteData& key, const ByteData& value);

  /**
   * @brief get input utxo full transaction.
   * @param[in] index  input index
   * @param[in] ignore_error   ignore error with empty data.
   * @param[out] is_witness    has witness.
   * @return utxo transaction
   */
  Transaction GetTxInUtxoFull(
      uint32_t index, bool ignore_error = false,
      bool* is_witness = nullptr) const;
  /**
   * @brief get input utxo output data.
   * @param[in] index  input index
   * @param[in] ignore_error   ignore error with empty data.
   * @param[out] is_witness    has witness.
   * @return utxo transaction output
   */
  TxOut GetTxInUtxo(
      uint32_t index, bool ignore_error = false,
      bool* is_witness = nullptr) const;
  /**
   * @brief get input redeem script.
   * @param[in] index  input index
   * @param[in] ignore_error   ignore error with empty data.
   * @param[out] is_witness    has witness.
   * @return redeem script (or witness script)
   */
  Script GetTxInRedeemScript(
      uint32_t index, bool ignore_error = false,
      bool* is_witness = nullptr) const;
  /**
   * @brief get input redeem script.
   * @param[in] index  input index
   * @param[in] ignore_error   ignore error with empty data.
   * @param[in] is_witness     getting target witness.
   * @return redeem script (or witness script)
   */
  Script GetTxInRedeemScriptDirect(
      uint32_t index, bool ignore_error = false, bool is_witness = true) const;
  /**
   * @brief get input key data list.
   * @param[in] index  input index
   * @return key data list
   */
  std::vector<KeyData> GetTxInKeyDataList(uint32_t index) const;
  /**
   * @brief get input key data (only list top data).
   * @param[in] index  input index
   * @param[in] ignore_error   ignore error with empty data.
   * @return key data
   */
  KeyData GetTxInKeyData(uint32_t index, bool ignore_error = false) const;
  /**
   * @brief get input key data list related to signature.
   * @param[in] index  input index
   * @return key data list
   */
  std::vector<Pubkey> GetTxInSignaturePubkeyList(uint32_t index) const;
  /**
   * @brief get input signature related pubkey.
   * @param[in] index  input index
   * @param[in] pubkey  pubkey
   * @return signature
   */
  ByteData GetTxInSignature(uint32_t index, const Pubkey& pubkey) const;
  /**
   * @brief exist input signature related pubkey.
   * @param[in] index  input index
   * @param[in] pubkey  pubkey
   * @retval true  exist signature
   * @retval false  signature not found
   */
  bool IsFindTxInSignature(uint32_t index, const Pubkey& pubkey) const;
  /**
   * @brief get input sighash type.
   * @param[in] index  input index
   * @return sighash type
   */
  SigHashType GetTxInSighashType(uint32_t index) const;
  /**
   * @brief exist input sighash type.
   * @param[in] index  input index
   * @retval true  exist sighash type
   * @retval false  sighash type not found
   */
  bool IsFindTxInSighashType(uint32_t index) const;
  /**
   * @brief get input final script.
   * @param[in] index  input index
   * @param[in] is_witness_stack  target witness flag
   * @return witness stack or scriptSig
   */
  std::vector<ByteData> GetTxInFinalScript(
      uint32_t index, bool is_witness_stack = true) const;
  /**
   * @brief get input record value.
   * @param[in] index  input index
   * @param[in] key    record key
   * @return record value
   */
  ByteData GetTxInRecord(uint32_t index, const ByteData& key) const;
  /**
   * @brief exist input record.
   * @param[in] index  input index
   * @param[in] key    record key
   * @retval true  exist record
   * @retval false  record not found
   */
  bool IsFindTxInRecord(uint32_t index, const ByteData& key) const;
  /**
   * @brief get record key list.
   * @param[in] index  input index
   * @return record key list
   */
  std::vector<ByteData> GetTxInRecordKeyList(uint32_t index) const;
  /**
   * @brief clear input sign data.
   * @details clear target is redeem script, signature, sighashtype.
   * @param[in] index  input index
   */
  void ClearTxInSignData(uint32_t index);

  /**
   * @brief add base transaction output.
   * @param[in] txout   transaction output.
   * @return added index.
   */
  uint32_t AddTxOut(const TxOut& txout);
  /**
   * @brief add base transaction output.
   * @param[in] txout   transaction output.
   * @return added index.
   */
  uint32_t AddTxOut(const TxOutReference& txout);
  /**
   * @brief add base transaction output.
   * @param[in] locking_script   locking script.
   * @param[in] amount  amount.
   * @return added index.
   */
  uint32_t AddTxOut(const Script& locking_script, const Amount& amount);

  /**
   * @brief set output data.
   * @param[in] index   output index
   * @param[in] key     output related pubkey
   */
  void SetTxOutData(uint32_t index, const KeyData& key);
  /**
   * @brief set output data.
   * @param[in] index          output index
   * @param[in] redeem_script  output redeem script (only script hash)
   * @param[in] key            output related pubkey
   */
  void SetTxOutData(
      uint32_t index, const Script& redeem_script, const KeyData& key);
  /**
   * @brief set output data.
   * @param[in] index          output index
   * @param[in] redeem_script  output redeem script (only script hash)
   * @param[in] key_list       output related pubkey list
   */
  void SetTxOutData(
      uint32_t index, const Script& redeem_script,
      const std::vector<KeyData>& key_list);
  /**
   * @brief set output record.
   * @param[in] index   output index
   * @param[in] key     record key
   * @param[in] value   record value
   */
  void SetTxOutRecord(
      uint32_t index, const ByteData& key, const ByteData& value);

  /**
   * @brief get output redeem script.
   * @param[in] index  output index
   * @param[in] ignore_error   ignore error with empty data.
   * @param[out] is_witness    has witness.
   * @return redeem script (or witness script)
   */
  Script GetTxOutScript(
      uint32_t index, bool ignore_error = false,
      bool* is_witness = nullptr) const;
  /**
   * @brief get output key data (only list top data).
   * @param[in] index  output index
   * @param[in] ignore_error   ignore error with empty data.
   * @return key data
   */
  KeyData GetTxOutKeyData(uint32_t index, bool ignore_error = false) const;
  /**
   * @brief get output key data list related to redeem script.
   * @param[in] index  output index
   * @return key data list
   */
  std::vector<KeyData> GetTxOutKeyDataList(uint32_t index) const;
  /**
   * @brief get output record value.
   * @param[in] index  output index
   * @param[in] key    record key
   * @return record value
   */
  ByteData GetTxOutRecord(uint32_t index, const ByteData& key) const;
  /**
   * @brief exist output record.
   * @param[in] index  output index
   * @param[in] key    record key
   * @retval true  exist record
   * @retval false  record not found
   */
  bool IsFindTxOutRecord(uint32_t index, const ByteData& key) const;
  /**
   * @brief get record key list.
   * @param[in] index  output index
   * @return record key list
   */
  std::vector<ByteData> GetTxOutRecordKeyList(uint32_t index) const;

  /**
   * @brief Get the psbt version.
   * @return psbt version
   */
  uint32_t GetPsbtVersion() const;
  /**
   * @brief set global extpubkey.
   * @param[in] key     extkey data.
   */
  void SetGlobalXpubkey(const KeyData& key);
  /**
   * @brief get global extpubkey.
   * @param[in] key    extpubkey
   * @return key data
   */
  KeyData GetGlobalXpubkeyBip32(const ExtPubkey& key) const;
  /**
   * @brief exist global extpubkey.
   * @param[in] key    extpubkey
   * @retval true  exist record
   * @retval false  record not found
   */
  bool IsFindGlobalXpubkey(const ExtPubkey& key) const;
  /**
   * @brief get global key data list.
   * @return key data list
   */
  std::vector<KeyData> GetGlobalXpubkeyDataList() const;
  /**
   * @brief set global record.
   * @param[in] key     record key
   * @param[in] value   record value
   */
  void SetGlobalRecord(const ByteData& key, const ByteData& value);
  /**
   * @brief get global record value.
   * @param[in] key    record key
   * @return record value
   */
  ByteData GetGlobalRecord(const ByteData& key) const;
  /**
   * @brief exist global record.
   * @param[in] key    record key
   * @retval true  exist record
   * @retval false  record not found
   */
  bool IsFindGlobalRecord(const ByteData& key) const;
  /**
   * @brief get record key list.
   * @return record key list
   */
  std::vector<ByteData> GetGlobalRecordKeyList() const;

 protected:
  void* wally_psbt_pointer_;  ///< libwally psbt pointer
  Transaction base_tx_;       ///< base transaction

  /**
   * @brief Free a heap address for libwally-core psbt object.
   * @param[in] wally_psbt_pointer  address
   */
  static void FreeWallyPsbtAddress(const void* wally_psbt_pointer);
  /**
   * @brief Rebuild base transaction.
   * @param[in] wally_psbt_pointer  address
   * @return Transaction
   */
  static Transaction RebuildTransaction(const void* wally_psbt_pointer);

  /**
   * @brief Check the index range of the TxIn array.
   * @param[in] index     input index
   * @param[in] line      file line
   * @param[in] caller    caller function name
   */
  virtual void CheckTxInIndex(
      uint32_t index, int line, const char* caller) const;
  /**
   * @brief Check the index range of the TxOut array.
   * @param[in] index     output index
   * @param[in] line      file line
   * @param[in] caller    caller function name
   */
  virtual void CheckTxOutIndex(
      uint32_t index, int line, const char* caller) const;
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_PSBT_H_
