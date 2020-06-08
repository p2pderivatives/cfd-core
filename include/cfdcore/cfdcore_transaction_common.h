// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_transaction_common.h
 *
 * @brief Transaction関連の共通クラスおよび基底クラスを定義する。
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
 * @brief ハッシュ種別定義
 */
enum HashType {
  kP2pkh = 0,   //!< P2pkh
  kP2sh = 1,    //!< P2sh
  kP2wpkh = 2,  //!< P2wpkh
  kP2wsh = 3    //!< P2wsh
};

/**
 * @brief witness情報の保持クラス
 */
class CFD_CORE_EXPORT ScriptWitness {
 public:
  /**
   * @brief コンストラクタ
   */
  ScriptWitness() : witness_stack_() {
    // do nothing
  }
  /**
   * @brief デストラクタ
   */
  virtual ~ScriptWitness() {
    // do nothing
  }
  /**
   * @brief witness stackを取得する.
   * @return witness stack
   */
  const std::vector<ByteData> GetWitness() const;
  /**
   * @brief witness stack数を取得する.
   * @return witness stack数
   */
  uint32_t GetWitnessNum() const;
  /**
   * @brief witness stackに追加する.
   * @param[in] data      バイトデータ
   */
  void AddWitnessStack(const ByteData& data);
  /**
   * @brief witness stackの指定indexを更新する.
   * @param[in] index     設定先index値
   * @param[in] data      バイトデータ
   */
  void SetWitnessStack(uint32_t index, const ByteData& data);
  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   */
  bool IsEmpty() const;

  /**
   * @brief witness stack情報をserializeする.
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
   * @brief 等価比較オペレータ
   * @param[in] object     比較対象
   * @retval true 等価
   * @retval false 不等価
   */
  bool operator==(const OutPoint& object) const;
  /**
   * @brief 不等価比較オペレータ
   * @param[in] object     比較対象
   * @retval true 不等価
   * @retval false 等価
   */
  bool operator!=(const OutPoint& object) const;

 private:
  Txid txid_;      //!< txid
  uint32_t vout_;  //!< vout
};

/**
 * @brief 不等価比較オペレータ
 * @param[in] source     比較元
 * @param[in] dest       比較対象
 * @retval true 不等価
 * @retval false 等価
 */
CFD_CORE_EXPORT bool operator<(const OutPoint& source, const OutPoint& dest);
/**
 * @brief 不等価比較オペレータ
 * @param[in] source     比較元
 * @param[in] dest       比較対象
 * @retval true 不等価
 * @retval false 等価
 */
CFD_CORE_EXPORT bool operator<=(const OutPoint& source, const OutPoint& dest);
/**
 * @brief 不等価比較オペレータ
 * @param[in] source     比較元
 * @param[in] dest       比較対象
 * @retval true 不等価
 * @retval false 等価
 */
CFD_CORE_EXPORT bool operator>(const OutPoint& source, const OutPoint& dest);
/**
 * @brief 不等価比較オペレータ
 * @param[in] source     比較元
 * @param[in] dest       比較対象
 * @retval true 不等価
 * @retval false 等価
 */
CFD_CORE_EXPORT bool operator>=(const OutPoint& source, const OutPoint& dest);

/**
 * @brief TxInの基本情報を保持する基底クラス
 */
class CFD_CORE_EXPORT AbstractTxIn {
 public:
  /**
   * @brief コンストラクタ.
   * @param[in] txid        txid
   * @param[in] index       txidのトランザクションのTxOutのIndex情報(vout)
   * @param[in] sequence    sequence情報
   */
  AbstractTxIn(const Txid& txid, uint32_t index, uint32_t sequence);
  /**
   * @brief コンストラクタ.
   * @param[in] txid              txid
   * @param[in] index             txidのトランザクションのTxOutのIndex情報(vout)
   * @param[in] sequence          sequence情報
   * @param[in] unlocking_script  unlocking script
   */
  AbstractTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script);
  /**
   * @brief デストラクタ
   */
  virtual ~AbstractTxIn() {
    // do nothing
  }
  /**
   * @brief txidを取得する.
   * @return Txidインスタンス
   */
  Txid GetTxid() const;
  /**
   * @brief voutを取得する.
   * @return vout
   */
  uint32_t GetVout() const;
  /**
   * @brief outpointを取得する.
   * @return outpoint
   */
  OutPoint GetOutPoint() const;
  /**
   * @brief unlocking scriptを取得する.
   * @return unlocking script
   */
  Script GetUnlockingScript() const;
  /**
   * @brief unlocking scriptを設定する.
   * @param[in] unlocking_script    unlocking script
   */
  void SetUnlockingScript(const Script& unlocking_script);
  /**
   * @brief sequenceを取得する.
   * @return sequence番号
   */
  uint32_t GetSequence() const;
  /**
   * @brief script witness情報を取得する.
   * @return ScriptWitnessインスタンス
   */
  ScriptWitness GetScriptWitness() const;
  /**
   * @brief script witnessの現在のstack数を取得する.
   * @return script witnessのstack数
   */
  uint32_t GetScriptWitnessStackNum() const;
  /**
   * @brief script witnessにバイトデータを追加する.
   * @param[in] data    witness stack情報
   * @return script witnessオブジェクト
   */
  ScriptWitness AddScriptWitnessStack(const ByteData& data);
  /**
   * @brief script witnessにバイトデータを設定する.
   * @param[in] index   witness stackのindex値
   * @param[in] data    witness stack情報
   * @return ScriptWitnessインスタンス
   */
  ScriptWitness SetScriptWitnessStack(uint32_t index, const ByteData& data);
  /**
   * @brief script witnessを全て削除する.
   */
  void RemoveScriptWitnessStackAll();

  /**
   * @brief txid/voutによりcoinbaseを判定する.
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
 * @brief TxInの基本情報を参照するための基底クラス
 */
class CFD_CORE_EXPORT AbstractTxInReference {
 public:
  /**
   * @brief コンストラクタ.
   * @param[in] tx_in 参照するTxInインスタンス
   */
  explicit AbstractTxInReference(const AbstractTxIn& tx_in);

  /**
   * @brief デストラクタ
   */
  virtual ~AbstractTxInReference() {
    // do nothing
  }
  /**
   * @brief txidを取得する.
   * @return Txidインスタンス
   */
  Txid GetTxid() const { return txid_; }
  /**
   * @brief voutを取得する.
   * @return vout
   */
  uint32_t GetVout() const { return vout_; }
  /**
   * @brief outpointを取得する.
   * @return outpoint
   */
  OutPoint GetOutPoint() const { return OutPoint(txid_, vout_); }
  /**
   * @brief unlocking scriptを取得する.
   * @return unlocking script
   */
  Script GetUnlockingScript() const { return unlocking_script_; }
  /**
   * @brief sequenceを取得する.
   * @return sequence番号
   */
  uint32_t GetSequence() const { return sequence_; }
  /**
   * @brief script witness情報を取得する.
   * @return ScriptWitnessインスタンス
   */
  ScriptWitness GetScriptWitness() const { return script_witness_; }
  /**
   * @brief script witnessの現在のstack数を取得する.
   * @return script witnessのstack数
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
 * @brief TxOutの基本情報を保持する基底クラス
 */
class CFD_CORE_EXPORT AbstractTxOut {
 public:
  /**
   * @brief コンストラクタ
   */
  AbstractTxOut();
  /**
   * @brief コンストラクタ
   * @param[in] value             amount value.
   * @param[in] locking_script    locking script.
   */
  AbstractTxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief コンストラクタ
   * @param[in] locking_script    locking script.
   */
  explicit AbstractTxOut(const Script& locking_script);
  /**
   * @brief デストラクタ
   */
  virtual ~AbstractTxOut() {
    // do nothing
  }
  /**
   * @brief Amountを取得する.
   * @return amount
   */
  const Amount GetValue() const;
  /**
   * @brief locking script を取得する
   * @return locking script
   */
  const Script GetLockingScript() const;
  /**
   * @brief get value amount.
   * @param[in] value    amount.
   */
  virtual void SetValue(const Amount& value);

 protected:
  Amount value_;           ///< 金額
  Script locking_script_;  ///< locking script
};

/**
 * @brief TxOutの基本情報を参照するための基底クラス
 */
class CFD_CORE_EXPORT AbstractTxOutReference {
 public:
  /**
   * @brief コンストラクタ
   * @param[in] tx_out 参照するTxOutインスタンス
   */
  explicit AbstractTxOutReference(const AbstractTxOut& tx_out);
  /**
   * @brief デストラクタ
   */
  virtual ~AbstractTxOutReference() {
    // do nothing
  }

  /**
   * @brief Amountを取得する.
   * @return amount
   */
  const Amount GetValue() const { return value_; }

  /**
   * @brief locking script を取得する
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
  Amount value_;           ///< 金額
  Script locking_script_;  ///< locking script
};

/**
 * @brief トランザクション情報の基底クラス
 */
class CFD_CORE_EXPORT AbstractTransaction {
 public:
  /// Transactionの最小サイズ
  static constexpr size_t kTransactionMinimumSize = 10;

  /**
   * @brief コンストラクタ
   */
  AbstractTransaction();
  /**
   * @brief デストラクタ
   */
  virtual ~AbstractTransaction() {
    AbstractTransaction::FreeWallyAddress(wally_tx_pointer_);
  }

  /**
   * @brief バージョン情報を取得する.
   * @return version番号
   */
  int32_t GetVersion() const;
  /**
   * @brief lock timeを取得する.
   * @return lock time
   */
  uint32_t GetLockTime() const;

  /**
   * @brief TxInのindexを取得する.
   * @param[in] txid   取得するTxInのtxid
   * @param[in] vout   取得するTxInのvout
   * @return 条件に合致するTxInのindex番号
   */
  virtual uint32_t GetTxInIndex(const Txid& txid, uint32_t vout) const = 0;
  /**
   * @brief TxOutのindexを取得する.
   * @param[in] locking_script  locking script
   * @return 条件に合致するTxOutのindex番号
   */
  virtual uint32_t GetTxOutIndex(const Script& locking_script) const = 0;

  /**
   * @brief Transactionの合計バイトサイズを取得する.
   * @return 合計バイトサイズ
   */
  virtual uint32_t GetTotalSize() const;
  /**
   * @brief Transactionのvsize情報を取得する.
   * @return vsize
   */
  virtual uint32_t GetVsize() const;
  /**
   * @brief TransactionのWeight情報を取得する.
   * @return weight
   */
  virtual uint32_t GetWeight() const;
  /**
   * @brief TransactionのTxOut合計額を取得する.
   * @return TxOut合計額
   */
  Amount GetValueOut() const;
  /**
   * @brief witness情報かどうかを取得する.
   * @retval true   witness
   * @retval false  witnessではない
   */
  virtual bool HasWitness() const;
  /**
   * @brief Transactionのハッシュ値を取得する.
   *
   * Witness形式の場合、Witness情報はハッシュ計算に含めない.
   * @return ハッシュ値
   */
  ByteData256 GetHash() const;
  /**
   * @brief Witness情報を含めたTransactionのハッシュ値を取得する.
   * @return ハッシュ値
   */
  ByteData256 GetWitnessHash() const;
  /**
   * @brief Transactionのバイトデータを取得する.
   * @return バイトデータ
   */
  virtual ByteData GetData() const;
  /**
   * @brief TransactionのバイトデータをHEX文字列変換して取得する.
   * @return HEX文字列
   */
  std::string GetHex() const;
  /**
   * @brief txidを取得する.
   *
   * GetHash()と同値となる.
   * @return txid
   */
  Txid GetTxid() const;
  /**
   * @brief coinbaseかどうか判定する.
   * @retval true  coinbase transaction
   * @retval false 通常のtransaction
   */
  bool IsCoinBase() const;

  /**
   * @brief libwally処理用フラグを取得する。
   * @return libwally用フラグ
   */
  virtual uint32_t GetWallyFlag() const = 0;

  /**
   * @brief size情報からvsizeを取得する。
   * @param[in] no_witness_size   非witness領域サイズ
   * @param[in] witness_size      witness領域サイズ
   * @return vsize
   */
  static uint32_t GetVsizeFromSize(
      uint32_t no_witness_size, uint32_t witness_size);

 protected:
  void* wally_tx_pointer_;  ///< libwally tx構造体アドレス

  /**
   * @brief This function is called by the state change.
   * @param[in] type    change type
   */
  virtual void CallbackStateChange(uint32_t type);
  /**
   * @brief TxInを追加する.
   * @param[in] txid                txid
   * @param[in] index               vout
   * @param[in] sequence            sequence
   * @param[in] unlocking_script    unlocking script (未指定時はEmptyを設定する. default Script::Empty)
   */
  void AddTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script = Script::Empty);
  /**
   * @brief TxIn情報を削除する.
   * @param[in] index     削除するindex位置
   */
  void RemoveTxIn(uint32_t index);
  /**
   * @brief unlocking scriptを設定する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] unlocking_script  TxInに設定するunlocking script (Push Op Only)
   */
  void SetUnlockingScript(
      uint32_t tx_in_index, const Script& unlocking_script);
  /**
   * @brief unlocking scriptを設定する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] unlocking_script  TxInに設定するunlocking scriptの構成要素リスト
   * @return 生成したUnlockingScript
   */
  Script SetUnlockingScript(
      uint32_t tx_in_index, const std::vector<ByteData>& unlocking_script);
  /**
   * @brief script witnessを全て削除する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   */
  void RemoveScriptWitnessStackAll(uint32_t tx_in_index);
  /**
   * @brief TxOut情報を追加する.
   * @param[in] value           amount
   * @param[in] locking_script  locking script
   */
  void AddTxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief TxOut情報を削除する.
   * @param[in] index     取得するindex位置
   */
  void RemoveTxOut(uint32_t index);

  /**
   * @brief TxIn配列のIndex範囲をチェックする.
   * @param[in] index     TxIn配列のIndex値
   * @param[in] line      行数
   * @param[in] caller    コール元関数名
   */
  virtual void CheckTxInIndex(
      uint32_t index, int line, const char* caller) const = 0;
  /**
   * @brief TxOut配列のIndex範囲をチェックする.
   * @brief check TxOut array range.
   * @param[in] index     TxOut配列のIndex値
   * @param[in] line      行数
   * @param[in] caller    コール元関数名
   */
  virtual void CheckTxOutIndex(
      uint32_t index, int line, const char* caller) const = 0;
  /**
   * @brief witness stackに情報を追加する.
   * @param[in] tx_in_index   TxIn配列のindex値
   * @param[in] data          witness stackに追加するバイトデータ
   */
  void AddScriptWitnessStack(
      uint32_t tx_in_index, const std::vector<uint8_t>& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   */
  void SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief transactionのハッシュ値を取得する.
   * @param[in] has_witness   witnessを計算に含めるか(wtxid計算を行うかどうか)
   * @return ハッシュ値
   */
  ByteData256 GetHash(bool has_witness) const;
  /**
   * @brief Transactionのバイトデータを取得する.
   * @param[in] has_witness   witnessを含めるかのフラグ
   * @return バイトデータ
   */
  virtual ByteData GetByteData(bool has_witness) const = 0;
  /**
   * @brief VariableIntデータを取得する.
   * @param[in] p_byte_data Byte配列アドレス
   * @param[in] data_size Byte配列サイズ
   * @param[out] p_result VariableIntデータ
   * @param[out] p_size VariableIntデータサイズ
   * @retval true   成功
   * @retval false  失敗
   */
  static bool GetVariableInt(
      const uint8_t* p_byte_data, size_t data_size, uint64_t* p_result,
      size_t* p_size);
  /**
   * @brief VariableIntデータをコピーする.
   * @param[in] v VariableIntデータ
   * @param[out] bytes_out コピー先アドレス
   * @return コピー先アドレス
   */
  static uint8_t* CopyVariableInt(uint64_t v, uint8_t* bytes_out);
  /**
   * @brief VariableBufferデータをコピーする.
   * @param[in] bytes Byte配列アドレス
   * @param[in] bytes_len Byte配列サイズ
   * @param[out] bytes_out コピー先アドレス
   * @return コピー先アドレス
   */
  static uint8_t* CopyVariableBuffer(
      const uint8_t* bytes, size_t bytes_len, uint8_t* bytes_out);
  /**
   * @brief libwallyのヒープアドレスを解放する。
   * @param[in] wally_tx_pointer  アドレス
   */
  static void FreeWallyAddress(const void* wally_tx_pointer);
};

/**
 * @brief signature計算を行うクラス.
 */
class CFD_CORE_EXPORT SignatureUtil {
 public:
  /**
   * @brief 楕円曲線暗号を用いて、秘密鍵からsignatureを計算する.
   * @param[in] signature_hash  signatureハッシュ
   * @param[in] private_key     秘密鍵
   * @param[in] has_grind_r     EC_FLAG_GRIND_Rフラグ有無
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

  /**
   * @brief Create a schnorr signature using the a given private key and nonce.
   * @param[in] oracle_key      the private key to sign with.
   * @param[in] k_value         the nonce to use in the signature generation.
   * @param[in] message         the message to sign.
   * @return signature (33 - 64)
   */
  static ByteData256 CalculateSchnorrSignatureWithNonce(
      const Privkey& oracle_key, const Privkey& k_value,
      const ByteData256& message);

  /**
   * @brief Create a schnorr signature using the a given private key and nonce.
   * @param[in] oracle_key      the private key to sign with.
   * @param[in] k_value         the nonce to use in the signature generation.
   * @param[in] message         the message to sign.
   * @return signature
   */
  static ByteData CalculateSchnorrSignature(
      const Privkey& oracle_key, const Privkey& k_value,
      const ByteData256& message);

  /**
   * @brief Verify if a signature with respect to a public key and a message.
   * @param[in] pubkey          The public key to verify the signature against.
   * @param[in] nonce           The nonce.
   * @param[in] signature       The signature to verify.
   * @param[in] message         The message to sign.
   * @return true if the signature is valid, false if not.
   */
  static bool VerifySchnorrSignatureWithNonce(
      const Pubkey& pubkey, const Pubkey& nonce, const ByteData256& signature,
      const ByteData256& message);

  /**
   * @brief Verify if a signature with respect to a public key and a message.
   * @param[in] pubkey          The public key to verify the signature against.
   * @param[in] signature       The signature to verify.
   * @param[in] message         The message to sign.
   * @return true if the signature is valid, false if not.
   */
  static bool VerifySchnorrSignature(
      const Pubkey& pubkey, const ByteData& signature,
      const ByteData256& message);

 private:
  SignatureUtil();
  // constructor抑止
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_COMMON_H_
