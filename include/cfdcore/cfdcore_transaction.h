// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_transaction.h
 *
 * @brief Transaction関連クラスを定義する。
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
 * @brief TxOut情報を保持するクラス
 */
class CFD_CORE_EXPORT TxOut : public AbstractTxOut {
 public:
  /**
   * @brief コンストラクタ
   */
  TxOut();
  /**
   * @brief コンストラクタ
   * @param[in] value             amount value.
   * @param[in] locking_script    locking script.
   */
  TxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief コンストラクタ
   * @param[in] value             amount value.
   * @param[in] address           out address.
   */
  TxOut(const Amount& value, const Address& address);
  /**
   * @brief デストラクタ
   */
  virtual ~TxOut() {
    // do nothing
  }
};

/**
 * @brief TxOut情報を参照するためのクラス
 */
class CFD_CORE_EXPORT TxOutReference : public AbstractTxOutReference {
 public:
  /**
   * @brief コンストラクタ
   * @param[in] tx_out 参照するTxOutインスタンス
   */
  explicit TxOutReference(const TxOut& tx_out);
  /**
   * @brief デフォルトコンストラクタ.
   *
   * リスト作成用。
   */
  TxOutReference() : TxOutReference(TxOut()) {
    // do nothing
  }
  /**
   * @brief デストラクタ
   */
  virtual ~TxOutReference() {
    // do nothing
  }
};

/**
 * @brief TxIn情報を保持するクラス
 */
class CFD_CORE_EXPORT TxIn : public AbstractTxIn {
 public:
  /**
   * @brief 最小のTxInサイズ
   * @details 対象サイズ：txid(64), vout(4), sequence(4), scriptLength(1(仮))
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
   * @brief コンストラクタ.
   * @param[in] txid        txid
   * @param[in] index       txidのトランザクションのTxOutのIndex情報(vout)
   * @param[in] sequence    sequence情報
   */
  TxIn(const Txid& txid, uint32_t index, uint32_t sequence);
  /**
   * @brief コンストラクタ.
   * @param[in] txid              txid
   * @param[in] index             txidのトランザクションのTxOutのIndex情報(vout)
   * @param[in] sequence          sequence情報
   * @param[in] unlocking_script  unlocking script
   */
  TxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script);
  /**
   * @brief デストラクタ
   */
  virtual ~TxIn() {
    // do nothing
  }
};

/**
 * @brief TxIn情報を参照するためのクラス
 */
class CFD_CORE_EXPORT TxInReference : public AbstractTxInReference {
 public:
  /**
   * @brief コンストラクタ.
   * @param[in] tx_in 参照するTxInインスタンス
   */
  explicit TxInReference(const TxIn& tx_in);
  /**
   * @brief デフォルトコンストラクタ.
   *
   * リスト作成用。
   */
  TxInReference() : TxInReference(TxIn(Txid(), 0, 0)) {
    // do nothing
  }

  /**
   * @brief デストラクタ
   */
  virtual ~TxInReference() {
    // do nothing
  }
};

/**
 * @brief トランザクション情報クラス
 */
class CFD_CORE_EXPORT Transaction : public AbstractTransaction {
 public:
  /**
   * @brief コンストラクタ.
   *
   * リスト作成用。
   */
  Transaction();
  /**
   * @brief コンストラクタ
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
   * @brief コンストラクタ
   * @param[in] hex_string    txバイトデータのHEX文字列
   */
  explicit Transaction(const std::string& hex_string);
  /**
   * @brief コンストラクタ
   * @param[in] transaction   トランザクション情報
   */
  explicit Transaction(const Transaction& transaction);
  /**
   * @brief デストラクタ
   */
  virtual ~Transaction() {
    // do nothing
  }
  /**
   * @brief コピーコンストラクタ.
   * @param[in] transaction   トランザクション情報
   * @return Transactionオブジェクト
   */
  Transaction& operator=(const Transaction& transaction) &;

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
   * @brief TxInを取得する.
   * @param[in] index   取得するindex位置
   * @return 指定indexのTxInインスタンス
   */
  const TxInReference GetTxIn(uint32_t index) const;
  /**
   * @brief TxInのindexを取得する.
   * @param[in] txid   取得するTxInのtxid
   * @param[in] vout   取得するTxInのvout
   * @return 条件に合致するTxInのindex番号
   */
  virtual uint32_t GetTxInIndex(const Txid& txid, uint32_t vout) const;
  /**
   * @brief 保持しているTxInの数を取得する.
   * @return TxIn数
   */
  uint32_t GetTxInCount() const;
  /**
   * @brief TxIn一覧を取得する.
   * @return TxInReference一覧
   */
  const std::vector<TxInReference> GetTxInList() const;
  /**
   * @brief TxInを追加する.
   * @param[in] txid                txid
   * @param[in] index               vout
   * @param[in] sequence            sequence
   * @param[in] unlocking_script    unlocking script (未指定時はEmptyを設定する. default Script::Empty)
   * @return 追加したTxInのindex位置
   */
  uint32_t AddTxIn(
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
   */
  void SetUnlockingScript(
      uint32_t tx_in_index, const std::vector<ByteData>& unlocking_script);
  /**
   * @brief witness stackの現在の個数を取得する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @return witness stackの個数
   */
  uint32_t GetScriptWitnessStackNum(uint32_t tx_in_index) const;
  /**
   * @brief witness stackに追加する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] data              witness stackに追加する情報
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData& data);
  /**
   * @brief witness stackに追加する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] data              witness stackに追加する20byte情報
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData160& data);
  /**
   * @brief witness stackに追加する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData256& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する情報
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する20byte情報
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData160& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData256& data);
  /**
   * @brief script witnessを全て削除する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   */
  void RemoveScriptWitnessStackAll(uint32_t tx_in_index);

  /**
   * @brief TxOutを取得する.
   * @param[in] index     取得するindex位置
   * @return TxOutReference
   */
  const TxOutReference GetTxOut(uint32_t index) const;
  /**
   * @brief TxOutのindexを取得する.
   * @param[in] locking_script  locking script
   * @return 条件に合致するTxOutのindex番号
   */
  virtual uint32_t GetTxOutIndex(const Script& locking_script) const;
  /**
   * @brief TxOutのindexを一括取得する.
   * @param[in] locking_script  locking script
   * @return 条件に合致するTxOutのindex番号の一覧
   */
  virtual std::vector<uint32_t> GetTxOutIndexList(
      const Script& locking_script) const;
  /**
   * @brief 保持しているTxOutの数を取得する.
   * @return TxOut数
   */
  uint32_t GetTxOutCount() const;
  /**
   * @brief TxOut一覧を取得する.
   * @return TxOutReference一覧
   */
  const std::vector<TxOutReference> GetTxOutList() const;
  /**
   * @brief TxOut情報を追加する.
   * @param[in] value           amount
   * @param[in] locking_script  locking script
   * @return 追加したTxOutのindex位置
   */
  uint32_t AddTxOut(const Amount& value, const Script& locking_script);
  /**
   * @brief TxOut情報を削除する.
   * @param[in] index     取得するindex位置
   */
  void RemoveTxOut(uint32_t index);
  /**
   * @brief signatureハッシュを取得する.
   * @param[in] txin_index    TxInのindex値
   * @param[in] script_data   unlocking script もしくは witness_program.
   * @param[in] sighash_type  SigHashType(@see cfdcore_util.h)
   * @param[in] value         TxInのAmount値.
   * @param[in] version       Witness version
   * @return signatureハッシュ
   */
  ByteData256 GetSignatureHash(
      uint32_t txin_index, const ByteData& script_data,
      SigHashType sighash_type, const Amount& value = Amount(),
      WitnessVersion version = WitnessVersion::kVersionNone) const;
  /**
   * @brief witness情報かどうかを取得する.
   * @retval true   witness
   * @retval false  witnessではない
   */
  virtual bool HasWitness() const;

  /**
   * @brief libwally処理用フラグを取得する。
   * @return libwally用フラグ
   */
  virtual uint32_t GetWallyFlag() const;

 protected:
  std::vector<TxIn> vin_;    ///< TxIn配列
  std::vector<TxOut> vout_;  ///< TxOut配列

  /**
   * @brief HEX文字列からTransaction情報を設定する.
   * @param[in] hex_string    TransactionバイトデータのHEX文字列
   */
  void SetFromHex(const std::string& hex_string);

 private:
  /**
   * @brief TxIn配列のIndex範囲をチェックする.
   * @param[in] index     TxIn配列のIndex値
   * @param[in] line      行数
   * @param[in] caller    コール元関数名
   */
  virtual void CheckTxInIndex(
      uint32_t index, int line, const char* caller) const;
  /**
   * @brief TxOut配列のIndex範囲をチェックする.
   * @brief check TxOut array range.
   * @param[in] index     TxOut配列のIndex値
   * @param[in] line      行数
   * @param[in] caller    コール元関数名
   */
  virtual void CheckTxOutIndex(
      uint32_t index, int line, const char* caller) const;
  /**
   * @brief witness stackに情報を追加する.
   * @param[in] tx_in_index   TxIn配列のindex値
   * @param[in] data          witness stackに追加するバイトデータ
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const std::vector<uint8_t>& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief Transactionのバイトデータを取得する.
   * @param[in] has_witness   witnessを含めるかのフラグ
   * @return バイトデータ
   */
  ByteData GetByteData(bool has_witness) const;
  /**
   * @brief TxOut領域のByteDataの整合性チェックと、TxOutへの設定を行う.
   *
   * tx_pointerがNULLではない場合のみ、TxOutへの設定を行う.
   * tx_pointerがNULLの場合は整合性チェックのみ行う.
   * @param[in] buffer         TxOut領域のByteData
   * @param[in] buf_size       TxOut領域のByteDataサイズ
   * @param[in] txout_num      TxOut領域のTxOut情報数
   * @param[in] txout_num_size TxOut情報領域サイズ
   * @param[out] tx_pointer    Transaction情報バッファ(NULL可)
   * @param[out] txout_list    TxOut配列(nullptr可)
   * @retval true   整合性チェックOK、およびTxOut情報コピーOK
   * @retval false  整合性チェックNG、もしくはTxOut情報コピー失敗
   */
  static bool CheckTxOutBuffer(
      const uint8_t* buffer, size_t buf_size, uint64_t txout_num,
      size_t txout_num_size, void* tx_pointer = NULL,
      std::vector<TxOut>* txout_list = nullptr);
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TRANSACTION_H_
