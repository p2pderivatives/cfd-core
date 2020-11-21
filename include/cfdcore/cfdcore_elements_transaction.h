// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_transaction.h
 *
 * @brief Elements Transaction関連クラスを定義する。
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_TRANSACTION_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_TRANSACTION_H_
#ifndef CFD_DISABLE_ELEMENTS

#include <cstddef>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_transaction_common.h"

namespace cfd {
namespace core {

class BlindFactor;

//! blind initial parameter (minimum bits)
constexpr const int kDefaultBlindMinimumBits = 52;

/**
 * @brief nonce情報を保持するクラス
 */
class CFD_CORE_EXPORT ConfidentialNonce {
 public:
  /**
   * @brief コンストラクタ.
   *
   * リスト定義等における初期化のため、定義する。
   */
  ConfidentialNonce();
  /**
   * @brief コンストラクタ.
   * @param[in] hex_string      hex string.
   */
  explicit ConfidentialNonce(const std::string& hex_string);
  /**
   * @brief コンストラクタ.
   * @param[in] byte_data       byte array data.
   */
  explicit ConfidentialNonce(const ByteData& byte_data);
  /**
   * @brief コンストラクタ.
   * @param[in] pubkey          pubkey.
   */
  explicit ConfidentialNonce(const Pubkey& pubkey);
  /**
   * @brief デストラクタ.
   */
  virtual ~ConfidentialNonce() {
    // do nothing
  }

  /**
   * @brief バイトデータを取得する.
   * @return byte array data.
   */
  ByteData GetData() const;
  /**
   * @brief HEX文字列を取得する.
   * @return hex string
   */
  std::string GetHex() const;
  /**
   * @brief blind有無を取得する.
   * @retval true  blind
   * @retval false unblind
   */
  bool HasBlinding() const;
  /**
   * @brief 空かどうかを取得する.
   * @retval true  empty
   * @retval false exist value
   */
  bool IsEmpty() const;

 private:
  ByteData data_;    //!< byte data
  uint8_t version_;  //!< version byte

  /**
   * @brief check version info.
   * @param[in] version     version info.
   */
  static void CheckVersion(uint8_t version);
};

/**
 * @brief AssetId情報を保持するクラス
 */
class CFD_CORE_EXPORT ConfidentialAssetId {
 public:
  /**
   * @brief コンストラクタ.
   *
   * リスト定義等における初期化のため、定義する。
   */
  ConfidentialAssetId();
  /**
   * @brief コンストラクタ.
   * @param[in] hex_string      hex string.
   */
  explicit ConfidentialAssetId(const std::string& hex_string);
  /**
   * @brief コンストラクタ.
   * @param[in] byte_data       byte array data.
   */
  explicit ConfidentialAssetId(const ByteData& byte_data);
  /**
   * @brief デストラクタ.
   */
  virtual ~ConfidentialAssetId() {
    // do nothing
  }

  /**
   * @brief バイトデータを取得する.
   * @return byte array data.
   */
  ByteData GetData() const;
  /**
   * @brief HEX文字列を取得する.
   * @return hex string (reverse data)
   */
  std::string GetHex() const;
  /**
   * @brief blind有無を取得する.
   * @retval true  blind
   * @retval false unblind
   */
  bool HasBlinding() const;
  /**
   * @brief unblind時、バイトデータを取得する.
   * @return byte array data.
   */
  ByteData GetUnblindedData() const;
  /**
   * @brief 空かどうかを取得する.
   * @retval true  empty
   * @retval false exist value
   */
  bool IsEmpty() const;

  /**
   * @brief Get commitment.
   * @param[in] unblind_asset       unblind asset id.
   * @param[in] asset_blind_factor  asset blind factor.
   * @return asset commitment.
   */
  static ConfidentialAssetId GetCommitment(
      const ConfidentialAssetId& unblind_asset,
      const BlindFactor& asset_blind_factor);

 private:
  ByteData data_;    //!< byte data
  uint8_t version_;  //!< version byte

  /**
   * @brief check version info.
   * @param[in] version     version info.
   */
  static void CheckVersion(uint8_t version);
};

/**
 * @brief value情報を保持するクラス
 */
class CFD_CORE_EXPORT ConfidentialValue {
 public:
  /**
   * @brief コンストラクタ.
   *
   * リスト定義等における初期化のため、定義する。
   */
  ConfidentialValue();
  /**
   * @brief コンストラクタ.
   * @param[in] hex_string      hex string.
   */
  explicit ConfidentialValue(const std::string& hex_string);
  /**
   * @brief コンストラクタ.
   * @param[in] byte_data       byte array data.
   */
  explicit ConfidentialValue(const ByteData& byte_data);
  /**
   * @brief コンストラクタ.
   * @param[in] amount          amount
   */
  explicit ConfidentialValue(const Amount& amount);
  /**
   * @brief デストラクタ.
   */
  virtual ~ConfidentialValue() {
    // do nothing
  }

  /**
   * @brief バイトデータを取得する.
   * @return byte array data.
   */
  ByteData GetData() const;
  /**
   * @brief HEX文字列を取得する.
   * @return hex string
   */
  std::string GetHex() const;
  /**
   * @brief Amountを取得する.
   *
   * なおblind状態では0を返却する。
   * @return Amount
   */
  Amount GetAmount() const;
  /**
   * @brief blind有無を取得する.
   * @retval true  blind
   * @retval false unblind
   */
  bool HasBlinding() const;
  /**
   * @brief 空かどうかを取得する.
   * @retval true  empty
   * @retval false exist value
   */
  bool IsEmpty() const;

  /**
   * @brief satoshiをConfidentialValueへと変換する.
   * @param[in] value     amount value.
   * @return ConfidentialValue
   */
  static ByteData ConvertToConfidentialValue(const Amount& value);
  /**
   * @brief ConfidentialValueをsatoshiへと変換する.
   * @param[in] value     ConfidentialValue.
   * @return amount value
   */
  static Amount ConvertFromConfidentialValue(const ByteData& value);

  /**
   * @brief Get commitment.
   * @param[in] amount               amount.
   * @param[in] asset_commitment     asset commitment.
   * @param[in] amount_blind_factor  amount blind factor.
   * @return amount commitment.
   */
  static ConfidentialValue GetCommitment(
      const Amount& amount, const ConfidentialAssetId& asset_commitment,
      const BlindFactor& amount_blind_factor);

 private:
  ByteData data_;    //!< byte data
  uint8_t version_;  //!< version byte

  /**
   * @brief check version info.
   * @param[in] version     version info.
   */
  static void CheckVersion(uint8_t version);
};

/**
 * @brief factor情報を保持するクラス
 */
class CFD_CORE_EXPORT BlindFactor {
 public:
  /**
   * @brief コンストラクタ.
   *
   * リスト定義等における初期化のため、定義する。
   */
  BlindFactor();
  /**
   * @brief コンストラクタ.
   * @param[in] hex_string      hex string.
   */
  explicit BlindFactor(const std::string& hex_string);
  /**
   * @brief コンストラクタ.
   * @param[in] byte_data       byte array data.
   */
  explicit BlindFactor(const ByteData& byte_data);
  /**
   * @brief コンストラクタ.
   * @param[in] byte_data       byte array data.
   */
  explicit BlindFactor(const ByteData256& byte_data);
  /**
   * @brief デストラクタ.
   */
  virtual ~BlindFactor() {
    // do nothing
  }

  /**
   * @brief バイトデータを取得する.
   * @return byte array data.
   */
  ByteData256 GetData() const;
  /**
   * @brief HEX文字列を取得する.
   * @return hex string (reverse data)
   */
  std::string GetHex() const;
  /**
   * @brief 空かどうかを取得する.
   * @retval true  empty
   * @retval false exist value
   */
  bool IsEmpty() const;

 private:
  ByteData256 data_;  //!< byte data
};

/**
 * @brief TxIn情報を保持するクラス
 */
class CFD_CORE_EXPORT ConfidentialTxIn : public AbstractTxIn {
 public:
  /**
   * @brief estimate txin's size, and witness size.
   * @param[in] addr_type           address type
   * @param[in] redeem_script       redeem script
   * @param[in] pegin_btc_tx_size   pegin bitcoin transaction size
   * @param[in] fedpeg_script       fedpeg script
   * @param[in] is_issuance         issuance transaction
   * @param[in] is_blind            blind transaction (for issuance/reissuance)
   * @param[out] witness_area_size     witness area size
   * @param[out] no_witness_area_size  no witness area size
   * @param[in] is_reissuance       reissuance transaction
   * @param[in] scriptsig_template     scriptsig template
   * @param[in] exponent                  rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits              rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[in,out] rangeproof_size       rangeproof size.
   *   0 is calclate from exponent and minimum bits. not 0 is using value.
   * @return TxIn size.
   */
  static uint32_t EstimateTxInSize(
      AddressType addr_type, Script redeem_script = Script(),
      uint32_t pegin_btc_tx_size = 0, Script fedpeg_script = Script(),
      bool is_issuance = false, bool is_blind = false,
      uint32_t* witness_area_size = nullptr,
      uint32_t* no_witness_area_size = nullptr, bool is_reissuance = false,
      const Script* scriptsig_template = nullptr, int exponent = 0,
      int minimum_bits = kDefaultBlindMinimumBits,
      uint32_t* rangeproof_size = nullptr);

  /**
   * @brief estimate txin's virtual size direct.
   * @param[in] addr_type           address type
   * @param[in] redeem_script       redeem script
   * @param[in] pegin_btc_tx_size   pegin bitcoin transaction size
   * @param[in] fedpeg_script       fedpeg script
   * @param[in] is_issuance         issuance transaction
   * @param[in] is_blind            blind transaction (for issuance/reissuance)
   * @param[in] is_reissuance       reissuance transaction
   * @param[in] scriptsig_template  scriptsig template
   * @param[in] exponent                  rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits              rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[in,out] rangeproof_size       rangeproof size.
   *   0 is calclate from exponent and minimum bits. not 0 is using value.
   * @return TxIn virtual size.
   */
  static uint32_t EstimateTxInVsize(
      AddressType addr_type, Script redeem_script = Script(),
      uint32_t pegin_btc_tx_size = 0, Script fedpeg_script = Script(),
      bool is_issuance = false, bool is_blind = false,
      bool is_reissuance = false, const Script* scriptsig_template = nullptr,
      int exponent = 0, int minimum_bits = kDefaultBlindMinimumBits,
      uint32_t* rangeproof_size = nullptr);

  /**
   * @brief コンストラクタ.
   */
  ConfidentialTxIn();
  /**
   * @brief コンストラクタ.
   * @param[in] txid        txid
   * @param[in] index       txidのトランザクションのTxOutのIndex情報(vout)
   */
  ConfidentialTxIn(const Txid& txid, uint32_t index);
  /**
   * @brief コンストラクタ.
   * @param[in] txid        txid
   * @param[in] index       txidのトランザクションのTxOutのIndex情報(vout)
   * @param[in] sequence    sequence情報
   */
  ConfidentialTxIn(const Txid& txid, uint32_t index, uint32_t sequence);
  /**
   * @brief コンストラクタ.
   * @param[in] txid              txid
   * @param[in] index             txidのトランザクションのTxOutのIndex情報(vout)
   * @param[in] sequence          sequence情報
   * @param[in] unlocking_script  unlocking script
   */
  ConfidentialTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script);
  /**
   * @brief コンストラクタ.
   * @param[in] txid              txid
   * @param[in] index             txidのトランザクションのTxOutのIndex情報(vout)
   * @param[in] sequence          sequence情報
   * @param[in] unlocking_script  unlocking script
   * @param[in] witness_stack     witness stack
   * @param[in] blinding_nonce    blinding nonce
   * @param[in] asset_entropy     asset entropy
   * @param[in] issuance_amount   issuance amount
   * @param[in] inflation_keys    inflation keys
   * @param[in] issuance_amount_rangeproof  issuance amount rangeproof
   * @param[in] inflation_keys_rangeproof   inflation keys rangeproof
   * @param[in] pegin_witness     pegin witness
   */
  ConfidentialTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script, const ScriptWitness& witness_stack,
      const ByteData256& blinding_nonce, const ByteData256& asset_entropy,
      const ConfidentialValue& issuance_amount,
      const ConfidentialValue& inflation_keys,
      const ByteData& issuance_amount_rangeproof,
      const ByteData& inflation_keys_rangeproof,
      const ScriptWitness& pegin_witness);
  /**
   * @brief デストラクタ
   */
  virtual ~ConfidentialTxIn() {
    // do nothing
  }

  /**
   * @brief 情報を更新する.
   * @param[in] blinding_nonce    blinding nonce
   * @param[in] asset_entropy     asset entropy
   * @param[in] issuance_amount   issuance amount
   * @param[in] inflation_keys    inflation keys
   * @param[in] issuance_amount_rangeproof  issuance amount rangeproof
   * @param[in] inflation_keys_rangeproof   inflation keys rangeproof
   */
  void SetIssuance(
      const ByteData256& blinding_nonce, const ByteData256& asset_entropy,
      const ConfidentialValue& issuance_amount,
      const ConfidentialValue& inflation_keys,
      const ByteData& issuance_amount_rangeproof,
      const ByteData& inflation_keys_rangeproof);
  /**
   * @brief BlindingNonceを取得する
   * @return BlindingNonceのByteData256インスタンス
   */
  ByteData256 GetBlindingNonce() const { return blinding_nonce_; }
  /**
   * @brief AssetEntropyを取得する
   * @return AssetEntropyのByteData256インスタンス
   */
  ByteData256 GetAssetEntropy() const { return asset_entropy_; }
  /**
   * @brief IssuanceAmountを取得する
   * @return IssuanceAmountのByteDataインスタンス
   */
  ConfidentialValue GetIssuanceAmount() const { return issuance_amount_; }
  /**
   * @brief InflationKeysを取得する
   * @return InflationKeysのByteDataインスタンス
   */
  ConfidentialValue GetInflationKeys() const { return inflation_keys_; }
  /**
   * @brief IssuanceAmountRangeproofを取得する
   * @return IssuanceAmountRangeproofのByteDataインスタンス
   */
  ByteData GetIssuanceAmountRangeproof() const {
    return issuance_amount_rangeproof_;
  }
  /**
   * @brief InflationKeysRangeproofを取得する
   * @return InflationKeysRangeproofのByteDataインスタンス
   */
  ByteData GetInflationKeysRangeproof() const {
    return inflation_keys_rangeproof_;
  }
  /**
   * @brief PeginWitnessを取得する
   * @return PeginWitnessのScriptWitnessインスタンス
   */
  ScriptWitness GetPeginWitness() const { return pegin_witness_; }
  /**
   * @brief pegin witnessの現在のstack数を取得する.
   * @return pegin witnessのstack数
   */
  uint32_t GetPeginWitnessStackNum() const {
    return pegin_witness_.GetWitnessNum();
  }

  /**
   * @brief pegin witnessにバイトデータを追加する.
   * @param[in] data    witness stack情報
   * @return pegin witnessのScriptWitnessインスタンス
   */
  ScriptWitness AddPeginWitnessStack(const ByteData& data);
  /**
   * @brief pegin witnessにバイトデータを設定する.
   * @param[in] index   witness stackのindex値
   * @param[in] data    witness stack情報
   * @return pegin witnessのScriptWitnessインスタンス
   */
  ScriptWitness SetPeginWitnessStack(uint32_t index, const ByteData& data);
  /**
   * @brief pegin witnessを全て削除する.
   */
  void RemovePeginWitnessStackAll();

  /**
   * @brief witness hashを取得する.
   * @return witness hash
   */
  ByteData256 GetWitnessHash() const;

 private:
  ByteData256 blinding_nonce_;           //!< nonce for blind
  ByteData256 asset_entropy_;            //!< asset entropy
  ConfidentialValue issuance_amount_;    //!< issuance_amount
  ConfidentialValue inflation_keys_;     //!< inflation key
  ByteData issuance_amount_rangeproof_;  //!< amount rangeproof
  ByteData inflation_keys_rangeproof_;   //!< inflation key rangeproof
  ScriptWitness pegin_witness_;          //!< witness stack for pegin
};

/**
 * @brief TxIn情報を参照するためのクラス
 */
class CFD_CORE_EXPORT ConfidentialTxInReference
    : public AbstractTxInReference {
 public:
  /**
   * @brief コンストラクタ.
   * @param[in] tx_in 参照するTxInインスタンス
   */
  explicit ConfidentialTxInReference(const ConfidentialTxIn& tx_in);
  /**
   * @brief デフォルトコンストラクタ.
   *
   * リスト作成用。
   */
  ConfidentialTxInReference();

  /**
   * @brief デストラクタ
   */
  virtual ~ConfidentialTxInReference() {
    // do nothing
  }

  /**
   * @brief BlindingNonceを取得する
   * @return BlindingNonceのByteData256インスタンス
   */
  ByteData256 GetBlindingNonce() const { return blinding_nonce_; }
  /**
   * @brief AssetEntropyを取得する
   * @return AssetEntropyのByteData256インスタンス
   */
  ByteData256 GetAssetEntropy() const { return asset_entropy_; }
  /**
   * @brief IssuanceAmountを取得する
   * @return IssuanceAmountのByteDataインスタンス
   */
  ConfidentialValue GetIssuanceAmount() const { return issuance_amount_; }
  /**
   * @brief InflationKeysを取得する
   * @return InflationKeysのByteDataインスタンス
   */
  ConfidentialValue GetInflationKeys() const { return inflation_keys_; }
  /**
   * @brief IssuanceAmountRangeproofを取得する
   * @return IssuanceAmountRangeproofのByteDataインスタンス
   */
  ByteData GetIssuanceAmountRangeproof() const {
    return issuance_amount_rangeproof_;
  }
  /**
   * @brief InflationKeysRangeproofを取得する
   * @return InflationKeysRangeproofのByteDataインスタンス
   */
  ByteData GetInflationKeysRangeproof() const {
    return inflation_keys_rangeproof_;
  }
  /**
   * @brief PeginWitnessを取得する
   * @return PeginWitnessのScriptWitnessインスタンス
   */
  ScriptWitness GetPeginWitness() const { return pegin_witness_; }
  /**
   * @brief pegin witnessの現在のstack数を取得する.
   * @return pegin witnessのstack数
   */
  uint32_t GetPeginWitnessStackNum() const {
    return pegin_witness_.GetWitnessNum();
  }

  /**
   * @brief estimate txin's size, and witness size.
   * @param[in] addr_type           address type
   * @param[in] redeem_script       redeem script
   * @param[in] is_blind            blind transaction (for issuance/reissuance)
   * @param[in] exponent                  rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits              rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[in] fedpeg_script       fedpeg script
   * @param[in] scriptsig_template     scriptsig template
   * @param[out] witness_area_size     witness area size
   * @param[out] no_witness_area_size  no witness area size
   * @return TxIn size.
   */
  uint32_t EstimateTxInSize(
      AddressType addr_type, Script redeem_script = Script(),
      bool is_blind = false, int exponent = 0,
      int minimum_bits = kDefaultBlindMinimumBits,
      Script fedpeg_script = Script(),
      const Script* scriptsig_template = nullptr,
      uint32_t* witness_area_size = nullptr,
      uint32_t* no_witness_area_size = nullptr) const;

  /**
   * @brief estimate txin's virtual size direct.
   * @param[in] addr_type           address type
   * @param[in] redeem_script       redeem script
   * @param[in] is_blind            blind transaction (for issuance/reissuance)
   * @param[in] exponent                  rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits              rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[in] fedpeg_script       fedpeg script
   * @param[in] scriptsig_template  scriptsig template
   * @return TxIn virtual size.
   */
  uint32_t EstimateTxInVsize(
      AddressType addr_type, Script redeem_script = Script(),
      bool is_blind = false, int exponent = 0,
      int minimum_bits = kDefaultBlindMinimumBits,
      Script fedpeg_script = Script(),
      const Script* scriptsig_template = nullptr) const;

 private:
  ByteData256 blinding_nonce_;           //!< nonce for blind
  ByteData256 asset_entropy_;            //!< asset entropy
  ConfidentialValue issuance_amount_;    //!< issuance_amount
  ConfidentialValue inflation_keys_;     //!< inflation key
  ByteData issuance_amount_rangeproof_;  //!< amount rangeproof
  ByteData inflation_keys_rangeproof_;   //!< inflation key rangeproof
  ScriptWitness pegin_witness_;          //!< witness stack for pegin
};

/**
 * @struct RangeProofInfo
 * @brief basic informations by decoding range-proof
 */
struct RangeProofInfo {
  int exponent;        //!< exponent value in the proof
  int mantissa;        //!< Number of bits covered by the proof
  uint64_t min_value;  //!< the minimum value that commit could have
  uint64_t max_value;  //!< the maximum value that commit could have
};

/**
 * @brief Confidential TransactionのTxOut情報を保持するクラス
 */
class CFD_CORE_EXPORT ConfidentialTxOut : public AbstractTxOut {
 public:
  /**
   * @brief コンストラクタ
   */
  ConfidentialTxOut();
  /**
   * @brief コンストラクタ.
   * @param[in] locking_script      locking script.
   * @param[in] asset               asset.
   * @param[in] confidential_value  value by confidential transaction.
   */
  ConfidentialTxOut(
      const Script& locking_script, const ConfidentialAssetId& asset,
      const ConfidentialValue& confidential_value);
  /**
   * @brief コンストラクタ.
   *
   * blind後の情報登録用.
   * @param[in] locking_script      locking script.
   * @param[in] asset               asset.
   * @param[in] confidential_value  value by confidential transaction.
   * @param[in] nonce               nonce.
   * @param[in] surjection_proof    surjection proof.
   * @param[in] range_proof         range proof.
   */
  ConfidentialTxOut(
      const Script& locking_script, const ConfidentialAssetId& asset,
      const ConfidentialValue& confidential_value,
      const ConfidentialNonce& nonce, const ByteData& surjection_proof,
      const ByteData& range_proof);
  /**
   * @brief コンストラクタ.
   *
   * fee追加用.
   * @param[in] asset               asset.
   * @param[in] confidential_value  value by confidential transaction.
   */
  ConfidentialTxOut(
      const ConfidentialAssetId& asset,
      const ConfidentialValue& confidential_value);
  /**
   * @brief コンストラクタ.
   *
   * fee追加用.
   * @param[in] asset               asset.
   * @param[in] amount              amount.
   */
  ConfidentialTxOut(const ConfidentialAssetId& asset, const Amount& amount);
  /**
   * @brief コンストラクタ.
   * @param[in] address             address.
   * @param[in] asset               asset.
   * @param[in] amount              amount.
   */
  ConfidentialTxOut(
      const Address& address, const ConfidentialAssetId& asset,
      const Amount& amount);
  /**
   * @brief コンストラクタ.
   * @param[in] confidential_address  confidential address.
   * @param[in] asset                 asset.
   * @param[in] amount                amount.
   */
  ConfidentialTxOut(
      const ElementsConfidentialAddress& confidential_address,
      const ConfidentialAssetId& asset, const Amount& amount);
  /**
   * @brief デストラクタ
   */
  virtual ~ConfidentialTxOut() {
    // do nothing
  }

  /**
   * @brief set commitment.
   *
   * for register api after blind/unblind.
   * @param[in] asset               asset.
   * @param[in] confidential_value  value commitment by confidential transaction.
   * @param[in] nonce               nonce.
   * @param[in] surjection_proof    surjection proof.
   * @param[in] range_proof         range proof.
   */
  void SetCommitment(
      const ConfidentialAssetId& asset,
      const ConfidentialValue& confidential_value,
      const ConfidentialNonce& nonce, const ByteData& surjection_proof,
      const ByteData& range_proof);

  /**
   * @brief set nonce.
   * @param[in] nonce   nonce.
   */
  void SetNonce(const ConfidentialNonce& nonce);
  /**
   * @brief valueを設定する。
   * @param[in] value     amount value.
   */
  virtual void SetValue(const Amount& value);
  /**
   * @brief assetを取得する。
   * @return asset
   */
  ConfidentialAssetId GetAsset() const { return asset_; }

  /**
   * @brief confidential valueを取得する。
   * @return confidential value
   */
  ConfidentialValue GetConfidentialValue() const {
    return confidential_value_;
  }

  /**
   * @brief nonceを取得する。
   * @return nonce
   */
  ConfidentialNonce GetNonce() const { return nonce_; }

  /**
   * @brief surjection proofを取得する。
   * @return surjection proof
   */
  ByteData GetSurjectionProof() const { return surjection_proof_; }

  /**
   * @brief range proofを取得する。
   * @return range proof
   */
  ByteData GetRangeProof() const { return range_proof_; }

  /**
   * @brief witness hashを取得する.
   * @return witness hash
   */
  ByteData256 GetWitnessHash() const;

  /**
   * @brief Create ConfidentialTxOut object for the destroy amount.
   * @param[in] asset               destroy asset.
   * @param[in] amount              destroy amount.
   * @return ConfidentialTxOut object.
   */
  static ConfidentialTxOut CreateDestroyAmountTxOut(
      const ConfidentialAssetId& asset, const Amount& amount);

  /**
   * @brief Decode range-proof and extract information.
   * @param[in] range_proof ByteData of range-proof value
   * @return struct RangeProofInfo including decoded range-proof information
   */
  static const RangeProofInfo DecodeRangeProofInfo(
      const ByteData& range_proof);

 private:
  ConfidentialAssetId asset_;             //!< confidential asset
  ConfidentialValue confidential_value_;  //!< confidential value.
  ConfidentialNonce nonce_;               //!< nonce
  ByteData surjection_proof_;             //!< surjection proof
  ByteData range_proof_;                  //!< range proof
};

/**
 * @brief Confidential TransactionのTxOut情報を参照するためのクラス
 */
class CFD_CORE_EXPORT ConfidentialTxOutReference
    : public AbstractTxOutReference {
 public:
  /**
   * @brief コンストラクタ
   * @param[in] tx_out            Confidential Transaction's TxOut.
   */
  explicit ConfidentialTxOutReference(const ConfidentialTxOut& tx_out);
  /**
   * @brief デフォルトコンストラクタ.
   *
   * リスト作成用。
   */
  ConfidentialTxOutReference()
      : ConfidentialTxOutReference(ConfidentialTxOut()) {
    // do nothing
  }
  /**
   * @brief デストラクタ
   */
  virtual ~ConfidentialTxOutReference() {
    // do nothing
  }

  /**
   * @brief assetを取得する。
   * @return asset
   */
  ConfidentialAssetId GetAsset() const { return asset_; }

  /**
   * @brief confidential valueを取得する。
   * @return confidential value
   */
  ConfidentialValue GetConfidentialValue() const {
    return confidential_value_;
  }

  /**
   * @brief nonceを取得する。
   * @return nonce
   */
  ConfidentialNonce GetNonce() const { return nonce_; }

  /**
   * @brief surjection proofを取得する。
   * @return surjection proof
   */
  ByteData GetSurjectionProof() const { return surjection_proof_; }

  /**
   * @brief range proofを取得する。
   * @return range proof
   */
  ByteData GetRangeProof() const { return range_proof_; }
  /**
   * @brief Get a serialized size.
   * @param[in] is_blinded             blinding or not.
   * @param[out] witness_area_size     witness area size.
   * @param[out] no_witness_area_size  no witness area size.
   * @param[in] exponent               rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits           rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[in,out] rangeproof_size    rangeproof size.
   *   0 is calclate from exponent and minimum bits. not 0 is using value.
   * @param[in] input_asset_count      tx input asset count. (contain issuance)
   * @return serialized size
   */
  uint32_t GetSerializeSize(
      bool is_blinded = true, uint32_t* witness_area_size = nullptr,
      uint32_t* no_witness_area_size = nullptr, int exponent = 0,
      int minimum_bits = kDefaultBlindMinimumBits,
      uint32_t* rangeproof_size = nullptr,
      uint32_t input_asset_count = 0) const;

  /**
   * @brief Get a serialized virtual size.
   * @param[in] is_blinded             blinding or not.
   * @param[in] exponent               rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits           rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[in,out] rangeproof_size    rangeproof size.
   *   0 is calclate from exponent and minimum bits. not 0 is using value.
   * @param[in] input_asset_count      tx input asset count. (contain issuance)
   * @return serialized virtual size.
   */
  uint32_t GetSerializeVsize(
      bool is_blinded = true, int exponent = 0,
      int minimum_bits = kDefaultBlindMinimumBits,
      uint32_t* rangeproof_size = nullptr,
      uint32_t input_asset_count = 0) const;

 private:
  ConfidentialAssetId asset_;             //!< confidential asset
  ConfidentialValue confidential_value_;  //!< confidential value.
  ConfidentialNonce nonce_;               //!< nonce
  ByteData surjection_proof_;             //!< surjection proof
  ByteData range_proof_;                  //!< range proof
};

/**
 * @brief Issuance出力情報構造体
 */
struct IssuanceParameter {
  BlindFactor entropy;        //!< entropy
  ConfidentialAssetId asset;  //!< asset
  ConfidentialAssetId token;  //!< token asset
};

/**
 * @brief Unblind出力情報構造体
 */
struct UnblindParameter {
  ConfidentialAssetId asset;  //!< confidential asset
  BlindFactor abf;            //!< asset blind factor
  BlindFactor vbf;            //!< value blind factor
  ConfidentialValue value;    //!< unblinded value
};

/**
 * @brief Blind用情報構造体
 */
using BlindParameter = UnblindParameter;

/**
 * @brief blind data.
 */
struct BlindData {
  uint32_t vout = 0;               //!< txout array number
  ConfidentialAssetId asset;       //!< confidential asset
  BlindFactor abf;                 //!< asset blind factor
  BlindFactor vbf;                 //!< value blind factor
  ConfidentialValue value;         //!< unblinded value
  OutPoint issuance_outpoint;      //!< issuance outpoint
  bool is_issuance = false;        //!< issuance asset
  bool is_issuance_token = false;  //!< issuance token
};

/**
 * @brief Issuance confidentialKeyペア構造体
 */
struct IssuanceBlindingKeyPair {
  Privkey asset_key;  //!< asset blinding key
  Privkey token_key;  //!< token blinding key
};

/**
 * @brief PegOut Key情報構造体
 */
struct PegoutKeyData {
  Pubkey btc_pubkey_bytes;   //!< bitcoin pubkey byte data
  ByteData whitelist_proof;  //!< whitelist proof
};

/**
 * @brief Confidential Transaction情報クラス
 */
class CFD_CORE_EXPORT ConfidentialTransaction : public AbstractTransaction {
 public:
  /// ElementsTransactionの最小サイズ
  static constexpr size_t kElementsTransactionMinimumSize = 11;

  /**
   * @brief コンストラクタ.
   *
   * リスト作成用。
   */
  ConfidentialTransaction();
  /**
   * @brief コンストラクタ
   * @param[in] version       version
   * @param[in] lock_time     lock time
   */
  explicit ConfidentialTransaction(int32_t version, uint32_t lock_time);
  /**
   * @brief コンストラクタ
   * @param[in] hex_string    txバイトデータのHEX文字列
   */
  explicit ConfidentialTransaction(const std::string& hex_string);
  /**
   * @brief constructor
   * @param[in] byte_data   tx byte data
   */
  explicit ConfidentialTransaction(const ByteData& byte_data);
  /**
   * @brief コンストラクタ
   * @param[in] transaction   トランザクション情報
   */
  explicit ConfidentialTransaction(const ConfidentialTransaction& transaction);
  /**
   * @brief デストラクタ
   */
  virtual ~ConfidentialTransaction() {
    // do nothing
  }
  /**
   * @brief コピーコンストラクタ.
   * @param[in] transaction   トランザクション情報
   * @return Confidential Transactionオブジェクト
   */
  ConfidentialTransaction& operator=(
      const ConfidentialTransaction& transaction) &;
  /**
   * @brief TxInを取得する.
   * @param[in] index   取得するindex位置
   * @return 指定indexのTxInインスタンス
   */
  const ConfidentialTxInReference GetTxIn(uint32_t index) const;
  /**
   * @brief TxInのindexを取得する.
   * @param[in] txid   取得するTxInのtxid
   * @param[in] vout   取得するTxInのvout
   * @return 条件に合致するTxInのindex番号
   */
  virtual uint32_t GetTxInIndex(const Txid& txid, uint32_t vout) const;
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
   * @brief 保持しているTxInの数を取得する.
   * @return TxIn数
   */
  uint32_t GetTxInCount() const;
  /**
   * @brief TxIn一覧を取得する.
   * @return TxInReference一覧
   */
  const std::vector<ConfidentialTxInReference> GetTxInList() const;
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
   * @brief 情報を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] blinding_nonce    blinding nonce
   * @param[in] asset_entropy     asset entropy
   * @param[in] issuance_amount   issuance amount
   * @param[in] inflation_keys    inflation keys
   * @param[in] issuance_amount_rangeproof  issuance amount rangeproof
   * @param[in] inflation_keys_rangeproof   inflation keys rangeproof
   */
  void SetIssuance(
      uint32_t tx_in_index, const ByteData256 blinding_nonce,
      const ByteData256 asset_entropy, const ConfidentialValue issuance_amount,
      const ConfidentialValue inflation_keys,
      const ByteData issuance_amount_rangeproof,
      const ByteData inflation_keys_rangeproof);
  /**
   * @brief witness stackの現在の個数を取得する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @return witness stackの個数
   */
  uint32_t GetPeginWitnessStackNum(uint32_t tx_in_index) const;
  /**
   * @brief witness stackに追加する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] data              witness stackに追加する情報
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const ByteData& data);
  /**
   * @brief witness stackに追加する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] data              witness stackに追加する20byte情報
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const ByteData160& data);
  /**
   * @brief witness stackに追加する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const ByteData256& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する情報
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する20byte情報
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData160& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData256& data);
  /**
   * @brief script witnessを全て削除する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   */
  void RemovePeginWitnessStackAll(uint32_t tx_in_index);

  /**
   * @brief IssueAssetの情報を設定する.
   * @param[in] tx_in_index           Txin index
   * @param[in] asset_amount          issuance amount
   * @param[in] asset_locking_script  asset locking script
   * @param[in] asset_nonce           asset nonce
   * @param[in] token_amount          inflation keys
   * @param[in] token_locking_script  token locking script
   * @param[in] token_nonce           token nonce
   * @param[in] is_blind              blinding issuance
   * @param[in] contract_hash         asset entropy
   * @return issuance entropy and asset parameter.
   */
  IssuanceParameter SetAssetIssuance(
      uint32_t tx_in_index, const Amount& asset_amount,
      const Script& asset_locking_script, const ConfidentialNonce& asset_nonce,
      const Amount& token_amount, const Script& token_locking_script,
      const ConfidentialNonce& token_nonce, bool is_blind,
      const ByteData256& contract_hash);
  /**
   * @brief IssueAssetの情報を設定する.
   * @param[in] tx_in_index                Txin index
   * @param[in] asset_amount               issuance amount
   * @param[in] asset_output_amount_list   asset output list
   * @param[in] asset_locking_script_list  asset locking script list
   * @param[in] asset_nonce_list           asset nonce list
   * @param[in] token_amount               inflation keys
   * @param[in] token_output_amount_list   token output list
   * @param[in] token_locking_script_list  token locking script list
   * @param[in] token_nonce_list           token nonce list
   * @param[in] is_blind                   blinding issuance
   * @param[in] contract_hash              asset entropy
   * @return issuance entropy and asset parameter.
   */
  IssuanceParameter SetAssetIssuance(
      uint32_t tx_in_index, const Amount& asset_amount,
      const std::vector<Amount>& asset_output_amount_list,
      const std::vector<Script>& asset_locking_script_list,
      const std::vector<ConfidentialNonce>& asset_nonce_list,
      const Amount& token_amount,
      const std::vector<Amount>& token_output_amount_list,
      const std::vector<Script>& token_locking_script_list,
      const std::vector<ConfidentialNonce>& token_nonce_list, bool is_blind,
      const ByteData256& contract_hash);

  /**
   * @brief ReissueAssetの情報を設定する.
   * @param[in] tx_in_index             Txin index
   * @param[in] asset_amount            reissuance amount
   * @param[in] asset_locking_script    asset locking script
   * @param[in] asset_blind_nonce       blind nonce
   * @param[in] asset_blind_factor      blind factor
   * @param[in] entropy                 entropy
   * @return reissuance entropy and asset parameter.
   */
  IssuanceParameter SetAssetReissuance(
      uint32_t tx_in_index, const Amount& asset_amount,
      const Script& asset_locking_script,
      const ConfidentialNonce& asset_blind_nonce,
      const BlindFactor& asset_blind_factor, const BlindFactor& entropy);
  /**
   * @brief ReissueAssetの情報を設定する.
   * @param[in] tx_in_index                Txin index
   * @param[in] asset_amount               reissuance amount
   * @param[in] asset_output_amount_list   asset output list
   * @param[in] asset_locking_script_list  asset locking script list
   * @param[in] asset_blind_nonce_list     asset nonce list
   * @param[in] asset_blind_factor         blind factor
   * @param[in] entropy                    entropy
   * @return reissuance entropy and asset parameter.
   */
  IssuanceParameter SetAssetReissuance(
      uint32_t tx_in_index, const Amount& asset_amount,
      const std::vector<Amount>& asset_output_amount_list,
      const std::vector<Script>& asset_locking_script_list,
      const std::vector<ConfidentialNonce>& asset_blind_nonce_list,
      const BlindFactor& asset_blind_factor, const BlindFactor& entropy);

  /**
   * @brief TxOutを取得する.
   * @param[in] index     取得するindex位置
   * @return TxOutReference
   */
  const ConfidentialTxOutReference GetTxOut(uint32_t index) const;
  /**
   * @brief 保持しているTxOutの数を取得する.
   * @return TxOut数
   */
  uint32_t GetTxOutCount() const;
  /**
   * @brief TxOut一覧を取得する.
   * @return TxOutReference一覧
   */
  const std::vector<ConfidentialTxOutReference> GetTxOutList() const;
  /**
   * @brief TxOut情報を追加する.
   * @param[in] value           amount
   * @param[in] asset           asset
   * @param[in] locking_script  locking script
   * @return 追加したTxOutのindex位置
   */
  uint32_t AddTxOut(
      const Amount& value, const ConfidentialAssetId& asset,
      const Script& locking_script);
  /**
   * @brief TxOut情報を追加する.
   * @param[in] value           amount
   * @param[in] asset           asset
   * @param[in] locking_script  locking script
   * @param[in] nonce           nonce
   * @return 追加したTxOutのindex位置
   */
  uint32_t AddTxOut(
      const Amount& value, const ConfidentialAssetId& asset,
      const Script& locking_script, const ConfidentialNonce& nonce);
  /**
   * @brief TxOut情報を追加する.
   * @param[in] value               amount
   * @param[in] asset               asset
   * @param[in] locking_script      locking script
   * @param[in] nonce               nonce.
   * @param[in] surjection_proof    surjection proof.
   * @param[in] range_proof         range proof.
   * @return 追加したTxOutのindex位置
   */
  uint32_t AddTxOut(
      const Amount& value, const ConfidentialAssetId& asset,
      const Script& locking_script, const ConfidentialNonce& nonce,
      const ByteData& surjection_proof, const ByteData& range_proof);
  /**
   * @brief TxOut情報としてfeeを追加する.
   * @param[in] value           amount
   * @param[in] asset           asset
   * @return 追加したTxOutのindex位置
   */
  uint32_t AddTxOutFee(const Amount& value, const ConfidentialAssetId& asset);
  /**
   * @brief set TxOut's value.
   * @param[in] index   target txout index
   * @param[in] value   amount
   */
  void SetTxOutValue(uint32_t index, const Amount& value);
  /**
   * @brief TxOut情報を更新する.
   * @param[in] index               index位置
   * @param[in] asset               asset
   * @param[in] value               amount
   * @param[in] nonce               nonce.
   * @param[in] surjection_proof    surjection proof.
   * @param[in] range_proof         range proof.
   */
  void SetTxOutCommitment(
      uint32_t index, const ConfidentialAssetId& asset,
      const ConfidentialValue& value, const ConfidentialNonce& nonce,
      const ByteData& surjection_proof, const ByteData& range_proof);
  /**
   * @brief TxOut情報を削除する.
   * @param[in] index     取得するindex位置
   */
  void RemoveTxOut(uint32_t index);
  /**
   * @brief Blinding transaction.
   * @param[in] txin_info_list            txin blind info list.
   * @param[in] issuance_blinding_keys    issue blinding key list.
   * @param[in] txout_confidential_keys   blinding pubkey list.
   * @param[in] minimum_range_value       rangeproof minimum value.
   *   0 to max(int64_t)
   * @param[in] exponent                  rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits              rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[out] blinder_list             blinder list. (default is null)
   */
  void BlindTransaction(
      const std::vector<BlindParameter>& txin_info_list,
      const std::vector<IssuanceBlindingKeyPair>& issuance_blinding_keys,
      const std::vector<Pubkey>& txout_confidential_keys,
      int64_t minimum_range_value = 1, int exponent = 0,
      int minimum_bits = kDefaultBlindMinimumBits,
      std::vector<BlindData>* blinder_list = nullptr);
  /**
   * @brief TransactionのTxOutのblindingを行う.
   * @param[in] txin_info_list            txin blind info list.
   * @param[in] txout_confidential_keys   blinding pubkey list.
   * @param[in] minimum_range_value       rangeproof minimum value.
   *   0 to max(int64_t)
   * @param[in] exponent                  rangeproof exponent value.
   *   -1 to 18. -1 is public value. 0 is most private.
   * @param[in] minimum_bits              rangeproof blinding bits.
   *   0 to 64. Number of bits of the value to keep private. 0 is auto.
   * @param[out] blinder_list             blinder list. (default is null)
   */
  void BlindTxOut(
      const std::vector<BlindParameter>& txin_info_list,
      const std::vector<Pubkey>& txout_confidential_keys,
      int64_t minimum_range_value = 1, int exponent = 0,
      int minimum_bits = kDefaultBlindMinimumBits,
      std::vector<BlindData>* blinder_list = nullptr);
  /**
   * @brief indexで指定されたInputに対して、unblind処理を行う.
   * @param tx_in_index TxInのindex値
   * @param blinding_key blinding key(秘密鍵)
   * @param token_blinding_key token blinding key(秘密鍵).
   * @return unblindの出力データを格納したUnblindParameter構造体
   */
  std::vector<UnblindParameter> UnblindTxIn(
      uint32_t tx_in_index, const Privkey& blinding_key,
      const Privkey token_blinding_key = Privkey());
  /**
   * @brief indexで指定されたOutputに対して、unblind処理を行う.
   * @param tx_out_index TxOutのindex値
   * @param blinding_key blinding key(秘密鍵)
   * @return unblindの出力データを格納したUnblindParameter構造体
   */
  UnblindParameter UnblindTxOut(
      uint32_t tx_out_index, const Privkey& blinding_key);
  /**
   * @brief Transactionの全てのOutputに対して、unblind処理を行う.
   * @param[in] blinding_keys blinding key(秘密鍵) list
   * @return unblindの出力データを格納したUnblindParameter構造体リスト
   */
  std::vector<UnblindParameter> UnblindTxOut(
      const std::vector<Privkey>& blinding_keys);

  /**
   * @brief Elements用signatureハッシュを取得する.
   * @param[in] txin_index    TxInのindex値
   * @param[in] script_data   unlocking script もしくは witness_program.
   * @param[in] sighash_type  SigHashType(@see cfdcore_util.h)
   * @param[in] value         TxInのAmount/amountcommitment値.
   * @param[in] version       Witness version
   * @return signatureハッシュ
   */
  ByteData256 GetElementsSignatureHash(
      uint32_t txin_index, const ByteData& script_data,
      SigHashType sighash_type,
      const ConfidentialValue& value = ConfidentialValue(),
      WitnessVersion version = WitnessVersion::kVersionNone) const;

  /**
   * @brief TxOutの順序をランダムソートする.
   * @details ブラインド前のみ実施可能.
   */
  void RandomSortTxOut();

  /**
   * @brief witness情報のみのHashを取得する.
   * @return witness only hash
   */
  ByteData256 GetWitnessOnlyHash() const;

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

  /**
   * @brief Bitcoin Transaction情報を取得する。
   * @param[in] bitcoin_tx_data     bitcoin transaction data
   * @param[in] is_remove_witness   remove witness flag
   * @return transaction data.
   */
  static ByteData GetBitcoinTransaction(
      const ByteData& bitcoin_tx_data, bool is_remove_witness = false);
  /**
   * @brief asset entropyの情報を算出する.
   * @param[in] txid              utxo txid
   * @param[in] vout              utxo vout
   * @param[in] contract_hash     asset entropy
   * @return asset entropy (BlindFactor).
   */
  static BlindFactor CalculateAssetEntropy(
      const Txid& txid, const uint32_t vout, const ByteData256& contract_hash);
  /**
   * @brief assetの情報を算出する.
   * @param[in] entropy           asset entropy
   * @return asset id (ConfidentialAssetId).
   */
  static ConfidentialAssetId CalculateAsset(const BlindFactor& entropy);
  /**
   * @brief reissuance tokenの情報を算出する.
   * @param[in] entropy           asset entropy
   * @param[in] is_blind          asset is blinded or not
   * @return reissuance token (ConfidentialAssetId).
   */
  static ConfidentialAssetId CalculateReissuanceToken(
      const BlindFactor& entropy, bool is_blind);
  /**
   * @brief IssueAssetの情報を設定する.
   * @param[in] txid              utxo txid
   * @param[in] vout              utxo vout
   * @param[in] is_blind          blinding issuance
   * @param[in] contract_hash     asset entropy
   * @param[in] asset_entropy     asset entropy for reissue
   * @return issuance entropy and asset parameter.
   */
  static IssuanceParameter CalculateIssuanceValue(
      const Txid& txid, uint32_t vout, bool is_blind,
      const ByteData256& contract_hash, const ByteData256& asset_entropy);
  /**
   * @brief issuance/reissuanceのblinding keyを取得する.
   * @param[in] master_blinding_key master blindingKey
   * @param[in] txid                issuance utxo txid
   * @param[in] vout                issuance utxo vout
   * @return issuance blinding key
   */
  static Privkey GetIssuanceBlindingKey(
      const Privkey& master_blinding_key, const Txid& txid, uint32_t vout);
  /**
   * @brief pegoutで使用するpubkey情報を取得する.
   * @param[in] online_pubkey       online pubkey
   * @param[in] master_online_key   online privkey
   * @param[in] bitcoin_descriptor  bip32 pubkey (m/0/\*)
   * @param[in] bip32_counter       bip32 pubkey counter (0 - 1000000000)
   * @param[in] whitelist           whitelist for block extension space
   * @param[in] net_type            network type
   * @param[in] pubkey_prefix       ext pubkey prefix (elements customize)
   * @param[in] elements_net_type   elements network type.\
   *                          (kLiquidV1, kElementsRegtest, kCustomChain)
   * @param[out] descriptor_derive_address  descriptor derive address.
   * @return pegout key data
   */
  static PegoutKeyData GetPegoutPubkeyData(
      const Pubkey& online_pubkey, const Privkey& master_online_key,
      const std::string& bitcoin_descriptor, uint32_t bip32_counter,
      const ByteData& whitelist, NetType net_type = NetType::kMainnet,
      const ByteData& pubkey_prefix = ByteData("0488b21e"),
      NetType elements_net_type = NetType::kLiquidV1,
      Address* descriptor_derive_address = nullptr);

 protected:
  std::vector<ConfidentialTxIn> vin_;    ///< TxIn配列
  std::vector<ConfidentialTxOut> vout_;  ///< TxOut配列

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
   * @brief witness stackに情報を追加する.
   * @param[in] tx_in_index   TxIn配列のindex値
   * @param[in] data          witness stackに追加するバイトデータ
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const std::vector<uint8_t>& data);
  /**
   * @brief witness stackの指定index位置を更新する.
   * @param[in] tx_in_index       設定するTxInのindex位置
   * @param[in] witness_index     witness stackのindex位置
   * @param[in] data              witness stackに追加する32byte情報
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief Transactionのバイトデータを取得する.
   * @param[in] has_witness   witnessを含めるかのフラグ
   * @return バイトデータ
   */
  ByteData GetByteData(bool has_witness) const;
  /**
   * @brief ElementsのTx状態フラグ(libwally値)を設定する。
   */
  void SetElementsTxState();
  /**
   * @brief 配列をByteDataへと変換する.
   * @param[in] data      buffer
   * @param[in] size      size
   * @return ByteData
   */
  static ByteData ConvertToByteData(const uint8_t* data, size_t size);
  /**
   * @brief ConfidentialNonce情報をコピーする。
   * @param[in] buffer            コピー元のバッファ
   * @param[in] buffer_size       バッファサイズ
   * @param[in] explicit_size     unblind時のサイズ
   * @param[in] address           コピー先のアドレス
   * @return 移動後のアドレス
   */
  static uint8_t* CopyConfidentialCommitment(
      const void* buffer, size_t buffer_size, size_t explicit_size,
      uint8_t* address);

  /**
   * blindされたデータに対して、unblind処理をかける
   * @param[in] nonce             nonce値
   * @param[in] blinding_key      blindingした際の秘密鍵
   * @param[in] rangeproof        asset amountの検証に用いる検証値
   * @param[in] value_commitment  blindされたvalueのcommitement値
   * @param[in] extra             unblindに必要な情報
   * @param[in] asset             confidential asset id
   * @return Unblindされた際に出力されたUnblindParameter構造体
   */
  static UnblindParameter CalculateUnblindData(
      const ConfidentialNonce& nonce, const Privkey& blinding_key,
      const ByteData& rangeproof, const ConfidentialValue& value_commitment,
      const Script& extra, const ConfidentialAssetId& asset);

  /**
   * blindされたIssueデータに対して、unblind処理をかける
   * @param[in] blinding_key      blindingした際の秘密鍵
   * @param[in] rangeproof        asset amountの検証に用いる検証値
   * @param[in] value_commitment  blindされたvalueのcommitement値
   * @param[in] extra             unblindに必要な情報
   * @param[in] asset             confidential asset id
   * @return Unblindされた際に出力されたUnblindParameter構造体
   */
  static UnblindParameter CalculateUnblindIssueData(
      const Privkey& blinding_key, const ByteData& rangeproof,
      const ConfidentialValue& value_commitment, const Script& extra,
      const ConfidentialAssetId& asset);

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
  static ByteData GetRangeProof(
      const uint64_t value, const Pubkey* pubkey, const Privkey& privkey,
      const ConfidentialAssetId& asset, const std::vector<uint8_t>& abf,
      const std::vector<uint8_t>& vbf, const Script& script,
      int64_t minimum_range_value, int exponent, int minimum_bits,
      std::vector<uint8_t>* commitment, std::vector<uint8_t>* range_proof);

  /**
   * @brief Descriptor情報から拡張Keyを生成する.
   * @param[in] bitcoin_descriptor    descriptor
   * @param[in] bip32_counter         bip32 counter
   * @param[in] prefix                extend pubkey prefix
   * @param[in] net_type              network type.
   * @param[in] elements_net_type     elements network type.
   * @param[out] base_ext_pubkey       base extkey
   * @param[out] descriptor_derive_address   descriptor derive address
   * @return extpubkey by bip32 counter
   */
  static ExtPubkey GenerateExtPubkeyFromDescriptor(
      const std::string& bitcoin_descriptor, uint32_t bip32_counter,
      const ByteData& prefix, NetType net_type, NetType elements_net_type,
      ExtPubkey* base_ext_pubkey, Address* descriptor_derive_address);
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_TRANSACTION_H_
