// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_transaction.h
 *
 * @brief Define Elements Transaction related classes.
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
 * @brief Class that holds nonce information
 */
class CFD_CORE_EXPORT ConfidentialNonce {
 public:
  /**
   * @brief constructor.
   */
  ConfidentialNonce();
  /**
   * @brief constructor.
   * @param[in] hex_string      hex string.
   */
  explicit ConfidentialNonce(const std::string& hex_string);
  /**
   * @brief constructor.
   * @param[in] byte_data       byte array data.
   */
  explicit ConfidentialNonce(const ByteData& byte_data);
  /**
   * @brief constructor.
   * @param[in] pubkey          pubkey.
   */
  explicit ConfidentialNonce(const Pubkey& pubkey);
  /**
   * @brief destructor.
   */
  virtual ~ConfidentialNonce() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  ConfidentialNonce(const ConfidentialNonce& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  ConfidentialNonce& operator=(const ConfidentialNonce& object);

  /**
   * @brief Get byte data.
   * @return byte array data.
   */
  ByteData GetData() const;
  /**
   * @brief Get the HEX string.
   * @return hex string
   */
  std::string GetHex() const;
  /**
   * @brief Get if it is blind.
   * @retval true  blind
   * @retval false unblind
   */
  bool HasBlinding() const;
  /**
   * @brief Get if it's empty.
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
 * @brief Class that holds AssetId information
 */
class CFD_CORE_EXPORT ConfidentialAssetId {
 public:
  /**
   * @brief constructor.
   */
  ConfidentialAssetId();
  /**
   * @brief constructor.
   * @param[in] hex_string      hex string.
   */
  explicit ConfidentialAssetId(const std::string& hex_string);
  /**
   * @brief constructor.
   * @param[in] byte_data       byte array data.
   */
  explicit ConfidentialAssetId(const ByteData& byte_data);
  /**
   * @brief destructor.
   */
  virtual ~ConfidentialAssetId() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  ConfidentialAssetId(const ConfidentialAssetId& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  ConfidentialAssetId& operator=(const ConfidentialAssetId& object);

  /**
   * @brief Get byte data.
   * @return byte array data.
   */
  ByteData GetData() const;
  /**
   * @brief Get the HEX string.
   * @return hex string (reverse data)
   */
  std::string GetHex() const;
  /**
   * @brief Get if it is blind.
   * @retval true  blind
   * @retval false unblind
   */
  bool HasBlinding() const;
  /**
   * @brief Get unblinded byte data.
   * @return byte array data.
   */
  ByteData GetUnblindedData() const;
  /**
   * @brief Get if it's empty.
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
 * @brief Class that holds value information
 */
class CFD_CORE_EXPORT ConfidentialValue {
 public:
  /**
   * @brief constructor.
   */
  ConfidentialValue();
  /**
   * @brief constructor.
   * @param[in] hex_string      hex string.
   */
  explicit ConfidentialValue(const std::string& hex_string);
  /**
   * @brief constructor.
   * @param[in] byte_data       byte array data.
   */
  explicit ConfidentialValue(const ByteData& byte_data);
  /**
   * @brief constructor.
   * @param[in] amount          amount
   */
  explicit ConfidentialValue(const Amount& amount);
  /**
   * @brief destructor.
   */
  virtual ~ConfidentialValue() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  ConfidentialValue(const ConfidentialValue& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  ConfidentialValue& operator=(const ConfidentialValue& object);

  /**
   * @brief Get byte data.
   * @return byte array data.
   */
  ByteData GetData() const;
  /**
   * @brief Get the HEX string.
   * @return hex string
   */
  std::string GetHex() const;
  /**
   * @brief Get Amount.
   *
   * In the blind state, 0 is returned.
   * @return Amount
   */
  Amount GetAmount() const;
  /**
   * @brief Get if it is blind.
   * @retval true  blind
   * @retval false unblind
   */
  bool HasBlinding() const;
  /**
   * @brief Get if it's empty.
   * @retval true  empty
   * @retval false exist value
   */
  bool IsEmpty() const;

  /**
   * @brief Convert satoshi to Confidential Value.
   * @param[in] value     amount value.
   * @return ConfidentialValue
   */
  static ByteData ConvertToConfidentialValue(const Amount& value);
  /**
   * @brief Convert Confidential Value to satoshi.
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
 * @brief Class that holds blind factor information
 */
class CFD_CORE_EXPORT BlindFactor {
 public:
  /**
   * @brief constructor.
   */
  BlindFactor();
  /**
   * @brief constructor.
   * @param[in] hex_string      hex string.
   */
  explicit BlindFactor(const std::string& hex_string);
  /**
   * @brief constructor.
   * @param[in] byte_data       byte array data.
   */
  explicit BlindFactor(const ByteData& byte_data);
  /**
   * @brief constructor.
   * @param[in] byte_data       byte array data.
   */
  explicit BlindFactor(const ByteData256& byte_data);
  /**
   * @brief destructor.
   */
  virtual ~BlindFactor() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  BlindFactor(const BlindFactor& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  BlindFactor& operator=(const BlindFactor& object);

  /**
   * @brief Get byte data.
   * @return byte array data.
   */
  ByteData256 GetData() const;
  /**
   * @brief Get the HEX string.
   * @return hex string (reverse data)
   */
  std::string GetHex() const;
  /**
   * @brief Get if it's empty.
   * @retval true  empty
   * @retval false exist value
   */
  bool IsEmpty() const;

 private:
  ByteData256 data_;  //!< byte data
};

/**
 * @brief Class that holds TxIn information
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
   * @brief constructor.
   */
  ConfidentialTxIn();
  /**
   * @brief constructor.
   * @param[in] txid        txid
   * @param[in] index       txout's index (vout)
   */
  ConfidentialTxIn(const Txid& txid, uint32_t index);
  /**
   * @brief constructor.
   * @param[in] txid        txid
   * @param[in] index       txout's index (vout)
   * @param[in] sequence    sequence
   */
  ConfidentialTxIn(const Txid& txid, uint32_t index, uint32_t sequence);
  /**
   * @brief constructor.
   * @param[in] txid              txid
   * @param[in] index             txout's index (vout)
   * @param[in] sequence          sequence
   * @param[in] unlocking_script  unlocking script
   */
  ConfidentialTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script);
  /**
   * @brief constructor.
   * @param[in] txid              txid
   * @param[in] index             txout's index (vout)
   * @param[in] sequence          sequence
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
   * @brief destructor
   */
  virtual ~ConfidentialTxIn() {
    // do nothing
  }

  /**
   * @brief Update issuance information.
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
   * @brief Get Blinding Nonce
   * @return BlindingNonce
   */
  ByteData256 GetBlindingNonce() const { return blinding_nonce_; }
  /**
   * @brief Get Asset Entropy
   * @return AssetEntropy
   */
  ByteData256 GetAssetEntropy() const { return asset_entropy_; }
  /**
   * @brief Get IssuanceAmount
   * @return IssuanceAmount
   */
  ConfidentialValue GetIssuanceAmount() const { return issuance_amount_; }
  /**
   * @brief Get InflationKeys
   * @return InflationKeys
   */
  ConfidentialValue GetInflationKeys() const { return inflation_keys_; }
  /**
   * @brief Get IssuanceAmountRangeproof
   * @return IssuanceAmountRangeproof
   */
  ByteData GetIssuanceAmountRangeproof() const {
    return issuance_amount_rangeproof_;
  }
  /**
   * @brief Get InflationKeysRangeproof
   * @return InflationKeysRangeproof
   */
  ByteData GetInflationKeysRangeproof() const {
    return inflation_keys_rangeproof_;
  }
  /**
   * @brief Get PeginWitness
   * @return PeginWitness's 'ScriptWitness
   */
  ScriptWitness GetPeginWitness() const { return pegin_witness_; }
  /**
   * @brief Get the current stack count of pegin witness.
   * @return stack count of pegin witness.
   */
  uint32_t GetPeginWitnessStackNum() const {
    return pegin_witness_.GetWitnessNum();
  }

  /**
   * @brief Add byte data to pegin witness.
   * @param[in] data    witness stack data
   * @return Script Witness instance of pegin witness
   */
  ScriptWitness AddPeginWitnessStack(const ByteData& data);
  /**
   * @brief Set byte data to pegin witness.
   * @param[in] index   witness stack index
   * @param[in] data    witness stack data
   * @return Script Witness instance of pegin witness
   */
  ScriptWitness SetPeginWitnessStack(uint32_t index, const ByteData& data);
  /**
   * @brief Remove all pegin witness.
   */
  void RemovePeginWitnessStackAll();

  /**
   * @brief Get the witness hash.
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
 * @brief Class for referencing TxIn information
 */
class CFD_CORE_EXPORT ConfidentialTxInReference
    : public AbstractTxInReference {
 public:
  /**
   * @brief constructor.
   * @param[in] tx_in   TxIn
   */
  explicit ConfidentialTxInReference(const ConfidentialTxIn& tx_in);
  /**
   * @brief default constructor.
   */
  ConfidentialTxInReference();

  /**
   * @brief destructor
   */
  virtual ~ConfidentialTxInReference() {
    // do nothing
  }

  /**
   * @brief Get Blinding Nonce
   * @return BlindingNonce
   */
  ByteData256 GetBlindingNonce() const { return blinding_nonce_; }
  /**
   * @brief Get AssetEntropy
   * @return AssetEntropy
   */
  ByteData256 GetAssetEntropy() const { return asset_entropy_; }
  /**
   * @brief Get IssuanceAmount
   * @return IssuanceAmount
   */
  ConfidentialValue GetIssuanceAmount() const { return issuance_amount_; }
  /**
   * @brief Get InflationKeys
   * @return InflationKeys
   */
  ConfidentialValue GetInflationKeys() const { return inflation_keys_; }
  /**
   * @brief Get IssuanceAmountRangeproof
   * @return IssuanceAmountRangeproof
   */
  ByteData GetIssuanceAmountRangeproof() const {
    return issuance_amount_rangeproof_;
  }
  /**
   * @brief Get InflationKeysRangeproof
   * @return InflationKeysRangeproof
   */
  ByteData GetInflationKeysRangeproof() const {
    return inflation_keys_rangeproof_;
  }
  /**
   * @brief Get PeginWitness
   * @return ScriptWitness instance of PeginWitness
   */
  ScriptWitness GetPeginWitness() const { return pegin_witness_; }
  /**
   * @brief Get the current stack count of pegin witness.
   * @return stack count of pegin witness.
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
 * @brief Class that holds TxOut information of Confidential Transaction
 */
class CFD_CORE_EXPORT ConfidentialTxOut : public AbstractTxOut {
 public:
  /**
   * @brief constructor
   */
  ConfidentialTxOut();
  /**
   * @brief constructor.
   * @param[in] locking_script      locking script.
   * @param[in] asset               asset.
   * @param[in] confidential_value  value by confidential transaction.
   */
  ConfidentialTxOut(
      const Script& locking_script, const ConfidentialAssetId& asset,
      const ConfidentialValue& confidential_value);
  /**
   * @brief constructor.
   *
   * For information registration after blind.
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
   * @brief constructor.
   *
   * For additional fee.
   * @param[in] asset               asset.
   * @param[in] confidential_value  value by confidential transaction.
   */
  ConfidentialTxOut(
      const ConfidentialAssetId& asset,
      const ConfidentialValue& confidential_value);
  /**
   * @brief constructor.
   *
   * For additional fee.
   * @param[in] asset               asset.
   * @param[in] amount              amount.
   */
  ConfidentialTxOut(const ConfidentialAssetId& asset, const Amount& amount);
  /**
   * @brief constructor.
   * @param[in] address             address.
   * @param[in] asset               asset.
   * @param[in] amount              amount.
   */
  ConfidentialTxOut(
      const Address& address, const ConfidentialAssetId& asset,
      const Amount& amount);
  /**
   * @brief constructor.
   * @param[in] confidential_address  confidential address.
   * @param[in] asset                 asset.
   * @param[in] amount                amount.
   */
  ConfidentialTxOut(
      const ElementsConfidentialAddress& confidential_address,
      const ConfidentialAssetId& asset, const Amount& amount);
  /**
   * @brief destructor
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
   * @brief set amount value.
   * @param[in] value     amount value.
   */
  virtual void SetValue(const Amount& value);
  /**
   * @brief set asset.
   * @return asset
   */
  ConfidentialAssetId GetAsset() const { return asset_; }

  /**
   * @brief Get confidential value.
   * @return confidential value
   */
  ConfidentialValue GetConfidentialValue() const {
    return confidential_value_;
  }

  /**
   * @brief Get nonce
   * @return nonce
   */
  ConfidentialNonce GetNonce() const { return nonce_; }

  /**
   * @brief Get surjection proof
   * @return surjection proof
   */
  ByteData GetSurjectionProof() const { return surjection_proof_; }

  /**
   * @brief Get range proof
   * @return range proof
   */
  ByteData GetRangeProof() const { return range_proof_; }

  /**
   * @brief Get witness hash
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
 * @brief Class for referencing TxOut information of Confidential Transaction
 */
class CFD_CORE_EXPORT ConfidentialTxOutReference
    : public AbstractTxOutReference {
 public:
  /**
   * @brief constructor
   * @param[in] tx_out            Confidential Transaction's TxOut.
   */
  explicit ConfidentialTxOutReference(const ConfidentialTxOut& tx_out);
  /**
   * @brief default constructor.
   */
  ConfidentialTxOutReference()
      : ConfidentialTxOutReference(ConfidentialTxOut()) {
    // do nothing
  }
  /**
   * @brief destructor
   */
  virtual ~ConfidentialTxOutReference() {
    // do nothing
  }

  /**
   * @brief Get asset
   * @return asset
   */
  ConfidentialAssetId GetAsset() const { return asset_; }

  /**
   * @brief Get confidential value
   * @return confidential value
   */
  ConfidentialValue GetConfidentialValue() const {
    return confidential_value_;
  }

  /**
   * @brief Get nonce
   * @return nonce
   */
  ConfidentialNonce GetNonce() const { return nonce_; }

  /**
   * @brief Get surjection proof
   * @return surjection proof
   */
  ByteData GetSurjectionProof() const { return surjection_proof_; }

  /**
   * @brief Get range proof
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
 * @brief Issuance output information structure
 */
struct IssuanceParameter {
  BlindFactor entropy;        //!< entropy
  ConfidentialAssetId asset;  //!< asset
  ConfidentialAssetId token;  //!< token asset
};

/**
 * @brief Unblind output information structure
 */
struct UnblindParameter {
  ConfidentialAssetId asset;  //!< confidential asset
  BlindFactor abf;            //!< asset blind factor
  BlindFactor vbf;            //!< value blind factor
  ConfidentialValue value;    //!< unblinded value
};

/**
 * @brief Information structure for Blind
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
 * @brief Issuance confidentialKey pair structure
 */
struct IssuanceBlindingKeyPair {
  Privkey asset_key;  //!< asset blinding key
  Privkey token_key;  //!< token blinding key
};

/**
 * @brief PegOut Key Information Structure
 */
struct PegoutKeyData {
  Pubkey btc_pubkey_bytes;   //!< bitcoin pubkey byte data
  ByteData whitelist_proof;  //!< whitelist proof
};

/**
 * @brief Confidential Transaction information class
 */
class CFD_CORE_EXPORT ConfidentialTransaction : public AbstractTransaction {
 public:
  /// Minimum size of Elements Transaction
  static constexpr size_t kElementsTransactionMinimumSize = 11;

  /**
   * @brief constructor.
   */
  ConfidentialTransaction();
  /**
   * @brief constructor
   * @param[in] version       version
   * @param[in] lock_time     lock time
   */
  explicit ConfidentialTransaction(int32_t version, uint32_t lock_time);
  /**
   * @brief constructor
   * @param[in] hex_string    tx hex string
   */
  explicit ConfidentialTransaction(const std::string& hex_string);
  /**
   * @brief constructor
   * @param[in] byte_data   tx byte data
   */
  explicit ConfidentialTransaction(const ByteData& byte_data);
  /**
   * @brief copy constructor
   * @param[in] transaction   transaction object
   */
  explicit ConfidentialTransaction(const ConfidentialTransaction& transaction);
  /**
   * @brief destructor
   */
  virtual ~ConfidentialTransaction() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] transaction   transaction object
   * @return Confidential Transaction
   */
  ConfidentialTransaction& operator=(
      const ConfidentialTransaction& transaction) &;
  /**
   * @brief Get TxIn.
   * @param[in] index   index
   * @return ConfidentialTxInReference
   */
  const ConfidentialTxInReference GetTxIn(uint32_t index) const;
  /**
   * @brief Get TxIn index.
   * @param[in] txid   txid
   * @param[in] vout   vout
   * @return index
   */
  virtual uint32_t GetTxInIndex(const Txid& txid, uint32_t vout) const;
  /**
   * @brief Get the index of TxOut.
   * @param[in] locking_script  locking script
   * @return TxOut index
   */
  virtual uint32_t GetTxOutIndex(const Script& locking_script) const;
  /**
   * @brief Get the indexes of TxOut.
   * @param[in] locking_script  locking script
   * @return TxOut index list.
   */
  virtual std::vector<uint32_t> GetTxOutIndexList(
      const Script& locking_script) const;

  /**
   * @brief Get the count of TxIns.
   * @return count of TxIns.
   */
  uint32_t GetTxInCount() const;
  /**
   * @brief Get TxIn list.
   * @return TxInReference list
   */
  const std::vector<ConfidentialTxInReference> GetTxInList() const;
  /**
   * @brief Add TxIn.
   * @param[in] txid                txid
   * @param[in] index               vout
   * @param[in] sequence            sequence
   * @param[in] unlocking_script    unlocking script
   * @return Added TxIn index
   */
  uint32_t AddTxIn(
      const Txid& txid, uint32_t index, uint32_t sequence,
      const Script& unlocking_script = Script::Empty);
  /**
   * @brief Delete TxIn
   * @param[in] index     txin index
   */
  void RemoveTxIn(uint32_t index);
  /**
   * @brief Set unlocking script.
   * @param[in] tx_in_index       TxIn index
   * @param[in] unlocking_script  unlocking script (Push Op Only)
   */
  void SetUnlockingScript(
      uint32_t tx_in_index, const Script& unlocking_script);
  /**
   * @brief Set unlocking script.
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
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData& data);
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData160& data);
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddScriptWitnessStack(
      uint32_t tx_in_index, const ByteData256& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData160& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Information to add to the witness stack
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
   * @brief 情報を更新する.
   * @param[in] tx_in_index       TxIn index
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
   * @param[in] tx_in_index       TxIn index
   * @return witness stackの個数
   */
  uint32_t GetPeginWitnessStackNum(uint32_t tx_in_index) const;
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const ByteData& data);
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const ByteData160& data);
  /**
   * @brief Add to witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const ByteData256& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData160& data);
  /**
   * @brief Update the specified index position of the witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index, const ByteData256& data);
  /**
   * @brief Remove all script witness.
   * @param[in] tx_in_index       TxIn index
   */
  void RemovePeginWitnessStackAll(uint32_t tx_in_index);

  /**
   * @brief Set the Issue Asset information.
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
   * @brief Set the Issue Asset information.
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
   * @brief ReSet the Issue Asset information.
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
   * @brief ReSet the Issue Asset information.
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
   * @brief Get TxOut.
   * @param[in] index     index
   * @return ConfidentialTxOutReference
   */
  const ConfidentialTxOutReference GetTxOut(uint32_t index) const;
  /**
   * @brief Get the count of TxOuts.
   * @return count of TxOuts.
   */
  uint32_t GetTxOutCount() const;
  /**
   * @brief Get TxOut list.
   * @return ConfidentialTxOutReference list
   */
  const std::vector<ConfidentialTxOutReference> GetTxOutList() const;
  /**
   * @brief Add TxOut information.
   * @param[in] value           amount
   * @param[in] asset           asset
   * @param[in] locking_script  locking script
   * @return Added TxOut index
   */
  uint32_t AddTxOut(
      const Amount& value, const ConfidentialAssetId& asset,
      const Script& locking_script);
  /**
   * @brief Add TxOut information.
   * @param[in] value           amount
   * @param[in] asset           asset
   * @param[in] locking_script  locking script
   * @param[in] nonce           nonce
   * @return Added TxOut index
   */
  uint32_t AddTxOut(
      const Amount& value, const ConfidentialAssetId& asset,
      const Script& locking_script, const ConfidentialNonce& nonce);
  /**
   * @brief Add TxOut information.
   * @param[in] value               amount
   * @param[in] asset               asset
   * @param[in] locking_script      locking script
   * @param[in] nonce               nonce.
   * @param[in] surjection_proof    surjection proof.
   * @param[in] range_proof         range proof.
   * @return Added TxOut index
   */
  uint32_t AddTxOut(
      const Amount& value, const ConfidentialAssetId& asset,
      const Script& locking_script, const ConfidentialNonce& nonce,
      const ByteData& surjection_proof, const ByteData& range_proof);
  /**
   * @brief Add fee as TxOut information.
   * @param[in] value           amount
   * @param[in] asset           asset
   * @return Added TxOut index
   */
  uint32_t AddTxOutFee(const Amount& value, const ConfidentialAssetId& asset);
  /**
   * @brief set TxOut's value.
   * @param[in] index   target txout index
   * @param[in] value   amount
   */
  void SetTxOutValue(uint32_t index, const Amount& value);
  /**
   * @brief Update TxOut information.
   * @param[in] index               index
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
   * @brief Delete the TxOut information.
   * @param[in] index     index
   */
  void RemoveTxOut(uint32_t index);

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
   * @brief Blinding TxOut of Transaction.
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
   * @brief Performs unblind processing for the specified Input.
   * @param tx_in_index TxIn index
   * @param blinding_key blinding key(private key)
   * @param token_blinding_key token blinding key(private key).
   * @return UnblindParameter structure containing unblind output data list
   */
  std::vector<UnblindParameter> UnblindTxIn(
      uint32_t tx_in_index, const Privkey& blinding_key,
      const Privkey token_blinding_key = Privkey());
  /**
   * @brief Performs unblind processing for the specified Output.
   * @param tx_out_index TxOut index
   * @param blinding_key blinding key(private key)
   * @return UnblindParameter structure containing unblind output data
   */
  UnblindParameter UnblindTxOut(
      uint32_t tx_out_index, const Privkey& blinding_key);
  /**
   * @brief Unblind processing is performed for all Outputs of Transaction.
   * @param[in] blinding_keys blinding key(private key) list
   * @return UnblindParameter structure containing unblind output data list
   */
  std::vector<UnblindParameter> UnblindTxOut(
      const std::vector<Privkey>& blinding_keys);

  /**
   * @brief Get the signature hash for Confidential Transaction.
   * @param[in] txin_index    TxIn index
   * @param[in] script_data   unlocking script or witness program.
   * @param[in] sighash_type  SigHashType(@see cfdcore_util.h)
   * @param[in] value         TxIn Amount/amountcommitment.
   * @param[in] version       Witness version
   * @return signature hash
   */
  ByteData256 GetElementsSignatureHash(
      uint32_t txin_index, const ByteData& script_data,
      SigHashType sighash_type,
      const ConfidentialValue& value = ConfidentialValue(),
      WitnessVersion version = WitnessVersion::kVersionNone) const;

  /**
   * @brief Randomly sort the order of TxOut.
   * @details Can only be done before the blinds.
   */
  void RandomSortTxOut();

  /**
   * @brief Get a Hash of witness information only.
   * @return witness only hash
   */
  ByteData256 GetWitnessOnlyHash() const;

  /**
   * @brief Get if it have witness information.
   * @retval true   witness exist
   * @retval false  witness not found
   */
  virtual bool HasWitness() const;

  /**
   * @brief libwally Get the processing flag.
   * @return libwally flag
   */
  virtual uint32_t GetWallyFlag() const;

  /**
   * @brief Get Bitcoin Transaction information.
   * @param[in] bitcoin_tx_data     bitcoin transaction data
   * @param[in] is_remove_witness   remove witness flag
   * @return transaction data.
   */
  static ByteData GetBitcoinTransaction(
      const ByteData& bitcoin_tx_data, bool is_remove_witness = false);
  /**
   * @brief Calculate asset entropy information.
   * @param[in] txid              utxo txid
   * @param[in] vout              utxo vout
   * @param[in] contract_hash     asset entropy
   * @return asset entropy (BlindFactor).
   */
  static BlindFactor CalculateAssetEntropy(
      const Txid& txid, const uint32_t vout, const ByteData256& contract_hash);
  /**
   * @brief Calculate asset information.
   * @param[in] entropy           asset entropy
   * @return asset id (ConfidentialAssetId).
   */
  static ConfidentialAssetId CalculateAsset(const BlindFactor& entropy);
  /**
   * @brief Calculate the reissuance token information.
   * @param[in] entropy           asset entropy
   * @param[in] is_blind          asset is blinded or not
   * @return reissuance token (ConfidentialAssetId).
   */
  static ConfidentialAssetId CalculateReissuanceToken(
      const BlindFactor& entropy, bool is_blind);
  /**
   * @brief Set the Issue Asset information.
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
   * @brief Get the blinding key of issuance / reissuance.
   * @param[in] master_blinding_key master blindingKey
   * @param[in] txid                issuance utxo txid
   * @param[in] vout                issuance utxo vout
   * @return issuance blinding key
   */
  static Privkey GetIssuanceBlindingKey(
      const Privkey& master_blinding_key, const Txid& txid, uint32_t vout);
  /**
   * @brief Get the pubkey information used by pegout.
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
  std::vector<ConfidentialTxIn> vin_;    ///< TxIn array
  std::vector<ConfidentialTxOut> vout_;  ///< TxOut array

  /**
   * @brief Set Transaction information from HEX string.
   * @param[in] hex_string    HEX string.
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
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetScriptWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief Add information to the pegin witness stack.
   * @param[in] tx_in_index   TxIn index
   * @param[in] data          data to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness AddPeginWitnessStack(
      uint32_t tx_in_index, const std::vector<uint8_t>& data);
  /**
   * @brief Update the specified index position of the pegin witness stack.
   * @param[in] tx_in_index       TxIn index
   * @param[in] witness_index     witness stack index
   * @param[in] data              Information to add to the witness stack
   * @return witness stack
   */
  const ScriptWitness SetPeginWitnessStack(
      uint32_t tx_in_index, uint32_t witness_index,
      const std::vector<uint8_t>& data);
  /**
   * @brief Get the byte data of Transaction.
   * @param[in] has_witness   Flag to include witness
   * @return ByteData
   */
  ByteData GetByteData(bool has_witness) const;
  /**
   * @brief Set the Tx status flag (libwally value) of Elements.
   */
  void SetElementsTxState();
  /**
   * @brief Convert the array to ByteData.
   * @param[in] data      buffer
   * @param[in] size      size
   * @return ByteData
   */
  static ByteData ConvertToByteData(const uint8_t* data, size_t size);
  /**
   * @brief Copy the Confidential Nonce information.
   * @param[in] buffer            Copy source buffer
   * @param[in] buffer_size       Copy source buffer size
   * @param[in] explicit_size     Unblind size
   * @param[in] address           Copy destination address
   * @return Address after moving
   */
  static uint8_t* CopyConfidentialCommitment(
      const void* buffer, size_t buffer_size, size_t explicit_size,
      uint8_t* address);

  /**
   * @brief Unblind processing is applied to blinded data
   * @param[in] nonce             nonce
   * @param[in] blinding_key      blinding private key
   * @param[in] rangeproof        asset amount rangeproof
   * @param[in] value_commitment  blind value commitement
   * @param[in] extra             unblind need data
   * @param[in] asset             confidential asset id
   * @return UnblindParameter structure output when unblinded
   */
  static UnblindParameter CalculateUnblindData(
      const ConfidentialNonce& nonce, const Privkey& blinding_key,
      const ByteData& rangeproof, const ConfidentialValue& value_commitment,
      const Script& extra, const ConfidentialAssetId& asset);

  /**
   * @brief Unblind processing is applied to the blinded Issue data
   * @param[in] blinding_key      blinding private key
   * @param[in] rangeproof        asset amount rangeproof
   * @param[in] value_commitment  blind value commitement
   * @param[in] extra             unblind need data
   * @param[in] asset             confidential asset id
   * @return UnblindParameter structure output when unblinded
   */
  static UnblindParameter CalculateUnblindIssueData(
      const Privkey& blinding_key, const ByteData& rangeproof,
      const ConfidentialValue& value_commitment, const Script& extra,
      const ConfidentialAssetId& asset);

  /**
   * @brief Generate rangeProof etc.
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
   * @brief Generate an extended Key from Descriptor information.
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
