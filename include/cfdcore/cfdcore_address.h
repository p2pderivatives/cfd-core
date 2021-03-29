// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_address.h
 *
 * @brief Bitcoin address definition file.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_

#include <map>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_taproot.h"

namespace cfd {
namespace core {

//! key: nettype
constexpr const char* const kNettype = "nettype";
//! nettype value: mainnet
constexpr const char* const kNettypeMainnet = "mainnet";
//! nettype value: testnet
constexpr const char* const kNettypeTestnet = "testnet";
//! nettype value: regtest
constexpr const char* const kNettypeRegtest = "regtest";
//! nettype value: liquidv1
constexpr const char* const kNettypeLiquidV1 = "liquidv1";
//! nettype value: elements regtest
constexpr const char* const kNettypeElementsRegtest = "elementsregtest";
//! key: p2pkh prefix
constexpr const char* const kPrefixP2pkh = "p2pkh";
//! key: p2sh prefix
constexpr const char* const kPrefixP2sh = "p2sh";
//! key: bech32 hrp
constexpr const char* const kPrefixBech32Hrp = "bech32";
//! key: blind p2pkh prefix
constexpr const char* const kPrefixBlindP2pkh = "blinded";
//! key: blind p2sh prefix
constexpr const char* const kPrefixBlindP2sh = "blinded";
//! key: blind bech32 hrp (blech32)
constexpr const char* const kPrefixBlindBech32Hrp = "blech32";

/**
 * @class AddressFormatData
 * @brief class for showing format data of address
 */
class CFD_CORE_EXPORT AddressFormatData {
 public:
  /**
   * @brief constructor.
   */
  AddressFormatData();
  /**
   * @brief constructor.
   * @param[in] default_format_name     default format name
   */
  explicit AddressFormatData(const std::string& default_format_name);
  /**
   * @brief constructor.
   * @param[in] map_data     prefix setting map
   */
  explicit AddressFormatData(
      const std::map<std::string, std::string>& map_data);

  /**
   * @brief Get string value.
   * @param[in] key   mapping key
   * @return value
   */
  std::string GetString(const std::string& key) const;
  /**
   * @brief Get numeric value from string.
   * @param[in] key   mapping key
   * @return uint32_t value
   */
  uint32_t GetValue(const std::string& key) const;

  /**
   * @brief Get P2pkh prefix.
   * @return P2pkh prefix
   */
  uint8_t GetP2pkhPrefix() const;
  /**
   * @brief Get P2sh prefix.
   * @return P2sh prefix
   */
  uint8_t GetP2shPrefix() const;
  /**
   * @brief Get hrp on bech32.
   * @return Bech32 hrp
   */
  std::string GetBech32Hrp() const;
  /**
   * @brief Get network type.
   * @return network type
   */
  NetType GetNetType() const;

  /**
   * @brief Get Address format data from json string.
   * @param[in] json_data       json string
   * @return Address format data
   */
  static AddressFormatData ConvertFromJson(const std::string& json_data);
  /**
   * @brief Get Address format data list from json string.
   * @param[in] json_data       json string
   * @return Address format data list
   */
  static std::vector<AddressFormatData> ConvertListFromJson(
      const std::string& json_data);

 private:
  std::map<std::string, std::string> map_;  //!< map
};

/**
 * @brief Get address format list by Bitcoin default.
 * @return Address format list by Bitcoin default.
 */
CFD_CORE_API std::vector<AddressFormatData> GetBitcoinAddressFormatList();

/**
 * @typedef AddressType
 * @brief Address type.
 */
enum AddressType {
  kP2shAddress = 1,    //!< Legacy address (Script Hash)
  kP2pkhAddress,       //!< Legacy address (PublicKey Hash)
  kP2wshAddress,       //!< Native segwit address (Script Hash)
  kP2wpkhAddress,      //!< Native segwit address (PublicKey Hash)
  kP2shP2wshAddress,   //!< P2sh wrapped address (Script Hash)
  kP2shP2wpkhAddress,  //!< P2sh wrapped address (Pubkey Hash)
  kTaprootAddress,     //!< Taproot (segwit v1) address
  kWitnessUnknown      //!< witness unknown address
};

/**
 * @class Address
 * @brief address class.
 */
class CFD_CORE_EXPORT Address {
 public:
  /**
   * @brief default constructor.
   */
  Address();
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  Address(const Address& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  Address& operator=(const Address& object);

  /**
   * @brief Constructor. (for string)
   * @param[in] address_string      address string
   */
  explicit Address(const std::string& address_string);
  /**
   * @brief Constructor. (for string)
   * @param[in] address_string      address string
   * @param[in] network_parameters  network parameter list
   */
  explicit Address(
      const std::string& address_string,
      const std::vector<AddressFormatData>& network_parameters);
  /**
   * @brief Constructor. (for string)
   * @param[in] address_string      address string
   * @param[in] network_parameter   network parameter
   */
  explicit Address(
      const std::string& address_string,
      const AddressFormatData& network_parameter);

  /**
   * @brief Constructor. (for P2PKH)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   */
  Address(NetType type, const Pubkey& pubkey);
  /**
   * @brief Constructor. (for P2PKH)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] prefix    p2pkh prefix
   */
  Address(NetType type, const Pubkey& pubkey, uint8_t prefix);
  /**
   * @brief Constructor. (for P2PKH)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, const Pubkey& pubkey,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for P2PKH)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, const Pubkey& pubkey,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Constructor. (for P2WPKH)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   */
  Address(NetType type, WitnessVersion witness_ver, const Pubkey& pubkey);
  /**
   * @brief Constructor. (for P2WPKH)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   * @param[in] bech32_hrp  bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const std::string& bech32_hrp);
  /**
   * @brief Constructor. (for P2WPKH)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for P2WPKH)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Constructor. (for P2SH)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   */
  Address(NetType type, const Script& redeem_script);
  /**
   * @brief Constructor. (for P2SH)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] prefix        p2sh prefix
   */
  Address(NetType type, const Script& redeem_script, uint8_t prefix);
  /**
   * @brief Constructor. (for P2SH)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, const Script& redeem_script,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for P2SH)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, const Script& redeem_script,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Constructor. (for P2WSH)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witness version
   * @param[in] redeem_script Redeem Script
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script);
  /**
   * @brief Constructor. (for P2WSH)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witness version
   * @param[in] redeem_script Redeem Script
   * @param[in] bech32_hrp    bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const std::string& bech32_hrp);
  /**
   * @brief Constructor. (for P2WSH)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witness version
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for P2WSH)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witness version
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   */
  Address(
      NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey);
  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   * @param[in] bech32_hrp  bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey,
      const std::string& bech32_hrp);
  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] pubkey      PublicKey
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] tree                tapscript tree
   * @param[in] internal_pubkey     internal PublicKey
   */
  Address(
      NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
      const SchnorrPubkey& internal_pubkey);
  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] tree                tapscript tree
   * @param[in] internal_pubkey     internal PublicKey
   * @param[in] bech32_hrp  bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
      const SchnorrPubkey& internal_pubkey, const std::string& bech32_hrp);
  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] tree                tapscript tree
   * @param[in] internal_pubkey     internal PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
      const SchnorrPubkey& internal_pubkey,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for Taproot)
   * @param[in] type        NetType
   * @param[in] witness_ver Witness version
   * @param[in] tree                tapscript tree
   * @param[in] internal_pubkey     internal PublicKey
   * @param[in] network_parameters  network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
      const SchnorrPubkey& internal_pubkey,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Constructor. (for P2PKH/P2SH)
   * @param[in] type          NetType
   * @param[in] addr_type     Address type
   * @param[in] hash          hashed data
   */
  Address(NetType type, AddressType addr_type, const ByteData160& hash);
  /**
   * @brief Constructor. (for P2PKH/P2SH)
   * @param[in] type          NetType
   * @param[in] addr_type     Address type
   * @param[in] hash          hashed data
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, AddressType addr_type, const ByteData160& hash,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for P2PKH/P2SH)
   * @param[in] type          NetType
   * @param[in] addr_type     Address type
   * @param[in] hash          hashed data
   * @param[in] network_parameters  network parameter list
   */
  Address(
      NetType type, AddressType addr_type, const ByteData160& hash,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Constructor. (for hashed data)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witness version
   * @param[in] hash          hashed data
   */
  Address(NetType type, WitnessVersion witness_ver, const ByteData& hash);
  /**
   * @brief Constructor. (for hashed data)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witness version
   * @param[in] hash          hashed data
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const ByteData& hash,
      const AddressFormatData& network_parameter);
  /**
   * @brief Constructor. (for hashed data)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witness version
   * @param[in] hash          hashed data
   * @param[in] network_parameters  network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const ByteData& hash,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief Get address string.
   * @return address string
   */
  std::string GetAddress() const;

  /**
   * @brief Get network type.
   * @return NetType
   */
  NetType GetNetType() const { return type_; }

  /**
   * @brief Get address type.
   * @return Address type
   */
  AddressType GetAddressType() const { return addr_type_; }

  /**
   * @brief Get witness version.
   * @return Witness version
   */
  WitnessVersion GetWitnessVersion() const { return witness_ver_; }

  /**
   * @brief Get address Hash.
   * @return address hash
   */
  ByteData GetHash() const { return hash_; }

  /**
   * @brief Get PublicKey.
   * @return Pubkey
   */
  Pubkey GetPubkey() const { return pubkey_; }

  /**
   * @brief Get Schnorr PublicKey.
   * @return Schnorr Pubkey
   */
  SchnorrPubkey GetSchnorrPubkey() const { return schnorr_pubkey_; }
  /**
   * @brief Get taproot script tree.
   * @return taproot script tree
   */
  TaprootScriptTree GetScriptTree() const { return script_tree_; }

  /**
   * @brief Get Redeem Script.
   * @return Script
   */
  Script GetScript() const { return redeem_script_; }

  /**
   * @brief Get AddressFormatData.
   * @return AddressFormatData
   */
  AddressFormatData GetAddressFormatData() const { return format_data_; }

  /**
   * @brief Get LockingScript
   * @return locking script
   */
  Script GetLockingScript() const;

 private:
  /**
   * @brief calculate P2SH Address
   * @param[in] prefix      p2sh prefix
   */
  void CalculateP2SH(uint8_t prefix = 0);
  /**
   * @brief calculate P2SH Address.
   * @param[in] hash_data   RedeemScript hash
   * @param[in] prefix      p2sh prefix
   */
  void CalculateP2SH(const ByteData160& hash_data, uint8_t prefix = 0);

  /**
   * @brief calculate P2PKH Address
   * @param[in] prefix      p2pkh prefix
   */
  void CalculateP2PKH(uint8_t prefix = 0);
  /**
   * @brief calculate P2PKH Address
   * @param[in] hash_data   Pubkey hash
   * @param[in] prefix      p2pkh prefix
   */
  void CalculateP2PKH(const ByteData160& hash_data, uint8_t prefix = 0);

  /**
   * @brief calculate P2WSH Address
   * @param[in] bech32_hrp    bech32 hrp
   */
  void CalculateP2WSH(const std::string& bech32_hrp = "");
  /**
   * @brief calculate P2WSH Address
   * @param[in] hash_data   RedeemScript hash
   * @param[in] bech32_hrp  bech32 hrp
   */
  void CalculateP2WSH(
      const ByteData256& hash_data,  // script hash
      const std::string& bech32_hrp = "");

  /**
   * @brief calculate P2WPKH Address
   * @param[in] bech32_hrp    bech32 hrp
   */
  void CalculateP2WPKH(const std::string& bech32_hrp = "");
  /**
   * @brief calculate P2WPKH Address
   * @param[in] hash_data   pubkey hash
   * @param[in] bech32_hrp  bech32 hrp
   */
  void CalculateP2WPKH(
      const ByteData160& hash_data,  // pubkey hash
      const std::string& bech32_hrp = "");

  /**
   * @brief calculate Taproot Address
   * @param[in] bech32_hrp    bech32 hrp
   */
  void CalculateTaproot(const std::string& bech32_hrp = "");
  /**
   * @brief calculate Bech32m Address
   * @param[in] hash_data   hash data
   * @param[in] bech32_hrp  bech32 hrp
   */
  void CalculateBech32m(
      const ByteData& hash_data,  // hash data
      const std::string& bech32_hrp = "");

  /**
   * @brief decode address from address string.
   * @param[in] address_string      address string
   * @param[in] network_parameters  network parameter list
   */
  void DecodeAddress(
      std::string address_string,  // LF
      const std::vector<AddressFormatData>* network_parameters);

  /**
   * @brief set network type.
   * @param[in] format_data   Address format data
   */
  void SetNetType(const AddressFormatData& format_data);

  /**
   * @brief set address type.
   * @param[in] addr_type   Address type
   */
  void SetAddressType(AddressType addr_type);

  /**
   * @brief Get AddressFormatData with NetType from format list.
   * @param[in] network_parameters  Address format data list
   * @param[in] type                NetType
   * @return Address format data
   */
  static AddressFormatData GetTargetFormatData(
      const std::vector<AddressFormatData>& network_parameters, NetType type);

  //! address's NetType
  NetType type_;

  //! address type
  AddressType addr_type_;

  //! Witness version
  WitnessVersion witness_ver_;

  //! address string
  std::string address_;

  //! address Hash
  ByteData hash_;

  //! PublicKey
  Pubkey pubkey_;

  SchnorrPubkey schnorr_pubkey_;   //!< Schnorr PublicKey
  TaprootScriptTree script_tree_;  //!< Taproot ScriptTree

  //! Redeem Script
  Script redeem_script_;

  //! checksum
  uint8_t checksum_[4];

  //! address prefix format data
  AddressFormatData format_data_;
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_
