// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_address.h
 *
 * @brief Addressクラス定義
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_

#include <map>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"

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
 * @brief Address format dataクラス
 */
class CFD_CORE_EXPORT AddressFormatData {
 public:
  /**
   * @brief コンストラクタ
   */
  AddressFormatData();
  /**
   * @brief コンストラクタ
   * @param[in] default_format_name     default format name
   */
  explicit AddressFormatData(const std::string& default_format_name);
  /**
   * @brief コンストラクタ
   * @param[in] map_data     prefix setting map
   */
  explicit AddressFormatData(
      const std::map<std::string, std::string>& map_data);

  /**
   * @brief 文字列情報を取得する.
   * @param[in] key   mapping key
   * @return value
   */
  std::string GetString(const std::string& key) const;
  /**
   * @brief 文字列情報を数値型に変換して取得する.
   * @param[in] key   mapping key
   * @return uint32_t value
   */
  uint32_t GetValue(const std::string& key) const;

  /**
   * @brief P2pkhのprefix値を取得する.
   * @return P2pkh prefix
   */
  uint8_t GetP2pkhPrefix() const;
  /**
   * @brief P2shのprefix値を取得する.
   * @return P2sh prefix
   */
  uint8_t GetP2shPrefix() const;
  /**
   * @brief bech32のhrpを取得する.
   * @return Bech32 hrp
   */
  std::string GetBech32Hrp() const;
  /**
   * @brief netTypeを取得する.
   * @return network type
   */
  NetType GetNetType() const;

  /**
   * @brief json文字列情報からAddress format dataを取得する.
   * @param[in] json_data       json string
   * @return Address format data
   */
  static AddressFormatData ConvertFromJson(const std::string& json_data);
  /**
   * @brief json文字列情報からAddress format data一覧を取得する.
   * @param[in] json_data       json string
   * @return Address format data list
   */
  static std::vector<AddressFormatData> ConvertListFromJson(
      const std::string& json_data);

 private:
  std::map<std::string, std::string> map_;  //!< map
};

/**
 * @brief Bitcoin のデフォルトのアドレスフォーマットリストを取得する.
 * @return Bitcoinデフォルトのアドレスフォーマットリスト
 */
CFD_CORE_API std::vector<AddressFormatData> GetBitcoinAddressFormatList();

/**
 * @typedef AddressType
 * @brief Address種別の定義
 */
enum AddressType {
  kP2shAddress = 1,   //!< Legacy address (Script Hash)
  kP2pkhAddress,      //!< Legacy address (PublicKey Hash)
  kP2wshAddress,      //!< Native segwit address (Script Hash)
  kP2wpkhAddress,     //!< Native segwit address (PublicKey Hash)
  kP2shP2wshAddress,  //!< P2sh wrapped address (Script Hash)
  kP2shP2wpkhAddress  //!< P2sh wrapped address (Pubkey Hash)
};

/**
 * @typedef WitnessVersion
 * @brief Witnessバージョンの定義
 */
enum WitnessVersion {
  kVersionNone = -1,  //!< Missing WitnessVersion
  kVersion0 = 0,      //!< version 0
  kVersion1,          //!< version 1 (for future use)
  kVersion2,          //!< version 2 (for future use)
  kVersion3,          //!< version 3 (for future use)
  kVersion4,          //!< version 4 (for future use)
  kVersion5,          //!< version 5 (for future use)
  kVersion6,          //!< version 6 (for future use)
  kVersion7,          //!< version 7 (for future use)
  kVersion8,          //!< version 8 (for future use)
  kVersion9,          //!< version 9 (for future use)
  kVersion10,         //!< version 10 (for future use)
  kVersion11,         //!< version 11 (for future use)
  kVersion12,         //!< version 12 (for future use)
  kVersion13,         //!< version 13 (for future use)
  kVersion14,         //!< version 14 (for future use)
  kVersion15,         //!< version 15 (for future use)
  kVersion16          //!< version 16 (for future use)
};

/**
 * @class Address
 * @brief アドレスの生成クラス
 */
class CFD_CORE_EXPORT Address {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  Address();

  /**
   * @brief コンストラクタ(hex文字列からの復元)
   * @param[in] address_string   アドレス文字列
   */
  explicit Address(const std::string& address_string);
  /**
   * @brief コンストラクタ(hex文字列からの復元)
   * @param[in] address_string      アドレス文字列
   * @param[in] network_parameters  network parameter list
   */
  explicit Address(
      const std::string& address_string,
      const std::vector<AddressFormatData>& network_parameters);
  /**
   * @brief コンストラクタ(hex文字列からの復元)
   * @param[in] address_string      アドレス文字列
   * @param[in] network_parameter   network parameter
   */
  explicit Address(
      const std::string& address_string,
      const AddressFormatData& network_parameter);

  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   */
  Address(NetType type, const Pubkey& pubkey);
  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] prefix    p2pkh prefix
   */
  Address(NetType type, const Pubkey& pubkey, uint8_t prefix);
  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, const Pubkey& pubkey,
      const AddressFormatData& network_parameter);
  /**
   * @brief コンストラクタ(P2PKH用)
   * @param[in] type      NetType
   * @param[in] pubkey    PublicKey
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, const Pubkey& pubkey,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief コンストラクタ(P2WPKH用)
   * @param[in] type        NetType
   * @param[in] witness_ver Witnessバージョン
   * @param[in] pubkey      PublicKey
   */
  Address(NetType type, WitnessVersion witness_ver, const Pubkey& pubkey);
  /**
   * @brief コンストラクタ(P2WPKH用)
   * @param[in] type        NetType
   * @param[in] witness_ver Witnessバージョン
   * @param[in] pubkey      PublicKey
   * @param[in] bech32_hrp  bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const std::string& bech32_hrp);
  /**
   * @brief コンストラクタ(P2WPKH用)
   * @param[in] type        NetType
   * @param[in] witness_ver Witnessバージョン
   * @param[in] pubkey      PublicKey
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const AddressFormatData& network_parameter);
  /**
   * @brief コンストラクタ(P2WPKH用)
   * @param[in] type        NetType
   * @param[in] witness_ver Witnessバージョン
   * @param[in] pubkey      PublicKey
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   */
  Address(NetType type, const Script& redeem_script);
  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] prefix        p2sh prefix
   */
  Address(NetType type, const Script& redeem_script, uint8_t prefix);
  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, const Script& redeem_script,
      const AddressFormatData& network_parameter);
  /**
   * @brief コンストラクタ(P2SH用)
   * @param[in] type          NetType
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, const Script& redeem_script,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief コンストラクタ(P2WSH用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] redeem_script Redeem Script
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script);
  /**
   * @brief コンストラクタ(P2WSH用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] redeem_script Redeem Script
   * @param[in] bech32_hrp    bech32 hrp
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const std::string& bech32_hrp);
  /**
   * @brief コンストラクタ(P2WSH用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const AddressFormatData& network_parameter);
  /**
   * @brief コンストラクタ(P2WSH用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] redeem_script Redeem Script
   * @param[in] network_parameters   network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const Script& redeem_script,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief コンストラクタ(P2PKH/P2SH用。AddressType明示)
   * @param[in] type          NetType
   * @param[in] addr_type     種別
   * @param[in] hash          ハッシュ化済みの値
   */
  Address(NetType type, AddressType addr_type, const ByteData160& hash);
  /**
   * @brief コンストラクタ(P2PKH/P2SH用。AddressType明示)
   * @param[in] type          NetType
   * @param[in] addr_type     種別
   * @param[in] hash          ハッシュ化済みの値
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, AddressType addr_type, const ByteData160& hash,
      const AddressFormatData& network_parameter);
  /**
   * @brief コンストラクタ(P2PKH/P2SH用。AddressType明示)
   * @param[in] type          NetType
   * @param[in] addr_type     種別
   * @param[in] hash          ハッシュ化済みの値
   * @param[in] network_parameters  network parameter list
   */
  Address(
      NetType type, AddressType addr_type, const ByteData160& hash,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief コンストラクタ(ハッシュ化済みの値用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] hash          ハッシュ化済みの値
   */
  Address(NetType type, WitnessVersion witness_ver, const ByteData& hash);
  /**
   * @brief コンストラクタ(ハッシュ化済みの値用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] hash          ハッシュ化済みの値
   * @param[in] network_parameter   network parameter
   */
  Address(
      NetType type, WitnessVersion witness_ver, const ByteData& hash,
      const AddressFormatData& network_parameter);
  /**
   * @brief コンストラクタ(ハッシュ化済みの値用)
   * @param[in] type          NetType
   * @param[in] witness_ver   Witnessバージョン
   * @param[in] hash          ハッシュ化済みの値
   * @param[in] network_parameters  network parameter list
   */
  Address(
      NetType type, WitnessVersion witness_ver, const ByteData& hash,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief アドレスのhex文字列を取得する.
   * @return アドレス文字列
   */
  std::string GetAddress() const;

  /**
   * @brief AddressのNetTypeを取得する.
   * @return NetType
   */
  NetType GetNetType() const { return type_; }

  /**
   * @brief Address種別を取得する.
   * @return Address種別
   */
  AddressType GetAddressType() const { return addr_type_; }

  /**
   * @brief Witnessバージョンを取得する.
   * @return Witnessバージョン
   */
  WitnessVersion GetWitnessVersion() const { return witness_ver_; }

  /**
   * @brief アドレスHashを取得する.
   * @return アドレスHashのByteDataインスタンス
   */
  ByteData GetHash() const { return hash_; }

  /**
   * @brief PublicKeyを取得する.
   * @return Pubkeyオブジェクト
   */
  Pubkey GetPubkey() const { return pubkey_; }

  /**
   * @brief Redeem Scriptを取得する.
   * @return Scriptオブジェクト
   */
  Script GetScript() const { return redeem_script_; }

  /**
   * @brief AddressFormatDataを取得する.
   * @return AddressFormatDataオブジェクト
   */
  AddressFormatData GetAddressFormatData() const { return format_data_; }

  /**
   * @brief LockingScriptを取得する
   * @return locking script
   */
  Script GetLockingScript() const;

 private:
  /**
   * @brief P2SH Addressの情報を算出する.
   * @param[in] prefix      p2sh prefix
   */
  void CalculateP2SH(uint8_t prefix = 0);
  /**
   * @brief P2SH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みRedeem script
   * @param[in] prefix      p2sh prefix
   */
  void CalculateP2SH(const ByteData160& hash_data, uint8_t prefix = 0);

  /**
   * @brief P2PKH Addressの情報を算出する.
   * @param[in] prefix      p2pkh prefix
   */
  void CalculateP2PKH(uint8_t prefix = 0);
  /**
   * @brief P2PKH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みPubkey
   * @param[in] prefix      p2pkh prefix
   */
  void CalculateP2PKH(const ByteData160& hash_data, uint8_t prefix = 0);

  /**
   * @brief P2WSH Addressの情報を算出する.
   * @param[in] bech32_hrp    bech32 hrp
   */
  void CalculateP2WSH(const std::string& bech32_hrp = "");
  /**
   * @brief P2WSH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みRedeemScript
   * @param[in] bech32_hrp  bech32 hrp
   */
  void CalculateP2WSH(
      const ByteData256& hash_data,  // script hash
      const std::string& bech32_hrp = "");

  /**
   * @brief P2WPKH Address算出()
   * @param[in] bech32_hrp    bech32 hrp
   */
  void CalculateP2WPKH(const std::string& bech32_hrp = "");
  /**
   * @brief P2WPKH Addressの情報を算出する.
   * @param[in] hash_data   ハッシュ化済みPubkey
   * @param[in] bech32_hrp  bech32 hrp
   */
  void CalculateP2WPKH(
      const ByteData160& hash_data,  // pubkey hash
      const std::string& bech32_hrp = "");

  /* Segwit Address Format
   *
   * 例：bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
   *
   *    "bc"or"tb"
   *        ：Human-readable part(bc=mainnet/tb=testnet)
   *    "1" ：Separator 1固定
   *    "v8f3t4"
   *        ：checksum
   *
   *    "qw508d6qejxtdg4y5r3zarvary0c5xw7k"をbase32Decode
   *    -> "0014751e76e8199196d454941c45d1b3a323f1433bd6"
   *    "00" ：witness version
   *    "14" ：data長(P2WPKHは20byte/P2WSHは32byte)
   *    "751e76e8199196d454941c45d1b3a323f1433bd6"
   *         ：witness program(PubkeyHash or ScriptHash)
   */
  /**
   * @brief Hex文字列をdecodeする.
   * @param[in] bs58                デコードするアドレスのbase58文字列
   * @param[in] network_parameters  network parameter list
   */
  void DecodeAddress(
      std::string bs58,  // LF
      const std::vector<AddressFormatData>* network_parameters);

  /**
   * @brief NetType設定用のWrapper関数.
   * @param[in] format_data   Address format data
   */
  void SetNetType(const AddressFormatData& format_data);

  /**
   * @brief AddressType設定用のWrapper関数.
   * @param[in] addr_type   Address type
   */
  void SetAddressType(AddressType addr_type);

  /**
   * @brief Address format data一覧から指定NetTypeの情報を取得する.
   * @param[in] network_parameters  Address format data list
   * @param[in] type                NetType
   * @return Address format data
   */
  static AddressFormatData GetTargetFormatData(
      const std::vector<AddressFormatData>& network_parameters, NetType type);

  //! アドレスのNetType
  NetType type_;

  //! アドレス種別
  AddressType addr_type_;

  //! Witnessバージョン
  WitnessVersion witness_ver_;

  //! アドレス文字列
  std::string address_;

  //! アドレスHash
  ByteData hash_;

  //! PublicKey
  Pubkey pubkey_;

  //! Redeem Script
  Script redeem_script_;

  //! チェックサム
  uint8_t checksum_[4];

  //! address prefix format data
  AddressFormatData format_data_;
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ADDRESS_H_
