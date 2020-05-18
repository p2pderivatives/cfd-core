// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_address.h
 *
 * @brief Elements対応したAddressクラス定義
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_ADDRESS_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_ADDRESS_H_
#ifndef CFD_DISABLE_ELEMENTS

#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"

namespace cfd {
namespace core {

/**
 * @brief ConfidentialKey(= Pubkey)の型定義
 * @see Pubkey
 */
using ConfidentialKey = Pubkey;

/**
 * @typedef ElementsNetType
 * @brief Elements Networkの定義
 */
using ElementsNetType = NetType;

/**
 * @typedef ElementsAddressType
 * @brief ElementsのAddress種別の定義
 */
using ElementsAddressType = AddressType;

/**
 * @brief Elements のデフォルトのアドレスフォーマットリストを取得する.
 * @return Elementsデフォルトのアドレスフォーマットリスト
 */
CFD_CORE_API std::vector<AddressFormatData> GetElementsAddressFormatList();

/**
 * @class ElementsConfidentialAddress
 * @brief ElementsのConfidentialアドレスを表現するクラス
 */
class CFD_CORE_EXPORT ElementsConfidentialAddress {
 public:
  /**
   * @brief get default blinding key.
   * @param[in] master_blinding_key master blindingKey
   * @param[in] locking_script      locking script by address.
   * @return blinding key
   */
  static Privkey GetBlindingKey(
      const Privkey& master_blinding_key, const Script& locking_script);

  /**
   * @brief デフォルトコンストラクタ
   */
  ElementsConfidentialAddress();

  /**
   * @brief コンストラクタ(UnblindedAddressからConfidentialAddress生成)
   * @param unblinded_address UnblindedAddress インスタンス
   * @param confidential_key  ConfidentialKey インスタンス
   */
  ElementsConfidentialAddress(
      const Address& unblinded_address,
      const ConfidentialKey& confidential_key);

  /**
   * @brief コンストラクタ(ConfidentialAddress文字列からのデコード)
   * @param[in] confidential_address confidential アドレス文字列
   */
  explicit ElementsConfidentialAddress(
      const std::string& confidential_address);

  /**
   * @brief コンストラクタ(ConfidentialAddress文字列からのデコード)
   * @param[in] confidential_address confidential アドレス文字列
   * @param[in] prefix_list  address prefix list
   */
  explicit ElementsConfidentialAddress(
      const std::string& confidential_address,
      const std::vector<AddressFormatData>& prefix_list);

  /**
   * @brief UnblindedAddressを取得
   * @return ConfidentialAddressに紐づくUnblindedAddressインスタンス
   */
  Address GetUnblindedAddress() const;

  /**
   * @brief ConfidentialKeyを取得
   * @return ConfidentialAddressに紐づくConfidentialKeyインスタンス
   */
  ConfidentialKey GetConfidentialKey() const;

  /**
   * @brief アドレスのhex文字列を取得する.
   * @return アドレス文字列
   */
  std::string GetAddress() const;

  /**
   * @brief AddressのElementsNetTypeを取得する.
   * @return ElementsNetType
   */
  ElementsNetType GetNetType() const;

  /**
   * @brief Address種別を取得する.
   * @return Elements Address種別
   */
  ElementsAddressType GetAddressType() const;

  /**
   * @brief アドレスHashを取得する.
   * @return アドレスHashのByteDataインスタンス
   */
  ByteData GetHash() const;

  /**
   * @brief LockingScriptを取得する
   * @return locking script
   */
  Script GetLockingScript() const;

  /**
   * @brief 引数で指定されたアドレスがBlindされているアドレスであるかを判定する
   * @param address アドレス(base58)文字列
   * @retval true Blindされているアドレスの場合
   * @retval false Blindされていないアドレスの場合
   */
  static bool IsConfidentialAddress(const std::string& address);

  /**
   * @brief 引数で指定されたアドレスがBlindされているアドレスであるかを判定する
   * @param[in] address アドレス文字列
   * @param[in] prefix_list アドレス文字列
   * @retval true Blindされているアドレスの場合
   * @retval false Blindされていないアドレスの場合
   */
  static bool IsConfidentialAddress(
      const std::string& address,
      const std::vector<AddressFormatData>& prefix_list);

 private:
  /**
   * @brief confidentialアドレス文字列からモデルのデコードを行う
   * @param[in] confidential_address  confidential address string
   * @param[in] prefix_list           address prefix list
   */
  void DecodeAddress(
      const std::string& confidential_address,
      const std::vector<AddressFormatData>& prefix_list);

  /**
   * @brief unblinded_addressとconfidential_keyから、confidential_addressを計算する.
   * @details Elementsのネットワーク種別については、ublinded_addressと同種のネットワークで計算を行う.
   * @param unblinded_address UnblindedAddressインスタンス
   * @param confidential_key Blindに利用するConfidentialKeyインスタンス
   */
  void CalculateAddress(
      const Address& unblinded_address,
      const ConfidentialKey& confidential_key);

  /// Unblinded Address
  Address unblinded_address_;

  /// Confidential Key
  ConfidentialKey confidential_key_;

  /// アドレス文字列
  std::string address_;
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_ADDRESS_H_
