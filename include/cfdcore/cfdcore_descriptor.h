// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_descriptor.h
 *
 * @brief Output Descriptor関連クラス定義
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_transaction_common.h"

namespace cfd {
namespace core {

/**
 * @brief DescriptorNode の種別定義.
 */
enum DescriptorNodeType {
  kDescriptorTypeNull,    //!< null
  kDescriptorTypeScript,  //!< script
  kDescriptorTypeKey,     //!< key
  kDescriptorTypeNumber,  //!< number
};

/**
 * @brief DescriptorNode のScript種別定義.
 */
enum DescriptorScriptType {
  kDescriptorScriptNull,         //!< null
  kDescriptorScriptSh,           //!< script hash
  kDescriptorScriptWsh,          //!< segwit script hash
  kDescriptorScriptPk,           //!< pubkey
  kDescriptorScriptPkh,          //!< pubkey hash
  kDescriptorScriptWpkh,         //!< segwit pubkey hash
  kDescriptorScriptCombo,        //!< combo
  kDescriptorScriptMulti,        //!< multisig
  kDescriptorScriptSortedMulti,  //!< sorted multisig
  kDescriptorScriptAddr,         //!< address
  kDescriptorScriptRaw,          //!< raw script
};

/**
 * @brief DescriptorNode のKey種別定義.
 */
enum DescriptorKeyType {
  kDescriptorKeyNull,       //!< null
  kDescriptorKeyPublic,     //!< pubkey
  kDescriptorKeyBip32,      //!< bip32 extpubkey
  kDescriptorKeyBip32Priv,  //!< bip32 extprivkey
};

/**
 * @brief key型descriptorの参照クラスです.
 */
class CFD_CORE_EXPORT DescriptorKeyReference {
 public:
  /**
   * @brief constructor.
   */
  DescriptorKeyReference();
  /**
   * @brief constructor.
   * @param[in] pubkey      pubkey
   */
  explicit DescriptorKeyReference(const Pubkey& pubkey);
  /**
   * @brief constructor.
   * @param[in] ext_privkey   ext privkey
   * @param[in] arg           argument
   */
  explicit DescriptorKeyReference(
      const ExtPrivkey& ext_privkey, const std::string* arg = nullptr);
  /**
   * @brief constructor.
   * @param[in] ext_pubkey   ext pubkey
   * @param[in] arg           argument
   */
  explicit DescriptorKeyReference(
      const ExtPubkey& ext_pubkey, const std::string* arg = nullptr);
  /**
   * @brief copy constructor.
   * @param[in] object    DescriptorKeyReference object
   * @return DescriptorKeyReference object
   */
  DescriptorKeyReference& operator=(const DescriptorKeyReference& object);

  /**
   * @brief getting pubkey.
   * @return pubkey
   */
  Pubkey GetPubkey() const;
  /**
   * @brief getting argument.
   * @return argument
   */
  std::string GetArgument() const;
  /**
   * @brief exist ext-privkey.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasExtPrivkey() const;
  /**
   * @brief exist ext-pubkey.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasExtPubkey() const;
  /**
   * @brief getting ext-privkey.
   * @details need ext-privkey exists.
   * @return ext-privkey
   */
  ExtPrivkey GetExtPrivkey() const;
  /**
   * @brief getting ext-pubkey.
   * @details need ext-pubkey exists.
   * @return ext-pubkey
   */
  ExtPubkey GetExtPubkey() const;
  /**
   * @brief getting key type.
   * @return key type
   */
  DescriptorKeyType GetKeyType() const;

 private:
  DescriptorKeyType key_type_;  //!< node key type
  Pubkey pubkey_;               //!< pubkey
  std::string key_info_;        //!< key string data
  std::string argument_;        //!< argument
};

/**
 * @brief Script型descriptorの参照クラスです.
 */
class CFD_CORE_EXPORT DescriptorScriptReference {
 public:
  /**
   * @brief constructor.
   */
  DescriptorScriptReference();
  /**
   * @brief constructor.
   * @details `raw` type only.
   * @param[in] locking_script    locking script
   * @param[in] script_type       script type
   * @param[in] address_prefixes  address prefix list
   */
  explicit DescriptorScriptReference(
      const Script& locking_script, DescriptorScriptType script_type,
      const std::vector<AddressFormatData>& address_prefixes);
  /**
   * @brief constructor.
   * @details `sh` or `wsh` type only.
   * @param[in] locking_script    locking script
   * @param[in] script_type       script type
   * @param[in] child_script      child script node
   * @param[in] address_prefixes  address prefix list
   */
  explicit DescriptorScriptReference(
      const Script& locking_script, DescriptorScriptType script_type,
      const DescriptorScriptReference& child_script,
      const std::vector<AddressFormatData>& address_prefixes);
  /**
   * @brief constructor.
   * @param[in] locking_script    locking script
   * @param[in] script_type       script type
   * @param[in] key_list          key(pubkey, extprivkey, extpubkey) list
   * @param[in] address_prefixes  address prefix list
   */
  explicit DescriptorScriptReference(
      const Script& locking_script, DescriptorScriptType script_type,
      const std::vector<DescriptorKeyReference>& key_list,
      const std::vector<AddressFormatData>& address_prefixes);
  /**
   * @brief constructor.
   * @param[in] address_script    address script
   * @param[in] address_prefixes  address prefix list
   */
  explicit DescriptorScriptReference(
      const Address& address_script,
      const std::vector<AddressFormatData>& address_prefixes);
  /**
   * @brief copy constructor.
   * @param[in] object    DescriptorScriptReference object
   * @return DescriptorScriptReference object
   */
  DescriptorScriptReference& operator=(
      const DescriptorScriptReference& object);

  /**
   * @brief getting locking script.
   * @return locking script
   */
  Script GetLockingScript() const;
  /**
   * @brief exist address data.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasAddress() const;
  /**
   * @brief getting address.
   * @param[in] net_type    network type
   * @return address
   */
  Address GenerateAddress(NetType net_type) const;
  /**
   * @brief getting address list.
   * @param[in] net_type    network type
   * @return address list
   */
  std::vector<Address> GenerateAddresses(NetType net_type) const;
  /**
   * @brief getting address type.
   * @return address type
   */
  AddressType GetAddressType() const;
  /**
   * @brief getting hash type.
   * @return hash type
   */
  HashType GetHashType() const;

  // script api
  /**
   * @brief exist redeem script.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasRedeemScript() const;
  /**
   * @brief getting redeem script.
   * @return redeem script
   */
  Script GetRedeemScript() const;
  /**
   * @brief exist child script node.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasChild() const;
  /**
   * @brief getting child script node.
   * @return child script node
   */
  DescriptorScriptReference GetChild() const;

  // key api
  /**
   * @brief exist key list.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasKey() const;
  /**
   * @brief getting key list number.
   * @return key list number
   */
  uint32_t GetKeyNum() const;
  /**
   * @brief getting key list.
   * @return key list
   */
  std::vector<DescriptorKeyReference> GetKeyList() const;
  /**
   * @brief getting script type.
   * @return script type
   */
  DescriptorScriptType GetScriptType() const;

 private:
  DescriptorScriptType script_type_;  //!< node script type
  Script locking_script_;             //!< locking script
  bool is_script_;                    //!< exist redeem script
  Script redeem_script_;              //!< redeem script
  Address address_script_;            //!< address script data
  //! child script
  std::shared_ptr<DescriptorScriptReference> child_script_ = nullptr;
  std::vector<DescriptorKeyReference> keys_;      //!< key list
  std::vector<AddressFormatData> addr_prefixes_;  //!< address prefixes
};

/**
 * @brief Descriptor用Node定義クラス
 */
class CFD_CORE_EXPORT DescriptorNode {
 public:
  /**
   * @brief parse output descriptor.
   * @param[in] output_descriptor   output descriptor
   * @param[in] network_parameters  network parameter
   * @return DescriptorNode object
   */
  static DescriptorNode Parse(
      const std::string& output_descriptor,
      const std::vector<AddressFormatData>& network_parameters);

  /**
   * @brief generate to checksum from descriptor.
   * @param[in] descriptor  output descriptor
   * @return checksum
   */
  static std::string GenerateChecksum(const std::string& descriptor);

  /**
   * @brief constructor.
   */
  DescriptorNode();
  /**
   * @brief constructor.
   * @param[in] network_parameters  network parameter
   */
  explicit DescriptorNode(
      const std::vector<AddressFormatData>& network_parameters);
  /**
   * @brief copy constructor.
   * @param[in] object    DescriptorNode object
   * @return DescriptorNode object
   */
  DescriptorNode& operator=(const DescriptorNode& object);

  /**
   * @brief get reference object.
   * @param[in] array_argument  argument
   * @return reference object
   */
  DescriptorScriptReference GetReference(
      std::vector<std::string>* array_argument) const;

  /**
   * @brief get reference object list.
   * @param[in] array_argument  argument
   * @return reference object list
   */
  std::vector<DescriptorScriptReference> GetReferences(
      std::vector<std::string>* array_argument) const;

  /**
   * @brief argumentに必要な数を取得する。
   * @return argument number.
   */
  uint32_t GetNeedArgumentNum() const;

  /**
   * @brief getting output descriptor.
   * @param[in] append_checksum  append checksum
   * @return output descriptor
   */
  std::string ToString(bool append_checksum = true) const;

  /**
   * @brief DescriptorNodeの種別を取得する。
   * @return DescriptorNodeType
   */
  DescriptorNodeType GetNodeType() const { return node_type_; }
  /**
   * @brief DescriptorNodeのScript種別を取得する。
   * @return DescriptorScriptType
   */
  DescriptorScriptType GetScriptType() const { return script_type_; }

  /**
   * @brief check checksum.
   * @param[in] descriptor    check target descriptor.
   */
  void CheckChecksum(const std::string& descriptor);

 protected:
  /**
   * @brief get pubkey.
   * @param[in] array_argument  argument array.
   * @return pubkey
   */
  Pubkey GetPubkey(std::vector<std::string>* array_argument) const;
  /**
   * @brief get key reference object.
   * @param[in] array_argument  argument
   * @return key reference object list
   */
  DescriptorKeyReference GetKeyReferences(
      std::vector<std::string>* array_argument) const;

 private:
  std::string name_;                              //!< node name
  std::string value_;                             //!< node value
  std::string key_info_;                          //!< key information
  uint32_t number_ = 0;                           //!< number value
  std::vector<DescriptorNode> child_node_;        //!< child nodes
  std::string checksum_;                          //!< checksum
  uint32_t depth_ = 0;                            //!< depth
  uint32_t need_arg_num_ = 0;                     //!< need argument num
  DescriptorNodeType node_type_;                  //!< node type
  DescriptorScriptType script_type_;              //!< node script type
  DescriptorKeyType key_type_;                    //!< node key type
  std::vector<AddressFormatData> addr_prefixes_;  //!< address prefixes

  /**
   * @brief analyze child node.
   * @param[in] descriptor  output descriptor
   * @param[in] depth       node depth
   */
  void AnalyzeChild(const std::string& descriptor, uint32_t depth);
  /**
   * @brief analyze all node.
   * @param[in] parent_name  parent node name
   */
  void AnalyzeAll(const std::string& parent_name);
  /**
   * @brief analyze key node.
   */
  void AnalyzeKey();
};

/**
 * @brief Output Descriptor定義クラス
 */
class CFD_CORE_EXPORT Descriptor {
 public:
  /**
   * @brief parse output descriptor.
   * @param[in] output_descriptor   output descriptor
   * @param[in] network_parameters  network parameter
   * @return DescriptorNode object
   */
  static Descriptor Parse(
      const std::string& output_descriptor,
      const std::vector<AddressFormatData>* network_parameters = nullptr);

#ifndef CFD_DISABLE_ELEMENTS
  /**
   * @brief parse output descriptor on Elements.
   * @details supported an Elements `addr` descriptor.
   * @param[in] output_descriptor   output descriptor
   * @return DescriptorNode object
   */
  static Descriptor ParseElements(const std::string& output_descriptor);
#endif  // CFD_DISABLE_ELEMENTS

  /**
   * @brief constructor.
   */
  Descriptor();

  /**
   * @brief check combo script.
   * @retval true  combo script
   * @retval false other script
   */
  bool IsComboScript() const;
  /**
   * @brief argumentに必要な数を取得する。
   * @return argument number.
   */
  uint32_t GetNeedArgumentNum() const;

  /**
   * @brief getting locking script.
   * @return locking script
   */
  Script GetLockingScript() const;

  /**
   * @brief getting locking script.
   * @param[in] argument        argument
   * @return locking script
   */
  Script GetLockingScript(const std::string& argument) const;
  /**
   * @brief getting locking script.
   * @param[in] array_argument  argument
   * @return locking script
   */
  Script GetLockingScript(
      const std::vector<std::string>& array_argument) const;

  /**
   * @brief getting locking script list.
   * @param[in] array_argument  argument
   * @return locking script
   */
  std::vector<Script> GetLockingScriptAll(
      const std::vector<std::string>* array_argument = nullptr) const;

  /**
   * @brief getting descriptor reference.
   * @param[in] array_argument  argument
   * @return descriptor reference
   */
  DescriptorScriptReference GetReference(
      const std::vector<std::string>* array_argument = nullptr) const;

  /**
   * @brief getting descriptor reference list.
   * @param[in] array_argument  argument
   * @return descriptor reference list
   */
  std::vector<DescriptorScriptReference> GetReferenceAll(
      const std::vector<std::string>* array_argument = nullptr) const;

  /**
   * @brief getting output descriptor.
   * @param[in] append_checksum  append checksum
   * @return output descriptor
   */
  std::string ToString(bool append_checksum = true) const;

  /**
   * @brief get descriptor node.
   * @return descriptor node
   */
  DescriptorNode GetNode() const;

 private:
  DescriptorNode root_node_;  //!< root node
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_DESCRIPTOR_H_
