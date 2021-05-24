// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_address.cpp
 * 
 * @brief Class to show address.
 */
#include "cfdcore/cfdcore_address.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_taproot.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT
#include "univalue.h"            // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::warn;

// -----------------------------------------------------------------------------
// AddressFormatData
// -----------------------------------------------------------------------------
AddressFormatData::AddressFormatData() : map_() {
  // do nothing
}

AddressFormatData::AddressFormatData(const std::string& default_format_name)
    : map_() {
  if (default_format_name == kNettypeMainnet) {
    map_.emplace(kNettype, kNettypeMainnet);
    map_.emplace(kPrefixP2pkh, "00");
    map_.emplace(kPrefixP2sh, "05");
    map_.emplace(kPrefixBech32Hrp, "bc");
  } else if (default_format_name == kNettypeTestnet) {
    map_.emplace(kNettype, kNettypeTestnet);
    map_.emplace(kPrefixP2pkh, "6f");
    map_.emplace(kPrefixP2sh, "c4");
    map_.emplace(kPrefixBech32Hrp, "tb");
  } else if (default_format_name == kNettypeRegtest) {
    map_.emplace(kNettype, kNettypeRegtest);
    map_.emplace(kPrefixP2pkh, "6f");
    map_.emplace(kPrefixP2sh, "c4");
    map_.emplace(kPrefixBech32Hrp, "bcrt");
  } else {
#ifndef CFD_DISABLE_ELEMENTS
    if (default_format_name == kNettypeLiquidV1) {
      map_.emplace(kNettype, kNettypeLiquidV1);
      map_.emplace(kPrefixP2pkh, "39");
      map_.emplace(kPrefixP2sh, "27");
      map_.emplace(kPrefixBech32Hrp, "ex");
      map_.emplace(kPrefixBlindP2pkh, "0c");
      map_.emplace(kPrefixBlindP2sh, "0c");
      map_.emplace(kPrefixBlindBech32Hrp, "lq");
    } else if (default_format_name == kNettypeElementsRegtest) {
      map_.emplace(kNettype, kNettypeElementsRegtest);
      map_.emplace(kPrefixP2pkh, "eb");
      map_.emplace(kPrefixP2sh, "4b");
      map_.emplace(kPrefixBech32Hrp, "ert");
      map_.emplace(kPrefixBlindP2pkh, "04");
      map_.emplace(kPrefixBlindP2sh, "04");
      map_.emplace(kPrefixBlindBech32Hrp, "el");
    }
#endif
  }
}

AddressFormatData::AddressFormatData(
    const std::map<std::string, std::string>& map_data)
    : map_(map_data) {}

std::string AddressFormatData::GetString(const std::string& key) const {
  if (map_.find(key) == map_.end()) {
    throw CfdException(
        CfdError::kCfdOutOfRangeError, "unknown key. key=" + key);
  }
  return map_.at(key);
}

uint32_t AddressFormatData::GetValue(const std::string& key) const {
  if (map_.find(key) == map_.end()) {
    throw CfdException(
        CfdError::kCfdOutOfRangeError, "unknown key. key=" + key);
  }
  return std::stoi(map_.at(key), nullptr, 16);
}

uint8_t AddressFormatData::GetP2pkhPrefix() const {
  return static_cast<uint8_t>(GetValue(kPrefixP2pkh));
}

uint8_t AddressFormatData::GetP2shPrefix() const {
  return static_cast<uint8_t>(GetValue(kPrefixP2sh));
}

std::string AddressFormatData::GetBech32Hrp() const {
  if (map_.find(kPrefixBech32Hrp) == map_.end()) {
    return "";
  }
  return GetString(kPrefixBech32Hrp);
}

NetType AddressFormatData::GetNetType() const {
  std::string net_type = GetString(kNettype);
  NetType result = NetType::kCustomChain;
  if (net_type == kNettypeMainnet) {
    result = NetType::kMainnet;
  } else if (net_type == kNettypeTestnet) {
    result = NetType::kTestnet;
  } else if (net_type == kNettypeRegtest) {
    result = NetType::kRegtest;
  } else {
#ifndef CFD_DISABLE_ELEMENTS
    if (net_type == kNettypeLiquidV1) {
      result = NetType::kLiquidV1;
    } else if (net_type == kNettypeElementsRegtest) {
      result = NetType::kElementsRegtest;
    }
#endif  // CFD_DISABLE_ELEMENTS
  }
  return result;
}

AddressFormatData AddressFormatData::ConvertFromJson(
    const std::string& json_data) {
  UniValue object;
  object.read(json_data);
  std::map<std::string, std::string> prefix_map;
  if (object.isObject() && object.exists(kNettype)) {
    std::map<std::string, UniValue> json_map;
    object.getObjMap(json_map);
    for (const auto& child : json_map) {
      if (child.second.isStr()) {
        prefix_map.emplace(child.first, child.second.getValStr());
      }
    }
  }
  if (prefix_map.empty() || (prefix_map.size() == 0)) {
    throw CfdException(
        kCfdIllegalArgumentError, "Invalid address prefix json data.");
  }
  AddressFormatData result(prefix_map);
  return result;
}

std::vector<AddressFormatData> AddressFormatData::ConvertListFromJson(
    const std::string& json_data) {
  UniValue object;
  object.read(json_data);
  std::vector<AddressFormatData> result;
  if (object.isArray()) {
    for (const auto& element : object.getValues()) {
      if (element.isObject() && element.exists(kNettype)) {
        std::map<std::string, std::string> prefix_map;
        std::map<std::string, UniValue> json_map;
        element.getObjMap(json_map);
        for (const auto& child : json_map) {
          if (child.second.isStr()) {
            prefix_map.emplace(child.first, child.second.getValStr());
          }
        }
        if ((!prefix_map.empty()) && (prefix_map.size() != 0)) {
          result.emplace_back(prefix_map);
        }
      }
    }
  }
  if (result.empty()) {
    throw CfdException(
        kCfdIllegalArgumentError, "Invalid address prefix json data.");
  }
  return result;
}

//! bitcoin address format list
const std::vector<AddressFormatData> kBitcoinAddressFormatList = {
    AddressFormatData(kNettypeMainnet), AddressFormatData(kNettypeTestnet),
    AddressFormatData(kNettypeRegtest)};

std::vector<AddressFormatData> GetBitcoinAddressFormatList() {
  return kBitcoinAddressFormatList;
}

// -----------------------------------------------------------------------------
// Address
// -----------------------------------------------------------------------------
Address::Address()
    : type_(kMainnet),
      addr_type_(kP2shAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  info(CFD_LOG_SOURCE, "call Address()");
}

Address::Address(const Address& object)
    : type_(object.type_),
      addr_type_(object.addr_type_),
      witness_ver_(object.witness_ver_),
      address_(object.address_),
      hash_(object.hash_),
      pubkey_(object.pubkey_),
      schnorr_pubkey_(object.schnorr_pubkey_),
      script_tree_(object.script_tree_),
      redeem_script_(object.redeem_script_) {
  memcpy(checksum_, object.checksum_, sizeof(checksum_));
  format_data_ = object.format_data_;
}

Address& Address::operator=(const Address& object) {
  if (this != &object) {
    type_ = object.type_;
    addr_type_ = object.addr_type_;
    witness_ver_ = object.witness_ver_;
    address_ = object.address_;
    hash_ = object.hash_;
    pubkey_ = object.pubkey_;
    schnorr_pubkey_ = object.schnorr_pubkey_;
    script_tree_ = object.script_tree_;
    redeem_script_ = object.redeem_script_;
    memcpy(checksum_, object.checksum_, sizeof(checksum_));
    format_data_ = object.format_data_;
  }
  return *this;
}

Address::Address(const std::string& address_string)
    : type_(kMainnet),
      addr_type_(kP2shAddress),
      witness_ver_(kVersionNone),
      address_(address_string),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  DecodeAddress(address_string, nullptr);
}

Address::Address(
    const std::string& address_string,
    const std::vector<AddressFormatData>& network_parameters)
    : type_(kMainnet),
      addr_type_(kP2shAddress),
      witness_ver_(kVersionNone),
      address_(address_string),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  const std::vector<AddressFormatData>* params = nullptr;
  if (!network_parameters.empty()) {
    params = &network_parameters;
  }
  DecodeAddress(address_string, params);
}

Address::Address(
    const std::string& address_string,
    const AddressFormatData& network_parameter)
    : type_(kMainnet),
      addr_type_(kP2shAddress),
      witness_ver_(kVersionNone),
      address_(address_string),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  const std::vector<AddressFormatData> params = {network_parameter};
  DecodeAddress(address_string, &params);
}

Address::Address(NetType type, const Pubkey& pubkey)
    : Address(type, pubkey, 0) {
  // do nothing
}

Address::Address(NetType type, const Pubkey& pubkey, uint8_t prefix)
    : type_((prefix != 0) ? kCustomChain : type),
      addr_type_(AddressType::kP2pkhAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2PKH(prefix);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2pkhAddress, prefix);
}

Address::Address(
    NetType type, const Pubkey& pubkey,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(AddressType::kP2pkhAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      schnorr_pubkey_(),
      redeem_script_(),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2PKH(network_parameter.GetP2pkhPrefix());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2pkhAddress, network_parameter.GetP2pkhPrefix());
}

Address::Address(
    NetType type, const Pubkey& pubkey,
    const std::vector<AddressFormatData>& network_parameters)
    : type_(type),
      addr_type_(AddressType::kP2pkhAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      schnorr_pubkey_(),
      redeem_script_(),
      format_data_(GetTargetFormatData(network_parameters, type)) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2PKH(format_data_.GetP2pkhPrefix());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2pkhAddress, format_data_.GetP2pkhPrefix());
}

Address::Address(NetType type, const Script& script)
    : Address(type, script, 0) {
  // do nothing
}

Address::Address(NetType type, const Script& script, uint8_t prefix)
    : type_((prefix != 0) ? kCustomChain : type),
      addr_type_(AddressType::kP2shAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(script) {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2SH(prefix);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2shAddress, prefix);
}

Address::Address(
    NetType type, const Script& script,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(AddressType::kP2shAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(script),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2SH(network_parameter.GetP2shPrefix());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2shAddress, network_parameter.GetP2shPrefix());
}

Address::Address(
    NetType type, const Script& script,
    const std::vector<AddressFormatData>& network_parameters)
    : type_(type),
      addr_type_(AddressType::kP2shAddress),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(script),
      format_data_(GetTargetFormatData(network_parameters, type)) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2SH(format_data_.GetP2shPrefix());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2shAddress, format_data_.GetP2shPrefix());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Pubkey& pubkey)
    : Address(type, witness_ver, pubkey, "") {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
    const std::string& bech32_hrp)
    : type_((!bech32_hrp.empty()) ? kCustomChain : type),
      addr_type_(AddressType::kP2wpkhAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2WPKH(bech32_hrp);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wpkhAddress, bech32_hrp);
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(AddressType::kP2wpkhAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      schnorr_pubkey_(),
      redeem_script_(),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2WPKH(network_parameter.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wpkhAddress, network_parameter.GetBech32Hrp());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Pubkey& pubkey,
    const std::vector<AddressFormatData>& network_parameters)
    : type_(type),
      addr_type_(AddressType::kP2wpkhAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(pubkey),
      schnorr_pubkey_(),
      redeem_script_(),
      format_data_(GetTargetFormatData(network_parameters, type)) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2WPKH(format_data_.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wpkhAddress, format_data_.GetBech32Hrp());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Script& script)
    : Address(type, witness_ver, script, "") {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Script& script,
    const std::string& bech32_hrp)
    : type_((!bech32_hrp.empty()) ? kCustomChain : type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(script) {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateP2WSH(bech32_hrp);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wshAddress, bech32_hrp);
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Script& script,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(script),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2WSH(network_parameter.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wshAddress, network_parameter.GetBech32Hrp());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const Script& script,
    const std::vector<AddressFormatData>& network_parameters)
    : type_(type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(script),
      format_data_(GetTargetFormatData(network_parameters, type)) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateP2WSH(format_data_.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_,
      AddressType::kP2wshAddress, format_data_.GetBech32Hrp());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey)
    : Address(type, witness_ver, pubkey, "") {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey,
    const std::string& bech32_hrp)
    : type_((!bech32_hrp.empty()) ? kCustomChain : type),
      addr_type_(AddressType::kTaprootAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(pubkey),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  CalculateTaproot(bech32_hrp);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_, addr_type_, bech32_hrp);
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(AddressType::kTaprootAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(pubkey),
      redeem_script_(),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateTaproot(network_parameter.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_, addr_type_,
      network_parameter.GetBech32Hrp());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const SchnorrPubkey& pubkey,
    const std::vector<AddressFormatData>& network_parameters)
    : type_(type),
      addr_type_(AddressType::kTaprootAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(pubkey),
      redeem_script_(),
      format_data_(GetTargetFormatData(network_parameters, type)) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  CalculateTaproot(format_data_.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_, addr_type_,
      format_data_.GetBech32Hrp());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
    const SchnorrPubkey& internal_pubkey)
    : Address(type, witness_ver, tree, internal_pubkey, "") {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
    const SchnorrPubkey& internal_pubkey, const std::string& bech32_hrp)
    : type_((!bech32_hrp.empty()) ? kCustomChain : type),
      addr_type_(AddressType::kTaprootAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      script_tree_(tree),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  schnorr_pubkey_ = tree.GetTweakedPubkey(internal_pubkey);
  CalculateTaproot(bech32_hrp);
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_, addr_type_, bech32_hrp);
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
    const SchnorrPubkey& internal_pubkey,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(AddressType::kTaprootAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      script_tree_(tree),
      redeem_script_(),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  schnorr_pubkey_ = tree.GetTweakedPubkey(internal_pubkey);
  CalculateTaproot(network_parameter.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_, addr_type_,
      network_parameter.GetBech32Hrp());
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const TaprootScriptTree& tree,
    const SchnorrPubkey& internal_pubkey,
    const std::vector<AddressFormatData>& network_parameters)
    : type_(type),
      addr_type_(AddressType::kTaprootAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(),
      pubkey_(),
      schnorr_pubkey_(),
      script_tree_(tree),
      redeem_script_(),
      format_data_(GetTargetFormatData(network_parameters, type)) {
  memset(checksum_, 0, sizeof(checksum_));
  SetNetType(format_data_);
  schnorr_pubkey_ = tree.GetTweakedPubkey(internal_pubkey);
  CalculateTaproot(format_data_.GetBech32Hrp());
  info(
      CFD_LOG_SOURCE, "call Address({},{},{})", type_, addr_type_,
      format_data_.GetBech32Hrp());
}

Address::Address(NetType type, AddressType addr_type, const ByteData160& hash)
    : type_(type),
      addr_type_(addr_type),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(hash.GetBytes()),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));
  if (addr_type == kP2pkhAddress) {
    CalculateP2PKH(hash);
  } else if (
      (addr_type == kP2shAddress) || (addr_type == kP2shP2wshAddress) ||
      (addr_type == kP2shP2wpkhAddress)) {
    CalculateP2SH(hash);
  } else {
    throw CfdException(
        kCfdIllegalArgumentError, "Support addressType is p2pkh or p2sh");
  }
}

Address::Address(
    NetType type, AddressType addr_type, const ByteData160& hash,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(addr_type),
      witness_ver_(kVersionNone),
      address_(""),
      hash_(hash.GetBytes()),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));
  if (addr_type == kP2pkhAddress) {
    CalculateP2PKH(hash, network_parameter.GetP2pkhPrefix());
  } else if (
      (addr_type == kP2shAddress) || (addr_type == kP2shP2wshAddress) ||
      (addr_type == kP2shP2wpkhAddress)) {
    CalculateP2SH(hash, network_parameter.GetP2shPrefix());
  } else {
    throw CfdException(
        kCfdIllegalArgumentError, "Support addressType is p2pkh or p2sh");
  }
}

Address::Address(
    NetType type, AddressType addr_type, const ByteData160& hash,
    const std::vector<AddressFormatData>& network_parameters)
    : Address(
          type, addr_type, hash,
          GetTargetFormatData(network_parameters, type)) {
  // do nothing
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const ByteData& hash)
    : type_(type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(hash),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_() {
  memset(checksum_, 0, sizeof(checksum_));

  if (witness_ver_ == WitnessVersion::kVersion0) {
    if (hash.GetDataSize() == kByteData160Length) {
      SetAddressType(kP2wpkhAddress);
      CalculateP2WPKH(ByteData160(hash.GetBytes()));
    } else if (hash.GetDataSize() == kByteData256Length) {
      SetAddressType(kP2wshAddress);
      CalculateP2WSH(ByteData256(hash.GetBytes()));
    } else {
      // format error
      info(CFD_LOG_SOURCE, "illegal hash data. hash={}", hash.GetHex());
      throw CfdException(kCfdIllegalArgumentError, "hash value error.");
    }
  } else if (witness_ver_ != WitnessVersion::kVersionNone) {
    if ((witness_ver_ == WitnessVersion::kVersion1) &&
        (hash.GetDataSize() == SchnorrPubkey::kSchnorrPubkeySize)) {
      SetAddressType(kTaprootAddress);
      schnorr_pubkey_ = SchnorrPubkey(hash);
    } else {
      SetAddressType(kWitnessUnknown);
    }
    CalculateBech32m(hash);
  }
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const ByteData& hash,
    const AddressFormatData& network_parameter)
    : type_(type),
      addr_type_(AddressType::kP2wshAddress),
      witness_ver_(witness_ver),
      address_(""),
      hash_(hash),
      pubkey_(),
      schnorr_pubkey_(),
      redeem_script_(),
      format_data_(network_parameter) {
  memset(checksum_, 0, sizeof(checksum_));

  if (witness_ver_ == WitnessVersion::kVersion0) {
    if (hash.GetDataSize() == kByteData160Length) {
      SetAddressType(kP2wpkhAddress);
      SetNetType(format_data_);
      CalculateP2WPKH(
          ByteData160(hash.GetBytes()), network_parameter.GetBech32Hrp());
    } else if (hash.GetDataSize() == kByteData256Length) {
      SetAddressType(kP2wshAddress);
      SetNetType(format_data_);
      CalculateP2WSH(
          ByteData256(hash.GetBytes()), network_parameter.GetBech32Hrp());
    } else {
      // format error
      info(CFD_LOG_SOURCE, "illegal hash data. hash={}", hash.GetHex());
      throw CfdException(kCfdIllegalArgumentError, "hash value error.");
    }
  } else if (witness_ver_ != WitnessVersion::kVersionNone) {
    if ((witness_ver_ == WitnessVersion::kVersion1) &&
        (hash.GetDataSize() == SchnorrPubkey::kSchnorrPubkeySize)) {
      SetAddressType(kTaprootAddress);
      schnorr_pubkey_ = SchnorrPubkey(hash);
    } else {
      SetAddressType(kWitnessUnknown);
    }
    SetNetType(format_data_);
    CalculateBech32m(hash, network_parameter.GetBech32Hrp());
  }
}

Address::Address(
    NetType type, WitnessVersion witness_ver, const ByteData& hash,
    const std::vector<AddressFormatData>& network_parameters)
    : Address(
          type, witness_ver, hash,
          GetTargetFormatData(network_parameters, type)) {
  // do nothing
}

std::string Address::GetAddress() const { return address_; }

void Address::CalculateP2SH(uint8_t prefix) {
  // create script hash.
  ByteData160 script_hash = HashUtil::Hash160(redeem_script_.GetData());
  CalculateP2SH(script_hash, prefix);
  hash_ = ByteData(script_hash.GetBytes());
}

void Address::CalculateP2SH(const ByteData160& hash_data, uint8_t prefix) {
  std::vector<uint8_t> address_data = hash_data.GetBytes();

  // Add first to the list the Address Prefix
  uint8_t addr_prefix = prefix;
  if ((addr_prefix == 0) && (kMainnet <= type_) && (type_ <= kRegtest)) {
    addr_prefix = kBitcoinAddressFormatList[type_].GetP2shPrefix();
    format_data_ = kBitcoinAddressFormatList[type_];
    SetNetType(format_data_);
  }
  address_data.insert(address_data.begin(), addr_prefix);

  char* output = NULL;
  uint32_t flags = BASE58_FLAG_CHECKSUM;
  int ret = wally_base58_from_bytes(
      address_data.data(), address_data.size(), flags, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(address_data));
    if (ret == WALLY_EINVAL) {
      throw CfdException(kCfdIllegalArgumentError, "Base58 encode error.");
    } else {
      throw CfdException(kCfdInternalError, "Base58 encode error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::CalculateP2PKH(uint8_t prefix) {
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey_.GetData());
  CalculateP2PKH(pubkey_hash, prefix);
  hash_ = ByteData(pubkey_hash.GetBytes());
}

void Address::CalculateP2PKH(const ByteData160& hash_data, uint8_t prefix) {
  std::vector<uint8_t> pubkey_hash = hash_data.GetBytes();

  // On the 0 byte, prefix is P2PKH
  // - If arbitrary prefix is 0, invalid (p2pkh mainnet reserved value)
  // - If arbtriary prefix is invalid and type value is valid,
  // 　refer bitcoin definition
  uint8_t addr_prefix = prefix;
  if ((addr_prefix == 0) && (kMainnet <= type_) && (type_ <= kRegtest)) {
    addr_prefix = kBitcoinAddressFormatList[type_].GetP2pkhPrefix();
    format_data_ = kBitcoinAddressFormatList[type_];
    SetNetType(format_data_);
  }
  pubkey_hash.insert(pubkey_hash.begin(), addr_prefix);

  // Base58check
  char* output = NULL;
  uint32_t flags = BASE58_FLAG_CHECKSUM;
  int ret = wally_base58_from_bytes(
      pubkey_hash.data(), pubkey_hash.size(), flags, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(pubkey_hash));
    if (ret == WALLY_EINVAL) {
      throw CfdException(kCfdIllegalArgumentError, "Base58 encode error.");
    } else {
      throw CfdException(kCfdInternalError, "Base58 encode error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::CalculateP2WSH(const std::string& bech32_hrp) {
  ByteData256 script_hash = HashUtil::Sha256(redeem_script_.GetData());
  CalculateP2WSH(script_hash, bech32_hrp);
  hash_ = ByteData(script_hash.GetBytes());
}

void Address::CalculateP2WSH(
    const ByteData256& hash_data, const std::string& bech32_hrp) {
  const std::vector<uint8_t>& script_hash_byte = hash_data.GetBytes();
  std::vector<uint8_t> segwit_data;

  // 0byte目にwitness_version, 1byte目にhashサイズ
  segwit_data.push_back(witness_ver_);
  segwit_data.push_back(static_cast<uint8_t>(script_hash_byte.size()));
  std::copy(
      script_hash_byte.begin(), script_hash_byte.end(),
      std::back_inserter(segwit_data));

  std::string human_code = bech32_hrp;
  if (human_code.empty() && (kMainnet <= type_) && (type_ <= kRegtest)) {
    human_code = kBitcoinAddressFormatList[type_].GetBech32Hrp();
    format_data_ = kBitcoinAddressFormatList[type_];
    SetNetType(format_data_);
  }
  char* output = NULL;
  // segwit
  int ret = wally_addr_segwit_from_bytes(
      segwit_data.data(), segwit_data.size(), human_code.data(), 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_addr_segwit_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(segwit_data));
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError, "Segwit-address create error.");
    } else {
      throw CfdException(kCfdInternalError, "Segwit-address create error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::CalculateP2WPKH(const std::string& bech32_hrp) {
  ByteData160 hash160 = HashUtil::Hash160(pubkey_.GetData());
  CalculateP2WPKH(hash160, bech32_hrp);
  hash_ = ByteData(hash160.GetBytes());
}

void Address::CalculateP2WPKH(
    const ByteData160& hash_data, const std::string& bech32_hrp) {
  // witness_version for 0 byte, hash size for 1 byte
  std::vector<uint8_t> pubkey_hash = hash_data.GetBytes();
  pubkey_hash.insert(pubkey_hash.begin(), HASH160_LEN);
  pubkey_hash.insert(pubkey_hash.begin(), witness_ver_);

  std::string human_code = bech32_hrp;
  if (human_code.empty() && (kMainnet <= type_) && (type_ <= kRegtest)) {
    human_code = kBitcoinAddressFormatList[type_].GetBech32Hrp();
    format_data_ = kBitcoinAddressFormatList[type_];
    SetNetType(format_data_);
  }
  char* output = NULL;
  // segwit
  int ret = wally_addr_segwit_from_bytes(
      pubkey_hash.data(), pubkey_hash.size(), human_code.data(), 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_addr_segwit_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(pubkey_hash));
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError, "Segwit-address create error.");
    } else {
      throw CfdException(kCfdInternalError, "Segwit-address create error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::CalculateTaproot(const std::string& bech32_hrp) {
  hash_ = schnorr_pubkey_.GetData();
  CalculateBech32m(hash_, bech32_hrp);
}

void Address::CalculateBech32m(
    const ByteData& hash_data, const std::string& bech32_hrp) {
  std::vector<uint8_t> pubkey_hash = hash_data.GetBytes();
  pubkey_hash.insert(
      pubkey_hash.begin(), static_cast<uint8_t>(kByteData256Length));
  uint8_t op_code = static_cast<uint8_t>(witness_ver_);
  op_code += static_cast<uint8_t>(kOp_1) - 1;
  pubkey_hash.insert(pubkey_hash.begin(), op_code);

  std::string human_code = bech32_hrp;
  if (human_code.empty() && (kMainnet <= type_) && (type_ <= kRegtest)) {
    human_code = kBitcoinAddressFormatList[type_].GetBech32Hrp();
    format_data_ = kBitcoinAddressFormatList[type_];
    SetNetType(format_data_);
  }
  char* output = NULL;
  int ret = wally_addr_segwit_from_bytes(
      pubkey_hash.data(), pubkey_hash.size(), human_code.data(), 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_addr_segwit_from_bytes error. ret={}.", ret);
    info(
        CFD_LOG_SOURCE, "input hash={}",
        StringUtil::ByteToString(pubkey_hash));
    if (ret == WALLY_EINVAL) {
      throw CfdException(
          kCfdIllegalArgumentError, "Segwit-address create error.");
    } else {
      throw CfdException(kCfdInternalError, "Segwit-address create error.");
    }
  }

  address_ = WallyUtil::ConvertStringAndFree(output);
}

void Address::DecodeAddress(
    std::string address_string,
    const std::vector<AddressFormatData>* network_parameters) {
  static const std::string kBech32Separator = "1";
  static const auto StartsWith = [](const std::string& message,
                                    const std::string& bech32_hrp) -> bool {
    return (message.find(bech32_hrp + kBech32Separator) == 0);
  };

  std::string bs58 = address_string;
  std::string segwit_prefix = "";
  int ret = -1;

  if (network_parameters != nullptr) {
    for (const AddressFormatData& param : *network_parameters) {
      // Custom parameter
      if ((!param.GetBech32Hrp().empty()) &&
          (param.GetBech32Hrp().length() < bs58.length()) &&
          (StartsWith(bs58, param.GetBech32Hrp()))) {
        segwit_prefix = param.GetBech32Hrp();
        format_data_ = param;
        break;
      }
    }
  } else {
    for (const auto& param : kBitcoinAddressFormatList) {
      if (StartsWith(bs58, param.GetBech32Hrp())) {
        segwit_prefix = param.GetBech32Hrp();
        format_data_ = param;
        break;
      }
    }
  }

  std::vector<uint8_t> data_part(128);
  size_t written = 0;

  if (!segwit_prefix.empty()) {
    // Bech32 Address
    ret = wally_addr_segwit_to_bytes(
        bs58.data(), segwit_prefix.data(), 0, data_part.data(),
        data_part.size(), &written);

    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_addr_segwit_to_bytes error. ret={}.", ret);
      if (ret == WALLY_EINVAL) {
        throw CfdException(
            kCfdIllegalArgumentError, "Segwit-address decode error.");
      } else {
        throw CfdException(kCfdInternalError, "Segwit-address decode error.");
      }
    }

    data_part.resize(written);
    Script script(ByteData(data_part.data(), static_cast<uint32_t>(written)));
    if (!script.IsWitnessProgram()) {
      throw CfdException(kCfdInternalError, "address decode check error.");
    }
    witness_ver_ = script.GetWitnessVersion();

    if (witness_ver_ == kVersion1) {
      if (written != (SchnorrPubkey::kSchnorrPubkeySize + 2)) {
        throw CfdException(
            kCfdInternalError, "segwit v1 address decode check error.");
      }
      SetAddressType(kTaprootAddress);
    } else if (witness_ver_ == kVersion0) {
      if (written == kScriptHashP2wpkhLength) {
        SetAddressType(kP2wpkhAddress);
      } else if (written == kScriptHashP2wshLength) {
        SetAddressType(kP2wshAddress);
      }
    }

    // Delete 0byte:WitnessVersion and 1byte:data_part
    data_part.erase(data_part.begin(), data_part.begin() + 2);

  } else {
    ret = wally_base58_to_bytes(
        bs58.data(), BASE58_FLAG_CHECKSUM, data_part.data(), data_part.size(),
        &written);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_base58_to_bytes error. ret={}.", ret);
      if (ret == WALLY_EINVAL) {
        throw CfdException(kCfdIllegalArgumentError, "Base58 decode error.");
      } else {
        throw CfdException(kCfdInternalError, "Base58 decode error.");
      }
    }

    data_part.resize(written);

    bool find_address_type = false;
    if (network_parameters != nullptr) {
      for (const AddressFormatData& param : *network_parameters) {
        if (data_part[0] == param.GetP2shPrefix()) {
          SetAddressType(kP2shAddress);
          find_address_type = true;
          format_data_ = param;
          break;
        } else if (data_part[0] == param.GetP2pkhPrefix()) {
          SetAddressType(kP2pkhAddress);
          find_address_type = true;
          format_data_ = param;
          break;
        }
      }
    } else {
      for (const auto& param : kBitcoinAddressFormatList) {
        if (data_part[0] == param.GetP2shPrefix()) {
          SetAddressType(kP2shAddress);
          find_address_type = true;
          format_data_ = param;
          break;
        } else if (data_part[0] == param.GetP2pkhPrefix()) {
          SetAddressType(kP2pkhAddress);
          find_address_type = true;
          format_data_ = param;
          break;
        }
      }
    }
    if (!find_address_type) {
      warn(CFD_LOG_SOURCE, "Unknown address prefix.");
      throw CfdException(kCfdIllegalArgumentError, "Unknown address prefix.");
    }
    witness_ver_ = kVersionNone;

    // Delete 0byte:prefix.
    data_part.erase(data_part.begin());
  }

  // Setting for Hash.
  hash_ = ByteData(data_part);
  if (witness_ver_ == kVersion1) schnorr_pubkey_ = SchnorrPubkey(hash_);
  SetNetType(format_data_);
  info(
      CFD_LOG_SOURCE, "DecodeAddress nettype={},{}", format_data_.GetNetType(),
      format_data_.GetString(kNettype));
}

void Address::SetNetType(const AddressFormatData& format_data) {
  type_ = format_data.GetNetType();
}

void Address::SetAddressType(AddressType addr_type) {
  if ((addr_type_ == kP2shP2wshAddress) ||
      (addr_type_ == kP2shP2wpkhAddress)) {
    if (addr_type != kP2shAddress) {
      addr_type_ = addr_type;
    }
  } else {
    addr_type_ = addr_type;
  }
}

AddressFormatData Address::GetTargetFormatData(
    const std::vector<AddressFormatData>& network_parameters, NetType type) {
  if (type == NetType::kCustomChain) {
    throw CfdException(
        kCfdIllegalArgumentError,
        "CustomChain is not supported for address format list.");
  }
  for (const auto& param : network_parameters) {
    if (type == param.GetNetType()) {
      return param;
    }
  }
  throw CfdException(
      kCfdIllegalArgumentError, "target address format unknown error.");
}

Script Address::GetLockingScript() const {
  Script locking_script;
  switch (addr_type_) {
    case AddressType::kTaprootAddress:
      locking_script =
          ScriptUtil::CreateTaprootLockingScript(ByteData256(hash_));
      break;
    case AddressType::kP2pkhAddress: {
      ByteData160 pubkey_hash(hash_.GetBytes());
      locking_script = ScriptUtil::CreateP2pkhLockingScript(pubkey_hash);
      break;
    }
    case AddressType::kP2shP2wpkhAddress:
      // fall-through
    case AddressType::kP2shP2wshAddress:
      // fall-through
    case AddressType::kP2shAddress: {
      ByteData160 script_hash(hash_.GetBytes());
      locking_script = ScriptUtil::CreateP2shLockingScript(script_hash);
      break;
    }
    case AddressType::kP2wpkhAddress: {
      ByteData160 pubkey_hash(hash_.GetBytes());
      locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey_hash);
      break;
    }
    case AddressType::kP2wshAddress: {
      ByteData256 script_hash(hash_.GetBytes());
      locking_script = ScriptUtil::CreateP2wshLockingScript(script_hash);
      break;
    }
    default:
      break;
  }
  return locking_script;
}

}  // namespace core
}  // namespace cfd
