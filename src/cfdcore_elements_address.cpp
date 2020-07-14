// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_address.cpp
 *
 * @brief \~japanese Elements対応したAddressクラス定義
 *   \~english definition of address class that handles Elements
 */
#ifndef CFD_DISABLE_ELEMENTS

#include "cfdcore/cfdcore_elements_address.h"

#include <algorithm>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::trace;
using logger::warn;

// -----------------------------------------------------------------------------
// global / internal
// -----------------------------------------------------------------------------
/**
 * @brief \~japanese blind addressのキーペア一覧を定義するための構造体.
 *   \~english Structure to define a list of key pairs for blind address.
 */
struct ElementsBlindAddressFormat {
  std::string prefix_key;          //!< prefix key
  std::string blinded_prefix_key;  //!< blinded prefix key
  bool is_segwit;                  //!< segwit有無
};

/**
 * \~english
 * @brief get Blind address key pair list.
 * @return Blind address key pair list.
 * \~japanese
 * @brief Blind addressのキーペア一覧を取得する.
 * @return Blind addressのキーペア一覧.
 */
static std::vector<ElementsBlindAddressFormat> GetBlindKeyPair() {
  std::vector<ElementsBlindAddressFormat> result = {
      {kPrefixP2pkh, kPrefixBlindP2pkh, false},
      {kPrefixP2sh, kPrefixBlindP2sh, false},
      {kPrefixBech32Hrp, kPrefixBlindBech32Hrp, true},
  };
  return result;
}

std::vector<AddressFormatData> GetElementsAddressFormatList() {
  std::vector<AddressFormatData> result = {
      AddressFormatData(kNettypeLiquidV1),
      AddressFormatData(kNettypeElementsRegtest)};
  return result;
}

// -----------------------------------------------------------------------------
// ElementsConfidentialAddress
// -----------------------------------------------------------------------------
Privkey ElementsConfidentialAddress::GetBlindingKey(
    const Privkey& master_blinding_key, const Script& locking_script) {
  ByteData256 data = CryptoUtil::HmacSha256(
      master_blinding_key.GetData(), locking_script.GetData());
  return Privkey(data);
}

ElementsConfidentialAddress::ElementsConfidentialAddress()
    : unblinded_address_(), confidential_key_(), address_() {
  // do nothing
}

ElementsConfidentialAddress::ElementsConfidentialAddress(
    const Address& unblinded_address, const ConfidentialKey& confidential_key)
    : unblinded_address_(unblinded_address),
      confidential_key_(confidential_key),
      address_() {
  CalculateAddress(unblinded_address_, confidential_key_);
}

ElementsConfidentialAddress::ElementsConfidentialAddress(
    const std::string& confidential_address)
    : unblinded_address_(),
      confidential_key_(),
      address_(confidential_address) {
  DecodeAddress(confidential_address, GetElementsAddressFormatList());
}

ElementsConfidentialAddress::ElementsConfidentialAddress(
    const std::string& confidential_address,
    const std::vector<AddressFormatData>& prefix_list)
    : unblinded_address_(),
      confidential_key_(),
      address_(confidential_address) {
  DecodeAddress(confidential_address, prefix_list);
}

void ElementsConfidentialAddress::DecodeAddress(
    const std::string& confidential_address,
    const std::vector<AddressFormatData>& prefix_list) {
  std::vector<uint8_t> pubkey_data(Pubkey::kCompressedPubkeySize);
  std::string address;
  char* output = nullptr;

  if (confidential_address.empty()) {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. confidential address empty."
        " : address={}.",
        confidential_address);
    throw CfdException(
        kCfdIllegalArgumentError, "DecodeAddress confidential address empty.");
  }

  int ret = -1;
  uint32_t prefix = 0;
  std::string hrp;
  bool is_find_blinded_prefix = false;
  for (const auto& data : prefix_list) {
    for (const auto& format : GetBlindKeyPair()) {
      try {
        output = nullptr;

        // Get confidential_key
        if (format.is_segwit) {
          hrp = data.GetString(format.blinded_prefix_key);
          is_find_blinded_prefix = true;
          ret = wally_confidential_addr_segwit_to_ec_public_key(
              confidential_address.c_str(), hrp.c_str(), pubkey_data.data(),
              pubkey_data.size());
          if (ret != WALLY_OK) {
            trace(CFD_LOG_SOURCE, "fail libwally. ret={} prefix={}", ret, hrp);
            trace(
                CFD_LOG_SOURCE, "confidential_address={}",
                confidential_address);
          }
        } else {
          prefix = data.GetValue(format.blinded_prefix_key);
          is_find_blinded_prefix = true;
          ret = wally_confidential_addr_to_ec_public_key(
              confidential_address.c_str(), prefix, pubkey_data.data(),
              pubkey_data.size());
          if (ret != WALLY_OK) {
            trace(
                CFD_LOG_SOURCE, "fail libwally. ret={} prefix={}", ret,
                prefix);
            trace(
                CFD_LOG_SOURCE, "confidential_address={}",
                confidential_address);
          }
        }

        if (ret != WALLY_OK) {
          // do nothing
        } else if (format.is_segwit) {
          ret = wally_confidential_addr_to_addr_segwit(
              confidential_address.c_str(), hrp.c_str(),
              data.GetString(format.prefix_key).c_str(), &output);
          if (ret != WALLY_OK) {
            trace(
                CFD_LOG_SOURCE, "fail libwally. ret={} prefix={}", ret,
                data.GetString(format.prefix_key).c_str());
          }
        } else {
          ret = wally_confidential_addr_to_addr(
              confidential_address.c_str(), prefix, &output);
          if (ret != WALLY_OK) {
            trace(
                CFD_LOG_SOURCE, "fail libwally. ret={} prefix={}", ret,
                prefix);
          }
        }

        if (ret == WALLY_OK) {
          address = WallyUtil::ConvertStringAndFree(output);
          unblinded_address_ = Address(address, data);
          confidential_key_ = ConfidentialKey(ByteData(pubkey_data));
          address_ = confidential_address;
          return;
        }
      } catch (const CfdException& except) {
        // Ignore
        trace(
            CFD_LOG_SOURCE, "DecodeAddress exception={}",
            std::string(except.what()));
      }
    }
  }

  if (is_find_blinded_prefix) {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. ConfidentialAddress prefix not found."
        " : address={}.",
        confidential_address);
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress confidential address prefix not found.");
  } else {
    warn(
        CFD_LOG_SOURCE,
        "DecodeAddress error. ConfidentialAddress prefix not registed."
        " : address={}.",
        confidential_address);
    throw CfdException(
        kCfdIllegalArgumentError,
        "DecodeAddress confidential address prefix not registed.");
  }
}

void ElementsConfidentialAddress::CalculateAddress(
    const Address& unblinded_address,
    const ConfidentialKey& confidential_key) {
  if (!confidential_key.IsValid()) {
    warn(
        CFD_LOG_SOURCE,
        "CalculateAddress error. Confidential key is invalid."
        " : confidential_key={}, size={}.",
        confidential_key.GetHex(), confidential_key.GetData().GetDataSize());
    throw CfdException(
        kCfdIllegalArgumentError,
        "CalculateAddress error. Confidential key is invalid.");
  }
  // 33bytes: ConfidentialKey
  if (!confidential_key.IsCompress()) {
    warn(
        CFD_LOG_SOURCE,
        "CalculateAddress error. Confidential key is not compressed."
        " : confidential_key={}, size={}.",
        confidential_key.GetHex(), confidential_key.GetData().GetDataSize());
    throw CfdException(
        kCfdIllegalArgumentError,
        "CalculateAddress error. Confidential key is not compressed.");
  }

  const std::vector<uint8_t>& pubkey_data =
      confidential_key.GetData().GetBytes();
  char* output = nullptr;

  int ret = -1;
  uint32_t prefix;
  std::string hrp;
  AddressFormatData data = unblinded_address.GetAddressFormatData();
  std::string address = unblinded_address.GetAddress();
  for (const auto& format : GetBlindKeyPair()) {
    try {
      output = nullptr;

      // Get confidential_key
      if (format.is_segwit) {
        hrp = data.GetString(format.blinded_prefix_key);
        ret = wally_confidential_addr_from_addr_segwit(
            address.c_str(), data.GetString(format.prefix_key).c_str(),
            hrp.c_str(), pubkey_data.data(), pubkey_data.size(), &output);
        if (ret != WALLY_OK) {
          trace(CFD_LOG_SOURCE, "fail libwally. ret={}", ret);
        }
      } else {
        prefix = data.GetValue(format.blinded_prefix_key);
        ret = wally_confidential_addr_from_addr(
            address.c_str(), prefix, pubkey_data.data(), pubkey_data.size(),
            &output);
        if (ret != WALLY_OK) {
          trace(CFD_LOG_SOURCE, "fail libwally. ret={}", ret);
        }
      }

      if (ret == WALLY_OK) {
        address_ = WallyUtil::ConvertStringAndFree(output);
        confidential_key_ = confidential_key;
        unblinded_address_ = unblinded_address;
        return;
      }
    } catch (const CfdException& except) {
      // Ignore
      trace(
          CFD_LOG_SOURCE, "CalculateAddress exception={}",
          std::string(except.what()));
    }
  }

  warn(
      CFD_LOG_SOURCE,
      "CalculateAddress error. Address prefix not found."
      " : address={}.",
      address);
  throw CfdException(
      kCfdIllegalArgumentError, "CalculateAddress address prefix not found.");
}

bool ElementsConfidentialAddress::IsConfidentialAddress(
    const std::string& address) {
  return ElementsConfidentialAddress::IsConfidentialAddress(
      address, GetElementsAddressFormatList());
}

bool ElementsConfidentialAddress::IsConfidentialAddress(
    const std::string& address,
    const std::vector<AddressFormatData>& prefix_list) {
  bool is_valid = false;

  try {
    ElementsConfidentialAddress addr(address, prefix_list);
    info(CFD_LOG_SOURCE, "ConfidentialAddress={}", addr.GetAddress());
    is_valid = true;
  } catch (...) {
    // Ignore
    warn(CFD_LOG_SOURCE, "IsConfidentialAddress error. address={}.", address);
  }
  return is_valid;
}

Address ElementsConfidentialAddress::GetUnblindedAddress() const {
  return unblinded_address_;
}

ConfidentialKey ElementsConfidentialAddress::GetConfidentialKey() const {
  return confidential_key_;
}

std::string ElementsConfidentialAddress::GetAddress() const {
  return address_;
}

ElementsNetType ElementsConfidentialAddress::GetNetType() const {
  return unblinded_address_.GetNetType();
}

ElementsAddressType ElementsConfidentialAddress::GetAddressType() const {
  return unblinded_address_.GetAddressType();
}

ByteData ElementsConfidentialAddress::GetHash() const {
  return unblinded_address_.GetHash();
}

Script ElementsConfidentialAddress::GetLockingScript() const {
  return unblinded_address_.GetLockingScript();
}

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
