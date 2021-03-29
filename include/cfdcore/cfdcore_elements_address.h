// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_address.h
 *
 * @brief The address class definition file used in Elements (liquid network).
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
 * @brief Type definition of ConfidentialKey (= Pubkey)
 * @see Pubkey
 */
using ConfidentialKey = Pubkey;

/**
 * @typedef ElementsNetType
 * @brief Elements Network definition
 */
using ElementsNetType = NetType;

/**
 * @typedef ElementsAddressType
 * @brief Definition of Address type of Elements
 */
using ElementsAddressType = AddressType;

/**
 * @brief Get the default address format list for Elements.
 * @return default address format list for Elements.
 */
CFD_CORE_API std::vector<AddressFormatData> GetElementsAddressFormatList();

/**
 * @class ElementsConfidentialAddress
 * @brief A class that represents the Confidential address of Elements
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
   * @brief default constructor.
   */
  ElementsConfidentialAddress();

  /**
   * @brief constructor. (Generate Confidential Address from Unblinded Address)
   * @param unblinded_address UnblindedAddress instance
   * @param confidential_key  ConfidentialKey instance
   */
  explicit ElementsConfidentialAddress(
      const Address& unblinded_address,
      const ConfidentialKey& confidential_key);

  /**
   * @brief constructor. (Decoding from the ConfidentialAddress string)
   * @param[in] confidential_address confidential address string.
   */
  explicit ElementsConfidentialAddress(
      const std::string& confidential_address);

  /**
   * @brief constructor. (Decoding from the ConfidentialAddress string)
   * @param[in] confidential_address confidential address string.
   * @param[in] prefix_list  address prefix list
   */
  explicit ElementsConfidentialAddress(
      const std::string& confidential_address,
      const std::vector<AddressFormatData>& prefix_list);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  ElementsConfidentialAddress(const ElementsConfidentialAddress& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  ElementsConfidentialAddress& operator=(
      const ElementsConfidentialAddress& object) &;

  /**
   * @brief Get UnblindedAddress
   * @return UnblindedAddress instance associated with ConfidentialAddress
   */
  Address GetUnblindedAddress() const;

  /**
   * @brief Get Confidential Key
   * @return Confidential Key instance associated with Confidential Address
   */
  ConfidentialKey GetConfidentialKey() const;

  /**
   * @brief Get the address string.
   * @return address string.
   */
  std::string GetAddress() const;

  /**
   * @brief Get the ElementsNetType of Address.
   * @return ElementsNetType
   */
  ElementsNetType GetNetType() const;

  /**
   * @brief Get the Address type.
   * @return Address type.
   */
  ElementsAddressType GetAddressType() const;

  /**
   * @brief Get the address Hash.
   * @return address Hash.
   */
  ByteData GetHash() const;

  /**
   * @brief Get LockingScript
   * @return locking script
   */
  Script GetLockingScript() const;

  /**
   * @brief Determines if the specified address is a Blinded address
   * @param address     address string
   * @retval true   has blind address
   * @retval false  not blind address
   */
  static bool IsConfidentialAddress(const std::string& address);

  /**
   * @brief Determines if the specified address is a Blinded address
   * @param[in] address     address string
   * @param[in] prefix_list     address prefix list
   * @retval true   has blind address
   * @retval false  not blind address
   */
  static bool IsConfidentialAddress(
      const std::string& address,
      const std::vector<AddressFormatData>& prefix_list);

 private:
  /**
   * @brief Decode the model from the confidential address string
   * @param[in] confidential_address  confidential address string
   * @param[in] prefix_list           address prefix list
   */
  void DecodeAddress(
      const std::string& confidential_address,
      const std::vector<AddressFormatData>& prefix_list);

  /**
   * @brief Calculate the confidential_address from the unblinded_address and confidential_key.
   * @details For the network type of Elements, the calculation is performed \
   *   on the same type of network as connected_address.
   * @param unblinded_address UnblindedAddress
   * @param confidential_key Confidential Key instance used for Blind
   */
  void CalculateAddress(
      const Address& unblinded_address,
      const ConfidentialKey& confidential_key);

  /// Unblinded Address
  Address unblinded_address_;

  /// Confidential Key
  ConfidentialKey confidential_key_;

  /// address string
  std::string address_;
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_ADDRESS_H_
