// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_coin.h
 *
 * @brief Coin (UTXO) related class definition.
 */

#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COIN_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COIN_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

/**
 * @brief transaction id class.
 */
class CFD_CORE_EXPORT Txid {
 public:
  /**
   * @brief default constructor
   */
  Txid();
  /**
   * @brief constructor
   * @param[in] hex     hex string
   */
  explicit Txid(const std::string& hex);
  /**
   * @brief constructor
   * @param[in] data    ByteData256 instance
   */
  explicit Txid(const ByteData256& data);
  /**
   * @brief destructor.
   */
  virtual ~Txid() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  Txid(const Txid& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  Txid& operator=(const Txid& object);
  /**
   * @brief Get a hex string.
   * @return hex string
   */
  const std::string GetHex() const;
  /**
   * @brief Get a ByteData object.
   * @return ByteData object.
   */
  const ByteData GetData() const;
  /**
   * @brief compare Txid.
   * @param txid  compare target.
   * @retval true   equals.
   * @retval false  not equals.
   */
  bool Equals(const Txid& txid) const;
  /**
   * @brief check valid data.
   * @retval true   valid.
   * @retval false  invalid.
   */
  bool IsValid() const;

 private:
  ByteData data_;  ///< byte data
};

/**
 * @brief block hash class.
 */
class CFD_CORE_EXPORT BlockHash {
 public:
  /**
   * @brief default constructor
   */
  BlockHash() {
    // do nothing
  }
  /**
   * @brief constructor
   * @param[in] hex     hex string
   */
  explicit BlockHash(const std::string& hex);
  /**
   * @brief constructor
   * @param[in] data    ByteData256 object.
   */
  explicit BlockHash(const ByteData256& data);
  /**
   * @brief destructor.
   */
  virtual ~BlockHash() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  BlockHash(const BlockHash& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  BlockHash& operator=(const BlockHash& object);
  /**
   * @brief Get a hex string.
   * @return hex string
   */
  const std::string GetHex() const;
  /**
   * @brief Get a ByteData object.
   * @return ByteData object.
   */
  const ByteData GetData() const;
  /**
   * @brief check valid data.
   * @retval true   valid.
   * @retval false  invalid.
   */
  bool IsValid() const;

 private:
  ByteData data_;  ///< byte data
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COIN_H_
