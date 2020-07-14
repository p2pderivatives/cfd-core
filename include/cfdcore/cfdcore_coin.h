// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_coin.h
 *
 * @brief Coin(UTXO)関連クラス定義
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
 * @brief transaction idクラス
 */
class CFD_CORE_EXPORT Txid {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  Txid();
  /**
   * @brief コンストラクタ
   * @param[in] hex     Hex文字列
   */
  explicit Txid(const std::string& hex);
  /**
   * @brief コンストラクタ
   * @param[in] data    ByteData256インスタンス
   */
  explicit Txid(const ByteData256& data);
  /**
   * @brief デストラクタ
   */
  virtual ~Txid() {
    // do nothing
  }
  /**
   * @brief Hex文字列を取得する.
   * @return Hex文字列
   */
  const std::string GetHex() const;
  /**
   * @brief ByteDataを取得する.
   * @return ByteDataオブジェクト
   */
  const ByteData GetData() const;
  /**
   * @brief Txid比較
   * @param txid 比較対象のオブジェクト
   * @return true:一致/false:不一致
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
 * @brief block hashクラス
 */
class CFD_CORE_EXPORT BlockHash {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  BlockHash() {
    // do nothing
  }
  /**
   * @brief コンストラクタ
   * @param[in] hex     Hex文字列
   */
  explicit BlockHash(const std::string& hex);
  /**
   * @brief コンストラクタ
   * @param[in] data    ByteData256インスタンス
   */
  explicit BlockHash(const ByteData256& data);
  /**
   * @brief デストラクタ
   */
  virtual ~BlockHash() {
    // do nothing
  }
  /**
   * @brief Hex文字列を取得する.
   * @return Hex文字列
   */
  const std::string GetHex() const;
  /**
   * @brief ByteDataを取得する.
   * @return ByteDataオブジェクト
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
