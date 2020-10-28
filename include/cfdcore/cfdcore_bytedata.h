// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_bytedata.h
 *
 * @brief ByteData関連クラス定義
 */

#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BYTEDATA_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BYTEDATA_H_

#include <cstddef>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

class ByteData160;
class ByteData256;

/**
 * @class ByteData
 * @brief 可変サイズのByte配列データクラス
 */
class CFD_CORE_EXPORT ByteData {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ByteData();

  /**
   * @brief コンストラクタ
   * @param[in] vector  格納Byte配列
   */
  ByteData(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief コンストラクタ
   * @param[in] hex  Byteデータ HEX文字列
   */
  explicit ByteData(const std::string& hex);

  /**
   * @brief constructor
   * @param[in] buffer    Byte data buffer
   * @param[in] size      Byte data size
   */
  explicit ByteData(const uint8_t* buffer, uint32_t size);

  /**
   * @brief HEX文字列を取得する.
   * @return HEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief Byte配列を取得する.
   * @return Byte配列
   */
  std::vector<uint8_t> GetBytes() const;

  /**
   * @brief データサイズを取得する.
   * @return Byte配列サイズ
   */
  size_t GetDataSize() const;

  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   */
  bool IsEmpty() const;

  /**
   * @brief ByteData比較
   * @param bytedata 比較対象のオブジェクト
   * @retval true 一致した場合
   * @retval false 不一致の場合
   */
  bool Equals(const ByteData& bytedata) const;

  /**
   * @brief Get head data only 1 byte.
   * @details empty is return 0.
   * @return 1byte data
   */
  uint8_t GetHeadData() const;

  /**
   * @brief byte data情報をserializeする.
   * @return serialize data
   */
  ByteData Serialize() const;

  /**
   * @brief serializeされたbyte dataのサイズを取得する。
   * @return serialize data size
   */
  size_t GetSerializeSize() const;

  /**
   * @brief Join byte data list.
   * @param[in] data  byte data.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteDataClass>
  ByteData Join(const ByteDataClass& data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] top   top byte data.
   * @param[in] args  byte data list.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteTop, class... ByteDataClass>
  ByteData Join(const ByteTop& top, const ByteDataClass&... args) const {
    ByteData result = Join(top);
    return result.Join(args...);
  }

  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteDataClass>
  ByteData PushBack(const ByteDataClass& back_insert_data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = back_insert_data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] data  byte data.
   * @return joined byte data.
   */
  template <class ByteDataClass>
  ByteData Concat(const ByteDataClass& data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] top   top byte data.
   * @param[in] args  byte data list.
   * @return joined byte data.
   */
  template <class ByteTop, class... ByteDataClass>
  ByteData Concat(const ByteTop& top, const ByteDataClass&... args) const {
    ByteData result = Concat(top);
    return result.Concat(args...);
  }

  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   * @return joined byte data.
   */
  void Push(const ByteData& back_insert_data);
  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   * @return joined byte data.
   */
  void Push(const ByteData160& back_insert_data);
  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   * @return joined byte data.
   */
  void Push(const ByteData256& back_insert_data);

  /**
   * @brief 可変長サイズ情報(バッファ)を取得する.
   * @param[in] value    size value
   * @return variable size buffer
   */
  static ByteData GetVariableInt(uint64_t value);

  /**
   * @brief 指定された2つのバッファのHEX値を比較する.
   * @param[in] source        source target
   * @param[in] destination   destination target
   * @retval true   大きい
   * @retval false  小さい
   */
  static bool IsLarge(const ByteData& source, const ByteData& destination);

 private:
  /**
   * @brief データ格納Byte配列
   */
  std::vector<uint8_t> data_;
};

/**
 * @class ByteData160
 * @brief サイズ固定(20byte)のByte配列データクラス
 */
class CFD_CORE_EXPORT ByteData160 {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ByteData160();

  /**
   * @brief コンストラクタ
   * @param[in] vector  20byteデータ格納Byte配列
   */
  ByteData160(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief コンストラクタ
   * @param[in] hex  ByteデータHEX文字列
   */
  explicit ByteData160(const std::string& hex);

  /**
   * @brief constructor
   * @param[in] byte_data   Byte data
   */
  explicit ByteData160(const ByteData& byte_data);

  /**
   * @brief HEX文字列を取得する.
   * @return HEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief Byte配列を取得する.
   * @return Byte配列
   */
  std::vector<uint8_t> GetBytes() const;

  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   */
  bool IsEmpty() const;

  /**
   * @brief ByteData比較
   * @param bytedata 比較対象のオブジェクト
   * @retval true 一致した場合
   * @retval false 不一致の場合
   */
  bool Equals(const ByteData160& bytedata) const;

  /**
   * @brief byte data情報を取得する.
   * @return byte data
   */
  ByteData GetData() const;

  /**
   * @brief Get head data only 1 byte.
   * @details empty is return 0.
   * @return 1byte data
   */
  uint8_t GetHeadData() const;

  /**
   * @brief Join byte data list.
   * @param[in] data  byte data.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteDataClass>
  ByteData Join(const ByteDataClass& data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] top   top byte data.
   * @param[in] args  byte data list.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteTop, class... ByteDataClass>
  ByteData Join(const ByteTop& top, const ByteDataClass&... args) const {
    ByteData result = Join(top);
    return result.Join(args...);
  }

  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteDataClass>
  ByteData PushBack(const ByteDataClass& back_insert_data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = back_insert_data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] data  byte data.
   * @return joined byte data.
   */
  template <class ByteDataClass>
  ByteData Concat(const ByteDataClass& data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] top   top byte data.
   * @param[in] args  byte data list.
   * @return joined byte data.
   */
  template <class ByteTop, class... ByteDataClass>
  ByteData Concat(const ByteTop& top, const ByteDataClass&... args) const {
    ByteData result = Concat(top);
    return result.Join(args...);
  }

  /**
   * @brief byte data情報をserializeする.
   * @return serialize data
   */
  ByteData Serialize() const;

 private:
  /**
   * @brief 20byte固定データ格納Byte配列
   */
  std::vector<uint8_t> data_;
};

/**
 * @class ByteData256
 * @brief サイズ固定(32byte)のByte配列データクラス
 */
class CFD_CORE_EXPORT ByteData256 {
 public:
  /**
   * @brief デフォルトコンストラクタ
   */
  ByteData256();

  /**
   * @brief コンストラクタ
   * @param[in] vector  32byteデータ格納Byte配列
   */
  ByteData256(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief コンストラクタ
   * @param[in] hex  ByteデータHEX文字列
   */
  explicit ByteData256(const std::string& hex);

  /**
   * @brief constructor
   * @param[in] byte_data   Byte data
   */
  explicit ByteData256(const ByteData& byte_data);

  /**
   * @brief HEX文字列を取得する.
   * @return HEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief Byte配列を取得する.
   * @return Byte配列
   */
  std::vector<uint8_t> GetBytes() const;

  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief データが空か取得する.
   * @retval true  データが空
   * @retval false データが存在
   */
  bool IsEmpty() const;

  /**
   * @brief ByteData比較
   * @param bytedata 比較対象のオブジェクト
   * @retval true 一致した場合
   * @retval false 不一致の場合
   */
  bool Equals(const ByteData256& bytedata) const;

  /**
   * @brief byte data情報を取得する.
   * @return byte data
   */
  ByteData GetData() const;

  /**
   * @brief Get head data only 1 byte.
   * @details empty is return 0.
   * @return 1byte data
   */
  uint8_t GetHeadData() const;

  /**
   * @brief Join byte data list.
   * @param[in] data  byte data.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteDataClass>
  ByteData Join(const ByteDataClass& data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] top   top byte data.
   * @param[in] args  byte data list.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteTop, class... ByteDataClass>
  ByteData Join(const ByteTop& top, const ByteDataClass&... args) const {
    ByteData result = Join(top);
    return result.Join(args...);
  }

  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   * @return joined byte data.
   * @deprecated refactoring.
   */
  template <class ByteDataClass>
  ByteData PushBack(const ByteDataClass& back_insert_data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = back_insert_data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] data  byte data.
   * @return joined byte data.
   */
  template <class ByteDataClass>
  ByteData Concat(const ByteDataClass& data) const {
    std::vector<uint8_t> result(data_);
    std::vector<uint8_t> insert_bytes = data.GetBytes();
    result.insert(result.end(), insert_bytes.begin(), insert_bytes.end());
    return ByteData(result);
  }

  /**
   * @brief Join byte data list.
   * @param[in] top   top byte data.
   * @param[in] args  byte data list.
   * @return joined byte data.
   */
  template <class ByteTop, class... ByteDataClass>
  ByteData Concat(const ByteTop& top, const ByteDataClass&... args) const {
    ByteData result = Concat(top);
    return result.Join(args...);
  }

  /**
   * @brief byte data情報をserializeする.
   * @return serialize data
   */
  ByteData Serialize() const;

 private:
  /**
   * @brief 32byte固定データ格納Byte配列
   */
  std::vector<uint8_t> data_;
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BYTEDATA_H_
