// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_bytedata.h
 *
 * @brief The ByteData related class definition.
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
 * @brief The variable size byte array data class.
 */
class CFD_CORE_EXPORT ByteData {
 public:
  /**
   * @brief default constructor.
   */
  ByteData();

  /**
   * @brief constructor
   * @param[in] vector  byte array.
   */
  ByteData(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief constructor
   * @param[in] hex  hex string.
   */
  explicit ByteData(const std::string& hex);

  /**
   * @brief constructor
   * @param[in] buffer    Byte data buffer
   * @param[in] size      Byte data size
   */
  explicit ByteData(const uint8_t* buffer, uint32_t size);

  /**
   * @brief constructor
   * @param[in] single_byte    1-Byte data
   */
  explicit ByteData(const uint8_t single_byte);

  /**
   * @brief Get a hex string.
   * @return hex string.
   */
  std::string GetHex() const;

  /**
   * @brief Get a byte array.
   * @return byte array.
   */
  std::vector<uint8_t> GetBytes() const;

  /**
   * @brief Get a byte data size.
   * @return byte data size.
   */
  size_t GetDataSize() const;

  /**
   * @brief Check is data empty.
   * @retval true   empty.
   * @retval false  not empty.
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief Check is data empty.
   * @retval true   empty.
   * @retval false  not empty.
   */
  bool IsEmpty() const;

  /**
   * @brief Check equals.
   * @param bytedata  compare target object.
   * @retval true   equals.
   * @retval false  not equals.
   */
  bool Equals(const ByteData& bytedata) const;

  /**
   * @brief Get head data only 1 byte.
   * @details empty is return 0.
   * @return 1byte data
   */
  uint8_t GetHeadData() const;

  /**
   * @brief Serialize byte data.
   * @return serialize data
   */
  ByteData Serialize() const;

  /**
   * @brief Get the serialized size.
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
   */
  void Push(const ByteData& back_insert_data);
  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   */
  void Push(const ByteData160& back_insert_data);
  /**
   * @brief Push to back.
   * @param[in] back_insert_data  back insert data.
   */
  void Push(const ByteData256& back_insert_data);

  /**
   * @brief Equals operator.
   * @param[in] object  target object.
   * @retval true   equals
   * @retval false  not equals
   */
  bool operator==(const ByteData& object) const;

  /**
   * @brief Get the variable integer buffer.
   * @param[in] value    size value
   * @return variable size buffer
   */
  static ByteData GetVariableInt(uint64_t value);

  /**
   * @brief Compare the HEX values ​​of the two specified buffers.
   * @param[in] source        source target
   * @param[in] destination   destination target
   * @retval true   Large
   * @retval false  Small or equals.
   */
  static bool IsLarge(const ByteData& source, const ByteData& destination);

 private:
  /**
   * @brief データbyte array.
   */
  std::vector<uint8_t> data_;
};

/**
 * @class ByteData160
 * @brief Fixed size (20 bytes) Byte array data class
 */
class CFD_CORE_EXPORT ByteData160 {
 public:
  /**
   * @brief default constructor
   */
  ByteData160();

  /**
   * @brief constructor
   * @param[in] vector  byte array(20byte).
   */
  ByteData160(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief constructor
   * @param[in] hex  hex string.
   */
  explicit ByteData160(const std::string& hex);

  /**
   * @brief constructor
   * @param[in] byte_data   Byte data
   */
  explicit ByteData160(const ByteData& byte_data);

  /**
   * @brief Get a hex string.
   * @return hex string.
   */
  std::string GetHex() const;

  /**
   * @brief Get a byte array.
   * @return byte array.
   */
  std::vector<uint8_t> GetBytes() const;

  /**
   * @brief Check is data empty.
   * @retval true   empty.
   * @retval false  not empty.
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief Check is data empty.
   * @retval true   empty.
   * @retval false  not empty.
   */
  bool IsEmpty() const;

  /**
   * @brief Check equals.
   * @param bytedata  compare target object.
   * @retval true   equals.
   * @retval false  not equals.
   */
  bool Equals(const ByteData160& bytedata) const;

  /**
   * @brief Get a byte data object.
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
   * @brief Serialize byte data.
   * @return serialize data
   */
  ByteData Serialize() const;

  /**
   * @brief Equals operator.
   * @param[in] object  target object.
   * @retval true   equals
   * @retval false  not equals
   */
  bool operator==(const ByteData160& object) const;

 private:
  /**
   * @brief 20byte fixed data.
   */
  std::vector<uint8_t> data_;
};

/**
 * @class ByteData256
 * @brief Fixed size (32 bytes) Byte array data class.
 */
class CFD_CORE_EXPORT ByteData256 {
 public:
  /**
   * @brief default constructor
   */
  ByteData256();

  /**
   * @brief constructor
   * @param[in] vector  byte array(32byte).
   */
  ByteData256(const std::vector<uint8_t>& vector);  // NOLINT

  /**
   * @brief constructor
   * @param[in] hex  hex string.
   */
  explicit ByteData256(const std::string& hex);

  /**
   * @brief constructor
   * @param[in] byte_data   Byte data
   */
  explicit ByteData256(const ByteData& byte_data);

  /**
   * @brief Get a hex string.
   * @return hex string.
   */
  std::string GetHex() const;

  /**
   * @brief Get a byte array.
   * @return byte array.
   */
  std::vector<uint8_t> GetBytes() const;

  /**
   * @brief Check is data empty.
   * @retval true   empty.
   * @retval false  not empty.
   * @deprecated replace to IsEmpty .
   */
  bool Empty() const;
  /**
   * @brief Check is data empty.
   * @retval true   empty.
   * @retval false  not empty.
   */
  bool IsEmpty() const;

  /**
   * @brief Check equals.
   * @param bytedata  compare target object.
   * @retval true   equals.
   * @retval false  not equals.
   */
  bool Equals(const ByteData256& bytedata) const;

  /**
   * @brief Get a byte data object.
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
   * @brief Serialize byte data.
   * @return serialize data
   */
  ByteData Serialize() const;

  /**
   * @brief Equals operator.
   * @param[in] object  target object.
   * @retval true   equals
   * @retval false  not equals
   */
  bool operator==(const ByteData256& object) const;

 private:
  /**
   * @brief 32byte fixed data.
   */
  std::vector<uint8_t> data_;
};

/**
 * @class Serializer
 * @brief A class that serializes a byte array.
 */
class CFD_CORE_EXPORT Serializer {
 public:
  static constexpr uint8_t kViTag16 = 253;  //!< VarInt16
  static constexpr uint8_t kViTag32 = 254;  //!< VarInt32
  static constexpr uint8_t kViTag64 = 255;  //!< VarInt64
  static constexpr uint8_t kViMax8 = 252;   //!< VarInt8

  /**
   * @brief get variable integer size.
   * @param[in] value  value
   * @return variable integer size
   */
  static uint32_t GetVariableIntSize(uint64_t value);

  /**
   * @brief constructor.
   */
  Serializer();
  /**
   * @brief constructor.
   * @param[in] initial_size  initial buffer size.
   */
  explicit Serializer(uint32_t initial_size);
  /**
   * @brief destructor.
   */
  virtual ~Serializer() {}
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  Serializer(const Serializer& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  Serializer& operator=(const Serializer& object);

  /**
   * @brief add variable integer.
   * @param[in] value  value
   */
  void AddVariableInt(uint64_t value);

  /**
   * @brief add variable buffer.
   * @param[in] buffer   buffer
   */
  void AddVariableBuffer(const ByteData& buffer);
  /**
   * @brief add prefix buffer.
   * @param[in] prefix        prefix
   * @param[in] buffer        buffer
   */
  void AddPrefixBuffer(uint64_t prefix, const ByteData& buffer);
  /**
   * @brief add direct byte array.
   * @param[in] buffer        buffer
   */
  void AddDirectBytes(const ByteData& buffer);
  /**
   * @brief add direct byte array.
   * @param[in] buffer        buffer
   */
  void AddDirectBytes(const ByteData256& buffer);

  /**
   * @brief add variable buffer.
   * @param[in] buffer        buffer
   * @param[in] buffer_size   buffer size
   */
  void AddVariableBuffer(const uint8_t* buffer, uint32_t buffer_size);
  /**
   * @brief add prefix buffer.
   * @param[in] prefix        prefix
   * @param[in] buffer        buffer
   * @param[in] buffer_size   buffer size
   */
  void AddPrefixBuffer(
      uint64_t prefix, const uint8_t* buffer, uint32_t buffer_size);
  /**
   * @brief add direct byte array.
   * @param[in] buffer        buffer
   * @param[in] buffer_size   buffer size
   */
  void AddDirectBytes(const uint8_t* buffer, uint32_t buffer_size);

  /**
   * @brief add direct byte data.
   * @param[in] byte_data     byte data
   */
  void AddDirectByte(uint8_t byte_data);
  /**
   * @brief add direct number.
   * @param[in] number     value
   */
  void AddDirectNumber(uint32_t number);
  /**
   * @brief add direct number.
   * @param[in] number     value
   */
  void AddDirectNumber(uint64_t number);
  /**
   * @brief add direct number.
   * @param[in] number     value
   */
  void AddDirectNumber(int64_t number);

  /**
   * @brief add direct byte array.
   * @param[in] buffer        buffer
   * @return serializer object.
   */
  Serializer& operator<<(const ByteData& buffer);
  /**
   * @brief add direct byte array.
   * @param[in] buffer        buffer
   * @return serializer object.
   */
  Serializer& operator<<(const ByteData256& buffer);
  /**
   * @brief add direct byte data.
   * @param[in] byte_data     byte data
   * @return serializer object.
   */
  Serializer& operator<<(uint8_t byte_data);
  /**
   * @brief add direct number.
   * @param[in] number     value
   * @return serializer object.
   */
  Serializer& operator<<(uint32_t number);
  /**
   * @brief add direct number.
   * @param[in] number     value
   * @return serializer object.
   */
  Serializer& operator<<(uint64_t number);
  /**
   * @brief add direct number.
   * @param[in] number     value
   * @return serializer object.
   */
  Serializer& operator<<(int64_t number);

  /**
   * @brief Output byte array.
   * @return byte array.
   */
  ByteData Output();

 protected:
  std::vector<uint8_t> buffer_;  //!< buffer
  uint32_t offset_;              //!< offset

  /**
   * @brief check need buffer size.
   * @param[in] need_size  need buffer size
   */
  void CheckNeedSize(uint32_t need_size);
};

/**
 * @class Deserializer
 * @brief A class that analyze a serialized byte array.
 */
class CFD_CORE_EXPORT Deserializer {
 public:
  /**
   * @brief constructor.
   */
  Deserializer() : offset_(0) {}
  /**
   * @brief constructor.
   * @param[in] buffer     buffer
   */
  explicit Deserializer(const std::vector<uint8_t>& buffer);
  /**
   * @brief constructor.
   * @param[in] buffer     buffer
   */
  explicit Deserializer(const ByteData& buffer);
  /**
   * @brief destructor.
   */
  virtual ~Deserializer() {}
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  Deserializer(const Deserializer& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  Deserializer& operator=(const Deserializer& object);

  /**
   * @brief read uint64.
   * @return uint64
   */
  uint64_t ReadUint64();
  /**
   * @brief read uint32.
   * @return uint32
   */
  uint32_t ReadUint32();
  /**
   * @brief read uint8.
   * @return uint8
   */
  uint8_t ReadUint8();

  /**
   * @brief read variable integer.
   * @return uint64
   */
  uint64_t ReadVariableInt();
  /**
   * @brief read buffer.
   * @param[in] size   read size.
   * @return buffer
   */
  std::vector<uint8_t> ReadBuffer(uint32_t size);
  /**
   * @brief read array.
   * @param[in,out] output   write array.
   * @param[in] size   read size.
   */
  void ReadArray(uint8_t* output, size_t size);

  /**
   * @brief read variable buffer.
   * @return buffer
   */
  std::vector<uint8_t> ReadVariableBuffer();
  /**
   * @brief read variable buffer.
   * @return buffer
   */
  ByteData ReadVariableData();

  /**
   * @brief get all read size.
   * @return size (offset)
   */
  uint32_t GetReadSize();

 protected:
  std::vector<uint8_t> buffer_;  //!< buffer
  uint32_t offset_;              //!< offset

  /**
   * @brief check read offset size.
   * @param[in] size  need size
   */
  void CheckReadSize(uint64_t size);
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BYTEDATA_H_
