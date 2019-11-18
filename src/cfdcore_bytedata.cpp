// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_bytedata.cpp
 *
 */
#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

using logger::warn;

// -----------------------------------------------------------------------------
// inner file
// -----------------------------------------------------------------------------
static constexpr uint8_t kViTag16 = 253;  //!< VarInt16
static constexpr uint8_t kViTag32 = 254;  //!< VarInt32
static constexpr uint8_t kViTag64 = 255;  //!< VarInt64
static constexpr uint8_t kViMax8 = 252;   //!< VarInt8

/**
 * @brief serialize from buffer.
 * @param[in] data    buffer
 * @result serialize buffer
 */
static std::vector<uint8_t> SerializeFromBuffer(
    const std::vector<uint8_t>& data) {
  std::vector<uint8_t> result;
  std::vector<uint8_t> count_buffer =
      ByteData::GetVariableInt(data.size()).GetBytes();
  result.insert(result.end(), count_buffer.begin(), count_buffer.end());
  if (data.size() != 0) {
    result.insert(result.end(), data.begin(), data.end());
  }
  return result;
}

//////////////////////////////////
/// ByteData
//////////////////////////////////
ByteData::ByteData() : data_(0) {
  // do nothing
}

ByteData::ByteData(const std::vector<uint8_t>& vector) : data_(vector) {}

ByteData::ByteData(const std::string& hex)
    : data_(StringUtil::StringToByte(hex)) {}

std::string ByteData::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData::GetBytes() const { return data_; }

size_t ByteData::GetDataSize() const { return data_.size(); }

bool ByteData::Empty() const { return data_.size() == 0; }

bool ByteData::Equals(const ByteData& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

ByteData ByteData::Serialize() const {
  return ByteData(SerializeFromBuffer(data_));
}

size_t ByteData::GetSerializeSize() const {
  ByteData size_buffer = GetVariableInt(data_.size());
  return size_buffer.GetDataSize() + data_.size();
}

ByteData ByteData::GetVariableInt(uint64_t v) {
  std::vector<uint8_t> size_byte;
  if (v <= kViMax8) {
    uint8_t v8 = static_cast<uint8_t>(v);
    size_byte.push_back(v8);
  } else if (v <= std::numeric_limits<uint16_t>::max()) {
    uint16_t v16 = static_cast<uint16_t>(v);
    size_byte.resize(sizeof(v16) + 1);
    size_byte[0] = kViTag16;
    memcpy(size_byte.data() + 1, &v16, sizeof(v16));
  } else if (v <= std::numeric_limits<uint32_t>::max()) {
    uint32_t v32 = static_cast<uint32_t>(v);
    size_byte.resize(sizeof(v32) + 1);
    size_byte[0] = kViTag32;
    memcpy(size_byte.data() + 1, &v32, sizeof(v32));
  } else {
    size_byte.resize(sizeof(v) + 1);
    size_byte[0] = kViTag64;
    memcpy(size_byte.data() + 1, &v, sizeof(v));
  }

  return ByteData(size_byte);
}

bool ByteData::IsLarge(const ByteData& source, const ByteData& destination) {
  return source.data_ < destination.data_;
}

//////////////////////////////////
/// ByteData160
//////////////////////////////////
ByteData160::ByteData160() : data_(std::vector<uint8_t>(kByteData160Length)) {
  memset(data_.data(), 0, data_.size());
}

ByteData160::ByteData160(const std::vector<uint8_t>& vector)
    : data_(std::vector<uint8_t>(kByteData160Length)) {
  if (vector.size() != kByteData160Length) {
    warn(CFD_LOG_SOURCE, "ByteData160 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData160 size unmatch.");
  }
  data_ = vector;
}

ByteData160::ByteData160(const std::string& hex)
    : data_(std::vector<uint8_t>(kByteData160Length)) {
  std::vector<uint8_t> vector = StringUtil::StringToByte(hex);
  if (vector.size() != kByteData160Length) {
    warn(CFD_LOG_SOURCE, "ByteData160 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData160 size unmatch.");
  }
  data_ = vector;
}

std::string ByteData160::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData160::GetBytes() const { return data_; }

bool ByteData160::Empty() const { return data_.size() == 0; }

bool ByteData160::Equals(const ByteData160& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

ByteData ByteData160::GetData() const { return ByteData(data_); }

ByteData ByteData160::Serialize() const {
  return ByteData(SerializeFromBuffer(data_));
}

//////////////////////////////////
/// ByteData256
//////////////////////////////////
ByteData256::ByteData256() : data_(std::vector<uint8_t>(kByteData256Length)) {
  memset(data_.data(), 0, data_.size());
}

ByteData256::ByteData256(const std::vector<uint8_t>& vector)
    : data_(std::vector<uint8_t>(kByteData256Length)) {
  if (vector.size() != kByteData256Length) {
    warn(CFD_LOG_SOURCE, "ByteData256 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData256 size unmatch.");
  }
  data_ = vector;
}

ByteData256::ByteData256(const std::string& hex)
    : data_(std::vector<uint8_t>(kByteData256Length)) {
  std::vector<uint8_t> vector = StringUtil::StringToByte(hex);
  if (vector.size() != kByteData256Length) {
    warn(CFD_LOG_SOURCE, "ByteData256 size unmatch. size={}.", vector.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ByteData256 size unmatch.");
  }
  data_ = vector;
}

std::string ByteData256::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData256::GetBytes() const { return data_; }

bool ByteData256::Empty() const { return data_.size() == 0; }

bool ByteData256::Equals(const ByteData256& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

ByteData ByteData256::GetData() const { return ByteData(data_); }

ByteData ByteData256::Serialize() const {
  return ByteData(SerializeFromBuffer(data_));
}

}  // namespace core
}  // namespace cfd
