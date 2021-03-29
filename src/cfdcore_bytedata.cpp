// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_bytedata.cpp
 *
 * @brief implimentation of ByteData class
 */
#include "cfdcore/cfdcore_bytedata.h"

#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

using logger::warn;

//////////////////////////////////
/// ByteData
//////////////////////////////////
ByteData::ByteData() : data_(0) {
  // do nothing
}

ByteData::ByteData(const std::vector<uint8_t>& vector) : data_(vector) {
  if (data_.size() > std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "It exceeds the handling size.");
    throw CfdException(kCfdIllegalStateError, "It exceeds the handling size.");
  }
}

ByteData::ByteData(const std::string& hex)
    : data_(StringUtil::StringToByte(hex)) {}

ByteData::ByteData(const uint8_t* buffer, uint32_t size) : data_(size) {
  if (buffer == nullptr) {
    if (size == 0) {
      // create empty buffer
    } else {
      warn(CFD_LOG_SOURCE, "buffer is null.");
      throw CfdException(kCfdIllegalArgumentError, "buffer is null.");
    }
  } else if (size != 0) {
    data_.resize(size);
    memcpy(data_.data(), buffer, size);
  }
}

ByteData::ByteData(const uint8_t single_byte) : data_(1) {
  data_[0] = single_byte;
}

std::string ByteData::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData::GetBytes() const { return data_; }

size_t ByteData::GetDataSize() const { return data_.size(); }

bool ByteData::Empty() const { return IsEmpty(); }

bool ByteData::IsEmpty() const { return data_.size() == 0; }

bool ByteData::Equals(const ByteData& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

uint8_t ByteData::GetHeadData() const {
  return (data_.empty()) ? 0 : data_[0];
}

ByteData ByteData::Serialize() const {
  Serializer obj(static_cast<uint32_t>(data_.size()));
  obj.AddVariableBuffer(data_.data(), static_cast<uint32_t>(data_.size()));
  return obj.Output();
}

size_t ByteData::GetSerializeSize() const {
  return Serializer::GetVariableIntSize(data_.size()) + data_.size();
}

ByteData ByteData::GetVariableInt(uint64_t v) {
  Serializer obj(sizeof(v) + 1);
  obj.AddVariableInt(v);
  return obj.Output();
}

bool ByteData::IsLarge(const ByteData& source, const ByteData& destination) {
  return source.data_ < destination.data_;
}

void ByteData::Push(const ByteData& back_insert_data) {
  if (back_insert_data.IsEmpty()) return;
  const std::vector<uint8_t>& insert_bytes = back_insert_data.data_;
  data_.reserve(data_.size() + insert_bytes.size() + 8);
  std::copy(
      insert_bytes.begin(), insert_bytes.end(), std::back_inserter(data_));
}

void ByteData::Push(const ByteData160& back_insert_data) {
  std::vector<uint8_t> insert_bytes = back_insert_data.GetBytes();
  data_.reserve(data_.size() + insert_bytes.size() + 8);
  std::copy(
      insert_bytes.begin(), insert_bytes.end(), std::back_inserter(data_));
}

void ByteData::Push(const ByteData256& back_insert_data) {
  std::vector<uint8_t> insert_bytes = back_insert_data.GetBytes();
  data_.reserve(data_.size() + insert_bytes.size() + 8);
  std::copy(
      insert_bytes.begin(), insert_bytes.end(), std::back_inserter(data_));
}

bool ByteData::operator==(const ByteData& object) const {
  return (data_ == object.data_);
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

ByteData160::ByteData160(const ByteData& byte_data)
    : ByteData160(byte_data.GetBytes()) {}

std::string ByteData160::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData160::GetBytes() const { return data_; }

bool ByteData160::Empty() const { return IsEmpty(); }

bool ByteData160::IsEmpty() const {
  std::vector<uint8_t> data(kByteData160Length);
  memset(data.data(), 0, data.size());
  return data_ == data;
}

bool ByteData160::Equals(const ByteData160& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

ByteData ByteData160::GetData() const { return ByteData(data_); }

uint8_t ByteData160::GetHeadData() const { return data_[0]; }

ByteData ByteData160::Serialize() const {
  Serializer obj(static_cast<uint32_t>(data_.size()));
  obj.AddVariableBuffer(data_.data(), static_cast<uint32_t>(data_.size()));
  return obj.Output();
}

bool ByteData160::operator==(const ByteData160& object) const {
  return (data_ == object.data_);
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

ByteData256::ByteData256(const ByteData& byte_data)
    : ByteData256(byte_data.GetBytes()) {}

std::string ByteData256::GetHex() const {
  return StringUtil::ByteToString(data_);
}

std::vector<uint8_t> ByteData256::GetBytes() const { return data_; }

bool ByteData256::Empty() const { return IsEmpty(); }

bool ByteData256::IsEmpty() const {
  std::vector<uint8_t> data(kByteData256Length);
  memset(data.data(), 0, data.size());
  return data_ == data;
}

bool ByteData256::Equals(const ByteData256& bytedata) const {
  if (data_ == bytedata.data_) {
    return true;
  }
  return false;
}

ByteData ByteData256::GetData() const { return ByteData(data_); }

uint8_t ByteData256::GetHeadData() const { return data_[0]; }

ByteData ByteData256::Serialize() const {
  Serializer obj(static_cast<uint32_t>(data_.size()));
  obj.AddVariableBuffer(data_.data(), static_cast<uint32_t>(data_.size()));
  return obj.Output();
}

bool ByteData256::operator==(const ByteData256& object) const {
  return (data_ == object.data_);
}

//////////////////////////////////
/// Serializer
//////////////////////////////////
Serializer::Serializer() : buffer_(8), offset_(0) {
  // do nothing
}

Serializer::Serializer(uint32_t initial_size)
    : buffer_(initial_size + 9), offset_(0) {
  // do nothing
}

Serializer::Serializer(const Serializer& object)
    : buffer_(object.buffer_), offset_(object.offset_) {
  // do nothing
}

Serializer& Serializer::operator=(const Serializer& object) {
  if (this != &object) {
    buffer_ = object.buffer_;
    offset_ = object.offset_;
  }
  return *this;
}

void Serializer::CheckNeedSize(uint32_t need_size) {
  size_t size = buffer_.size() - static_cast<size_t>(offset_);
  if (size < need_size) {
    size_t cap = buffer_.capacity() - static_cast<size_t>(offset_);
    if (cap < (need_size * 2)) {
      buffer_.reserve(buffer_.capacity() + (need_size * 10));
    }
    buffer_.resize(buffer_.size() + (need_size * 2));
  }
}

uint32_t Serializer::GetVariableIntSize(uint64_t value) {
  if (value <= kViMax8)
    return 1;
  else if (value <= std::numeric_limits<uint16_t>::max())
    return 3;
  else if (value <= std::numeric_limits<uint32_t>::max())
    return 5;
  else
    return 9;
}

void Serializer::AddVariableInt(uint64_t value) {
  // TODO(k-matsuzawa) need endian support.
  CheckNeedSize(9);
  uint8_t* buf = &buffer_.data()[offset_];
  if (value <= kViMax8) {
    *buf = static_cast<uint8_t>(value);
    ++offset_;
  } else if (value <= std::numeric_limits<uint16_t>::max()) {
    *buf = kViTag16;
    ++buf;
    uint16_t v16 = static_cast<uint16_t>(value);
    memcpy(buf, &v16, sizeof(v16));
    offset_ += sizeof(v16) + 1;
  } else if (value <= std::numeric_limits<uint32_t>::max()) {
    *buf = kViTag32;
    ++buf;
    uint32_t v32 = static_cast<uint32_t>(value);
    memcpy(buf, &v32, sizeof(v32));
    offset_ += sizeof(v32) + 1;
  } else {
    *buf = kViTag64;
    ++buf;
    uint64_t v64 = value;
    memcpy(buf, &v64, sizeof(v64));
    offset_ += sizeof(v64) + 1;
  }
}

void Serializer::AddVariableBuffer(const ByteData& buffer) {
  auto buf = buffer.GetBytes();
  if (buf.size() > std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "It exceeds the handling size.");
    throw CfdException(kCfdIllegalStateError, "It exceeds the handling size.");
  }
  AddVariableBuffer(buf.data(), static_cast<uint32_t>(buf.size()));
}

void Serializer::AddPrefixBuffer(uint64_t prefix, const ByteData& buffer) {
  auto buf = buffer.GetBytes();
  if (buf.size() > std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "It exceeds the handling size.");
    throw CfdException(kCfdIllegalStateError, "It exceeds the handling size.");
  }
  AddPrefixBuffer(prefix, buf.data(), static_cast<uint32_t>(buf.size()));
}

void Serializer::AddDirectBytes(const ByteData& buffer) {
  auto buf = buffer.GetBytes();
  if (buf.size() > std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "It exceeds the handling size.");
    throw CfdException(kCfdIllegalStateError, "It exceeds the handling size.");
  }
  AddDirectBytes(buf.data(), static_cast<uint32_t>(buf.size()));
}

void Serializer::AddDirectBytes(const ByteData256& buffer) {
  auto buf = buffer.GetBytes();
  AddDirectBytes(buf.data(), static_cast<uint32_t>(buf.size()));
}

void Serializer::AddVariableBuffer(
    const uint8_t* buffer, uint32_t buffer_size) {
  AddVariableInt(buffer_size);
  AddDirectBytes(buffer, buffer_size);
}

void Serializer::AddPrefixBuffer(
    uint64_t prefix, const uint8_t* buffer, uint32_t buffer_size) {
  uint32_t size = GetVariableIntSize(prefix) + buffer_size;
  AddVariableInt(size);
  AddVariableInt(prefix);
  AddDirectBytes(buffer, buffer_size);
}

void Serializer::AddDirectBytes(const uint8_t* buffer, uint32_t buffer_size) {
  if ((buffer != nullptr) && (buffer_size != 0)) {
    CheckNeedSize(buffer_size);
    uint8_t* buf = &buffer_.data()[offset_];
    memcpy(buf, buffer, buffer_size);
    offset_ += buffer_size;
  }
}

void Serializer::AddDirectByte(uint8_t byte_data) {
  CheckNeedSize(4);
  uint8_t* buf = &buffer_.data()[offset_];
  *buf = byte_data;
  ++offset_;
}

void Serializer::AddDirectNumber(uint32_t number) {
  CheckNeedSize(sizeof(number));
  uint8_t* buf = &buffer_.data()[offset_];
  // TODO(k-matsuzawa) need endian support.
  memcpy(buf, &number, sizeof(number));
  offset_ += sizeof(number);
}

void Serializer::AddDirectNumber(uint64_t number) {
  CheckNeedSize(sizeof(number));
  uint8_t* buf = &buffer_.data()[offset_];
  // TODO(k-matsuzawa) need endian support.
  memcpy(buf, &number, sizeof(number));
  offset_ += sizeof(number);
}

void Serializer::AddDirectNumber(int64_t number) {
  CheckNeedSize(sizeof(number));
  uint8_t* buf = &buffer_.data()[offset_];
  // TODO(k-matsuzawa) need endian support.
  memcpy(buf, &number, sizeof(number));
  offset_ += sizeof(number);
}

Serializer& Serializer::operator<<(const ByteData& buffer) {
  AddDirectBytes(buffer);
  return *this;
}

Serializer& Serializer::operator<<(const ByteData256& buffer) {
  AddDirectBytes(buffer);
  return *this;
}

Serializer& Serializer::operator<<(uint8_t byte_data) {
  AddDirectByte(byte_data);
  return *this;
}

Serializer& Serializer::operator<<(uint32_t number) {
  AddDirectNumber(number);
  return *this;
}

Serializer& Serializer::operator<<(uint64_t number) {
  AddDirectNumber(number);
  return *this;
}

Serializer& Serializer::operator<<(int64_t number) {
  AddDirectNumber(number);
  return *this;
}

ByteData Serializer::Output() { return ByteData(buffer_.data(), offset_); }

Deserializer::Deserializer(const std::vector<uint8_t>& buffer)
    : buffer_(buffer), offset_(0) {
  // do nothing
}

Deserializer::Deserializer(const ByteData& buffer)
    : Deserializer(buffer.GetBytes()) {
  // do nothing
}

Deserializer::Deserializer(const Deserializer& object)
    : buffer_(object.buffer_), offset_(object.offset_) {
  // do nothing
}

Deserializer& Deserializer::operator=(const Deserializer& object) {
  if (this != &object) {
    buffer_ = object.buffer_;
    offset_ = object.offset_;
  }
  return *this;
}

uint64_t Deserializer::ReadUint64() {
  uint64_t result = 0;
  CheckReadSize(sizeof(result));
  memcpy(&result, &buffer_.data()[offset_], sizeof(result));
  offset_ += sizeof(result);
  return result;
}

uint32_t Deserializer::ReadUint32() {
  uint32_t result = 0;
  CheckReadSize(sizeof(result));
  memcpy(&result, &buffer_.data()[offset_], sizeof(result));
  offset_ += sizeof(result);
  return result;
}

uint8_t Deserializer::ReadUint8() {
  uint8_t result = 0;
  CheckReadSize(sizeof(result));
  memcpy(&result, &buffer_.data()[offset_], sizeof(result));
  offset_ += sizeof(result);
  return result;
}

uint64_t Deserializer::ReadVariableInt() {
  CheckReadSize(1);
  const uint8_t* buf = buffer_.data() + offset_;
  uint64_t value = 0;
  if (*buf <= Serializer::kViMax8) {
    value = *buf;
    offset_ += 1;
  } else if (*buf == Serializer::kViTag16) {
    CheckReadSize(3);
    ++buf;
    uint16_t num;
    memcpy(&num, buf, sizeof(num));
    value = num;
    offset_ += 1 + sizeof(num);
  } else if (*buf == Serializer::kViTag32) {
    CheckReadSize(5);
    ++buf;
    uint32_t num;
    memcpy(&num, buf, sizeof(num));
    value = num;
    offset_ += 1 + sizeof(num);
  } else {
    CheckReadSize(9);
    ++buf;
    uint64_t num;
    memcpy(&num, buf, sizeof(num));
    value = num;
    offset_ += 1 + sizeof(num);
  }
  return value;
}

std::vector<uint8_t> Deserializer::ReadBuffer(uint32_t size) {
  CheckReadSize(size);
  std::vector<uint8_t> result(size);
  memcpy(result.data(), &buffer_.data()[offset_], size);
  offset_ += size;
  return result;
}

void Deserializer::ReadArray(uint8_t* output, size_t size) {
  if (output != nullptr) {
    CheckReadSize(size);
    memcpy(output, &buffer_.data()[offset_], size);
    offset_ += static_cast<uint32_t>(size);
  }
}

std::vector<uint8_t> Deserializer::ReadVariableBuffer() {
  // TODO(k-matsuzawa) need endian support.
  uint64_t data_size = ReadVariableInt();
  if (data_size == 0) {
    return std::vector<uint8_t>();
  }
  CheckReadSize(data_size);

  uint8_t* buf = buffer_.data() + offset_;
  std::vector<uint8_t> result(data_size);
  memcpy(result.data(), buf, data_size);
  offset_ += static_cast<uint32_t>(data_size);
  return result;
}

ByteData Deserializer::ReadVariableData() {
  return ByteData(ReadVariableBuffer());
}

uint32_t Deserializer::GetReadSize() { return offset_; }

void Deserializer::CheckReadSize(uint64_t size) {
  if (size > std::numeric_limits<uint32_t>::max()) {
    warn(CFD_LOG_SOURCE, "It exceeds the handling size.");
    throw CfdException(kCfdIllegalStateError, "It exceeds the handling size.");
  }
  if (buffer_.size() < (offset_ + size)) {
    warn(CFD_LOG_SOURCE, "deserialize buffer EOF.");
    throw CfdException(kCfdIllegalStateError, "deserialize buffer EOF.");
  }
}

}  // namespace core
}  // namespace cfd
