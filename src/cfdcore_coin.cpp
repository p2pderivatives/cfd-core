// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_coin.cpp
 *
 * @brief \~japanese Coin(UTXO)関連クラス
 *   \~english Classes related to Coin(UTXO)
 */
#include "cfdcore/cfdcore_coin.h"

#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

using logger::warn;

// -----------------------------------------------------------------------------
// Txid
// -----------------------------------------------------------------------------
Txid::Txid() : data_(ByteData()) {
  // do nothing
}

Txid::Txid(const std::string& hex) : data_() {
  const std::vector<uint8_t>& data = StringUtil::StringToByte(hex);
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  if (reverse_buffer.size() != kByteData256Length) {
    warn(CFD_LOG_SOURCE, "Txid size Invalid. size={}.", reverse_buffer.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Txid size Invalid.");
  }
  data_ = ByteData(reverse_buffer);
}

Txid::Txid(const ByteData256& data) : data_(ByteData(data.GetBytes())) {
  // do nothing
}

const std::string Txid::GetHex() const {
  const std::vector<uint8_t>& data = data_.GetBytes();
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  return StringUtil::ByteToString(reverse_buffer);
}

const ByteData Txid::GetData() const { return data_; }

bool Txid::Equals(const Txid& txid) const {
  if (data_.Equals(txid.data_)) {
    return true;
  }
  return false;
}

bool Txid::IsValid() const {
  return (data_.GetDataSize() == kByteData256Length);
}

// -----------------------------------------------------------------------------
// BlockHash
// -----------------------------------------------------------------------------
BlockHash::BlockHash(const std::string& hex) : data_() {
  const std::vector<uint8_t>& data = StringUtil::StringToByte(hex);
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  if (reverse_buffer.size() != kByteData256Length) {
    warn(
        CFD_LOG_SOURCE, "BlockHash size Invalid. size={}.",
        reverse_buffer.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "BlockHash size Invalid.");
  }
  data_ = ByteData(reverse_buffer);
}

BlockHash::BlockHash(const ByteData256& data)
    : data_(ByteData(data.GetBytes())) {
  // do nothing
}

const std::string BlockHash::GetHex() const {
  const std::vector<uint8_t>& data = data_.GetBytes();
  std::vector<uint8_t> reverse_buffer(data.crbegin(), data.crend());
  return StringUtil::ByteToString(reverse_buffer);
}

const ByteData BlockHash::GetData() const { return data_; }

bool BlockHash::IsValid() const {
  return (data_.GetDataSize() == kByteData256Length);
}

}  // namespace core
}  // namespace cfd
