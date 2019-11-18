// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_key.cpp
 *
 * @brief Pubkey/Privkey関連クラス定義
 */

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT
#include "wally_address.h"       // NOLINT

namespace cfd {
namespace core {

using logger::warn;

// ----------------------------------------------------------------------------
// Public Key
// ----------------------------------------------------------------------------
Pubkey::Pubkey() : data_() {}

bool Pubkey::IsValid(const ByteData& byte_data) {
  const std::vector<uint8_t>& buffer = byte_data.GetBytes();
  if (buffer.size() > 0) {
    uint8_t header = buffer[0];
    if (header == 0x02 || header == 0x03) {
      return buffer.size() == Pubkey::kCompressedPubkeySize;
    } else if (header == 0x04 || header == 0x06 || header == 0x07) {
      return buffer.size() == Pubkey::kPubkeySize;
    }
  }
  return false;
}

Pubkey::Pubkey(ByteData byte_data) : data_(byte_data) {
  if (!Pubkey::IsValid(data_)) {
    warn(CFD_LOG_SOURCE, "Invalid Pubkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey data.");
  }
}

Pubkey::Pubkey(const std::string& hex_string) : Pubkey(ByteData(hex_string)) {
  // do nothing
}

std::string Pubkey::GetHex() const { return data_.GetHex(); }

ByteData Pubkey::GetData() const { return data_.GetBytes(); }

bool Pubkey::IsCompress() const {
  std::vector<uint8_t> buffer = data_.GetBytes();
  if (buffer.size() > 0) {
    uint8_t header = buffer[0];
    if (header == 0x02 || header == 0x03) {
      return true;
    } else if (header == 0x04 || header == 0x06 || header == 0x07) {
      return false;
    }
  }
  return false;
}

bool Pubkey::IsValid() const { return IsValid(data_); }

bool Pubkey::Equals(const Pubkey& pubkey) const {
  return data_.Equals(pubkey.data_);
}

Pubkey Pubkey::CombinePubkey(Pubkey pubkey, Pubkey message_key) {
  std::vector<ByteData> data_list;
  data_list.push_back(ByteData(pubkey.GetData()));
  data_list.push_back(ByteData(message_key.GetData()));

  return Pubkey(WallyUtil::CombinePubkeySecp256k1Ec(data_list));
}

bool Pubkey::IsLarge(const Pubkey& source, const Pubkey& destination) {
  return ByteData::IsLarge(source.data_, destination.data_);
}

// ----------------------------------------------------------------------------
// Private Key
// ----------------------------------------------------------------------------
/// Mainnet Prefix
static constexpr uint32_t kPrefixMainnet = 0x80;
/// Testnet Prefix
static constexpr uint32_t kPrefixTestnet = 0xef;

Privkey::Privkey() : data_() {
  // do nothing
}

Privkey::Privkey(const ByteData& byte_data) : data_(byte_data) {
  if (!IsValid(data_.GetBytes())) {
    warn(CFD_LOG_SOURCE, "Invalid Privkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data.");
  }
}

Privkey::Privkey(const ByteData256& byte_data)
    : data_(ByteData(byte_data.GetBytes())) {
  if (!IsValid(data_.GetBytes())) {
    warn(CFD_LOG_SOURCE, "Invalid Privkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data.");
  }
}

Privkey::Privkey(const std::string& hex_str) : data_(ByteData(hex_str)) {
  if (!IsValid(data_.GetBytes())) {
    warn(CFD_LOG_SOURCE, "Invalid Privkey data. hex={}.", data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data.");
  }
}

std::string Privkey::GetHex() const { return data_.GetHex(); }

ByteData Privkey::GetData() const { return data_.GetBytes(); }

std::string Privkey::ConvertWif(NetType net_type, bool is_compressed) {
  uint32_t prefix = (net_type == kMainnet ? kPrefixMainnet : kPrefixTestnet);
  uint32_t flags =
      (is_compressed ? WALLY_WIF_FLAG_COMPRESSED
                     : WALLY_WIF_FLAG_UNCOMPRESSED);
  char* wif_ptr = NULL;

  int ret = wally_wif_from_bytes(
      data_.GetBytes().data(), data_.GetDataSize(), prefix, flags, &wif_ptr);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "wally_wif_from_bytes error. ret={} bytes={}.", ret,
        data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Error Private key to WIF.");
  }
  std::string wif = WallyUtil::ConvertStringAndFree(wif_ptr);
  return wif;
}

Privkey Privkey::FromWif(
    const std::string& wif, NetType net_type, bool is_compressed) {
  std::vector<uint8_t> privkey(kPrivkeySize);
  uint32_t prefix = (net_type == kMainnet ? kPrefixMainnet : kPrefixTestnet);
  uint32_t flags =
      (is_compressed ? WALLY_WIF_FLAG_COMPRESSED
                     : WALLY_WIF_FLAG_UNCOMPRESSED);

  int ret = wally_wif_to_bytes(
      wif.data(), prefix, flags, privkey.data(), kPrivkeySize);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_wif_to_bytes error. ret={} wif={}.", ret, wif);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Error WIF to Private key.");
  }
  if (!IsValid(privkey)) {
    warn(
        CFD_LOG_SOURCE, "Invalid Privkey data. data={}",
        ByteData(privkey).GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Privkey data");
  }
  return Privkey(ByteData(privkey));
}

Pubkey Privkey::GeneratePubkey(bool is_compressed) const {
  std::vector<uint8_t> pubkey(Pubkey::kCompressedPubkeySize);
  int ret = wally_ec_public_key_from_private_key(
      data_.GetBytes().data(), data_.GetDataSize(), pubkey.data(),
      pubkey.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "wally_ec_public_key_from_private_key error. ret={} privkey={}.", ret,
        data_.GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Generate Pubkey error.");
  }
  if (is_compressed) {
    return Pubkey(pubkey);
  }

  std::vector<uint8_t> uncompressed_pubkey(Pubkey::kPubkeySize);
  ret = wally_ec_public_key_decompress(
      pubkey.data(), pubkey.size(), uncompressed_pubkey.data(),
      uncompressed_pubkey.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE,
        "wally_ec_public_key_decompress error. ret={} compressed pubkey={}.",
        ret, ByteData(pubkey).GetHex());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Decompressed Pubkey error.");
  }
  return Pubkey(uncompressed_pubkey);
}

Privkey Privkey::GenerageRandomKey() {
  std::vector<uint8_t> privkey;
  int ret = WALLY_OK;

  do {
    privkey = RandomNumberUtil::GetRandomBytes(kPrivkeySize);
    ret = wally_ec_private_key_verify(privkey.data(), privkey.size());
  } while (ret != WALLY_OK);

  return Privkey(ByteData(privkey));
}

bool Privkey::IsInvalid() const {
  if (IsValid(data_.GetBytes())) {
    return false;
  }
  return true;
}

bool Privkey::IsValid(const std::vector<uint8_t>& buffer) {
  if (buffer.size() > 0) {
    int ret = wally_ec_private_key_verify(buffer.data(), buffer.size());
    return ret == WALLY_OK;
    // return buffer.size() == kPrivkeySize;
  }
  return false;
}

}  // namespace core
}  // namespace cfd
