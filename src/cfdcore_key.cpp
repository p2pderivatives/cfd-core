// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_key.cpp
 *
 * @brief-eng definition for Pubkey/Privkey class
 * @brief-jp Pubkey/Privkey関連クラス定義
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
  // TODO(MariSoejima) review valid conditions / valid条件見直し要
  if (buffer.size() > 0) {
    return buffer.size() == kPrivkeySize;
  }
  return false;
}

// ----------------------------------------------------------------------------
// ExtKey
// ----------------------------------------------------------------------------

ExtKey::ExtKey() {
  // do nothing
}

ExtKey::ExtKey(const ByteData& serialize_data) {
  // unserialize
  const std::vector<uint8_t>& data = serialize_data.GetBytes();
  struct ext_key output;
  int ret = bip32_key_unserialize(data.data(), data.size(), &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_unserialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey unserialize error.");
  }
  serialize_data_ = serialize_data;
  prefix_ = ByteData(std::vector<uint8_t>(data.data(), data.data() + 4));
  depth_ = output.depth;
  child_ = output.child_num;
  std::vector<uint8_t> chaincode(kByteData256Length);
  memcpy(chaincode.data(), output.chain_code, chaincode.size());
  chaincode_ = ByteData256(chaincode);
  if (output.priv_key[0] == BIP32_FLAG_KEY_PRIVATE) {
    // privkey
    std::vector<uint8_t> privkey(kByteData256Length);
    memcpy(privkey.data(), &output.priv_key[1], privkey.size());
    privkey_ = Privkey(ByteData256(privkey));
  }
  std::vector<uint8_t> pubkey(Pubkey::kCompressedPubkeySize);
  memcpy(pubkey.data(), output.pub_key, pubkey.size());
  pubkey_ = Pubkey(pubkey);
}

ExtKey::ExtKey(const std::string& base58_data) {
  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN + BASE58_CHECKSUM_LEN);
  size_t written = 0;
  int ret = wally_base58_to_bytes(
      base58_data.data(), BASE58_FLAG_CHECKSUM, data.data(), data.size(),
      &written);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_to_bytes error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey base58 decode error.");
  }
  data.resize(written);

  struct ext_key output;
  ret = bip32_key_unserialize(data.data(), written, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_unserialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey unserialize error.");
  }
  serialize_data_ = ByteData(data);
  prefix_ = ByteData(std::vector<uint8_t>(data.data(), data.data() + 4));
  depth_ = output.depth;
  child_ = output.child_num;
  std::vector<uint8_t> chaincode(kByteData256Length);
  memcpy(chaincode.data(), output.chain_code, chaincode.size());
  chaincode_ = ByteData256(chaincode);
  if (output.priv_key[0] == BIP32_FLAG_KEY_PRIVATE) {
    // privkey
    std::vector<uint8_t> privkey(kByteData256Length);
    memcpy(privkey.data(), &output.priv_key[1], privkey.size());
    privkey_ = Privkey(ByteData256(privkey));
  }
  std::vector<uint8_t> pubkey(Pubkey::kCompressedPubkeySize);
  memcpy(pubkey.data(), output.pub_key, pubkey.size());
  pubkey_ = Pubkey(pubkey);
}

ExtKey::ExtKey(const ByteData& seed, uint32_t prefix) {
  std::vector<uint8_t> seed_byte = seed.GetBytes();
  if ((seed_byte.size() != kSeed128Size) &&
      (seed_byte.size() != kSeed256Size) &&
      (seed_byte.size() != kSeed512Size)) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Seed length error.");
  }

  struct ext_key output;
  int ret = bip32_key_from_seed(
      seed_byte.data(), seed_byte.size(), prefix, 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_from_seed error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey gen from seed error.");
  }

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(&output, 0, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey serialize error.");
  }

  serialize_data_ = ByteData(data);
  prefix_ = ByteData(std::vector<uint8_t>(data.data(), data.data() + 4));
  depth_ = output.depth;
  child_ = output.child_num;
  std::vector<uint8_t> chaincode(kByteData256Length);
  memcpy(chaincode.data(), output.chain_code, chaincode.size());
  chaincode_ = ByteData256(chaincode);
  if (output.priv_key[0] == BIP32_FLAG_KEY_PRIVATE) {
    // privkey
    std::vector<uint8_t> privkey(kByteData256Length);
    memcpy(privkey.data(), &output.priv_key[1], privkey.size());
    privkey_ = Privkey(ByteData256(privkey));
  }
  std::vector<uint8_t> pubkey(Pubkey::kCompressedPubkeySize);
  memcpy(pubkey.data(), output.pub_key, pubkey.size());
  pubkey_ = Pubkey(pubkey);
}

bool ExtKey::IsPrivkey() const { return !privkey_.IsInvalid(); }

ByteData ExtKey::GetData() const { return serialize_data_; }

std::string ExtKey::GetBase58String() const {
  char* output = nullptr;
  int ret = wally_base58_from_bytes(
      serialize_data_.GetBytes().data(), BIP32_SERIALIZED_LEN,
      BASE58_FLAG_CHECKSUM, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey base58 encode error.");
  }
  return WallyUtil::ConvertStringAndFree(output);
}

ByteData ExtKey::GetPrefix() const { return prefix_; }

uint8_t ExtKey::GetDepth() const { return depth_; }

Pubkey ExtKey::GetPubkey() const { return pubkey_; }

Privkey ExtKey::GetPrivkey() const { return privkey_; }

bool ExtKey::IsInvalid() const {
  return privkey_.IsInvalid() && (!pubkey_.IsValid());
}

ExtKey ExtKey::DerivePubkey(uint32_t child_num) const {
  if (IsInvalid() || (!pubkey_.IsValid())) {
    warn(CFD_LOG_SOURCE, "Invalid Pubkey data.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid Pubkey data.");
  }
  if (pubkey_.GetData().GetDataSize() != Pubkey::kCompressedPubkeySize) {
    warn(CFD_LOG_SOURCE, "Pubkey uncompress.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Pubkey uncompress.");
  }

  uint32_t flag = BIP32_FLAG_KEY_PUBLIC;
  const std::vector<uint8_t>& data = serialize_data_.GetBytes();
  struct ext_key parent;
  int ret = bip32_key_unserialize(data.data(), data.size(), &parent);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_unserialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey unserialize error.");
  }

  struct ext_key child;
  ret = bip32_key_from_parent(&parent, child_num, flag, &child);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_from_parent error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey from parent error.");
  }

  std::vector<uint8_t> serial(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(&child, flag, serial.data(), serial.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtKey serialize error.");
  }

  return ExtKey(ByteData(serial));
}

ByteData256 ExtKey::DerivePubTweak(
    const std::vector<uint32_t>& key_paths) const {
  ByteData256 tweak_sum;
  ByteData256 tweak;
  ExtKey target = *this;
  ExtKey child;
  ByteData256 tweak_result;
  for (const uint32_t key_path : key_paths) {
    child = target.DerivePubkey(key_path);
    tweak = target.GetDerivePubkeyTweak(key_path);
    target = child;
    tweak_sum = WallyUtil::AddTweakPrivkey(tweak_sum, tweak);
  }
  return tweak_sum;
}

ByteData256 ExtKey::GetDerivePubkeyTweak(uint32_t child_num) const {
  std::vector<uint8_t> child_num_byte(4);
  // cpu_to_be32(child_num);
  child_num_byte[0] = (child_num >> 24) & 0xff;
  child_num_byte[1] = (child_num >> 16) & 0xff;
  child_num_byte[2] = (child_num >> 8) & 0xff;
  child_num_byte[3] = child_num & 0xff;

  const std::vector<uint8_t>& pubkey = pubkey_.GetData().GetBytes();
  std::vector<uint8_t> tweak(Privkey::kPrivkeySize);
  std::vector<uint8_t> key(32);
  std::vector<uint8_t> message(37);  // pubkey + uint32_t
  memcpy(key.data(), chaincode_.GetBytes().data(), key.size());
  memcpy(message.data(), pubkey.data(), pubkey.size());
  memcpy(&message[pubkey.size()], child_num_byte.data(), sizeof(child_num));

  ByteData data = CryptoUtil::HmacSha512(key, ByteData(message));
  memcpy(tweak.data(), data.GetBytes().data(), tweak.size());
  return ByteData256(tweak);
}

}  // namespace core
}  // namespace cfd
