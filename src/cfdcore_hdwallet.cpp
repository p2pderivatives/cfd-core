// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_hdwallet.cpp
 *
 * @brief \~japanese BIP32/BIP39/BIP44関連クラスの実装
 *   \~english implementation of BIP32/BIP39/BIP44 classes
 */

#include "cfdcore/cfdcore_hdwallet.h"

#include <cstdlib>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::warn;

// ----------------------------------------------------------------------------
// ファイル内定義
// ----------------------------------------------------------------------------
/// empty seed string (64byte)
static constexpr const char* kEmptySeedStr =
    "00000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000";  // NOLINT

/**
 * @brief Bip32鍵情報の解析を行う。
 * @param[in] extkey              extkey
 * @param[in] base58              base58 data
 * @param[in,out] serialize_data  serialize data
 * @param[out] version            version
 * @param[out] depth              depth
 * @param[out] child              child
 * @param[out] chaincode          chaincode
 * @param[out] privkey            privkey
 * @param[out] pubkey             pubkey
 * @param[out] fingerprint        finger print
 */
static void AnalyzeBip32KeyData(
    const void* extkey, const std::string* base58,
    std::vector<uint8_t>* serialize_data, uint32_t* version, uint8_t* depth,
    uint32_t* child, ByteData256* chaincode, Privkey* privkey, Pubkey* pubkey,
    uint32_t* fingerprint) {
  struct ext_key output = {};
  std::string clsname = (privkey != nullptr) ? "ExtPrivkey" : "ExtPubkey";
  const std::vector<uint8_t>* serialize_bytes = nullptr;
  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN + BASE58_CHECKSUM_LEN);
  int ret;

  if (extkey != nullptr) {
    memcpy(&output, extkey, sizeof(output));
  } else if (base58 != nullptr) {
    size_t written = 0;
    ret = wally_base58_to_bytes(
        base58->c_str(), BASE58_FLAG_CHECKSUM, data.data(), data.size(),
        &written);
    if (ret != WALLY_OK) {
      warn(
          CFD_LOG_SOURCE, "{} wally_base58_to_bytes error. ret={}", clsname,
          ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          clsname + " base58 decode error.");
    }
    data.resize(written);
    serialize_bytes = &data;
    if (serialize_data != nullptr) {
      *serialize_data = data;
    }
  } else {
    serialize_bytes = serialize_data;
  }

  if (serialize_bytes != nullptr) {
    // unserialize
    ret = bip32_key_unserialize(
        serialize_bytes->data(), serialize_bytes->size(), &output);
    if (ret != WALLY_OK) {
      warn(
          CFD_LOG_SOURCE, "{} bip32_key_unserialize error. ret={}", clsname,
          ret);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, clsname + " unserialize error.");
    }
  }

  *version = output.version;
  *depth = output.depth;
  *child = output.child_num;
  if (fingerprint) {
    memcpy(fingerprint, output.parent160, sizeof(*fingerprint));
  }
  std::vector<uint8_t> chaincode_bytes(kByteData256Length);
  memcpy(chaincode_bytes.data(), output.chain_code, chaincode_bytes.size());
  *chaincode = ByteData256(chaincode_bytes);
  if (privkey != nullptr) {
    if (output.priv_key[0] != BIP32_FLAG_KEY_PRIVATE) {
      warn(CFD_LOG_SOURCE, "{} privkey disabled.", clsname);
      throw CfdException(
          CfdError::kCfdIllegalStateError, clsname + " keytype error.");
    }
    // privkey
    std::vector<uint8_t> privkey_bytes(kByteData256Length);
    memcpy(privkey_bytes.data(), &output.priv_key[1], privkey_bytes.size());
    *privkey = Privkey(ByteData256(privkey_bytes));
  } else if (pubkey != nullptr) {
    if (output.priv_key[0] == BIP32_FLAG_KEY_PRIVATE) {
      warn(CFD_LOG_SOURCE, "{} privkey enabled.", clsname);
      throw CfdException(
          CfdError::kCfdIllegalStateError, clsname + " keytype error.");
    }
    std::vector<uint8_t> pubkey_bytes(Pubkey::kCompressedPubkeySize);
    memcpy(pubkey_bytes.data(), output.pub_key, pubkey_bytes.size());
    *pubkey = Pubkey(pubkey_bytes);
  }
}

/**
 * @brief Base58変換を行う。
 * @param[in] serialize_data    serialize data
 * @param[in] caller_name       caller class name
 * @return base58 string
 */
static std::string ToBase58String(
    const ByteData& serialize_data, const std::string& caller_name) {
  char* output = nullptr;
  if (serialize_data.GetDataSize() != BIP32_SERIALIZED_LEN) {
    warn(
        CFD_LOG_SOURCE, "{} serialize_data size illegal. size={}", caller_name,
        serialize_data.GetDataSize());
    throw CfdException(
        CfdError::kCfdIllegalStateError,
        caller_name + " serialize_data size error.");
  }
  int ret = wally_base58_from_bytes(
      serialize_data.GetBytes().data(), BIP32_SERIALIZED_LEN,
      BASE58_FLAG_CHECKSUM, &output);
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "{}, wally_base58_from_bytes error. ret={}",
        caller_name, ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        caller_name + " base58 encode error.");
  }
  return WallyUtil::ConvertStringAndFree(output);
}

/**
 * @brief 文字列パスから配列を取得する。
 * @param[in] string_path       child number string path
 * @param[in] caller_name       caller class name
 * @param[in] depth             current key depth
 * @return uint32_t array
 */
static std::vector<uint32_t> ToArrayFromString(
    const std::string& string_path, const std::string& caller_name,
    uint8_t depth) {
  std::vector<uint32_t> result;
  std::vector<std::string> list = StringUtil::Split(string_path, "/");
  for (size_t index = 0; index < list.size(); ++index) {
    std::string str = list[index];
    bool hardened = false;
    if (str.size() <= 1) {
      // do nothing
    } else if (
        (str.back() == '\'') || (str.back() == 'h') || (str.back() == 'H')) {
      str = str.substr(0, str.size() - 1);
      hardened = true;
    }
    if ((str == "m") || (str == "M")) {
      if (depth != 0) {
        warn(
            CFD_LOG_SOURCE, "{} bip32 path fail. this key is not master key.",
            caller_name);
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            caller_name + " bip32 path fail. this key is not master key.");
      }
      continue;  // master key
    }
    if (str.empty()) {
      if (index == 0) {
        // start slash pattern
        continue;
      } else {
        warn(
            CFD_LOG_SOURCE, "{} bip32 string path fail. empty item.",
            caller_name);
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            caller_name + " bip32 string path fail. empty item.");
      }
    }

    // strtol関数による変換
    char* p_str_end = nullptr;
    uint32_t value;
    if ((str.size() > 2) && (str[0] == '0') && (str[1] == 'x')) {
      value = std::strtoul(str.c_str(), &p_str_end, 16);
    } else {
      value = std::strtoul(str.c_str(), &p_str_end, 10);
    }
    if (str.empty() || ((p_str_end != nullptr) && (*p_str_end != '\0'))) {
      warn(CFD_LOG_SOURCE, "{} bip32 string path fail.", caller_name);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          caller_name + " bip32 string path fail.");
    }
    if (hardened) value |= 0x80000000;
    result.push_back(static_cast<uint32_t>(value));
  }

  if (result.empty()) {
    warn(CFD_LOG_SOURCE, "{} bip32 string path empty.", caller_name);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        caller_name + " bip32 string path empty.");
  }

  return result;
}

// ----------------------------------------------------------------------------
// HDWallet
// ----------------------------------------------------------------------------
HDWallet::HDWallet() : seed_(ByteData(kEmptySeedStr)) {
  // do nothing
}

HDWallet::HDWallet(const ByteData& seed) : seed_(seed) {
  if ((seed.GetDataSize() != HDWallet::kSeed128Size) &&
      (seed.GetDataSize() != HDWallet::kSeed256Size) &&
      (seed.GetDataSize() != HDWallet::kSeed512Size)) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Seed length error.");
  }
}

HDWallet::HDWallet(
    std::vector<std::string> mnemonic, std::string passphrase,
    bool use_ideographic_space)
    : seed_(ByteData(kEmptySeedStr)) {
  seed_ = ConvertMnemonicToSeed(mnemonic, passphrase, use_ideographic_space);
  if ((seed_.GetDataSize() != HDWallet::kSeed128Size) &&
      (seed_.GetDataSize() != HDWallet::kSeed256Size) &&
      (seed_.GetDataSize() != HDWallet::kSeed512Size)) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Seed length error.");
  }
}

ByteData HDWallet::GetSeed() const { return seed_; }

ExtPrivkey HDWallet::GeneratePrivkey(NetType network_type) const {
  return ExtPrivkey(seed_, network_type);
}

ExtPrivkey HDWallet::GeneratePrivkey(
    NetType network_type, uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return GeneratePrivkey(network_type, path);
}

ExtPrivkey HDWallet::GeneratePrivkey(
    NetType network_type, const std::vector<uint32_t>& path) const {
  ExtPrivkey privkey(seed_, network_type);
  return privkey.DerivePrivkey(path);
}

ExtPrivkey HDWallet::GeneratePrivkey(
    NetType network_type, const std::string& string_path) const {
  ExtPrivkey privkey(seed_, network_type);
  return privkey.DerivePrivkey(string_path);
}

ExtPubkey HDWallet::GeneratePubkey(NetType network_type) const {
  ExtPrivkey privkey(seed_, network_type);
  return privkey.GetExtPubkey();
}

ExtPubkey HDWallet::GeneratePubkey(
    NetType network_type, uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return GeneratePubkey(network_type, path);
}

ExtPubkey HDWallet::GeneratePubkey(
    NetType network_type, const std::vector<uint32_t>& path) const {
  ExtPrivkey privkey(seed_, network_type);
  return privkey.DerivePubkey(path);
}

ExtPubkey HDWallet::GeneratePubkey(
    NetType network_type, const std::string& string_path) const {
  ExtPrivkey privkey(seed_, network_type);
  return privkey.DerivePubkey(string_path);
}

std::vector<std::string> HDWallet::GetMnemonicWordlist(
    const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::GetMnemonicWordlist(language);
}

std::vector<std::string> HDWallet::ConvertEntropyToMnemonic(
    const ByteData& entropy, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertEntropyToMnemonic(entropy, language);
}

ByteData HDWallet::ConvertMnemonicToEntropy(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertMnemonicToEntropy(mnemonic, language);
}

bool HDWallet::CheckValidMnemonic(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::CheckValidMnemonic(mnemonic, language);
}

bool HDWallet::CheckSupportedLanguages(const std::string& language) {
  std::vector<std::string> slangs = WallyUtil::GetSupportedMnemonicLanguages();
  return (
      std::find(slangs.cbegin(), slangs.cend(), language) != slangs.cend());
}

ByteData HDWallet::ConvertMnemonicToSeed(
    const std::vector<std::string>& mnemonic, const std::string& passphrase,
    bool use_ideographic_space) {
  return WallyUtil::ConvertMnemonicToSeed(
      mnemonic, passphrase, use_ideographic_space);
}

// ----------------------------------------------------------------------------
// ExtPrivkey
// ----------------------------------------------------------------------------
ExtPrivkey::ExtPrivkey() {
  // do nothing
}

ExtPrivkey::ExtPrivkey(const ByteData& seed, NetType network_type) {
  std::vector<uint8_t> seed_byte = seed.GetBytes();
  if ((seed_byte.size() != HDWallet::kSeed128Size) &&
      (seed_byte.size() != HDWallet::kSeed256Size) &&
      (seed_byte.size() != HDWallet::kSeed512Size)) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey Seed length error.");
  }
  uint32_t version = kVersionTestnetPrivkey;
  if ((network_type == NetType::kMainnet) ||
      (network_type == NetType::kLiquidV1)) {
    version = kVersionMainnetPrivkey;
  }

  struct ext_key extkey;
  int ret = bip32_key_from_seed(
      seed_byte.data(), seed_byte.size(), version, 0, &extkey);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_from_seed error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey gen from seed error.");
  }

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(
      &extkey, BIP32_FLAG_KEY_PRIVATE, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey serialize error.");
  }
  serialize_data_ = ByteData(data);

  AnalyzeBip32KeyData(
      &extkey, nullptr, nullptr, &version_, &depth_, &child_num_, &chaincode_,
      &privkey_, nullptr, &fingerprint_);
}

ExtPrivkey::ExtPrivkey(const ByteData& serialize_data)
    : ExtPrivkey(serialize_data, ByteData256()) {
  // do nothing
}

ExtPrivkey::ExtPrivkey(
    const ByteData& serialize_data, const ByteData256& tweak_sum) {
  // unserialize
  tweak_sum_ = tweak_sum;
  serialize_data_ = serialize_data;
  std::vector<uint8_t> data = serialize_data.GetBytes();
  AnalyzeBip32KeyData(
      nullptr, nullptr, &data, &version_, &depth_, &child_num_, &chaincode_,
      &privkey_, nullptr, &fingerprint_);
}

ExtPrivkey::ExtPrivkey(const std::string& base58_data)
    : ExtPrivkey(base58_data, ByteData256()) {
  // do nothing
}

ExtPrivkey::ExtPrivkey(
    const std::string& base58_data, const ByteData256& tweak_sum) {
  std::vector<uint8_t> data;
  AnalyzeBip32KeyData(
      nullptr, &base58_data, &data, &version_, &depth_, &child_num_,
      &chaincode_, &privkey_, nullptr, &fingerprint_);
  serialize_data_ = ByteData(data);
  tweak_sum_ = tweak_sum;
}

ExtPrivkey::ExtPrivkey(
    NetType network_type, const Privkey& parent_key,
    const ByteData256& parent_chain_code, uint8_t parent_depth,
    uint32_t child_num) {
  if (!parent_key.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid privkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to privkey. ExtPrivkey invalid privkey.");
  }

  // create simple parent data
  struct ext_key parent = {};
  memset(&parent, 0, sizeof(parent));
  parent.version = kVersionTestnetPrivkey;
  if ((network_type == NetType::kMainnet) ||
      (network_type == NetType::kLiquidV1)) {
    parent.version = kVersionMainnetPrivkey;
  }
  parent.depth = parent_depth;
  Pubkey pubkey = parent_key.GeneratePubkey(true);
  std::vector<uint8_t> privkey_bytes = parent_key.GetData().GetBytes();
  std::vector<uint8_t> pubkey_bytes = pubkey.GetData().GetBytes();
  std::vector<uint8_t> pubkey_hash = HashUtil::Hash160(pubkey).GetBytes();
  std::vector<uint8_t> chain_bytes = parent_chain_code.GetData().GetBytes();
  parent.priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
  memcpy(&parent.priv_key[1], privkey_bytes.data(), privkey_bytes.size());
  memcpy(parent.pub_key, pubkey_bytes.data(), pubkey_bytes.size());
  memcpy(parent.hash160, pubkey_hash.data(), pubkey_hash.size());
  memcpy(parent.chain_code, chain_bytes.data(), chain_bytes.size());

  struct ext_key extkey = {};
  memset(&extkey, 0, sizeof(extkey));
  int ret = bip32_key_from_parent(
      &parent, child_num, BIP32_FLAG_KEY_PRIVATE, &extkey);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_from_parent error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPubkey generatekey error.");
  }

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(
      &extkey, BIP32_FLAG_KEY_PRIVATE, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey serialize error.");
  }
  serialize_data_ = ByteData(data);
  tweak_sum_ = ByteData256();

  AnalyzeBip32KeyData(
      &extkey, nullptr, nullptr, &version_, &depth_, &child_num_, &chaincode_,
      &privkey_, nullptr, &fingerprint_);
}

ExtPrivkey::ExtPrivkey(
    NetType network_type, const Privkey& parent_key, const Privkey& privkey,
    const ByteData256& chain_code, uint8_t depth, uint32_t child_num)
    : ExtPrivkey(
          network_type,
          HashUtil::Hash160(parent_key.GeneratePubkey()).GetData(), privkey,
          chain_code, depth, child_num) {
  if (!parent_key.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid privkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to privkey. ExtPrivkey invalid privkey.");
  }
}

ExtPrivkey::ExtPrivkey(
    NetType network_type, const ByteData& parent_fingerprint,
    const Privkey& privkey, const ByteData256& chain_code, uint8_t depth,
    uint32_t child_num) {
  if (!privkey.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid privkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to privkey. ExtPrivkey invalid privkey.");
  }

  // create simple parent data
  struct ext_key extkey = {};
  memset(&extkey, 0, sizeof(extkey));
  extkey.version = kVersionTestnetPrivkey;
  if ((network_type == NetType::kMainnet) ||
      (network_type == NetType::kLiquidV1)) {
    extkey.version = kVersionMainnetPrivkey;
  }
  extkey.depth = depth;
  extkey.child_num = child_num;
  Pubkey pubkey = privkey.GeneratePubkey(true);
  std::vector<uint8_t> privkey_bytes = privkey.GetData().GetBytes();
  std::vector<uint8_t> pubkey_bytes = pubkey.GetData().GetBytes();
  std::vector<uint8_t> pubkey_hash = HashUtil::Hash160(pubkey).GetBytes();
  std::vector<uint8_t> fingerprint_bytes = parent_fingerprint.GetBytes();
  std::vector<uint8_t> chain_bytes = chain_code.GetData().GetBytes();
  extkey.priv_key[0] = BIP32_FLAG_KEY_PRIVATE;
  memcpy(&extkey.priv_key[1], privkey_bytes.data(), privkey_bytes.size());
  memcpy(extkey.pub_key, pubkey_bytes.data(), pubkey_bytes.size());
  // parent160: use top 4-byte only
  fingerprint_bytes.resize(4);
  memcpy(extkey.parent160, fingerprint_bytes.data(), fingerprint_bytes.size());
  memcpy(extkey.hash160, pubkey_hash.data(), pubkey_hash.size());
  memcpy(extkey.chain_code, chain_bytes.data(), chain_bytes.size());

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  int ret = bip32_key_serialize(
      &extkey, BIP32_FLAG_KEY_PRIVATE, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey serialize error.");
  }
  serialize_data_ = ByteData(data);
  tweak_sum_ = ByteData256();

  AnalyzeBip32KeyData(
      &extkey, nullptr, nullptr, &version_, &depth_, &child_num_, &chaincode_,
      &privkey_, nullptr, &fingerprint_);
}

ByteData ExtPrivkey::GetData() const { return serialize_data_; }

std::string ExtPrivkey::ToString() const {
  return ToBase58String(serialize_data_, "ExtPrivkey");
}

Privkey ExtPrivkey::GetPrivkey() const { return privkey_; }

ExtPrivkey ExtPrivkey::DerivePrivkey(uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return DerivePrivkey(path);
}

ExtPrivkey ExtPrivkey::DerivePrivkey(const std::vector<uint32_t>& path) const {
  struct ext_key extkey;
  struct ext_key child_key;

  const std::vector<uint8_t>& serialize_data = serialize_data_.GetBytes();
  int ret = bip32_key_unserialize(
      serialize_data.data(), serialize_data.size(), &extkey);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_unserialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey unserialize error.");
  }

#ifndef CFD_DISABLE_ELEMENTS
  // write pub_key_tweak_sum to ext_key
  memcpy(
      extkey.pub_key_tweak_sum, tweak_sum_.GetBytes().data(),
      sizeof(extkey.pub_key_tweak_sum));
#endif  // CFD_DISABLE_ELEMENTS
  uint32_t flag = BIP32_FLAG_KEY_PRIVATE;
  ret = bip32_key_from_parent_path(
      &extkey, path.data(), path.size(), flag | BIP32_FLAG_KEY_TWEAK_SUM,
      &child_key);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_from_parent_path error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey derive error.");
  }

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(&child_key, flag, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey serialize error.");
  }

  ByteData256 tweak_sum_data;
#ifndef CFD_DISABLE_ELEMENTS
  // collect pub_key_tweak_sum from ext_key
  std::vector<uint8_t> tweak_sum(sizeof(extkey.pub_key_tweak_sum));
  memcpy(tweak_sum.data(), extkey.pub_key_tweak_sum, tweak_sum.size());
  tweak_sum_data = ByteData256(tweak_sum);
#endif  // CFD_DISABLE_ELEMENTS
  return ExtPrivkey(ByteData(data), tweak_sum_data);
}

ExtPrivkey ExtPrivkey::DerivePrivkey(const std::string& string_path) const {
  std::vector<uint32_t> path =
      ToArrayFromString(string_path, "ExtPrivkey", depth_);
  return DerivePrivkey(path);
}

ExtPubkey ExtPrivkey::GetExtPubkey() const {
  struct ext_key extkey;

  const std::vector<uint8_t>& serialize_data = serialize_data_.GetBytes();
  int ret = bip32_key_unserialize(
      serialize_data.data(), serialize_data.size(), &extkey);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_unserialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey unserialize error.");
  }

  // copy data
  extkey.priv_key[0] = BIP32_FLAG_KEY_PUBLIC;
  // その他設定の上書きはlibwallyに任せる

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(
      &extkey, BIP32_FLAG_KEY_PUBLIC, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(
        CFD_LOG_SOURCE, "GetExtPubkey bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "ExtPrivkey Pubkey serialize error.");
  }

  return ExtPubkey(ByteData(data), tweak_sum_);
}

ExtPubkey ExtPrivkey::DerivePubkey(uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return DerivePubkey(path);
}

ExtPubkey ExtPrivkey::DerivePubkey(const std::vector<uint32_t>& path) const {
  ExtPrivkey privkey = DerivePrivkey(path);
  return privkey.GetExtPubkey();
}

ExtPubkey ExtPrivkey::DerivePubkey(const std::string& string_path) const {
  ExtPrivkey privkey = DerivePrivkey(string_path);
  return privkey.GetExtPubkey();
}

bool ExtPrivkey::IsValid() const { return privkey_.IsValid(); }

ByteData256 ExtPrivkey::GetChainCode() const { return chaincode_; }

uint32_t ExtPrivkey::GetVersion() const { return version_; }

uint8_t ExtPrivkey::GetDepth() const { return depth_; }

uint32_t ExtPrivkey::GetChildNum() const { return child_num_; }

ByteData ExtPrivkey::GetVersionData() const {
  std::vector<uint8_t> byte_data(4);
  byte_data[0] = (version_ >> 24) & 0xff;
  byte_data[1] = (version_ >> 16) & 0xff;
  byte_data[2] = (version_ >> 8) & 0xff;
  byte_data[3] = version_ & 0xff;
  return ByteData(byte_data);
}

uint32_t ExtPrivkey::GetFingerprint() const { return fingerprint_; }

ByteData ExtPrivkey::GetFingerprintData() const {
  std::vector<uint8_t> byte_data(4);
  byte_data[3] = (fingerprint_ >> 24) & 0xff;
  byte_data[2] = (fingerprint_ >> 16) & 0xff;
  byte_data[1] = (fingerprint_ >> 8) & 0xff;
  byte_data[0] = fingerprint_ & 0xff;
  return ByteData(byte_data);
}

ByteData256 ExtPrivkey::GetPubTweakSum() const { return tweak_sum_; }

NetType ExtPrivkey::GetNetworkType() const {
  if (version_ == ExtPrivkey::kVersionMainnetPrivkey) {
    return NetType::kMainnet;
  }
  return NetType::kTestnet;
}

// ----------------------------------------------------------------------------
// ExtPubkey
// ----------------------------------------------------------------------------
ExtPubkey::ExtPubkey() {
  // do nothing
}

ExtPubkey::ExtPubkey(const ByteData& serialize_data)
    : ExtPubkey(serialize_data, ByteData256()) {
  // do nothing
}

ExtPubkey::ExtPubkey(
    const ByteData& serialize_data, const ByteData256& tweak_sum) {
  // unserialize
  tweak_sum_ = tweak_sum;
  serialize_data_ = serialize_data;
  std::vector<uint8_t> data = serialize_data.GetBytes();
  AnalyzeBip32KeyData(
      nullptr, nullptr, &data, &version_, &depth_, &child_num_, &chaincode_,
      nullptr, &pubkey_, &fingerprint_);
}

ExtPubkey::ExtPubkey(const std::string& base58_data)
    : ExtPubkey(base58_data, ByteData256()) {
  // do nothing
}

ExtPubkey::ExtPubkey(
    const std::string& base58_data, const ByteData256& tweak_sum) {
  std::vector<uint8_t> data;
  AnalyzeBip32KeyData(
      nullptr, &base58_data, &data, &version_, &depth_, &child_num_,
      &chaincode_, nullptr, &pubkey_, &fingerprint_);
  serialize_data_ = ByteData(data);
  tweak_sum_ = tweak_sum;
}

ExtPubkey::ExtPubkey(
    NetType network_type, const Pubkey& parent_key,
    const ByteData256& parent_chain_code, uint8_t parent_depth,
    uint32_t child_num) {
  if (!parent_key.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid pubkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to pubkey. ExtPubkey invalid pubkey.");
  }
  Pubkey key = parent_key;
  if (!key.IsCompress()) {
    key = key.Compress();
  }

  // create simple parent data
  struct ext_key parent = {};
  memset(&parent, 0, sizeof(parent));
  parent.version = kVersionTestnetPubkey;
  if ((network_type == NetType::kMainnet) ||
      (network_type == NetType::kLiquidV1)) {
    parent.version = kVersionMainnetPubkey;
  }
  parent.depth = parent_depth;
  parent.priv_key[0] = BIP32_FLAG_KEY_PUBLIC;
  std::vector<uint8_t> pubkey_bytes = key.GetData().GetBytes();
  std::vector<uint8_t> pubkey_hash = HashUtil::Hash160(key).GetBytes();
  std::vector<uint8_t> chain_bytes = parent_chain_code.GetData().GetBytes();
  memcpy(parent.pub_key, pubkey_bytes.data(), pubkey_bytes.size());
  memcpy(parent.hash160, pubkey_hash.data(), pubkey_hash.size());
  memcpy(parent.chain_code, chain_bytes.data(), chain_bytes.size());

  struct ext_key extkey = {};
  memset(&extkey, 0, sizeof(extkey));
  int ret = bip32_key_from_parent(
      &parent, child_num, BIP32_FLAG_KEY_PUBLIC, &extkey);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_from_parent error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPubkey generatekey error.");
  }

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(
      &extkey, BIP32_FLAG_KEY_PUBLIC, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey serialize error.");
  }
  serialize_data_ = ByteData(data);
  tweak_sum_ = ByteData256();

  AnalyzeBip32KeyData(
      &extkey, nullptr, nullptr, &version_, &depth_, &child_num_, &chaincode_,
      nullptr, &pubkey_, &fingerprint_);
}

ExtPubkey::ExtPubkey(
    NetType network_type, const Pubkey& parent_key, const Pubkey& pubkey,
    const ByteData256& chain_code, uint8_t depth, uint32_t child_num)
    : ExtPubkey(
          network_type, HashUtil::Hash160(parent_key).GetData(), pubkey,
          chain_code, depth, child_num) {
  if (!parent_key.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid pubkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to pubkey. ExtPubkey invalid pubkey.");
  }
}

ExtPubkey::ExtPubkey(
    NetType network_type, const ByteData& parent_fingerprint,
    const Pubkey& pubkey, const ByteData256& chain_code, uint8_t depth,
    uint32_t child_num) {
  if (!pubkey.IsValid()) {
    warn(CFD_LOG_SOURCE, "invalid pubkey.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to pubkey. ExtPubkey invalid pubkey.");
  }
  Pubkey key = pubkey;
  if (!key.IsCompress()) {
    key = key.Compress();
  }

  // create simple parent data
  struct ext_key extkey = {};
  memset(&extkey, 0, sizeof(extkey));
  extkey.version = kVersionTestnetPubkey;
  if ((network_type == NetType::kMainnet) ||
      (network_type == NetType::kLiquidV1)) {
    extkey.version = kVersionMainnetPubkey;
  }
  extkey.depth = depth;
  extkey.child_num = child_num;
  extkey.priv_key[0] = BIP32_FLAG_KEY_PUBLIC;
  std::vector<uint8_t> pubkey_bytes = key.GetData().GetBytes();
  std::vector<uint8_t> pubkey_hash = HashUtil::Hash160(key).GetBytes();
  std::vector<uint8_t> fingerprint_bytes = parent_fingerprint.GetBytes();
  std::vector<uint8_t> chain_bytes = chain_code.GetData().GetBytes();
  memcpy(extkey.pub_key, pubkey_bytes.data(), pubkey_bytes.size());
  // parent160: use top 4-byte only
  fingerprint_bytes.resize(4);
  memcpy(extkey.parent160, fingerprint_bytes.data(), fingerprint_bytes.size());
  memcpy(extkey.hash160, pubkey_hash.data(), pubkey_hash.size());
  memcpy(extkey.chain_code, chain_bytes.data(), chain_bytes.size());

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  int ret = bip32_key_serialize(
      &extkey, BIP32_FLAG_KEY_PUBLIC, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPrivkey serialize error.");
  }
  serialize_data_ = ByteData(data);
  tweak_sum_ = ByteData256();

  AnalyzeBip32KeyData(
      &extkey, nullptr, nullptr, &version_, &depth_, &child_num_, &chaincode_,
      nullptr, &pubkey_, &fingerprint_);

#ifndef CFD_DISABLE_ELEMENTS
  // collect pub_key_tweak_sum from ext_key
  std::vector<uint8_t> tweak_sum(sizeof(extkey.pub_key_tweak_sum));
  memcpy(tweak_sum.data(), extkey.pub_key_tweak_sum, tweak_sum.size());
  tweak_sum_ = ByteData256(tweak_sum);
#endif  // CFD_DISABLE_ELEMENTS
}

ByteData ExtPubkey::GetData() const { return serialize_data_; }

std::string ExtPubkey::ToString() const {
  return ToBase58String(serialize_data_, "ExtPubkey");
}

Pubkey ExtPubkey::GetPubkey() const { return pubkey_; }

ExtPubkey ExtPubkey::DerivePubkey(uint32_t child_num) const {
  std::vector<uint32_t> path = {child_num};
  return DerivePubkey(path);
}

ExtPubkey ExtPubkey::DerivePubkey(const std::vector<uint32_t>& path) const {
  struct ext_key extkey;
  struct ext_key child_key;

  const std::vector<uint8_t>& serialize_data = serialize_data_.GetBytes();
  int ret = bip32_key_unserialize(
      serialize_data.data(), serialize_data.size(), &extkey);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_unserialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPubkey unserialize error.");
  }

#ifndef CFD_DISABLE_ELEMENTS
  // write pub_key_tweak_sum to ext_key
  memcpy(
      extkey.pub_key_tweak_sum, tweak_sum_.GetBytes().data(),
      sizeof(extkey.pub_key_tweak_sum));
#endif  // CFD_DISABLE_ELEMENTS
  uint32_t flag = BIP32_FLAG_KEY_PUBLIC;
  ret = bip32_key_from_parent_path(
      &extkey, path.data(), path.size(), flag | BIP32_FLAG_KEY_TWEAK_SUM,
      &child_key);
  if (ret != WALLY_OK) {
    // hardened check
    for (const auto& value : path) {
      if ((value & ExtPrivkey::kHardenedKey) != 0) {
        warn(
            CFD_LOG_SOURCE,
            "bip32_key_from_parent_path error. ret={} hardened=true", ret);
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "ExtPubkey hardened derive error.");
      }
    }
    warn(CFD_LOG_SOURCE, "bip32_key_from_parent_path error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPubkey derive error.");
  }

  std::vector<uint8_t> data(BIP32_SERIALIZED_LEN);
  ret = bip32_key_serialize(&child_key, flag, data.data(), data.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "bip32_key_serialize error. ret={}", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "ExtPubkey serialize error.");
  }

  ByteData256 tweak_sum_data;
#ifndef CFD_DISABLE_ELEMENTS
  // collect pub_key_tweak_sum from ext_key
  std::vector<uint8_t> tweak_sum(sizeof(child_key.pub_key_tweak_sum));
  memcpy(tweak_sum.data(), child_key.pub_key_tweak_sum, tweak_sum.size());
  tweak_sum_data = ByteData256(tweak_sum);
#endif  // CFD_DISABLE_ELEMENTS
  return ExtPubkey(ByteData(data), tweak_sum_data);
}

ExtPubkey ExtPubkey::DerivePubkey(const std::string& string_path) const {
  std::vector<uint32_t> path =
      ToArrayFromString(string_path, "ExtPubkey", depth_);
  return DerivePubkey(path);
}

ByteData256 ExtPubkey::DerivePubTweak(
    const std::vector<uint32_t>& path) const {
  ExtPubkey key = DerivePubkey(path);
  return key.GetPubTweakSum();
}

ByteData256 ExtPubkey::GetPubTweakSum() const { return tweak_sum_; }

bool ExtPubkey::IsValid() const { return pubkey_.IsValid(); }

ByteData256 ExtPubkey::GetChainCode() const { return chaincode_; }

uint32_t ExtPubkey::GetVersion() const { return version_; }

uint8_t ExtPubkey::GetDepth() const { return depth_; }

uint32_t ExtPubkey::GetChildNum() const { return child_num_; }

ByteData ExtPubkey::GetVersionData() const {
  std::vector<uint8_t> byte_data(4);
  byte_data[0] = (version_ >> 24) & 0xff;
  byte_data[1] = (version_ >> 16) & 0xff;
  byte_data[2] = (version_ >> 8) & 0xff;
  byte_data[3] = version_ & 0xff;
  return ByteData(byte_data);
}

uint32_t ExtPubkey::GetFingerprint() const { return fingerprint_; }

ByteData ExtPubkey::GetFingerprintData() const {
  std::vector<uint8_t> byte_data(4);
  byte_data[3] = (fingerprint_ >> 24) & 0xff;
  byte_data[2] = (fingerprint_ >> 16) & 0xff;
  byte_data[1] = (fingerprint_ >> 8) & 0xff;
  byte_data[0] = fingerprint_ & 0xff;
  return ByteData(byte_data);
}

NetType ExtPubkey::GetNetworkType() const {
  if (version_ == ExtPubkey::kVersionMainnetPubkey) {
    return NetType::kMainnet;
  }
  return NetType::kTestnet;
}

}  // namespace core
}  // namespace cfd
