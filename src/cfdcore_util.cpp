// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_util.cpp
 *
 * @brief \~japanese Utility関連クラス定義
 *   \~english definition related to Utility classes
 */

#include "cfdcore/cfdcore_util.h"

#include <iterator>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::warn;

//////////////////////////////////
/// SigHashType
//////////////////////////////////
SigHashType::SigHashType()
    : hash_algorithm_(SigHashAlgorithm::kSigHashAll),
      is_anyone_can_pay_(false),
      is_fork_id_(false) {
  // nothing
}

SigHashType::SigHashType(
    SigHashAlgorithm algorithm, bool is_anyone_can_pay, bool is_fork_id)
    : hash_algorithm_(algorithm),
      is_anyone_can_pay_(is_anyone_can_pay),
      is_fork_id_(is_fork_id) {
  // nothing
}

SigHashType::SigHashType(const SigHashType &sighash_type) {
  hash_algorithm_ = sighash_type.hash_algorithm_;
  is_anyone_can_pay_ = sighash_type.is_anyone_can_pay_;
  is_fork_id_ = sighash_type.is_fork_id_;
}

SigHashType &SigHashType::operator=(const SigHashType &sighash_type) {
  hash_algorithm_ = sighash_type.hash_algorithm_;
  is_anyone_can_pay_ = sighash_type.is_anyone_can_pay_;
  is_fork_id_ = sighash_type.is_fork_id_;
  return *this;
}

uint32_t SigHashType::GetSigHashFlag() const {
  uint32_t flag = hash_algorithm_;
  if (is_anyone_can_pay_) {
    flag |= kSigHashAnyOneCanPay;
  }
  if (is_fork_id_) {
    flag |= kSigHashForkId;
  }
  return flag;
}

SigHashAlgorithm SigHashType::GetSigHashAlgorithm() const {
  return hash_algorithm_;
}

bool SigHashType::IsAnyoneCanPay() const { return is_anyone_can_pay_; }

bool SigHashType::IsForkId() const { return is_fork_id_; }

void SigHashType::SetFromSigHashFlag(uint8_t flag) {
  uint32_t sighash_byte = flag;
  bool is_anyone_can_pay = false;
  bool is_fork_id = false;
  if (sighash_byte & SigHashType::kSigHashAnyOneCanPay) {
    sighash_byte &= ~kSigHashAnyOneCanPay;
    is_anyone_can_pay = true;
  }
  if (sighash_byte & SigHashType::kSigHashForkId) {
    sighash_byte &= ~kSigHashForkId;
    is_fork_id = true;
  }
  hash_algorithm_ = static_cast<SigHashAlgorithm>(sighash_byte);
  is_anyone_can_pay_ = is_anyone_can_pay;
  is_fork_id_ = is_fork_id;
}

//////////////////////////////////
/// HashUtil
//////////////////////////////////
// Hash160 -----------------------------------------------------------------
ByteData160 HashUtil::Hash160(const std::string &str) {
  std::vector<uint8_t> output(HASH160_LEN);

  // Hash160
  int ret = wally_hash160(
      reinterpret_cast<const uint8_t *>(str.data()), str.size(), output.data(),
      output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_hash160 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "hash160 calc error.");
  }

  ByteData160 byte160(output);
  return byte160;
}

ByteData160 HashUtil::Hash160(const std::vector<uint8_t> &bytes) {
  std::vector<uint8_t> output(HASH160_LEN);

  // Hash160
  int ret =
      wally_hash160(bytes.data(), bytes.size(), output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_hash160 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "hash160 calc error.");
  }

  ByteData160 byte160(output);
  return byte160;
}

ByteData160 HashUtil::Hash160(const ByteData &data) {
  return Hash160(data.GetBytes());
}

ByteData160 HashUtil::Hash160(const ByteData160 &data) {
  return Hash160(data.GetBytes());
}

ByteData160 HashUtil::Hash160(const ByteData256 &data) {
  return Hash160(data.GetBytes());
}

ByteData160 HashUtil::Hash160(const Pubkey &pubkey) {
  return Hash160(pubkey.GetData().GetBytes());
}

ByteData160 HashUtil::Hash160(const Script &script) {
  return Hash160(script.GetData().GetBytes());
}

// Sha256 -----------------------------------------------------------------
ByteData256 HashUtil::Sha256(const std::string &str) {
  std::vector<uint8_t> output(SHA256_LEN);

  // SHA256
  int ret = wally_sha256(
      reinterpret_cast<const uint8_t *>(str.data()), str.size(), output.data(),
      output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_sha256 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "sha256 calc error.");
  }

  return ByteData256(output);
}

ByteData256 HashUtil::Sha256(const std::vector<uint8_t> &bytes) {
  std::vector<uint8_t> output(SHA256_LEN);

  // SHA256
  int ret =
      wally_sha256(bytes.data(), bytes.size(), output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_sha256 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "sha256 calc error.");
  }

  return ByteData256(output);
}

ByteData256 HashUtil::Sha256(const ByteData &data) {
  return Sha256(data.GetBytes());
}

ByteData256 HashUtil::Sha256(const ByteData160 &data) {
  return Sha256(data.GetBytes());
}

ByteData256 HashUtil::Sha256(const ByteData256 &data) {
  return Sha256(data.GetBytes());
}

ByteData256 HashUtil::Sha256(const Pubkey &pubkey) {
  return Sha256(pubkey.GetData().GetBytes());
}

ByteData256 HashUtil::Sha256(const Script &script) {
  return Sha256(script.GetData().GetBytes());
}

// Sha256D -----------------------------------------------------------------
ByteData256 HashUtil::Sha256D(const std::string &str) {
  std::vector<uint8_t> output(SHA256_LEN);

  // SHA256D
  int ret = wally_sha256d(
      reinterpret_cast<const uint8_t *>(str.data()), str.size(), output.data(),
      output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_sha256d NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "sha256d calc error.");
  }

  return ByteData256(output);
}

ByteData256 HashUtil::Sha256D(const std::vector<uint8_t> &bytes) {
  std::vector<uint8_t> output(SHA256_LEN);

  // SHA256D
  int ret =
      wally_sha256d(bytes.data(), bytes.size(), output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_sha256d NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "sha256d calc error.");
  }

  return ByteData256(output);
}

ByteData256 HashUtil::Sha256D(const ByteData &data) {
  return Sha256D(data.GetBytes());
}

ByteData256 HashUtil::Sha256D(const ByteData160 &data) {
  return Sha256D(data.GetBytes());
}

ByteData256 HashUtil::Sha256D(const ByteData256 &data) {
  return Sha256D(data.GetBytes());
}

ByteData256 HashUtil::Sha256D(const Pubkey &pubkey) {
  return Sha256D(pubkey.GetData());
}

ByteData256 HashUtil::Sha256D(const Script &script) {
  return Sha256D(script.GetData());
}

// Sha512 -----------------------------------------------------------------
ByteData HashUtil::Sha512(const std::string &str) {
  std::vector<uint8_t> output(SHA512_LEN);

  // SHA512
  int ret = wally_sha512(
      reinterpret_cast<const uint8_t *>(str.data()), str.size(), output.data(),
      output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_sha512 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "sha512 calc error.");
  }

  return ByteData(output);
}

ByteData HashUtil::Sha512(const std::vector<uint8_t> &bytes) {
  std::vector<uint8_t> output(SHA512_LEN);

  // SHA512
  int ret =
      wally_sha512(bytes.data(), bytes.size(), output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_sha512 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "sha512 calc error.");
  }

  return ByteData(output);
}

ByteData HashUtil::Sha512(const ByteData &data) {
  return Sha512(data.GetBytes());
}

ByteData HashUtil::Sha512(const ByteData160 &data) {
  return Sha512(data.GetBytes());
}

ByteData HashUtil::Sha512(const ByteData256 &data) {
  return Sha512(data.GetBytes());
}

ByteData HashUtil::Sha512(const Pubkey &pubkey) {
  return Sha512(pubkey.GetData());
}

ByteData HashUtil::Sha512(const Script &script) {
  return Sha512(script.GetData());
}

//////////////////////////////////
/// CrytoUtil
//////////////////////////////////
ByteData CryptoUtil::EncryptAes256(
    const std::vector<uint8_t> &key, const std::string &data) {
  if (key.size() != AES_KEY_LEN_256) {
    warn(CFD_LOG_SOURCE, "wally_aes key size NG.");
    throw CfdException(kCfdIllegalStateError, "EncryptAes256 key size error.");
  }

  size_t data_size = data.size();
  if (data.size() % kAesBlockLength != 0) {
    data_size = (((data.size() / kAesBlockLength) + 1) * kAesBlockLength);
  }
  std::vector<uint8_t> input(data_size);
  std::vector<uint8_t> output(data_size);

  // To fill the end with 0
  memcpy(
      input.data(), reinterpret_cast<const uint8_t *>(data.data()),
      data.size());

  // Encrypt data using AES (ECB mode, no padding).
  int ret = wally_aes(
      key.data(), key.size(), input.data(), input.size(), AES_FLAG_ENCRYPT,
      output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_aes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "EncryptAes256 error.");
  }

  return ByteData(output);
}

std::string CryptoUtil::DecryptAes256ToString(
    const std::vector<uint8_t> &key, const ByteData &data) {
  if (key.size() != AES_KEY_LEN_256) {
    warn(CFD_LOG_SOURCE, "wally_aes key size NG.");
    throw CfdException(kCfdIllegalStateError, "DecryptAes256 key size error.");
  }

  std::vector<uint8_t> output(data.GetDataSize());

  // Encrypt data using AES (ECB mode, no padding).
  int ret = wally_aes(
      key.data(), key.size(), data.GetBytes().data(), data.GetDataSize(),
      AES_FLAG_DECRYPT, output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_aes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "DecryptAes256 error.");
  }

  std::string ret_str;
  ret_str.append(reinterpret_cast<const char *>(output.data()), output.size());
  return ret_str;
}

ByteData CryptoUtil::EncryptAes256Cbc(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
    const std::string &data) {
  ByteData byte_data(
      reinterpret_cast<const uint8_t *>(data.data()),
      static_cast<uint32_t>(data.size()));
  return EncryptAes256Cbc(ByteData(key), ByteData(iv), byte_data);
}

ByteData CryptoUtil::EncryptAes256Cbc(
    const ByteData &key, const ByteData &iv, const ByteData &data) {
  if (key.GetDataSize() != AES_KEY_LEN_256) {
    warn(CFD_LOG_SOURCE, "wally_aes key size NG.");
    throw CfdException(
        kCfdIllegalStateError, "EncryptAes256Cbc key size error.");
  }

  if (data.IsEmpty()) {
    warn(CFD_LOG_SOURCE, "wally_aes data is Empty.");
    throw CfdException(
        kCfdIllegalStateError, "EncryptAes256Cbc data isEmpty.");
  }

  size_t data_size =
      (((data.GetDataSize() / kAesBlockLength) + 1) * kAesBlockLength);
  std::vector<uint8_t> output(data_size);
  std::vector<uint8_t> key_data = key.GetBytes();
  std::vector<uint8_t> iv_data = iv.GetBytes();
  size_t written = 0;

  // Encrypt data using AES(CBC mode, PKCS#7 padding).
  int ret = wally_aes_cbc(
      key_data.data(), key_data.size(), iv_data.data(), iv_data.size(),
      data.GetBytes().data(), data.GetDataSize(), AES_FLAG_ENCRYPT,
      output.data(), output.size(), &written);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_aes_cbc NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "EncryptAes256Cbc error.");
  }

  output.resize(written);
  return ByteData(output);
}

std::string CryptoUtil::DecryptAes256CbcToString(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
    const ByteData &data) {
  ByteData decrypt_data = DecryptAes256Cbc(ByteData(key), ByteData(iv), data);
  std::vector<uint8_t> output = decrypt_data.GetBytes();
  std::string decrypt_string;
  decrypt_string.append(
      reinterpret_cast<const char *>(output.data()), output.size());
  return decrypt_string;
}

ByteData CryptoUtil::DecryptAes256Cbc(
    const ByteData &key, const ByteData &iv, const ByteData &data) {
  if (key.GetDataSize() != AES_KEY_LEN_256) {
    warn(CFD_LOG_SOURCE, "wally_aes key size NG.");
    throw CfdException(
        kCfdIllegalStateError, "DecryptAes256Cbc key size error.");
  }

  std::vector<uint8_t> output(data.GetDataSize());
  std::vector<uint8_t> key_data = key.GetBytes();
  std::vector<uint8_t> iv_data = iv.GetBytes();
  size_t written = 0;

  // Decrypt data using AES(CBC mode, PKCS#7 padding).
  int ret = wally_aes_cbc(
      key_data.data(), key_data.size(), iv_data.data(), iv_data.size(),
      data.GetBytes().data(), data.GetDataSize(), AES_FLAG_DECRYPT,
      output.data(), output.size(), &written);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_aes_cbc NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "DecryptAes256Cbc error.");
  }

  output.resize(written);
  return ByteData(output);
}

ByteData256 CryptoUtil::HmacSha256(
    const std::vector<uint8_t> &key, const ByteData &data) {
  std::vector<uint8_t> output(HMAC_SHA256_LEN);

  // HMAC SHA-256
  int ret = wally_hmac_sha256(
      key.data(), key.size(), data.GetBytes().data(), data.GetBytes().size(),
      output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_hmac_sha256 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "HmacSha256 error.");
  }

  return ByteData256(output);
}

ByteData256 CryptoUtil::HmacSha256(const ByteData &key, const ByteData &data) {
  return HmacSha256(key.GetBytes(), data);
}

ByteData CryptoUtil::HmacSha512(
    const std::vector<uint8_t> &key, const ByteData &data) {
  std::vector<uint8_t> output(HMAC_SHA512_LEN);

  // HMAC SHA-512
  int ret = wally_hmac_sha512(
      key.data(), key.size(), data.GetBytes().data(), data.GetBytes().size(),
      output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_hmac_sha512 NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "HmacSha512 error.");
  }

  return ByteData(output);
}

ByteData CryptoUtil::NormalizeSignature(const ByteData &signature) {
  std::vector<uint8_t> sig = signature.GetBytes();
  std::vector<uint8_t> output(EC_SIGNATURE_LEN);
  int ret = wally_ec_sig_normalize(
      sig.data(), sig.size(), output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_ec_sig_normalize NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "ec normalize error.");
  }
  return ByteData(output);
}

ByteData CryptoUtil::ConvertSignatureToDer(
    const ByteData &signature, const SigHashType &sighash_type) {
  std::vector<uint8_t> sig = signature.GetBytes();
  // Secure the size considering SigHashType(1byte).
  std::vector<uint8_t> output(EC_SIGNATURE_DER_MAX_LEN + 1);
  size_t written = 0;

  if ((output.size() - 2) <= sig.size()) {
    try {
      SigHashType temp_sighash;
      ConvertSignatureFromDer(signature, &temp_sighash);
      uint8_t flag = static_cast<uint8_t>(sighash_type.GetSigHashFlag());
      if (flag == temp_sighash.GetSigHashFlag()) {
        return signature;
      }
    } catch (const CfdException &except) {
      info(
          CFD_LOG_SOURCE, "ConvertSignatureFromDer fail. fall through. ({})",
          std::string(except.what()));
    }
  }

  // Convert a compact signature to DER encoding.
  int ret = wally_ec_sig_to_der(
      sig.data(), sig.size(), output.data(), output.size(), &written);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_ec_sig_to_der NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "der encode error.");
  }

  if (written <= EC_SIGNATURE_DER_MAX_LEN) {
    // add SigHashType
    info(
        CFD_LOG_SOURCE, "size[{}]. append[{}]", written,
        sighash_type.GetSigHashFlag());
    output[written] = static_cast<uint8_t>(sighash_type.GetSigHashFlag());
    ++written;
  }
  output.resize(written);

  return ByteData(output);
}

ByteData CryptoUtil::ConvertSignatureToDer(
    const std::string &hex_string, const SigHashType &sighash_type) {
  return ConvertSignatureToDer(ByteData(hex_string), sighash_type);
}

ByteData CryptoUtil::ConvertSignatureFromDer(
    const ByteData &der_data, SigHashType *sighash_type) {
  std::vector<uint8_t> der_sig = der_data.GetBytes();

  if (der_sig.size() == 0) {
    warn(CFD_LOG_SOURCE, "Empty signature.");
    throw CfdException(kCfdIllegalStateError, "der decode error.");
  }

  if (der_sig.size() <= (EC_SIGNATURE_DER_MAX_LEN + 1)) {
    uint8_t sighash_byte = der_sig[der_sig.size() - 1];
    der_sig.resize(der_sig.size() - 1);

    if (sighash_type != nullptr) {
      sighash_type->SetFromSigHashFlag(sighash_byte);
    }
  }

  std::vector<uint8_t> output(EC_SIGNATURE_LEN);
  int ret = wally_ec_sig_from_der(
      der_sig.data(), der_sig.size(), output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_ec_sig_from_der NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "der decode error.");
  }
  return ByteData(output);
}

/**
 * \~english
 * @brief Table info used for Base64encode
 * @return Character string used in Base64
 * \~japanese
 * @brief Base64encodeに用いるtable情報
 * @return Base64で利用する文字列
 */
static const std::string kBase64EncodeTable(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

std::string CryptoUtil::EncodeBase64(const ByteData &data) {
  std::vector<uint8_t> src(data.GetBytes());
  std::string dst;
  std::string cdst;

  for (std::size_t i = 0; i < src.size(); ++i) {
    switch (i % 3) {
      case 0:
        cdst.push_back(kBase64EncodeTable[(src[i] & 0xFC) >> 2]);
        if (i + 1 == src.size()) {
          cdst.push_back(kBase64EncodeTable[(src[i] & 0x03) << 4]);
          cdst.push_back('=');
          cdst.push_back('=');
        }

        break;
      case 1:
        cdst.push_back(
            kBase64EncodeTable
                [((src[i - 1] & 0x03) << 4) | ((src[i + 0] & 0xF0) >> 4)]);
        if (i + 1 == src.size()) {
          cdst.push_back(kBase64EncodeTable[(src[i] & 0x0F) << 2]);
          cdst.push_back('=');
        }

        break;
      case 2:
        cdst.push_back(
            kBase64EncodeTable
                [((src[i - 1] & 0x0F) << 2) | ((src[i + 0] & 0xC0) >> 6)]);
        cdst.push_back(kBase64EncodeTable[src[i] & 0x3F]);

        break;
    }
  }

  dst.swap(cdst);
  return dst;
}

ByteData CryptoUtil::DecodeBase64(const std::string &str) {
  std::vector<uint8_t> dst;
  if (str.size() & 0x00000003) {
    ByteData byteData(dst);
    return byteData;
  }

  std::vector<uint8_t> cdst;
  for (std::size_t i = 0; i < str.size(); i += 4) {
    if (str[i + 0] == '=') {
      ByteData byteData(dst);
      return byteData;

    } else if (str[i + 1] == '=') {
      ByteData byteData(dst);
      return byteData;

    } else if (str[i + 2] == '=') {
      const std::string::size_type s1 = kBase64EncodeTable.find(str[i + 0]);
      const std::string::size_type s2 = kBase64EncodeTable.find(str[i + 1]);

      if (s1 == std::string::npos || s2 == std::string::npos) {
        ByteData byteData(dst);
        return byteData;
      }

      cdst.push_back(
          static_cast<uint8_t>(((s1 & 0x3F) << 2) | ((s2 & 0x30) >> 4)));

      break;
    } else if (str[i + 3] == '=') {
      const std::string::size_type s1 = kBase64EncodeTable.find(str[i + 0]);
      const std::string::size_type s2 = kBase64EncodeTable.find(str[i + 1]);
      const std::string::size_type s3 = kBase64EncodeTable.find(str[i + 2]);

      if (s1 == std::string::npos || s2 == std::string::npos ||
          s3 == std::string::npos) {
        ByteData byteData(dst);
        return byteData;
      }

      cdst.push_back(
          static_cast<uint8_t>(((s1 & 0x3F) << 2) | ((s2 & 0x30) >> 4)));
      cdst.push_back(
          static_cast<uint8_t>(((s2 & 0x0F) << 4) | ((s3 & 0x3C) >> 2)));

      break;
    } else {
      const std::string::size_type s1 = kBase64EncodeTable.find(str[i + 0]);
      const std::string::size_type s2 = kBase64EncodeTable.find(str[i + 1]);
      const std::string::size_type s3 = kBase64EncodeTable.find(str[i + 2]);
      const std::string::size_type s4 = kBase64EncodeTable.find(str[i + 3]);

      if (s1 == std::string::npos || s2 == std::string::npos ||
          s3 == std::string::npos || s4 == std::string::npos) {
        ByteData byteData(dst);
        return byteData;
      }

      cdst.push_back(
          static_cast<uint8_t>(((s1 & 0x3F) << 2) | ((s2 & 0x30) >> 4)));
      cdst.push_back(
          static_cast<uint8_t>(((s2 & 0x0F) << 4) | ((s3 & 0x3C) >> 2)));
      cdst.push_back(
          static_cast<uint8_t>(((s3 & 0x03) << 6) | ((s4 & 0x3F) >> 0)));
    }
  }
  dst.swap(cdst);
  ByteData byteData(dst);
  return byteData;
}

ByteData CryptoUtil::DecodeBase58(const std::string &str) {
  std::vector<uint8_t> output(1024);
  size_t written = 0;

  int ret = wally_base58_to_bytes(
      str.data(), 0, output.data(), output.size(), &written);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_to_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "Decode base58 error.");
  }

  output.resize(written);
  return ByteData(output);
}

ByteData CryptoUtil::DecodeBase58Check(const std::string &str) {
  std::vector<uint8_t> output(1024);
  size_t written = 0;

  int ret = wally_base58_to_bytes(
      str.data(), BASE58_FLAG_CHECKSUM, output.data(), output.size(),
      &written);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_to_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "Decode base58 error.");
  }

  output.resize(written);
  return ByteData(output);
}

std::string CryptoUtil::EncodeBase58(const ByteData &data) {
  std::vector<uint8_t> byte_array = data.GetBytes();
  char *output = nullptr;

  int ret = wally_base58_from_bytes(
      byte_array.data(), byte_array.size(), 0, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "Decode base58 error.");
  }
  return WallyUtil::ConvertStringAndFree(output);
}

std::string CryptoUtil::EncodeBase58Check(const ByteData &data) {
  std::vector<uint8_t> byte_array = data.GetBytes();
  char *output = nullptr;

  int ret = wally_base58_from_bytes(
      byte_array.data(), byte_array.size(), BASE58_FLAG_CHECKSUM, &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_base58_from_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "Decode base58 error.");
  }
  return WallyUtil::ConvertStringAndFree(output);
}

ByteData256 CryptoUtil::ComputeFastMerkleRoot(
    const std::vector<ByteData256> &hashes) {
  static constexpr uint32_t kUintValue1 = 1;
  ByteData256 result_hash;
  if (hashes.size() == 0) return result_hash;

  // inner is an array of eagerly computed subtree hashes, indexed by tree
  // level (0 being the leaves).
  // For example, when count is 25 (11001 in binary), inner[4] is the hash of
  // the first 16 leaves, inner[3] of the next 8 leaves, and inner[0] equal to
  // the last leaf. The other inner entries are undefined.
  //
  // First process all leaves into 'inner' values.
  ByteData256 inner[33];
  uint32_t count = 0;
  int level;
  while (count < hashes.size()) {
    ByteData256 temp_hash = hashes[count];
    ++count;
    // For each of the lower bits in count that are 0, do 1 step. Each
    // corresponds to an inner value that existed before processing the
    // current leaf, and each needs a hash to combine it.
    level = 0;
    while ((count & (kUintValue1 << level)) == 0) {
      temp_hash = MerkleHashSha256Midstate(inner[level], temp_hash);
      ++level;
    }
    // Store the resulting hash at inner position level.
    inner[level] = temp_hash;
  }

  // Do a final 'sweep' over the rightmost branch of the tree to process
  // odd levels, and reduce everything to a single top value.
  // Level is the level (counted from the bottom) up to which we've sweeped.
  //
  // As long as bit number level in count is zero, skip it. It means there
  // is nothing left at this level.
  level = 0;
  while ((count & (kUintValue1 << level)) == 0) {
    ++level;
  }
  result_hash = inner[level];

  while (count != (kUintValue1 << level)) {
    // If we reach this point, hash is an inner value that is not the top.
    // We combine it with itself (Bitcoin's special rule for odd levels in
    // the tree) to produce a higher level one.

    // Increment count to the value it would have if two entries at this
    // level had existed and propagate the result upwards accordingly.
    count += (kUintValue1 << level);
    ++level;
    while ((count & (kUintValue1 << level)) == 0) {
      result_hash = MerkleHashSha256Midstate(inner[level], result_hash);
      ++level;
    }
  }
  return result_hash;
}

ByteData256 CryptoUtil::MerkleHashSha256Midstate(
    const ByteData256 &left, const ByteData256 &right) {
  // CSHA256().Write(left.begin(), 32).Write(right.begin(), 32)
  // .Midstate(output.begin(), NULL, NULL);
  std::vector<uint8_t> output(32);
  std::vector<uint8_t> buffer = left.GetBytes();
  std::vector<uint8_t> right_buffer = right.GetBytes();
  buffer.insert(buffer.end(), right_buffer.begin(), right_buffer.end());
  int ret = wally_sha256_midstate(
      buffer.data(), buffer.size(), output.data(), output.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_sha256_midstate NG[{}].", ret);
    throw CfdException(kCfdIllegalStateError, "MerkleHash calc error.");
  }
  return ByteData256(output);
}

//////////////////////////////////
/// RandomNumberUtil
//////////////////////////////////
std::vector<uint8_t> RandomNumberUtil::GetRandomBytes(int len) {
#if defined(_WIN32) && defined(__GNUC__) && (__GNUC__ < 9)
  // for mingw gcc lower 9
  static std::mt19937 engine(static_cast<unsigned int>(time(nullptr)));
#else
  static std::random_device rd;
  static std::mt19937 engine(rd());
#endif
  std::vector<uint8_t> result(len);

  int index = 0;
  for (int i = 0; i < len / 4; i++) {
    uint32_t random = engine();
    memcpy(&result[index], reinterpret_cast<uint8_t *>(&random), 4);
    index += 4;
  }

  int remainder = len % 4;
  if (remainder != 0) {
    uint32_t random = engine();
    memcpy(&result[index], reinterpret_cast<uint8_t *>(&random), remainder);
  }

  return result;
}

std::vector<uint32_t> RandomNumberUtil::GetRandomIndexes(uint32_t length) {
#if defined(_WIN32) && defined(__GNUC__) && (__GNUC__ < 9)
  // for mingw gcc lower 9
  static std::mt19937 engine(static_cast<unsigned int>(time(nullptr)));
#else
  static std::random_device rd;
  static std::mt19937 engine(rd());
#endif
  std::uniform_int_distribution<> dist(0, length);
  std::vector<uint32_t> result(length);
  std::set<uint32_t> exist_value;
  uint32_t value;

  if (length == 1) {
    result[0] = 0;
  } else if (length > 1) {
    uint32_t index = 0;
    while (index < (length - 1)) {
      value = dist(engine);
      if (value >= length) {
        value /= length;
      }
      if ((exist_value.empty()) || (exist_value.count(value) == 0)) {  // MSVC
        result[index] = value;
        exist_value.insert(value);
        ++index;
      }
    }

    for (value = 0; value < length; ++value) {
      if (exist_value.count(value) == 0) {
        result[length - 1] = value;
        break;
      }
    }
  }

  return result;
}

bool RandomNumberUtil::GetRandomBool(std::vector<bool> *random_cache) {
#if defined(_WIN32) && defined(__GNUC__) && (__GNUC__ < 9)
  // for mingw gcc lower 9
  static std::mt19937 engine(static_cast<unsigned int>(time(nullptr)));
#else
  static std::random_device rd;
  static std::mt19937 engine(rd());
#endif
  if (random_cache == nullptr) {
    throw CfdException(kCfdIllegalArgumentError, "GetRandomBool error.");
  }

  if (random_cache->empty()) {
    uint32_t random = engine();
    for (int i = 0; i < 32; i++) {
      bool value = (random >> i) & 1;
      random_cache->push_back(value);
    }
  }
  bool ret = random_cache->back();
  random_cache->pop_back();
  return ret;
}

//////////////////////////////////
/// StringUtil
//////////////////////////////////
std::vector<uint8_t> StringUtil::StringToByte(const std::string &hex_str) {
  if (hex_str.empty()) {
    info(CFD_LOG_SOURCE, "hex_str empty. return empty buffer.");
    return std::vector<uint8_t>();
  }
  std::vector<uint8_t> buffer(hex_str.size() + 1);
  size_t buf_size = 0;
  int ret = wally_hex_to_bytes(
      hex_str.data(), buffer.data(), buffer.size(), &buf_size);
  if (ret == WALLY_OK) {
    buffer.resize(buf_size);
  } else {
    warn(CFD_LOG_SOURCE, "wally_hex_to_bytes NG[{}].", ret);
    throw CfdException(kCfdIllegalArgumentError, "hex to byte convert error.");
  }

  return buffer;
}

std::string StringUtil::ByteToString(const std::vector<uint8_t> &bytes) {
  std::string byte_str;
  if (bytes.empty()) {
    info(CFD_LOG_SOURCE, "bytes empty. return empty string.");
  } else {
    char *buffer = NULL;
    int ret = wally_hex_from_bytes(bytes.data(), bytes.size(), &buffer);
    if (ret == WALLY_OK) {
      byte_str = WallyUtil::ConvertStringAndFree(buffer);
    } else {
      warn(CFD_LOG_SOURCE, "wally_hex_from_bytes NG[{}].", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "byte to hex convert error.");
    }
  }
  return byte_str;
}

std::vector<std::string> StringUtil::Split(
    const std::string &str, const std::string &delim) {
  std::vector<std::string> results;

  size_t pos = 0, prev = 0;
  std::string item;
  while ((pos = str.find(delim, prev)) != std::string::npos) {
    item = str.substr(prev, pos - prev);
    results.push_back(item);
    prev = pos + std::char_traits<char>::length(delim.c_str());
  }
  item = str.substr(prev);
  results.push_back(item);

  return results;
}

std::string StringUtil::Join(
    const std::vector<std::string> &str_list,
    const std::string &separate_word) {
  std::stringstream ss;
  std::copy(
      str_list.begin(), str_list.end(),
      std::ostream_iterator<std::string>(ss, separate_word.c_str()));
  std::string result = ss.str();

  if (result.size() < std::char_traits<char>::length(separate_word.c_str()))
    return result;

  result.erase(
      result.size() - std::char_traits<char>::length(separate_word.c_str()));
  return result;
}

}  // namespace core
}  // namespace cfd
