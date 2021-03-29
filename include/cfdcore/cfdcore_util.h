// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_util.h
 *
 * @brief The utility related class definition
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_UTIL_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_UTIL_H_

#include <cstddef>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"

namespace cfd {
namespace core {

/**
 * @brief 20byte length
 */
const uint32_t kByteData160Length = 20;

/**
 * @brief 32byte length
 */
const uint32_t kByteData256Length = 32;

/**
 * @brief 64byte length
 */
const uint32_t kByteData512Length = 64;

/**
 * @brief Sighash flags for transaction signing.
 */
enum SigHashAlgorithm {
  kSigHashDefault = 0,      //!< default (= SIGHASH_ALL)
  kSigHashAll = 0x01,       //!< SIGHASH_ALL
  kSigHashNone = 0x02,      //!< SIGHASH_NONE
  kSigHashSingle = 0x03,    //!< SIGHASH_SINGLE
  kSigHashUnknown = 0xffff  //!< invalid
};

/**
 * @brief Type when calculating SigHash
 */
class CFD_CORE_EXPORT SigHashType {
 public:
  /**
   * @brief SIGHASH_FORKID flag
   */
  const uint8_t kSigHashForkId = 0x40;
  /*
   * @brief SIGHASH_RANGEPROOF flag
   */
  // const uint8_t kSigHashRangeproof = 0x40;

  // for feature
  /**
   * @brief SIGHASH_ANYONECANPAY flag
   */
  const uint8_t kSigHashAnyOneCanPay = 0x80;

  /**
   * @brief Create by SigHash flag.
   * @param[in] flag  SigHash flag
   * @param[in] is_append_anyone_can_pay add SIGHASH_ANYONECANPAY if true.
   * @param[in] is_append_fork_id add SIGHASH_FORKID if true.
   * @return SigHashType
   */
  static SigHashType Create(
      uint8_t flag, bool is_append_anyone_can_pay = false,
      bool is_append_fork_id = false);

  /**
   * @brief default constructor.
   */
  SigHashType();

  /**
   * @brief constructor.
   * @param algorithm Sighash algorithm
   * @param is_anyone_can_pay SIGHASH_ANYONECANPAY flag
   * @param is_fork_id SIGHASH_FORKID flag
   */
  explicit SigHashType(
      SigHashAlgorithm algorithm, bool is_anyone_can_pay = false,
      bool is_fork_id = false);
  /**
   * @brief copy constructor.
   * @param[in] sighash_type        SigHashType
   */
  SigHashType(const SigHashType &sighash_type);
  /**
   * @brief copy constructor.
   * @param[in] sighash_type        SigHashType
   * @return SigHashType
   */
  SigHashType &operator=(const SigHashType &sighash_type);

  /**
   * @brief Get a SigHash flag.
   * @return SigHash flag
   */
  uint32_t GetSigHashFlag() const;

  /**
   * @brief Get SigHash algorithm.
   * @return SigHash algorithm
   */
  SigHashAlgorithm GetSigHashAlgorithm() const;
  /**
   * @brief has SIGHASH_ANYONECANPAY flag.
   * @retval true  set SIGHASH_ANYONECANPAY
   * @retval false unuse SIGHASH_ANYONECANPAY
   */
  bool IsAnyoneCanPay() const;
  /**
   * @brief has SIGHASH_FORKID flag.
   * @retval true  set SIGHASH_FORKID
   * @retval false unuse SIGHASH_FORKID
   */
  bool IsForkId() const;

  /**
   * @brief Valid sighash state.
   * @retval true   valid
   * @retval false  invalid
   */
  bool IsValid() const;

  /**
   * @brief Set parameter from SigHash flag.
   * @param[in] flag  SigHash flag
   */
  void SetFromSigHashFlag(uint8_t flag);
  /**
   * @brief Set SIGHASH_ANYONECANPAY flag.
   * @param[in] is_anyone_can_pay SIGHASH_ANYONECANPAY flag
   */
  void SetAnyoneCanPay(bool is_anyone_can_pay);

  /**
   * @brief Get string.
   * @return SigHashType string.
   */
  std::string ToString() const;

 private:
  /**
   * @brief Sighash algorithm
   */
  SigHashAlgorithm hash_algorithm_;

  /**
   * @brief SIGHASH_ANYONECANPAY flag
   */
  bool is_anyone_can_pay_;

  /**
   * @brief SIGHASH_FORKID flag
   */
  bool is_fork_id_;
};

/**
 * @brief Util class that defines the Hash function.
 */
class CFD_CORE_EXPORT HashUtil {
 public:
  // Ripemd160 --------------------------------------------------------------
  /**
   * @brief Hash the string with Ripemd160.
   * @param[in] str   message text
   * @return hashed data
   */
  static ByteData160 Ripemd160(const std::string &str);
  /**
   * @brief Hash the byte array with Ripemd160.
   * @param[in] bytes   message data
   * @return hashed data
   */
  static ByteData160 Ripemd160(const std::vector<uint8_t> &bytes);
  /**
   * @brief Hash the byte array with Ripemd160.
   * @param[in] data  message data
   * @return hashed data
   */
  static ByteData160 Ripemd160(const ByteData &data);
  /**
   * @brief Hash the byte array with Ripemd160.
   * @param[in] data  message data
   * @return hashed data
   */
  static ByteData160 Ripemd160(const ByteData160 &data);
  /**
   * @brief Hash the byte array with Ripemd160.
   * @param[in] data  message data
   * @return hashed data
   */
  static ByteData160 Ripemd160(const ByteData256 &data);
  /**
   * @brief Hash the pubkey bytes with Ripemd160.
   * @param[in] pubkey Pubkey
   * @return pubkey hash
   */
  static ByteData160 Ripemd160(const Pubkey &pubkey);
  /**
   * @brief Hash the script bytes with Ripemd160.
   * @param[in] script Script
   * @return script hash
   */
  static ByteData160 Ripemd160(const Script &script);

  // Hash160 --------------------------------------------------------------
  /**
   * @brief Hash the string.
   * @param[in] str string
   * @return hashed data
   */
  static ByteData160 Hash160(const std::string &str);
  /**
   * @brief Hash the byte data array.
   * @param[in] bytes byte array
   * @return hashed data
   */
  static ByteData160 Hash160(const std::vector<uint8_t> &bytes);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData160 Hash160(const ByteData &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData160 Hash160(const ByteData160 &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData160 Hash160(const ByteData256 &data);
  /**
   * @brief Hash the pubkey.
   * @param[in] pubkey Pubkey
   * @return pubkey hash
   */
  static ByteData160 Hash160(const Pubkey &pubkey);
  /**
   * @brief Hash the script.
   * @param[in] script Script
   * @return script hash
   */
  static ByteData160 Hash160(const Script &script);

  // Sha256 --------------------------------------------------------------
  /**
   * @brief Hash the string.
   * @param[in] str string
   * @return hashed data
   */
  static ByteData256 Sha256(const std::string &str);
  /**
   * @brief Hash the byte data array.
   * @param[in] bytes byte array
   * @return hashed data
   */
  static ByteData256 Sha256(const std::vector<uint8_t> &bytes);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData256 Sha256(const ByteData &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData256 Sha256(const ByteData160 &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData256 Sha256(const ByteData256 &data);
  /**
   * @brief Hash the pubkey.
   * @param[in] pubkey Pubkey
   * @return pubkey hash
   */
  static ByteData256 Sha256(const Pubkey &pubkey);
  /**
   * @brief Hash the script bytes with Ripemd160.
   * @param[in] script Script
   * @return script hash
   */
  static ByteData256 Sha256(const Script &script);

  // Sha256D --------------------------------------------------------------
  /**
   * @brief Hash the string.
   * @param[in] str string
   * @return hashed data
   */
  static ByteData256 Sha256D(const std::string &str);
  /**
   * @brief Hash the byte data array.
   * @param[in] bytes byte array
   * @return hashed data
   */
  static ByteData256 Sha256D(const std::vector<uint8_t> &bytes);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData256 Sha256D(const ByteData &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData256 Sha256D(const ByteData160 &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData256 Sha256D(const ByteData256 &data);
  /**
   * @brief Hash the pubkey.
   * @param[in] pubkey Pubkey
   * @return pubkey hash
   */
  static ByteData256 Sha256D(const Pubkey &pubkey);
  /**
   * @brief Hash the script bytes with Ripemd160.
   * @param[in] script Script
   * @return script hash
   */
  static ByteData256 Sha256D(const Script &script);

  // Sha512 ---------------------------------------------------------------
  /**
   * @brief Hash the string.
   * @param[in] str string
   * @return hashed data
   */
  static ByteData Sha512(const std::string &str);
  /**
   * @brief Hash the byte data array.
   * @param[in] bytes byte array
   * @return hashed data
   */
  static ByteData Sha512(const std::vector<uint8_t> &bytes);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData Sha512(const ByteData &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData Sha512(const ByteData160 &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hashed data
   */
  static ByteData Sha512(const ByteData256 &data);
  /**
   * @brief Hash the pubkey.
   * @param[in] pubkey Pubkey
   * @return pubkey hash
   */
  static ByteData Sha512(const Pubkey &pubkey);
  /**
   * @brief Hash the script bytes with Ripemd160.
   * @param[in] script Script
   * @return script hash
   */
  static ByteData Sha512(const Script &script);

  // builder ---------------------------------------------------------------
  //! HashType: Ripemd160
  static constexpr uint8_t kRipemd160 = 1;
  //! HashType: Hash160
  static constexpr uint8_t kHash160 = 2;
  //! HashType: Sha256
  static constexpr uint8_t kSha256 = 3;
  //! HashType: Sha256D
  static constexpr uint8_t kSha256D = 4;
  //! HashType: Sha512
  static constexpr uint8_t kSha512 = 5;

  /**
   * @brief constructor.
   * @param[in] hash_type       hash type.
   */
  explicit HashUtil(uint8_t hash_type);
  /**
   * @brief constructor.
   * @param[in] hash_type       hash type.
   */
  explicit HashUtil(const std::string &hash_type);
  /**
   * @brief destructor.
   */
  virtual ~HashUtil() {}
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  HashUtil(const HashUtil &object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  HashUtil &operator=(const HashUtil &object);

  /**
   * @brief Hash the string.
   * @param[in] str string
   * @return hash util object.
   */
  HashUtil &operator<<(const std::string &str);
  /**
   * @brief Hash the byte data array.
   * @param[in] bytes byte array
   * @return hash util object.
   */
  HashUtil &operator<<(const std::vector<uint8_t> &bytes);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hash util object.
   */
  HashUtil &operator<<(const ByteData &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hash util object.
   */
  HashUtil &operator<<(const ByteData160 &data);
  /**
   * @brief Hash the byte data array.
   * @param[in] data    byte array
   * @return hash util object.
   */
  HashUtil &operator<<(const ByteData256 &data);
  /**
   * @brief Hash the pubkey.
   * @param[in] pubkey Pubkey
   * @return hash util object.
   */
  HashUtil &operator<<(const Pubkey &pubkey);
  /**
   * @brief Hash the script bytes with Ripemd160.
   * @param[in] script Script
   * @return hash util object.
   */
  HashUtil &operator<<(const Script &script);
  /**
   * @brief Output data.
   * @return hashed data
   */
  ByteData Output();
  /**
   * @brief Output data.
   * @return hashed data
   */
  ByteData160 Output160();
  /**
   * @brief Output data.
   * @return hashed data
   */
  ByteData256 Output256();

 private:
  HashUtil();

  uint8_t hash_type_;  //!< hash type
  ByteData buffer_;    //!< buffer
};

/**
 * @class CryptoUtil
 * @brief Utility class of encryption / decryption function
 */
class CFD_CORE_EXPORT CryptoUtil {
 public:
  /// AES Block size
  static const size_t kAesBlockLength = 16;

  /**
   * @brief AES256 encryption of the string.
   * @param[in] key     32-byte array data as a key
   * @param[in] data    String to encrypt
   * @return Encrypted ByteData
   */
  static ByteData EncryptAes256(
      const std::vector<uint8_t> &key, const std::string &data);
  /**
   * @brief Encrypto ByteData with AES256.
   * @param[in] key key array with 32Byte.
   * @param[in] data target byte data.
   * @return encrypted byte data.
   */
  static ByteData EncryptAes256(const ByteData &key, const ByteData &data);
  /**
   * @brief Decrypt ByteData to AES256.
   * @param[in] key key array with 32Byte.
   * @param[in] data encrypted byte data.
   * @return decrypted byte data.
   */
  static std::string DecryptAes256ToString(
      const std::vector<uint8_t> &key, const ByteData &data);
  /**
   * @brief Decrypto ByteData with AES256.
   * @param[in] key key array with 32Byte.
   * @param[in] data target encrypted byte data.
   * @return decrypted byte data.
   */
  static ByteData DecryptAes256(const ByteData &key, const ByteData &data);
  /**
   * @brief AES256CBC encryption of the string.
   * @param[in] key 32-byte array data as a key
   * @param[in] iv  16Byte array data that will be the initial vector
   * @param[in] data target byte data.
   * @return encrypted byte data.
   */
  static ByteData EncryptAes256Cbc(
      const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
      const std::string &data);
  /**
   * @brief Encrypto ByteData with AES256-CBC.
   * @param[in] key key array with 32Byte.
   * @param[in] iv  initial vector with 16Byte.
   * @param[in] data target byte data.
   * @return encrypted byte data.
   */
  static ByteData EncryptAes256Cbc(
      const ByteData &key, const ByteData &iv, const ByteData &data);
  /**
   * @brief Decrypt ByteData to AES256CBC.
   * @param[in] key key array with 32Byte.
   * @param[in] iv  initial vector with 16Byte.
   * @param[in] data target encrypted byte data.
   * @return decrypted byte data.
   */
  static std::string DecryptAes256CbcToString(
      const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
      const ByteData &data);
  /**
   * @brief Decrypto ByteData with AES256-CBC.
   * @param[in] key key array with 32Byte.
   * @param[in] iv  initial vector with 16Byte.
   * @param[in] data target encrypted byte data.
   * @return decrypted byte data.
   */
  static ByteData DecryptAes256Cbc(
      const ByteData &key, const ByteData &iv, const ByteData &data);
  /**
   * @brief Calculate HMAC-SHA256 for ByteData.
   * @param[in] key Byte array data as a key
   * @param[in] data ByteData object
   * @return ByteData256 data
   */
  static ByteData256 HmacSha256(
      const std::vector<uint8_t> &key, const ByteData &data);
  /**
   * @brief calculate HMAC-SHA256.
   * @param[in] key key-byte-array
   * @param[in] data input-data
   * @return ByteData256
   */
  static ByteData256 HmacSha256(const ByteData &key, const ByteData &data);
  /**
   * @brief Calculate HMAC-SHA512 for ByteData.
   * @param[in] key key-byte-array
   * @param[in] data input-data
   * @return ByteData
   */
  static ByteData HmacSha512(
      const std::vector<uint8_t> &key, const ByteData &data);
  /**
   * @brief Normalize signature.
   * @param[in] signature  signature
   * @return Normalized signature
   */
  static ByteData NormalizeSignature(const ByteData &signature);
  /**
   * @brief Convert signature to DER format
   * @param[in] signature  signature
   * @param[in] sighash_type signature hash type(SIGHASH_TYPE)
   * @return DER format signature
   */
  static ByteData ConvertSignatureToDer(
      const ByteData &signature, const SigHashType &sighash_type);
  /**
   * @brief Convert signature to DER format
   * @param[in] hex_string hex string of signature
   * @param[in] sighash_type signature hash type(SIGHASH_TYPE)
   * @return DER format signature
   */
  static ByteData ConvertSignatureToDer(
      const std::string &hex_string, const SigHashType &sighash_type);
  /**
   * @brief Convert signature from DER format
   * @param[in] der_data  DER format signature
   * @param[in,out] sighash_type signature hash type(SIGHASH_TYPE)
   * @return DER format signature
   */
  static ByteData ConvertSignatureFromDer(
      const ByteData &der_data, SigHashType *sighash_type);
  /**
   * @brief Base64 encode ByteData.
   * @param[in] data ByteData to encode
   * @return encoded string
   */
  static std::string EncodeBase64(const ByteData &data);
  /**
   * @brief Base64 decode the string.
   * @param[in] str     Base64 encoded string
   * @return decoded ByteData
   */
  static ByteData DecodeBase64(const std::string &str);
  /**
   * @brief decode Base58.
   * @param[in] str   Base58 encoding string
   * @return decode's ByteData
   */
  static ByteData DecodeBase58(const std::string &str);
  /**
   * @brief Base58 decode and checksum check the string.
   * @param[in] str   Base58 encoded string
   * @return decoded ByteData
   */
  static ByteData DecodeBase58Check(const std::string &str);
  /**
   * @brief encode Base58.
   * @param[in] data  byte data
   * @return Base58 encode string.
   */
  static std::string EncodeBase58(const ByteData &data);
  /**
   * @brief encode Base58 and append checksum.
   * @param[in] data  byte data
   * @return Base58 encode string.
   */
  static std::string EncodeBase58Check(const ByteData &data);

  /**
   * @brief Perform a simple calculation of merkle root.
   * @param[in] hashes  hash list
   * @return merkle root
   */
  static ByteData256 ComputeFastMerkleRoot(
      const std::vector<ByteData256> &hashes);

  /**
   * @brief Perform merkle hash calculation.
   * @param[in] left  left hash
   * @param[in] right right hash
   * @return merkle hash
   */
  static ByteData256 MerkleHashSha256Midstate(
      const ByteData256 &left, const ByteData256 &right);

 private:
  CryptoUtil();
};

/**
 * @class RandomNumberUtil
 * @brief Utility class of random number related functions
 */
class CFD_CORE_EXPORT RandomNumberUtil {
 public:
  /**
   * @brief Generate random numbers.
   * @param[in] len     Random number length
   * @return Random number array
   */
  static std::vector<uint8_t> GetRandomBytes(int len);
  /**
   * @brief Generate IndexList of specified range with random numbers.
   * @param[in] length  List length
   * @return index list
   */
  static std::vector<uint32_t> GetRandomIndexes(uint32_t length);
  /**
   * @brief Generate a random bool value.
   * @param[in,out] random_cache    Random number cache value
   * @return true/false
   */
  static bool GetRandomBool(std::vector<bool> *random_cache);

 private:
  RandomNumberUtil();
};

/**
 * @class StringUtil
 * @brief String manipulation Util class.
 */
class CFD_CORE_EXPORT StringUtil {
 public:
  /**
   * @brief Check hex string.
   * @param[in] hex_str HEX string
   * @retval true       valid hex string.
   * @retval false      invalid string.
   */
  static bool IsValidHexString(const std::string &hex_str);
  /**
   * @brief Convert from hex character string to byte data array.
   * @param[in] hex_str HEX string
   * @return byte data array.
   */
  static std::vector<uint8_t> StringToByte(const std::string &hex_str);
  /**
   * @brief Convert from byte data array to HEX character string.
   * @param[in] bytes byte data array
   * @return HEX string
   */
  static std::string ByteToString(const std::vector<uint8_t> &bytes);
  /**
   * @brief Divide the string by the delimiter.
   * @param[in] str     Character string to be divided
   * @param[in] delim   Delimiter string
   * @return String vector separated by delimiter
   */
  static std::vector<std::string> Split(
      const std::string &str, const std::string &delim);
  /**
   * @brief Concatenate string arrays.
   * @param[in] str_list        String array
   * @param[in] separate_word   Concatenated string
   * @return Concatenated string
   */
  static std::string Join(
      const std::vector<std::string> &str_list,
      const std::string &separate_word);

 private:
  StringUtil();
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_UTIL_H_
