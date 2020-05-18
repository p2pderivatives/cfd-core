// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_util.h
 *
 * @brief Utility関連クラス定義
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
 * @brief 20byte長
 */
const uint32_t kByteData160Length = 20;

/**
 * @brief 32byte長
 */
const uint32_t kByteData256Length = 32;

/**
 * @brief 64byte長
 */
const uint32_t kByteData512Length = 64;

/**
 * @brief Sighash flags for transaction signing.
 */
enum SigHashAlgorithm {
  kSigHashAll = 0x01,     //!< SIGHASH_ALL
  kSigHashNone = 0x02,    //!< SIGHASH_NONE
  kSigHashSingle = 0x03,  //!< SIGHASH_SINGLE
};

/**
 * @brief SigHash算出時の種別
 */
class CFD_CORE_EXPORT SigHashType {
 public:
  /**
   * @brief SIGHASH_FORKIDフラグ
   */
  const uint8_t kSigHashForkId = 0x40;

  /**
   * @brief SIGHASH_ANYONECANPAYフラグ
   */
  const uint8_t kSigHashAnyOneCanPay = 0x80;

  /**
   * @brief デフォルトコンストラクタ
   */
  SigHashType();

  /**
   * @brief コンストラクタ
   * @param algorithm Sighashアルゴリズム
   * @param is_anyone_can_pay SIGHASH_ANYONECANPAYフラグ有無
   * @param is_fork_id SIGHASH_FORKIDフラグ有無
   */
  explicit SigHashType(
      SigHashAlgorithm algorithm, bool is_anyone_can_pay = false,
      bool is_fork_id = false);
  /**
   * @brief コピーコンストラクタ.
   * @param[in] sighash_type        SigHashType オブジェクト
   * @return SigHashType オブジェクト
   */
  SigHashType &operator=(const SigHashType &sighash_type);

  /**
   * @brief SigHashフラグ取得
   * @return SigHashフラグ
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
   * @brief Set parameter from SigHash flag.
   * @param[in] flag  SigHash flag
   */
  void SetFromSigHashFlag(uint8_t flag);

 private:
  /**
   * @brief Sighashアルゴリズム
   */
  SigHashAlgorithm hash_algorithm_;

  /**
   * @brief SIGHASH_ANYONECANPAYフラグ有無
   */
  bool is_anyone_can_pay_;

  /**
   * @brief SIGHASH_FORKIDフラグ有無
   */
  bool is_fork_id_;
};

/**
 * @brief Hash関数を定義したUtilクラス
 */
class CFD_CORE_EXPORT HashUtil {
 public:
  // Hash160 --------------------------------------------------------------
  /**
   * @brief 文字列をHash160でハッシュする.
   * @param[in] str 文字列
   * @return hashed ByteData160データ
   */
  static ByteData160 Hash160(const std::string &str);
  /**
   * @brief byteデータ配列をHash160でハッシュする.
   * @param[in] bytes byteデータ配列
   * @return hashed ByteData160データ
   */
  static ByteData160 Hash160(const std::vector<uint8_t> &bytes);
  /**
   * @brief ByteDataをHash160でハッシュする.
   * @param[in] data ByteDataインスタンス
   * @return hashed ByteData160データ
   */
  static ByteData160 Hash160(const ByteData &data);
  /**
   * @brief ByteData160をHash160でハッシュする.
   * @param[in] data byteデータ配列
   * @return hashed ByteData160データ
   */
  static ByteData160 Hash160(const ByteData160 &data);
  /**
   * @brief ByteData256をHash160でハッシュする.
   * @param[in] data byteデータ配列
   * @return hashed ByteData160データ
   */
  static ByteData160 Hash160(const ByteData256 &data);
  /**
   * @brief 公開鍵をHash160でハッシュする.
   * @param[in] pubkey Pubkeyインスタンス
   * @return pubkey hash
   */
  static ByteData160 Hash160(const Pubkey &pubkey);
  /**
   * @brief ScriptをHash160でハッシュする.
   * @param[in] script Scriptインスタンス
   * @return script hash
   */
  static ByteData160 Hash160(const Script &script);

  // Sha256 --------------------------------------------------------------
  /**
   * @brief 文字列をSha256でハッシュする.
   * @param[in] str 文字列
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256(const std::string &str);
  /**
   * @brief byteデータ配列をSha256でハッシュする.
   * @param[in] bytes byteデータ配列
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256(const std::vector<uint8_t> &bytes);
  /**
   * @brief ByteDataをSha256でハッシュする.
   * @param[in] data ByteDataインスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256(const ByteData &data);
  /**
   * @brief ByteData160をSha256でハッシュする.
   * @param[in] data ByteData160インスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256(const ByteData160 &data);
  /**
   * @brief ByteData256をSha256でハッシュする.
   * @param[in] data ByteData256インスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256(const ByteData256 &data);
  /**
   * @brief 公開鍵をSha256でハッシュする.
   * @param[in] pubkey Pubkeyインスタンス
   * @return pubkey hash
   */
  static ByteData256 Sha256(const Pubkey &pubkey);
  /**
   * @brief ScriptをSha256でハッシュする.
   * @param[in] script Scriptインスタンス
   * @return script hash
   */
  static ByteData256 Sha256(const Script &script);

  // Sha256D --------------------------------------------------------------
  /**
   * @brief 文字列をSha256Dでハッシュ化する.
   * @param[in] str 文字列
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256D(const std::string &str);
  /**
   * @brief byteデータ配列をSha256Dでハッシュ化する.
   * @param[in] bytes byteデータ配列
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256D(const std::vector<uint8_t> &bytes);
  /**
   * @brief ByteDataをSha256Dでハッシュ化する.
   * @param[in] data ByteDataインスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256D(const ByteData &data);
  /**
   * @brief ByteData160をSha256Dでハッシュ化する.
   * @param[in] data ByteData160インスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256D(const ByteData160 &data);
  /**
   * @brief ByteData256をSha256Dでハッシュ化する.
   * @param[in] data ByteData256インスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256D(const ByteData256 &data);
  /**
   * @brief 公開鍵をSha256Dでハッシュ化する.
   * @param[in] pubkey Pubkeyインスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256D(const Pubkey &pubkey);
  /**
   * @brief ScriptをSha256Dでハッシュ化する.
   * @param[in] script Scriptインスタンス
   * @return hashed ByteData256データ
   */
  static ByteData256 Sha256D(const Script &script);

  // Sha512 ---------------------------------------------------------------
  /**
   * @brief 文字列をSha512でハッシュ化する.
   * @param[in] str 文字列
   * @return hashed ByteDataデータ
   */
  static ByteData Sha512(const std::string &str);
  /**
   * @brief byteデータ配列をSha512でハッシュ化する.
   * @param[in] bytes byteデータ配列
   * @return hashed ByteDataデータ
   */
  static ByteData Sha512(const std::vector<uint8_t> &bytes);
  /**
   * @brief ByteDataをSha512でハッシュ化する.
   * @param[in] data ByteDataインスタンス
   * @return hashed ByteDataデータ
   */
  static ByteData Sha512(const ByteData &data);
  /**
   * @brief ByteData160をSha512でハッシュ化する.
   * @param[in] data ByteData160インスタンス
   * @return hashed ByteDataデータ
   */
  static ByteData Sha512(const ByteData160 &data);
  /**
   * @brief ByteData256をSha512でハッシュ化する.
   * @param[in] data ByteData256インスタンス
   * @return hashed ByteDataデータ
   */
  static ByteData Sha512(const ByteData256 &data);
  /**
   * @brief 公開鍵をSha512でハッシュ化する.
   * @param[in] pubkey Pubkeyインスタンス
   * @return hashed ByteDataデータ
   */
  static ByteData Sha512(const Pubkey &pubkey);
  /**
   * @brief ScriptをSha512でハッシュ化する.
   * @param[in] script Scriptインスタンス
   * @return hashed ByteDataデータ
   */
  static ByteData Sha512(const Script &script);

 private:
  HashUtil();
};

/**
 * @class CryptoUtil
 * @brief 暗号化/復号化関数のUtilクラス
 */
class CFD_CORE_EXPORT CryptoUtil {
 public:
  /// AES Blockサイズ
  static const size_t kAesBlockLength = 16;

  /**
   * @brief 文字列をAES256暗号化する.
   * @param[in] key keyとなる32Byteの配列データ
   * @param[in] data 暗号化する文字列
   * @return 暗号化したByteData
   */
  static ByteData EncryptAes256(
      const std::vector<uint8_t> &key, const std::string &data);
  /**
   * @brief ByteDataをAES256復号化する.
   * @param[in] key keyとなる32Byteの配列データ
   * @param[in] data 暗号化されたByteData
   * @return 復号化した文字列
   */
  static std::string DecryptAes256ToString(
      const std::vector<uint8_t> &key, const ByteData &data);
  /**
   * @brief 文字列をAES256CBC暗号化する.
   * @param[in] key keyとなる32Byteの配列データ
   * @param[in] iv  initial vectorとなる16Byteの配列データ
   * @param[in] data 暗号化するByteData
   * @return 暗号化したByteData
   */
  static ByteData EncryptAes256Cbc(
      const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
      const std::string &data);
  /**
   * @brief ByteDataをAES256CBC復号化する.
   * @param[in] key keyとなる32Byteの配列データ
   * @param[in] iv  initial vectorとなる16Byteの配列データ
   * @param[in] data 暗号化されたByteData
   * @return 復号化した文字列
   */
  static std::string DecryptAes256CbcToString(
      const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
      const ByteData &data);
  /**
   * @brief ByteDataのHMAC-SHA256を計算する.
   * @param[in] key keyとなるByte配列データ
   * @param[in] data ByteDataインスタンス
   * @return ByteData256データ
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
   * @brief ByteDataのHMAC-SHA512を計算する.
   * @param[in] key keyとなるByte配列データ
   * @param[in] data ByteDataインスタンス
   * @return ByteDataデータ
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
   * @brief ByteDataをBase64エンコードする.
   * @param[in] data エンコードするByteData
   * @return encodeした文字列
   */
  static std::string EncodeBase64(const ByteData &data);
  /**
   * @brief 文字列をBase64デコードする.
   * @param[in] str Base64エンコードされた文字列
   * @return decodeしたByteData
   */
  static ByteData DecodeBase64(const std::string &str);
  /**
   * @brief 文字列をBase58デコードする.
   * @param[in] str Base58エンコードされた文字列
   * @return decodeしたByteData
   */
  static ByteData DecodeBase58Check(const std::string &str);

  /**
   * @brief merkle rootの簡易計算を行う。
   * @param[in] hashes  hash list
   * @return merkle root
   */
  static ByteData256 ComputeFastMerkleRoot(
      const std::vector<ByteData256> &hashes);

  /**
   * @brief merkle hash計算を行う。
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
 * @brief 乱数関連関数のUtilクラス
 */
class CFD_CORE_EXPORT RandomNumberUtil {
 public:
  /**
   * 乱数を生成する.
   * @param[in] len 乱数の長さ
   * @return 乱数配列
   */
  static std::vector<uint8_t> GetRandomBytes(int len);
  /**
   * 乱数で指定範囲のIndexListを生成する.
   * @param[in] length リストの長さ
   * @return index list
   */
  static std::vector<uint32_t> GetRandomIndexes(uint32_t length);
  /**
   * ランダムなbool値を生成する.
   * @param[in,out] random_cache 乱数キャッシュ値
   * @return true/false
   */
  static bool GetRandomBool(std::vector<bool> *random_cache);

 private:
  RandomNumberUtil();
};

/**
 * @class StringUtil
 * @brief 文字列操作Utilクラス
 */
class CFD_CORE_EXPORT StringUtil {
 public:
  /**
   * @brief hex文字列からbyteデータ配列への変換をする.
   * @param[in] hex_str HEX文字列
   * @return byteデータ配列
   */
  static std::vector<uint8_t> StringToByte(const std::string &hex_str);
  /**
   * @brief byteデータ配列からHEX文字列への変換をする.
   * @param[in] bytes byteデータ配列
   * @return HEX文字列
   */
  static std::string ByteToString(const std::vector<uint8_t> &bytes);
  /**
   * @brief 文字列を区切り文字で分割する.
   * @param[in] str     分割対象文字列
   * @param[in] delim   区切り文字列
   * @return 区切り文字で区切られた文字列vector
   */
  static std::vector<std::string> Split(
      const std::string &str, const std::string &delim);
  /**
   * @brief 文字列配列を連結する.
   * @param[in] str_list        文字列配列
   * @param[in] separate_word   連結文字列
   * @return 連結された文字列
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
