// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_hdwallet.h
 *
 * @brief BIP32/BIP39/BIP44関連クラス
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"

namespace cfd {
namespace core {

class ExtPrivkey;
class ExtPubkey;

/**
 * @brief HDWalletを表現するデータクラス
 */
class CFD_CORE_EXPORT HDWallet {
 public:
  /**
   * @brief seed byte size (128bit)
   */
  static constexpr uint32_t kSeed128Size = 16;  // BIP32_ENTROPY_LEN_128
  /**
   * @brief seed byte size (256bit)
   */
  static constexpr uint32_t kSeed256Size = 32;  // BIP32_ENTROPY_LEN_256
  /**
   * @brief seed byte size (512bit)
   */
  static constexpr uint32_t kSeed512Size = 64;  // BIP32_ENTROPY_LEN_512

  /**
   * @brief デフォルトコンストラクタ
   */
  HDWallet();

  /**
   * @brief コンストラクタ
   * @param[in] seed シード値
   */
  explicit HDWallet(const ByteData& seed);

  /**
   * @brief コンストラクタ
   * @param[in] mnemonic                ニーモニック文字列配列
   * @param[in] passphrase              パスフレーズ
   * @param[in] use_ideographic_space   全角スペース利用フラグ(default: false)
   */
  HDWallet(
      std::vector<std::string> mnemonic, std::string passphrase,
      bool use_ideographic_space = false);

  /**
   * @brief seedを取得する
   * @return seed値ByteData
   */
  ByteData GetSeed() const;

  /**
   * @brief 拡張秘密鍵を生成する。
   * @param[in] network_type      network type
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(NetType network_type) const;
  /**
   * @brief 拡張秘密鍵を生成する。
   * @param[in] network_type      network type
   * @param[in] child_num         child number
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(NetType network_type, uint32_t child_num) const;
  /**
   * @brief 拡張秘密鍵を生成する。
   * @param[in] network_type      network type
   * @param[in] path              child number path
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(
      NetType network_type, const std::vector<uint32_t>& path) const;
  /**
   * @brief 拡張秘密鍵を生成する。
   * @param[in] network_type      network type
   * @param[in] string_path       child number string path
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(
      NetType network_type, const std::string& string_path) const;

  /**
   * @brief 拡張公開鍵を生成する。
   * @param[in] network_type      network type
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(NetType network_type) const;
  /**
   * @brief 拡張公開鍵を生成する。
   * @param[in] network_type      network type
   * @param[in] child_num         child number
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(NetType network_type, uint32_t child_num) const;
  /**
   * @brief 拡張公開鍵を生成する。
   * @param[in] network_type      network type
   * @param[in] path              child number path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(
      NetType network_type, const std::vector<uint32_t>& path) const;
  /**
   * @brief 拡張公開鍵を生成する。
   * @param[in] network_type      network type
   * @param[in] string_path       child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(
      NetType network_type, const std::string& string_path) const;

  /**
   * @brief Mnemonic で利用できる Wordlist を取得する.
   * @param[in] language 取得するWordlistの言語
   * @return Wordlist配列
   * @throws CfdException 非対応の言語が渡された場合
   */
  static std::vector<std::string> GetMnemonicWordlist(
      const std::string& language);

  /**
   * @brief Mnemonic で利用できる Wordlist を取得する.
   * @param[in] entropy     Mnemonic生成のエントロピー値
   * @param[in] language    Mnemonicの言語
   * @return ニーモニック配列
   * @throws CfdException 非対応の言語が渡された場合
   */
  static std::vector<std::string> ConvertEntropyToMnemonic(
      const ByteData& entropy, const std::string& language);

  /**
   * @brief Mnemonic から Entropy へ変換する.
   * @param[in] mnemonic  エントロピーを導出するニーモニック配列
   * @param[in] language  ニーモニックの言語
   * @return エントロピー値バイトデータ
   * @throws CfdException If invalid language passed.
   */
  static ByteData ConvertMnemonicToEntropy(
      const std::vector<std::string>& mnemonic, const std::string& language);

  /**
   * @brief Verify mnemonic is valid
   * @param[in] mnemonic                mnemonic vector to check valid
   * @param[in] language                language to verify
   * @retval true   mnemonic checksum is valid
   * @retval true   mnemonic checksum is invalid
   */
  static bool CheckValidMnemonic(
      const std::vector<std::string>& mnemonic, const std::string& language);

 private:
  ByteData seed_;  //!< seed

  /**
   * @brief Mnemonic でサポートしている言語であるかを判定する.
   * @param[in] language  language used by mnemonic.
   * @retval true   If language is supported.
   * @retval false  If language is not supported.
   */
  static bool CheckSupportedLanguages(const std::string& language);

  /**
   * @brief mnemonic と passphrase から seed を生成する.
   * @param[in] mnemonic                ニーモニック配列
   * @param[in] passphrase              パスフレーズ
   * @param[in] use_ideographic_space   全角スペースで区切るかのフラグ
   * @return シード値バイトデータ
   */
  static ByteData ConvertMnemonicToSeed(
      const std::vector<std::string>& mnemonic, const std::string& passphrase,
      bool use_ideographic_space = false);
};

/**
 * @brief 拡張秘密鍵を表現するデータクラス
 */
class CFD_CORE_EXPORT ExtPrivkey {
 public:
  /**
   * @brief bip32 serialize size
   */
  static constexpr uint32_t kSerializeSize = 78;  // BIP32_SERIALIZED_LEN
  /**
   * @brief 強化鍵定義
   */
  static constexpr uint32_t kHardenedKey = 0x80000000;
  /**
   * @brief mainnet privkey version (BIP32_VER_MAIN_PRIVATE)
   */
  static constexpr uint32_t kVersionMainnetPrivkey = 0x0488ade4;
  /**
   * @brief testnet privkey version (BIP32_VER_TEST_PRIVATE)
   */
  static constexpr uint32_t kVersionTestnetPrivkey = 0x04358394;

  /**
   * @brief デフォルトコンストラクタ
   */
  ExtPrivkey();
  /**
   * @brief コンストラクタ
   * @param[in] seed          seed byte
   * @param[in] network_type  network type
   */
  explicit ExtPrivkey(const ByteData& seed, NetType network_type);
  /**
   * @brief コンストラクタ
   * @param[in] serialize_data  serialize data
   */
  explicit ExtPrivkey(const ByteData& serialize_data);
  /**
   * @brief コンストラクタ
   * @param[in] serialize_data  serialize data
   * @param[in] tweak_sum       tweak sum
   */
  explicit ExtPrivkey(
      const ByteData& serialize_data, const ByteData256& tweak_sum);
  /**
   * @brief コンストラクタ
   * @param[in] base58_data  base58 data
   */
  explicit ExtPrivkey(const std::string& base58_data);
  /**
   * @brief コンストラクタ
   * @param[in] base58_data  base58 data
   * @param[in] tweak_sum    tweak sum
   */
  explicit ExtPrivkey(
      const std::string& base58_data, const ByteData256& tweak_sum);
  /**
   * @brief コンストラクタ
   * @param[in] network_type       network type
   * @param[in] parent_key         parent privkey
   * @param[in] parent_chain_code  parent chain code
   * @param[in] parent_depth       parent depth
   * @param[in] child_num          child num
   */
  explicit ExtPrivkey(
      NetType network_type, const Privkey& parent_key,
      const ByteData256& parent_chain_code, uint8_t parent_depth,
      uint32_t child_num);

  /**
   * @brief 拡張keyのSerialize情報を取得する.
   * @return serialize data
   */
  ByteData GetData() const;
  /**
   * @brief 拡張keyのBase58文字列を取得する.
   * @return base58 string
   */
  std::string ToString() const;

  /**
   * @brief Privkeyインスタンスを取得する.
   * @return Privkeyインスタンス
   */
  Privkey GetPrivkey() const;
  /**
   * @brief 指定階層の拡張秘密鍵を取得する。
   * @param[in] child_num         child number
   * @return extended pubprivkeykey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey DerivePrivkey(uint32_t child_num) const;
  /**
   * @brief 指定階層の拡張秘密鍵を取得する。
   * @param[in] path              child number path
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey DerivePrivkey(const std::vector<uint32_t>& path) const;
  /**
   * @brief 指定階層の拡張秘密鍵を取得する。
   * @param[in] string_path     child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey DerivePrivkey(const std::string& string_path) const;

  /**
   * @brief 同一階層の拡張公開鍵を取得する。
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GetExtPubkey() const;
  /**
   * @brief 指定階層の拡張公開鍵を取得する。
   * @param[in] child_num         child number
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(uint32_t child_num) const;
  /**
   * @brief 指定階層の拡張公開鍵を取得する。
   * @param[in] path              child number path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::vector<uint32_t>& path) const;
  /**
   * @brief 指定階層の拡張公開鍵を取得する。
   * @param[in] string_path     child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::string& string_path) const;

  /**
   * @brief 状態が正常であるかを返却する.
   * @retval true 正常
   * @retval false 不正
   */
  bool IsValid() const;

  /**
   * @brief 拡張keyのDepthを取得する.
   * @return depth value
   */
  uint8_t GetDepth() const;
  /**
   * @brief version部を取得する.
   * @return version data (4byte)
   */
  uint32_t GetVersion() const;
  /**
   * @brief child number部を取得する.
   * @return child number (4byte)
   */
  uint32_t GetChildNum() const;
  /**
   * @brief chain code部を取得する.
   * @return chain code (32byte)
   */
  ByteData256 GetChainCode() const;
  /**
   * @brief version部を取得する.
   * @return version data (4byte)
   */
  ByteData GetVersionData() const;
  /**
   * @brief fingerprint部を取得する.
   * @return fingerprint data (4byte)
   */
  uint32_t GetFingerprint() const;
  /**
   * @brief fingerprint部を取得する.
   * @return fingerprint data (4byte)
   */
  ByteData GetFingerprintData() const;
  /**
   * @brief 派生Pubkeyを生成する過程で生成されたtweak値の合成値を取得する。
   * @return tweak sum
   */
  ByteData256 GetPubTweakSum() const;

 private:
  ByteData serialize_data_;   //!< serialize data
  uint32_t version_ = 0;      //!< version
  uint32_t fingerprint_ = 0;  //!< finger print
  uint8_t depth_ = 0;         //!< depth
  uint32_t child_num_ = 0;    //!< child number
  ByteData256 chaincode_;     //!< chain code
  Privkey privkey_;           //!< private key
  ByteData256 tweak_sum_;     //!< tweak sum
};

/**
 * @brief 拡張公開鍵を表現するデータクラス
 */
class CFD_CORE_EXPORT ExtPubkey {
 public:
  /**
   * @brief mainnet pubkey version (BIP32_VER_MAIN_PUBLIC)
   */
  static constexpr uint32_t kVersionMainnetPubkey = 0x0488b21e;
  /**
   * @brief testnet pubkey version (BIP32_VER_TEST_PUBLIC)
   */
  static constexpr uint32_t kVersionTestnetPubkey = 0x043587cf;

  /**
   * @brief デフォルトコンストラクタ
   */
  ExtPubkey();
  /**
   * @brief コンストラクタ
   * @param[in] serialize_data  serialize data
   */
  explicit ExtPubkey(const ByteData& serialize_data);
  /**
   * @brief コンストラクタ
   * @param[in] serialize_data  serialize data
   * @param[in] tweak_sum       tweak sum
   */
  explicit ExtPubkey(
      const ByteData& serialize_data, const ByteData256& tweak_sum);
  /**
   * @brief コンストラクタ
   * @param[in] base58_data  base58 data
   */
  explicit ExtPubkey(const std::string& base58_data);
  /**
   * @brief コンストラクタ
   * @param[in] base58_data  base58 data
   * @param[in] tweak_sum    tweak sum
   */
  explicit ExtPubkey(
      const std::string& base58_data, const ByteData256& tweak_sum);
  /**
   * @brief コンストラクタ
   * @param[in] network_type       network type
   * @param[in] parent_key         parent pubkey
   * @param[in] parent_chain_code  parent chain code
   * @param[in] parent_depth       parent depth
   * @param[in] child_num          child num
   */
  explicit ExtPubkey(
      NetType network_type, const Pubkey& parent_key,
      const ByteData256& parent_chain_code, uint8_t parent_depth,
      uint32_t child_num);

  /**
   * @brief 拡張keyのSerialize情報を取得する.
   * @return serialize data
   */
  ByteData GetData() const;
  /**
   * @brief 拡張keyのBase58文字列を取得する.
   * @return base58 string
   */
  std::string ToString() const;

  /**
   * @brief Pubkeyインスタンスを取得する.
   * @return Pubkeyインスタンス
   */
  Pubkey GetPubkey() const;
  /**
   * @brief 指定階層の拡張公開鍵を取得する。
   * @param[in] child_num         child number
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(uint32_t child_num) const;
  /**
   * @brief 指定階層の拡張公開鍵を取得する。
   * @param[in] path              child number path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::vector<uint32_t>& path) const;
  /**
   * @brief 指定階層の拡張公開鍵を取得する。
   * @param[in] string_path     child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::string& string_path) const;

  /**
   * @brief 派生Pubkeyを生成する過程で生成されたtweak値の合成値を取得する。
   * @param[in] path    child number path
   * @return tweak sum
   */
  ByteData256 DerivePubTweak(const std::vector<uint32_t>& path) const;
  /**
   * @brief 派生Pubkeyを生成する過程で生成されたtweak値の合成値を取得する。
   * @return tweak sum
   */
  ByteData256 GetPubTweakSum() const;

  /**
   * @brief 状態が正常であるかを返却する.
   * @retval true 正常
   * @retval false 不正
   */
  bool IsValid() const;

  /**
   * @brief 拡張keyのDepthを取得する.
   * @return depth value
   */
  uint8_t GetDepth() const;
  /**
   * @brief version部を取得する.
   * @return version data (4byte)
   */
  uint32_t GetVersion() const;
  /**
   * @brief child number部を取得する.
   * @return child number (4byte)
   */
  uint32_t GetChildNum() const;
  /**
   * @brief chain code部を取得する.
   * @return chain code (32byte)
   */
  ByteData256 GetChainCode() const;
  /**
   * @brief version部を取得する.
   * @return version data (4byte)
   */
  ByteData GetVersionData() const;
  /**
   * @brief fingerprint部を取得する.
   * @return fingerprint data (4byte)
   */
  uint32_t GetFingerprint() const;
  /**
   * @brief fingerprint部を取得する.
   * @return fingerprint data (4byte)
   */
  ByteData GetFingerprintData() const;

 private:
  ByteData serialize_data_;   //!< serialize data
  uint32_t version_ = 0;      //!< version
  uint32_t fingerprint_ = 0;  //!< finger print
  uint8_t depth_ = 0;         //!< depth
  uint32_t child_num_ = 0;    //!< child number
  ByteData256 chaincode_;     //!< chain code
  Pubkey pubkey_;             //!< public key
  ByteData256 tweak_sum_;     //!< tweak sum
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_
