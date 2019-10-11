// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_key.h
 *
 * @brief Pubkey/Privkey関連クラス定義
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_KEY_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_KEY_H_

#include <string>
#include <vector>
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

/**
 * @typedef NetType
 * @brief Bitcoin networkの定義
 */
typedef enum {
  kMainnet = 0,               //!< MAINNET
  kTestnet,                   //!< TESTNET
  kRegtest,                   //!< REGTEST
  kLiquidV1,                  //!< LiquidV1
  kElementsRegtest,           //!< Elements Regtest
  kCustomChain,               //!< Custom chain
  kNetTypeNum = kCustomChain  //!< NETTYPE_NUM
} NetType;

/**
 * @brief PublicKeyを表現するデータクラス
 */
class CFD_CORE_EXPORT Pubkey {
 public:
  /**
   * @brief Uncompress Pubkey byte size
   */
  static constexpr uint32_t kPubkeySize = 65;
  /**
   * @brief Compress Pubkey byte size
   */
  static constexpr uint32_t kCompressedPubkeySize = 33;

  /**
   * @brief デフォルトコンストラクタ
   */
  Pubkey();

  /**
   * @brief コンストラクタ
   * @param[in] byte_data   公開鍵のByteDataインスタンス
   */
  explicit Pubkey(ByteData byte_data);

  /**
   * @brief HEX文字列からPublicKeyモデルを復元するコンストラクタ.
   * @param[in] hex_string PublicKeyのHEX文字列
   */
  explicit Pubkey(const std::string& hex_string);

  /**
   * @brief 自身のByteDataからHEX文字列を取得する.
   * @return 公開鍵のHEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief 自身のByteDataを取得する.
   * @return 公開鍵のByteData
   */
  ByteData GetData() const;

  /**
   * @brief 公開鍵がCompress形式であるかを返却する.
   * @return Compressであればtrue, Uncompressであればfalse
   */
  bool IsCompress() const;

  /**
   * @brief 公開鍵として正しい形式であるかを検証する.
   * @retval true   正常フォーマット
   * @retval false  不正フォーマット
   */
  bool IsValid() const;

  /**
   * @brief 公開鍵が一致するかチェックする.
   * @param[in] pubkey 比較対象Pubkey
   * @retval true   一致
   * @retval false  不一致
   */
  bool Equals(const Pubkey& pubkey) const;

  /**
   * @brief 合成Pubkeyを生成する.
   * @param[in] pubkey 合成元Pubkey
   * @param[in] message_key 合成するmessage Pubkey
   * @return 合成したPubkeyインスタンス
   */
  static Pubkey CombinePubkey(Pubkey pubkey, Pubkey message_key);

  /**
   * @brief 公開鍵として正しい形式であるかを検証する.
   * @param[in] byte_data 公開鍵のByteData
   * @retval true   正常フォーマット
   * @retval false  不正フォーマット
   */
  static bool IsValid(const ByteData& byte_data);

 private:
  /**
   * @brief ByteData of PublicKey
   */
  ByteData data_;
};

/**
 * @brief Private Keyを表現するデータクラス
 */
class CFD_CORE_EXPORT Privkey {
 public:
  /**
   * @brief Private key byte size
   */
  static constexpr uint32_t kPrivkeySize = 32;  // EC_PRIVATE_KEY_LEN
  /**
   * @brief デフォルトコンストラクタ
   */
  Privkey();

  /**
   * @brief コンストラクタ
   * @param[in] byte_data 秘密鍵のByteDataインスタンス
   */
  explicit Privkey(const ByteData& byte_data);

  /**
   * @brief コンストラクタ
   * @param[in] byte_data 秘密鍵のByteDataインスタンス
   */
  explicit Privkey(const ByteData256& byte_data);

  /**
   * @brief 文字列からPrivateKeyモデルを復元するコンストラクタ.
   * @param[in] hex_str PrivateKeyのHEX文字列
   */
  explicit Privkey(const std::string& hex_str);

  /**
   * @brief 自身のByteDataからHEX文字列を取得する.
   * @return 秘密鍵のHEX文字列
   */
  std::string GetHex() const;

  /**
   * @brief 自身のByteDataを取得する.
   * @return 秘密鍵のByteData
   */
  ByteData GetData() const;

  /**
   * @brief WIFに変換する.
   * @param[in] net_type Mainnet or Testnet
   * @param[in] is_compressed privatekeyから導出するpubkeyのcompress有無
   * @return WIF文字列
   */
  std::string ConvertWif(NetType net_type, bool is_compressed = true);

  /**
   * @brief WIFからPrivKeyインスタンスを生成する.
   * @param[in] wif WIF文字列
   * @param[in] net_type Mainnet or Testnet
   * @param[in] is_compressed privatekeyから導出するpubkeyのcompress有無
   * @return Privkeyインスタンス
   */
  static Privkey FromWif(
      const std::string& wif, NetType net_type, bool is_compressed = true);

  /**
   * @brief 乱数からPrivkeyインスタンスを生成する.
   *
   * 生成できるまで繰り返すため、時間がかかる場合がある.
   * @return Privkeyインスタンス
   */
  static Privkey GenerageRandomKey();

  /**
   * @brief Private keyからPubkeyインスタンスを生成する.
   * @param[in] is_compressed privatekeyから導出するpubkeyのcompress有無
   * @return Pubkeyインスタンス
   */
  Pubkey GeneratePubkey(bool is_compressed = true) const;

  /**
   * @brief PrivateKeyの設定状態が不正であるかを返却する.
   * @retval true 状態が不正
   * @retval false 状態は正常
   */
  bool IsInvalid() const;

 private:
  /**
   * @brief ByteData of Private key.
   */
  ByteData data_;

  /**
   * @brief 秘密鍵として正しい形式であるかを検証する.
   * @param[in] buffer 秘密鍵のByteData
   * @retval true   正常フォーマット
   * @retval false  不正フォーマット
   */
  static bool IsValid(const std::vector<uint8_t>& buffer);
};

/**
 * @brief 拡張Keyを表現するデータクラス
 */
class CFD_CORE_EXPORT ExtKey {
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
   * @brief bip32 serialize size
   */
  static constexpr uint32_t kSerializeSize = 78;  // BIP32_SERIALIZED_LEN
  /**
   * @brief mainnet pubkey prefix (BIP32_VER_MAIN_PUBLIC)
   */
  static constexpr uint32_t kPrefixMainnetPubkey = 0x0488b21e;
  /**
   * @brief mainnet privkey prefix (BIP32_VER_MAIN_PRIVATE)
   */
  static constexpr uint32_t kPrefixMainnetPrivkey = 0x0488ade4;
  /**
   * @brief testnet pubkey prefix (BIP32_VER_TEST_PUBLIC)
   */
  static constexpr uint32_t kPrefixTestnetPubkey = 0x043587c;
  /**
   * @brief testnet privkey prefix (BIP32_VER_TEST_PRIVATE)
   */
  static constexpr uint32_t kPrefixTestnetPrivkey = 0x04358394;

  /**
   * @brief デフォルトコンストラクタ
   */
  ExtKey();

  /**
   * @brief コンストラクタ
   * @param[in] serialize_data  serialize data
   */
  explicit ExtKey(const ByteData& serialize_data);

  /**
   * @brief コンストラクタ
   * @param[in] base58_data  base58 data
   */
  explicit ExtKey(const std::string& base58_data);

  /**
   * @brief コンストラクタ
   * @param[in] seed      seed byte
   * @param[in] prefix    prefix data
   */
  explicit ExtKey(const ByteData& seed, uint32_t prefix);

  /**
   * @brief privkeyの存在有無を取得する.
   * @retval true   存在
   * @retval false  未存在
   */
  bool IsPrivkey() const;

  /**
   * @brief 拡張keyのSerialize情報を取得する.
   * @return serialize data
   */
  ByteData GetData() const;

  /**
   * @brief 拡張keyのBase58文字列を取得する.
   * @return base58 string
   */
  std::string GetBase58String() const;

  /**
   * @brief prefix部を取得する.
   * @return prefix data (4byte)
   */
  ByteData GetPrefix() const;

  /**
   * @brief 拡張keyのDepthを取得する.
   * @return depth value
   */
  uint8_t GetDepth() const;

  /**
   * @brief Pubkeyインスタンスを取得する.
   * @return Pubkeyインスタンス
   */
  Pubkey GetPubkey() const;

  /**
   * @brief Privkeyインスタンスを取得する.
   * @return Privkeyインスタンス
   */
  Privkey GetPrivkey() const;

  /**
   * @brief Keyの設定状態が不正であるかを返却する.
   * @retval true 状態が不正
   * @retval false 状態は正常
   */
  bool IsInvalid() const;
  /**
   * @brief 派生Pubkeyを生成する。
   * @param[in] child_num   child number
   * @return child key
   */
  ExtKey DerivePubkey(uint32_t child_num) const;
  /**
   * @brief 派生Pubkeyを生成する過程で生成されたtweak値の合成値を取得する。
   * @param[in] key_paths   child number list
   * @return tweak sum
   */
  ByteData256 DerivePubTweak(const std::vector<uint32_t>& key_paths) const;

 private:
  ByteData serialize_data_;  //!< serialize data
  ByteData prefix_;          //!< prefix
  uint8_t depth_ = 0;        //!< depth
  uint32_t child_ = 0;       //!< child number
  ByteData256 chaincode_;    //!< chain code
  Pubkey pubkey_;            //!< public key
  Privkey privkey_;          //!< private key

  /**
   * @brief 派生Pubkeyを生成する際のTweak値を取得する。
   * @param[in] child_num   child number
   * @return tweak
   */
  ByteData256 GetDerivePubkeyTweak(uint32_t child_num) const;
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_KEY_H_
