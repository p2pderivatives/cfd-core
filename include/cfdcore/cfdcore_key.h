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
   * @param[in] pubkeys 合成元Pubkey list
   * @return 合成したPubkeyインスタンス
   */
  static Pubkey CombinePubkey(const std::vector<Pubkey>& pubkeys);

  /**
   * @brief 合成Pubkeyを生成する.
   * @param[in] pubkey 合成元Pubkey
   * @param[in] message_key 合成するmessage Pubkey
   * @return 合成したPubkeyインスタンス
   */
  static Pubkey CombinePubkey(const Pubkey& pubkey, const Pubkey& message_key);

  /**
   * @brief Create new public key with tweak added.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of pubkey key with tweak added.
   */
  Pubkey CreateTweakAdd(const ByteData256& tweak) const;

  /**
   * @brief Create new negated public key with tweak multiplied.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of pubkey key with tweak added.
   */
  Pubkey CreateTweakMul(const ByteData256& tweak) const;

  /**
   * @brief Create new negated public key.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @return new instance of pubkey key with tweak added.
   */
  Pubkey CreateNegate() const;

  /**
   * @brief Create new uncompressed public key.
   * @return new instance of pubkey key with uncompressed.
   */
  Pubkey Compress() const;

  /**
   * @brief Create new uncompressed public key.
   * @return new instance of pubkey key with uncompressed.
   */
  Pubkey Uncompress() const;

  /**
   * @brief Verify if a signature with respect to a public key and a message.
   * @param[in] signature_hash  the message to verify the signature against.
   * @param[in] signature       the signature to verify.
   * @return true if the signature is valid, false if not.
   */
  bool VerifyEcSignature(
      const ByteData256& signature_hash, const ByteData& signature) const;

  /**
   * @brief function for schnorr public key.
   * @param[in] oracle_pubkey   the public key of the oracle.
   * @param[in] oracle_r_point  the R point for the event.
   * @param[in] message         the message for the outcome.
   * @return data of public key.
   * @throw CfdException if invalid data.
   */
  static Pubkey GetSchnorrPubkey(
      const Pubkey& oracle_pubkey, const Pubkey& oracle_r_point,
      const ByteData256& message);

  /**
   * @brief 公開鍵として正しい形式であるかを検証する.
   * @param[in] byte_data 公開鍵のByteData
   * @retval true   正常フォーマット
   * @retval false  不正フォーマット
   */
  static bool IsValid(const ByteData& byte_data);

  /**
   * @brief 指定された2つの公開鍵のHEX値を比較する.
   * @param[in] source        source target
   * @param[in] destination   destination target
   * @retval true   大きい
   * @retval false  小さい
   */
  static bool IsLarge(const Pubkey& source, const Pubkey& destination);

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
  std::string ConvertWif(NetType net_type, bool is_compressed = true) const;

  /**
   * @brief Private keyからPubkeyインスタンスを生成する.
   * @param[in] is_compressed privatekeyから導出するpubkeyのcompress有無
   * @return Pubkeyインスタンス
   */
  Pubkey GeneratePubkey(bool is_compressed = true) const;

  /**
   * @brief Create new private key with tweak added.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of private key with tweak added.
   */
  Privkey CreateTweakAdd(const ByteData256& tweak) const;

  /**
   * @brief Create new private key with tweak multiplied.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @return new instance of private key with tweak added.
   */
  Privkey CreateTweakMul(const ByteData256& tweak) const;

  /**
   * @brief Create new negated private key.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @return new instance of private key with tweak added.
   */
  Privkey CreateNegate() const;

  /**
   * @brief get schnorr public nonce.
   * @return data of public nonce.
   */
  Pubkey GetSchnorrPublicNonce() const;

  /**
   * @brief PrivateKeyの設定状態が不正であるかを返却する.
   * @retval true 状態が不正
   * @retval false 状態は正常
   * @deprecated API整理時に削除予定
   */
  bool IsInvalid() const;

  /**
   * @brief PrivateKeyの設定状態が正常であるかを返却する.
   * @retval true 状態は正常
   * @retval false 状態が不正
   */
  bool IsValid() const;

  /**
   * @brief Check this privkey and argument key byte is match or not.
   * @param[in] privkey   private key to be compared
   * @retval true   match
   * @retval false  not match
   */
  bool Equals(const Privkey& privkey) const;

  /**
   * @brief calculate ec signature from sighash.
   * @param[in] signature_hash  signature hash
   * @param[in] has_grind_r     use EC_FLAG_GRIND_R.(default: true)
   * @return signature
   */
  ByteData CalculateEcSignature(
      const ByteData256& signature_hash, bool has_grind_r = true) const;

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

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_KEY_H_
