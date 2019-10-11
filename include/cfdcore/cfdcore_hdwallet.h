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

namespace cfd {
namespace core {

using cfd::core::ByteData;

/**
 * @brief HDWalletを表現するデータクラス
 */
class CFD_CORE_EXPORT HDWallet {
 public:
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

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_
