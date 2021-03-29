// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_wally_util.h
 *
 * @brief libwally internal utility.
 *
 */
#ifndef CFD_CORE_SRC_CFDCORE_WALLY_UTIL_H_
#define CFD_CORE_SRC_CFDCORE_WALLY_UTIL_H_
#ifdef __cplusplus

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore_secp256k1.h"  // NOLINT
#include "wally_address.h"      // NOLINT
#include "wally_bip32.h"        // NOLINT
#include "wally_bip38.h"        // NOLINT
#include "wally_bip39.h"        // NOLINT
#include "wally_core.h"         // NOLINT
#include "wally_crypto.h"       // NOLINT
#include "wally_descriptor.h"   // NOLINT
#include "wally_psbt.h"         // NOLINT
#include "wally_script.h"       // NOLINT
#include "wally_transaction.h"  // NOLINT

namespace cfd {
namespace core {

/**
 * @brief libwally utility.
 */
class WallyUtil {
 public:
  /**
   * @brief VarIntサイズ
   */
  static constexpr uint8_t kMaxVarIntSize = 5;
  /**
   * @brief converts char* to std::string, and call wally_free_string.
   * @param[in] wally_string    libwally created string buffer.
   * @result std::string object.
   */
  static std::string ConvertStringAndFree(char* wally_string);

  /**
   * @brief Pubkey合成処理
   * @param[in] pubkey_list 合成するPubkeyリスト
   * @return 合成したPubkeyデータ
   */
  static ByteData CombinePubkeySecp256k1Ec(
      const std::vector<ByteData>& pubkey_list);

  /**
   * @brief compress pubkey.
   * @param[in] uncompressed_pubkey  uncompressed pubkey.
   * @return data of compressed Pubkey
   */
  static ByteData CompressPubkey(const ByteData& uncompressed_pubkey);

  /**
   * @brief 加算によるPrivkey調整処理
   * @param[in] privkey           Privkey
   * @param[in] tweak             調整値
   * @return 調整後のPrivkey ByteData
   */
  static ByteData AddTweakPrivkey(
      const ByteData& privkey, const ByteData256& tweak);

  /**
   * @brief 乗算によるPrivkey調整処理
   * @param[in] privkey           Privkey
   * @param[in] tweak             調整値
   * @return 調整後のPrivkey ByteData
   */
  static ByteData MulTweakPrivkey(
      const ByteData& privkey, const ByteData256& tweak);

  /**
   * @brief 加算によるPubkey調整処理
   * @param[in] pubkey            Pubkey
   * @param[in] tweak             調整値
   * @param[in] is_tweak_check    pubkey調整チェック実施有無
   * @return 調整後のPubkeyデータ
   */
  static ByteData AddTweakPubkey(
      const ByteData& pubkey, const ByteData256& tweak,
      bool is_tweak_check = false);

  /**
   * @brief 乗算によるPubkey調整処理
   * @param[in] pubkey            Pubkey
   * @param[in] tweak             調整値
   * @return 調整後のPubkeyデータ
   */
  static ByteData MulTweakPubkey(
      const ByteData& pubkey, const ByteData256& tweak);

  /**
   * @brief Scriptにpushするデータを生成する
   * @param[in] bytes 追加データ
   * @param[in] flags hashフラグ(@see wally_script_push_from_bytes)
   * @return 生成データ
   */
  static std::vector<uint8_t> CreateScriptDataFromBytes(
      const std::vector<uint8_t>& bytes, int32_t flags = 0);

  /**
   * @brief Privkey negate処理
   * @param[in] privkey           Privkey
   * @return Negate 後の Privkey ByteData
   */
  static ByteData NegatePrivkey(const ByteData& privkey);

  /**
   * @brief Pubkey negate処理
   * @param[in] pubkey            Pubkey
   * @return Negate 後の Pubkey ByteData
   */
  static ByteData NegatePubkey(const ByteData& pubkey);

  /**
   * @brief Decode range-proof and extract some information.
   * @param[in]  range_proof  ByteData of range-proof
   * @param[out] exponent     exponent value in the proof
   * @param[out] mantissa     Number of bits covered by the proof
   * @param[out] min_value    the minimum value that commit could have
   * @param[out] max_value    the maximum value that commit could have
   */
  static void RangeProofInfo(
      const ByteData& range_proof, int* exponent, int* mantissa,
      uint64_t* min_value, uint64_t* max_value);

  /**
   * @brief Whitelist 証明情報生成処理
   * @param[in] offline_pubkey    offline pubkey
   * @param[in] online_privkey    online private key
   * @param[in] tweak_sum         tweak sum data
   * @param[in] online_keys       whitelist online key list
   * @param[in] offline_keys      whitelist offline key list
   * @param[in] whitelist_index   whitelist target index
   * @return Whitelist proof
   */
  static ByteData SignWhitelist(
      const ByteData& offline_pubkey, const ByteData256& online_privkey,
      const ByteData256& tweak_sum, const std::vector<ByteData>& online_keys,
      const std::vector<ByteData>& offline_keys, uint32_t whitelist_index);

  /**
   * @brief Mnemonic で利用できる Wordlist を取得する.
   * @param[in] language    language to use.
   * @return wordlist to use mnemonic which supported by bip39.
   * @throws CfdException   If invalid argument passed.
   */
  static std::vector<std::string> GetMnemonicWordlist(
      const std::string& language);

  /**
   * @brief mnemonic と passphrase から seed を生成する.
   * @details This function doesn't check mnemonic words strictly.
   *     If you need to check mnemonic is valid, may use CheckValidMnemonic.
   * @param[in] mnemonic    mnemonic words list.
   * @param[in] passphrase  passphrase used as a solt.
   * @param[in] use_ideographic_space   flag of using ideographic space
   *     for mnemonic separator
   * @return binary seed to use hdwallet.
   * @throws CfdException   If invalid argument passed.
   */
  static ByteData ConvertMnemonicToSeed(
      const std::vector<std::string>& mnemonic, const std::string& passphrase,
      bool use_ideographic_space = false);

  /**
   * @brief Entropy から Mnemonic を生成する.
   * @param[in] entropy     entropy to generate mnemonic.
   * @param[in] language    language to use mnemonic.
   * @return mnemonic which is generated from entropy.
   * @throws CfdException   If invalid argument passed.
   */
  static std::vector<std::string> ConvertEntropyToMnemonic(
      const ByteData& entropy, const std::string& language);

  /**
   * @brief Mnemonic から Entropy へ変換する.
   * @param[in] mnemonic    mnemonic to derive entropy.
   * @param[in] language    language used by mnemonic.
   * @param[in] use_ideographic_space   flag of using ideographic space
   *     for mnemonic separator
   * @return binary entropy.
   * @throws CfdException   If invalid argument passed.
   */
  static ByteData ConvertMnemonicToEntropy(
      const std::vector<std::string>& mnemonic, const std::string& language,
      bool use_ideographic_space = false);

  /**
   * @brief Mnemonic でサポートしている言語を取得する.
   * @return supported language vector.
   */
  static std::vector<std::string> GetSupportedMnemonicLanguages();

  /**
   * @brief Verify mnemonic is valid 
   * @param[in] mnemonic                mnemonic vector to check valid
   * @param[in] language                language to verify
   * @retval true   mnemonic checksum is valid
   * @retval false  mnemonic checksum is invalid
   */
  static bool CheckValidMnemonic(
      const std::vector<std::string>& mnemonic, const std::string& language);

 private:
  /**
   * @brief default constructor.
   */
  WallyUtil();

  /**
   * @brief Get the 'index'th word from passed BIP39 wordlist.
   * @param[in] wardlist    the wordlist to get the word from.
   * @param[in] index       target index number of wordlist.
   * @return string of the word from wordlist.
   * @throws CfdException   If invalid arguments passed.
   */
  static std::string GetMnemonicWord(
      const words* wardlist, const size_t index);
};

}  // namespace core
}  // namespace cfd

#endif  // __cplusplus
#endif  // CFD_CORE_SRC_CFDCORE_WALLY_UTIL_H_
