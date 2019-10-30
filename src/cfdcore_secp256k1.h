// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_secp256k1.h
 * @brief secp256k1 utility.
 *
 */
#ifndef CFD_CORE_SRC_CFDCORE_SECP256K1_H_
#define CFD_CORE_SRC_CFDCORE_SECP256K1_H_

#include <vector>
#include "cfdcore/cfdcore_bytedata.h"

namespace cfd {
namespace core {

/**
 * @brief sept256k1 class / secp256k1クラス.
 */
class Secp256k1 {
 public:
  /**
   * @brief Construct / コンストラクタ
   * @param[in] context Secp256k1 Context / Secp256k1コンテキスト
   */
  explicit Secp256k1(void* context);

  /**
   * [ENG]
   * @brief function for join Pubkey
   * @param[in] pubkey_list input list for Pubkey to join
   * @return data of combined Pubkey
   * [JP]
   * @brief Pubkey合成処理
   * @param[in] pubkey_list 合成するPubkeyリスト
   * @return 合成したPubkeyデータ
   */
  ByteData CombinePubkeySecp256k1Ec(const std::vector<ByteData>& pubkey_list);

  /**
   * [ENG]
   * @brief function for adjusting Pubkey
   * @param[in] pubkey            Pubkey
   * @param[in] tweak             adjustment value
   * @param[in] is_tweak_check    boolean check for pubkey adjustment
   * @return data of adjusted Pubkey data
   * [JP]
   * @brief Pubkey調整処理
   * @param[in] pubkey            Pubkey
   * @param[in] tweak             調整値
   * @param[in] is_tweak_check    pubkey調整チェック実施有無
   * @return 調整後のPubkeyデータ
   */
  ByteData AddTweakPubkeySecp256k1Ec(
      const ByteData& pubkey, const ByteData& tweak, bool is_tweak_check);

  /**
   * [ENG]
   * @brief function for adjusting Privkey
   * @param[in] privkey           Privkey
   * @param[in] tweak             Adjustment value
   * @return data of adjusted Privkey data
   * [JP]
   * @brief Privkey調整処理
   * @param[in] privkey           Privkey
   * @param[in] tweak             調整値
   * @return 調整後のPrivkeyデータ
   */
  ByteData256 AddTweakPrivkeySecp256k1Ec(
      const ByteData256& privkey, const ByteData256& tweak);

  /**
   * [ENG]
   * @brief function for negate Pubkey
   * @param[in] pubkey            Pubkey
   * @return data of negated Pubkey
   * [JP]
   * @brief Pubkey negate処理
   * @param[in] pubkey            Pubkey
   * @return 加工後のPubkeyデータ
   */
  ByteData NegatePubkeySecp256k1Ec(const ByteData& pubkey);

  /**
   * @brief Decode range-proof and extract some information.
   * @param[in]  range_proof  ByteData of range-proof
   * @param[out] exponent     exponent value in the proof
   * @param[out] mantissa     Number of bits covered by the proof
   * @param[out] min_value    the minimum value that commit could have
   * @param[out] max_value    the maximum value that commit could have
   * @throws CfdException if invalid range_proof data passed.
   */
  void RangeProofInfoSecp256k1(
      const ByteData& range_proof, int* exponent, int* mantissa,
      uint64_t* min_value, uint64_t* max_value);

  /**
   * @brief-eng Whitelist generation process for certificate info
   * @brief-jp Whitelist 証明情報生成処理
   * @param[in] offline_pubkey    offline pubkey
   * @param[in] online_privkey    online private key
   * @param[in] tweak_sum         tweak sum data
   * @param[in] online_keys       whitelist online key list
   * @param[in] offline_keys      whitelist offline key list
   * @param[in] whitelist_index   whitelist target index
   * @return Whitelist proof
   */
  ByteData SignWhitelistSecp256k1Ec(
      const ByteData& offline_pubkey, const ByteData256& online_privkey,
      const ByteData256& tweak_sum, const std::vector<ByteData>& online_keys,
      const std::vector<ByteData>& offline_keys, uint32_t whitelist_index);

 private:
  /**
   * @brief Secp256k1 Context / Secp256k1コンテキスト
   */
  void* secp256k1_context_;
};

}  // namespace core
}  // namespace cfd
#endif  // CFD_CORE_SRC_CFDCORE_SECP256K1_H_
