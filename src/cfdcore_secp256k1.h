// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_secp256k1.h
 * @brief secp256k1 utilities.
 *
 */
#ifndef CFD_CORE_SRC_CFDCORE_SECP256K1_H_
#define CFD_CORE_SRC_CFDCORE_SECP256K1_H_

#include <cstdint>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"

namespace cfd {
namespace core {

/**
 * @brief secp256k1 class
 */
class Secp256k1 {
 public:
  /**
   * @brief Get surjectionproof input limit count.
   * @return limit count.
   */
  static uint32_t GetSurjectionproofInputLimit();

  /**
   * @brief Construct
   * @param[in] context Secp256k1 Context
   */
  explicit Secp256k1(void* context);

  /**
   * @brief function for join Pubkey
   * @param[in] pubkey_list input list for Pubkey to join
   * @return  data of combined Pubkey
   */
  ByteData CombinePubkeySecp256k1Ec(const std::vector<ByteData>& pubkey_list);

  /**
   * @brief compress pubkey.
   * @param[in] uncompressed_pubkey  uncompressed pubkey.
   * @return data of compressed Pubkey
   */
  ByteData CompressPubkeySecp256k1Ec(const ByteData& uncompressed_pubkey);

  /**
   * @brief Tweak a private key by adding tweak.
   * @param[in] privkey     private key.(must 32-byte)
   * @param[in] tweak       tweak value to be added.(32-byte)
   * @return ByteData instance shows private key
   */
  ByteData AddTweakPrivkeySecp256k1Ec(
      const ByteData& privkey, const ByteData& tweak);

  /**
   * @brief Tweak a private key by multiplying it by a tweak.
   * @param[in] privkey     private key.(must 32-byte)
   * @param[in] tweak       tweak value to be multiplied.(32-byte)
   * @return ByteData instance shows private key
   */
  ByteData MulTweakPrivkeySecp256k1Ec(
      const ByteData& privkey, const ByteData& tweak);

  /**
   * @brief function for adjusting Pubkey
   * @param[in] pubkey            Pubkey
   * @param[in] tweak             tweak value to be added.(32-byte)
   * @param[in] is_tweak_check    boolean check for pubkey adjustment
   * @return  data of adjusted Pubkey data
   */
  ByteData AddTweakPubkeySecp256k1Ec(
      const ByteData& pubkey, const ByteData& tweak, bool is_tweak_check);

  /**
   * @brief Tweak a public key by multiplying it by a tweak value.
   * @param[in] pubkey            Pubkey
   * @param[in] tweak             tweak value to be multiplied.(32-byte)
   * @return  data of adjusted Pubkey data
   */
  ByteData MulTweakPubkeySecp256k1Ec(
      const ByteData& pubkey, const ByteData& tweak);

  /**
   * @brief function for negate Privkey
   * @param[in] privkey         Privkey
   * @return data of negated Privkey
   */
  ByteData NegatePrivkeySecp256k1Ec(const ByteData& privkey);

  /**
   * @brief function for negate Pubkey
   * @param[in] pubkey            Pubkey
   * @return data of negated Pubkey
   */
  ByteData NegatePubkeySecp256k1Ec(const ByteData& pubkey);

  /**
   * @brief Decode range-proof and extract some information.
   * @param[in]  range_proof  ByteData of range-proof
   * @param[out] exponent     exponent value in the proof
   * @param[out] mantissa     Number of bits covered by the proof
   * @param[out] min_value    the minimum value that commit could have
   * @param[out] max_value    the maximum value that commit could have
   * @throw CfdException if invalid range_proof data passed.
   */
  void RangeProofInfoSecp256k1(
      const ByteData& range_proof, int* exponent, int* mantissa,
      uint64_t* min_value, uint64_t* max_value);

  /**
   * @brief Whitelist generation process for certificate info
   * \~
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
   * @brief Secp256k1 Context
   */
  void* secp256k1_context_;
};

}  // namespace core
}  // namespace cfd
#endif  // CFD_CORE_SRC_CFDCORE_SECP256K1_H_
