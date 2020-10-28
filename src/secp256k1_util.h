// Copyright 2020 CryptoGarage

#ifndef CFD_CORE_SRC_SECP256K1_UTIL_H_
#define CFD_CORE_SRC_SECP256K1_UTIL_H_

#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "secp256k1.h"            // NOLINT
#include "secp256k1_extrakeys.h"  // NOLINT

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::Pubkey;

/**
 * @brief Parses a cfd-core Pubkey object into a secp256k1_pubkey struct.
 *
 * @param pubkey the pubkey to parse.
 * @return secp256k1_pubkey
 */
secp256k1_pubkey ParsePubkey(const Pubkey& pubkey);

/**
 * @brief Parses a signature contained inside a ByteData object to a
 * secp256k1_ecdsa_signature struct. 
 *
 * @param signature 
 * @return secp256k1_ecdsa_signature
 */
secp256k1_ecdsa_signature ParseSignature(const ByteData& signature);

/**
 * @brief Converts a secp256k1_pubkey struct to a cfd-core Pubkey object.
 *
 * @param pubkey the pubkey struct to convert.
 * @return Pubkey
 */
Pubkey ConvertSecpPubkey(const secp256k1_pubkey& pubkey);

/**
 * @brief Parses a cfd-core SchnorrPubkey object to a secp256k1_xonly_pubkey struct.
 *
 * @param pubkey the Schnorr pubkey to parse.
 * @return secp256k1_xonly_pubkey
 */
secp256k1_xonly_pubkey ParseXOnlyPubkey(const SchnorrPubkey& pubkey);

/**
 * @brief Get a secp256k1_pubkey struct to a secp256k1_xonly_pubkey struct.
 *
 * @param[in] pubkey the pubkey struct to convert.
 * @param[out] parity the parity of the tweaked pubkey.
 * @return secp256k1_xonly_pubkey
 */
secp256k1_xonly_pubkey GetXOnlyPubkeyFromPubkey(
    const secp256k1_pubkey& pubkey, bool* parity);

/**
 * @brief Tweak add a cfd-core SchnorrPubkey object to a ByteData256 object.
 *
 * @param pubkey the Schnorr pubkey.
 * @param tweak the tweak add bytes.
 * @param parity the parity of the tweaked pubkey.
 * @return Tweaked SchnorrPubkey bytes
 */
ByteData256 TweakAddXonlyPubkey(
    const SchnorrPubkey& pubkey, const ByteData256& tweak, bool* parity);

/**
 * @brief Check a tweak cfd-core ByteData256 object.
 *
 * @param tweaked_pubkey the tweaked Schnorr pubkey.
 * @param base_pubkey the base pubkey.
 * @param tweak the tweak bytes.
 * @param parity the parity of the tweaked pubkey.
 * @retval true   tweaked.
 * @retval false  not tweaked.
 */
bool CheckTweakAddXonlyPubkey(
    const SchnorrPubkey& tweaked_pubkey, const SchnorrPubkey& base_pubkey,
    const ByteData256& tweak, bool parity);

/**
 * @brief Converts a secp256k1_xonly_pubkey struct to a cfd-core ByteData256 object.
 *
 * @param pubkey the xonly pubkey struct to convert.
 * @return SchnorrPubkey bytes
 */
ByteData256 ConvertSchnorrPubkey(const secp256k1_xonly_pubkey& pubkey);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_SRC_SECP256K1_UTIL_H_
