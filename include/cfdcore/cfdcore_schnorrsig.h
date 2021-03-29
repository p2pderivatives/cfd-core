// Copyright 2020 CryptoGarage
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCHNORRSIG_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCHNORRSIG_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SigHashType;

class SchnorrSignature;

/**
 * @brief A Schnorr public key.
 *
 */
class CFD_CORE_EXPORT SchnorrPubkey {
 public:
  /**
  * @brief Size of a Schnorr public key.
  *
  */
  static constexpr uint32_t kSchnorrPubkeySize = 32;

  /**
   * @brief Default constructor.
   */
  SchnorrPubkey();

  /**
   * @brief Construct a new SchnorrPubkey object from ByteData
   *
   * @param data the data representing the adaptor nonce
   */
  explicit SchnorrPubkey(const ByteData &data);
  /**
   * @brief Construct a new SchnorrPubkey object from ByteData256
   *
   * @param data the data representing the adaptor nonce
   */
  explicit SchnorrPubkey(const ByteData256 &data);
  /**
   * @brief Construct a new Schnorr Pubkey object from a string
   *
   * @param data the data representing the adaptor nonce
   */
  explicit SchnorrPubkey(const std::string &data);

  /**
   * @brief Get the underlying ByteData object
   *
   * @return ByteData
   */
  ByteData GetData() const;
  /**
   * @brief Get the underlying ByteData256 object
   *
   * @return ByteData256
   */
  ByteData256 GetByteData256() const;
  /**
   * @brief Get the hex string.
   *
   * @return hex string.
   */
  std::string GetHex() const;
  /**
   * @brief Equals a key.
   * @param[in] pubkey  a key to compare
   * @retval true   equal.
   * @retval false  not equal.
   */
  bool Equals(const SchnorrPubkey &pubkey) const;
  /**
   * @brief Verify format.
   * @retval true   valid
   * @retval false  invalid
   */
  bool IsValid() const;

  /**
   * @brief Create new public key with tweak added.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @param[out] parity   the parity of the tweaked pubkey.
   * @return new instance of pubkey key with tweak added.
   */
  SchnorrPubkey CreateTweakAdd(
      const ByteData256 &tweak, bool *parity = nullptr) const;
  /**
   * @brief Create new public key with tweak added.
   * @details This function doesn't have no side-effect.
   *     It always returns new instance of Privkey.
   * @param[in] tweak     tweak to be added
   * @param[out] parity   the parity of the tweaked pubkey.
   * @return new instance of pubkey key with tweak added.
   */
  SchnorrPubkey CreateTweakAdd(
      const SchnorrPubkey &tweak, bool *parity = nullptr) const;
  /**
   * @brief Is tweaked pubkey from a based pubkey.
   *
   * @param base_pubkey the base pubkey.
   * @param tweak the tweak bytes.
   * @param parity the parity of the tweaked pubkey.
   * @retval true   tweak from based pubkey
   * @retval false  other
   */
  bool IsTweaked(
      const SchnorrPubkey &base_pubkey, const ByteData256 &tweak,
      bool parity) const;
  /**
   * @brief Verify a Schnorr signature.
   *
   * @param signature the signature to verify.
   * @param msg the message to verify the signature against.
   * @retval true if the signature is valid
   * @retval false if the signature is invalid
   */
  bool Verify(const SchnorrSignature &signature, const ByteData256 &msg) const;

  /**
   * @brief Create public key.
   * @details This function is need set the parity.
   * @param[in] parity  the parity of the pubkey.
   * @return pubkey
   */
  Pubkey CreatePubkey(bool parity = false) const;

  /**
   * @brief get schnorr public key from private key.
   *
   * @param[in] privkey the private key from which to create the Schnorr public key.
   * @param[out] parity the parity of the tweaked pubkey.
   * @return SchnorrPubkey the public key associated with the given private key
   * generated according to BIP340.
   */
  static SchnorrPubkey FromPrivkey(
      const Privkey &privkey, bool *parity = nullptr);
  /**
   * @brief get schnorr public key from public key.
   *
   * @param[in] pubkey the public key from which to create the Schnorr public key.
   * @param[out] parity the parity of the tweaked pubkey.
   * @return SchnorrPubkey the public key associated with the given private key
   * generated according to BIP340.
   */
  static SchnorrPubkey FromPubkey(
      const Pubkey &pubkey, bool *parity = nullptr);
  /**
   * @brief Create tweak add pubkey from base privkey.
   *
   * @param[in] privkey the private key from which to create the Schnorr public key.
   * @param[in] tweak the tweak to be added
   * @param[out] tweaked_privkey the tweaked private key.
   * @param[out] parity the parity of the tweaked pubkey.
   * @return SchnorrPubkey the tweaked public key associated with the given private key
   * generated according to BIP340.
   */
  static SchnorrPubkey CreateTweakAddFromPrivkey(
      const Privkey &privkey, const ByteData256 &tweak,
      Privkey *tweaked_privkey, bool *parity = nullptr);

  /**
   * @brief tweak add pubkey.
   * @param[in] right   tweak data
   * @return tweaked pubkey
   */
  SchnorrPubkey operator+=(const ByteData256 &right);
  /**
   * @brief negate and tweak add for pubkey.
   * @param[in] right   tweak data (before negate)
   * @return tweaked pubkey
   */
  SchnorrPubkey operator-=(const ByteData256 &right);

 private:
  ByteData256 data_;  //!< The underlying data
};

/**
 * @brief A Schnorr signature.
 *
 */
class CFD_CORE_EXPORT SchnorrSignature {
 public:
  /**
  * @brief Size of a Schnorr signature.
  *
  */
  static constexpr uint32_t kSchnorrSignatureSize = 64;

  /**
   * @brief Default constructor.
   */
  SchnorrSignature();

  /**
   * @brief Construct a new Schnorr Signature object from ByteData
   *
   * @param data the data representing the adaptor signature
   */
  explicit SchnorrSignature(const ByteData &data);

  /**
   * @brief Construct a new Schnorr Signature object from a string
   *
   * @param data the data representing the adaptor signature
   */
  explicit SchnorrSignature(const std::string &data);
  /**
   * @brief Construct a new Schnorr Signature object from a Signature object.
   *
   * @param[in] object the data representing the adaptor signature
   */
  SchnorrSignature(const SchnorrSignature &object);
  /**
   * @brief copy constructor.
   * @param[in] object the data representing the adaptor signature
   * @return object
   */
  SchnorrSignature &operator=(const SchnorrSignature &object);

  /**
   * @brief Get the underlying ByteData object
   * 
   * @param[in] append_sighash_type     add sighash type.
   * @return ByteData
   */
  ByteData GetData(bool append_sighash_type = false) const;
  /**
   * @brief Get the hex string.
   *
   * @param[in] append_sighash_type     add sighash type.
   * @return hex string.
   */
  std::string GetHex(bool append_sighash_type = false) const;
  /**
   * @brief Get the sighash type.
   *
   * @return sighash type.
   */
  SigHashType GetSigHashType() const;

  /**
   * @brief Return the nonce part of the signature.
   *
   * @return
   */
  SchnorrPubkey GetNonce() const;

  /**
   * @brief Returns the second part of the signature as a Privkey instance.
   *
   * @return Privkey
   */
  Privkey GetPrivkey() const;

  /**
   * @brief Get the sighash type.
   * @param[in] sighash_type    sighash type
   */
  void SetSigHashType(const SigHashType &sighash_type);

  /**
   * @brief check valid sighash type.
   * @param[in] sighash_type_value      sighash type
   * @retval true   valid
   * @retval false  invalid
   */
  static bool IsValidSigHashType(uint8_t sighash_type_value);

 private:
  /**
   * @brief The underlying data
   *
   */
  ByteData data_;
  /**
   * @brief The sighash type
   *
   */
  SigHashType sighash_type_;
};

/**
 * @brief This class contain utility functions to work with schnorr signatures.
 */
class CFD_CORE_EXPORT SchnorrUtil {
 public:
  /**
   * @brief Create a schnorr signature over the given message using the given
   * private key and auxiliary random data.
   *
   * @param msg the message to create the signature for.
   * @param sk the secret key to create the signature with.
   * @return SchnorrSignature
   */
  static SchnorrSignature Sign(const ByteData256 &msg, const Privkey &sk);

  /**
   * @brief Create a schnorr signature over the given message using the given
   * private key and auxiliary random data.
   *
   * @param msg the message to create the signature for.
   * @param sk the secret key to create the signature with.
   * @param aux_rand the auxiliary random data used to create the nonce.
   * @return SchnorrSignature
   */
  static SchnorrSignature Sign(
      const ByteData256 &msg, const Privkey &sk, const ByteData256 &aux_rand);

  /**
   * @brief Create a schnorr signature over the given message using the given
   * private key.
   *
   * @param msg the message to create the signature for.
   * @param sk the secret key to create the signature with.
   * @param nonce the nonce to use to create the signature.
   * @return SchnorrSignature
   */
  static SchnorrSignature SignWithNonce(
      const ByteData256 &msg, const Privkey &sk, const Privkey &nonce);

  /**
   * @brief Compute a signature point for a Schnorr signature.
   *
   * @param msg the message that will be signed.
   * @param nonce the public component of the nonce that will be used.
   * @param pubkey the public key for which the signature will be valid.
   * @return Pubkey the signature point.
   */
  static Pubkey ComputeSigPoint(
      const ByteData256 &msg, const SchnorrPubkey &nonce,
      const SchnorrPubkey &pubkey);

  /**
   * @brief Compute the sum of signature points for a set of Schnorr signature.
   * This enable reducing the number of EC multiplications done when computing the
   * addition of multiple signature points. So instead of computing:
   * S = (R_0 + X * H(X || R_0 || m_0)) + ... + (R_n + X * H(X || R_n || m_n))
   * This function computes:
   * S = (R_0 + ... + R_n) + X * (H(X || R_0 || m_0) + ... + H(X || R_n || m_n))
   *
   * @param msgs the set of messages that will be signed.
   * @param nonces the public component of the nonces that will be used.
   * @param pubkey the public key for which the signatures will be valid.
   * @return Pubkey the signature point.
   */
  static Pubkey ComputeSigPointBatch(
      const std::vector<ByteData256> &msgs,
      const std::vector<SchnorrPubkey> &nonces, const SchnorrPubkey &pubkey);

  /**
   * @brief Verify a Schnorr signature.
   *
   * @param signature the signature to verify.
   * @param msg the message to verify the signature against.
   * @param pubkey the public key to verify the signature against.
   * @retval true if the signature is valid
   * @retval false if the signature is invalid
   */
  static bool Verify(
      const SchnorrSignature &signature, const ByteData256 &msg,
      const SchnorrPubkey &pubkey);
};

// global operator overloading

/**
 * @brief tweak add privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak data
 * @return tweaked privkey
 */
CFD_CORE_EXPORT SchnorrPubkey
operator+(const SchnorrPubkey &left, const ByteData256 &right);
/**
 * @brief negate and tweak add for privkey.
 * @param[in] left    base privkey
 * @param[in] right   tweak data (before negate)
 * @return tweaked privkey
 */
CFD_CORE_EXPORT SchnorrPubkey
operator-(const SchnorrPubkey &left, const ByteData256 &right);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCHNORRSIG_H_
