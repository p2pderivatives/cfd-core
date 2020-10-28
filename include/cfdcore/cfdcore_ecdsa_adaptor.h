// Copyright 2020 CryptoGarage

#include <string>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"

#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ECDSA_ADAPTOR_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ECDSA_ADAPTOR_H_

namespace cfd {
namespace core {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;

/**
 * @brief An adaptor signature.
 *
 */
class CFD_CORE_EXPORT AdaptorSignature {
 public:
  /**
   * @brief Size of an adaptor signature.
   *
   */
  static constexpr uint32_t kAdaptorSignatureSize = 65;
  /**
   * @brief Construct a new Adaptor Signature object from ByteData
   *
   * @param data the data representing the adaptor signature
   */
  explicit AdaptorSignature(const ByteData &data);
  /**
   * @brief Construct a new Adaptor Signature object from a string
   *
   * @param data the data representing the adaptor signature
   */
  explicit AdaptorSignature(const std::string &data);

  /**
   * @brief Get the underlying ByteData object
   *
   * @return ByteData
   */
  ByteData GetData() const;

 private:
  /**
   * @brief The underlying data
   *
   */
  ByteData data_;
};

/**
 * @brief A proof for an adaptor signature.
 *
 */
class CFD_CORE_EXPORT AdaptorProof {
 public:
  /**
   * @brief The size of an adaptor proof.
   *
   */
  static constexpr uint32_t kAdaptorProofSize = 97;
  /**
   * @brief Construct a new Adaptor Proof from ByteData
   *
   * @param data the data representing the proof
   */
  explicit AdaptorProof(const ByteData &data);
  /**
   * @brief Construct a new Adaptor Proof object from a string
   *
   * @param data the data representing the proof
   */
  explicit AdaptorProof(const std::string &data);

  /**
   * @brief Get the underlying ByteData object.
   *
   * @return ByteData
   */
  ByteData GetData() const;

 private:
  /**
   * @brief The underlying data
   *
   */
  ByteData data_;
};

/**
 * @brief A pair of an adaptor signature together with the proof attached to it.
 *
 */
struct AdaptorPair {
  /**
   * @brief An adaptor signature
   *
   */
  AdaptorSignature signature;
  /**
   * @brief An adaptor proof
   *
   */
  AdaptorProof proof;
};

/**
 * @brief This class contain utility functions to work with adaptor signatures.
 */
class CFD_CORE_EXPORT AdaptorUtil {
 public:
  /**
   * @brief Create an adaptor signature over the given message using the given
   * private key. Returns an AdaptorPair of the adaptor signature and its proof.
   *
   * @param msg the message to create the signature for.
   * @param sk the secret key to create the signature with.
   * @param adaptor the adaptor to adapt the signature with.
   * @return AdaptorPair
   */
  static AdaptorPair Sign(
      const ByteData256 &msg, const Privkey &sk, const Pubkey &adaptor);

  /**
   * @brief "Decrypt" an adaptor signature using the provided secret, returning
   * an ecdsa signature in compact format.
   *
   * @param signature the adaptor signature
   * @param adaptor_secret the secret
   * @return ByteData
   */
  static ByteData Adapt(
      const AdaptorSignature &signature, const Privkey &adaptor_secret);

  /**
   * @brief Extract an adaptor secret from an ECDSA signature for a given
   * adaptor signature.
   *
   * @param adaptor_signature the adaptor signature
   * @param signature the ECDSA signature
   * @param adaptor the adaptor for the signature
   * @return Privkey
   */
  static Privkey ExtractSecret(
      const AdaptorSignature &adaptor_signature, const ByteData &signature,
      const Pubkey &adaptor);

  /**
   * @brief Verify that an adaptor proof is valid with respect to a given
   * adaptor signature, adaptor, message and public key.
   *
   * @param adaptor_signature
   * @param proof
   * @param adaptor
   * @param msg
   * @param pubkey
   * @retval true
   * @retval false
   */
  static bool Verify(
      const AdaptorSignature &adaptor_signature, const AdaptorProof &proof,
      const Pubkey &adaptor, const ByteData256 &msg, const Pubkey &pubkey);
};

}  // namespace core
}  // namespace cfd
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ECDSA_ADAPTOR_H_
