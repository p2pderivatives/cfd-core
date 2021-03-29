// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_taproot.h
 *
 * @brief This file defines the taproot utility class.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TAPROOT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TAPROOT_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_util.h"

namespace cfd {
namespace core {

/**
 * @brief This class implements a taproot script tree branch.
 */
class CFD_CORE_EXPORT TapBranch {
 public:
  /**
   * @brief default constructor.
   */
  TapBranch();
  /**
   * @brief constructor.
   * @param[in] commitment      commitment
   */
  explicit TapBranch(const ByteData256& commitment);
  /**
   * @brief copy constructor.
   * @param[in] branch    branch object
   */
  TapBranch(const TapBranch& branch);
  /**
   * @brief destructor.
   */
  virtual ~TapBranch() {}
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  TapBranch& operator=(const TapBranch& object);

  /**
   * @brief Add branch.
   * @param[in] pubkey  schnorr pubkey
   */
  virtual void AddBranch(const SchnorrPubkey& pubkey);
  /**
   * @brief Add branch.
   * @param[in] commitment    branch commitment.
   */
  virtual void AddBranch(const ByteData256& commitment);
  /**
   * @brief Add branch.
   * @param[in] branch    branch.
   */
  void AddBranch(const TapBranch& branch);
  /**
   * @brief Get a base hash.
   * @return base hash.
   */
  ByteData256 GetBaseHash() const;
  /**
   * @brief Get a current branch hash.
   * @return branch hash.
   */
  ByteData256 GetCurrentBranchHash() const;
  /**
   * @brief Get a branch hash.
   * @param[in] depth   depth
   * @return branch hash.
   */
  ByteData256 GetBranchHash(uint8_t depth = 255) const;

  /**
   * @brief Exist a tapleaf.
   * @retval true   exist
   * @retval false  not exist
   */
  bool HasTapLeaf() const;
  /**
   * @brief Get a leaf version.
   * @return leaf version.
   */
  uint8_t GetLeafVersion() const;

  /**
   * @brief Get a tapscript.
   * @return tapscript.
   */
  Script GetScript() const;
  /**
   * @brief Get a node list.
   * @return node list.
   */
  std::vector<TapBranch> GetBranchList() const;
  /**
   * @brief Get a node list.
   * @return node list.
   */
  virtual std::vector<ByteData256> GetNodeList() const;

  /**
   * @brief find tapscript in this branch.
   * @param[in] tapscript       tapscript
   * @retval true       find this branch.
   * @retval false      not found.
   */
  bool IsFindTapScript(const Script& tapscript) const;

  /**
   * @brief Get a string format. (cfd original)
   * @return text data.
   */
  std::string ToString() const;

  /**
   * @brief Change tapleaf.
   * @param[in] tapscript       leaf tapscript.
   * @param[in] target_nodes    target nodes.
   * @return object
   */
  TapBranch ChangeTapLeaf(
      const Script& tapscript, const std::vector<ByteData256>& target_nodes =
                                   std::vector<ByteData256>()) const;

  /**
   * @brief Convert from string format. (cfd original)
   * @param[in] text        string format.
   * @return object
   * @see TapBranch::ToString()
   */
  static TapBranch FromString(const std::string& text);

 protected:
  bool has_leaf_;                       //!< exist leaf
  uint8_t leaf_version_;                //!< leaf version
  Script script_;                       //!< tapscript
  ByteData256 root_commitment_;         //!< root commitment data
  std::vector<TapBranch> branch_list_;  //!< branch list
};

/**
 * @brief This class implements a taproot Merklized Alternative Script Trees.
 * @see https://bitcoinops.org/en/newsletters/2019/05/14/
 */
class CFD_CORE_EXPORT TaprootScriptTree : public TapBranch {
 public:
  /**
   * @brief The taproot control node maximum count.
   */
  static constexpr size_t kTaprootControlMaxNodeCount = 128;
  /**
   * @brief The tapleaf version on tapscript.
   */
  static constexpr uint8_t kTapScriptLeafVersion = 0xc0;

  /**
   * @brief constructor.
   */
  TaprootScriptTree();
  /**
   * @brief constructor.
   * @param[in] script  tapscript
   */
  explicit TaprootScriptTree(const Script& script);
  /**
   * @brief constructor.
   * @param[in] leaf_version    leaf version
   * @param[in] script          tapscript
   */
  explicit TaprootScriptTree(uint8_t leaf_version, const Script& script);
  /**
   * @brief constructor. convert from tapleaf branch.
   * @param[in] leaf_branch    leaf branch
   */
  explicit TaprootScriptTree(const TapBranch& leaf_branch);
  /**
   * @brief copy constructor.
   * @param[in] tap_tree    tree object
   */
  TaprootScriptTree(const TaprootScriptTree& tap_tree);
  /**
   * @brief destructor.
   */
  virtual ~TaprootScriptTree() {}
  /**
   * @brief copy constructor.
   * @param[in] object    tree object
   * @return object
   */
  TaprootScriptTree& operator=(const TaprootScriptTree& object) &;

  using TapBranch::AddBranch;
  /**
   * @brief Add branch.
   * @param[in] commitment    branch commitment.
   */
  virtual void AddBranch(const ByteData256& commitment);
  /**
   * @brief Add branch.
   * @param[in] branch    branch.
   */
  void AddBranch(const TapBranch& branch);
  /**
   * @brief Add branch.
   * @param[in] tree    script tree node.
   */
  void AddBranch(const TaprootScriptTree& tree);

  /**
   * @brief Get a tapleaf hash.
   * @return tapleaf hash.
   */
  ByteData256 GetTapLeafHash() const;
  /**
   * @brief Get tweak.
   * @param[in] internal_pubkey     internal pubkey
   * @return tweak.
   */
  ByteData256 GetTapTweak(const SchnorrPubkey& internal_pubkey) const;

  /**
   * @brief Get a tweaked pubkey.
   * @param[in] internal_pubkey     internal pubkey
   * @param[out] parity             parity flag.
   * @return tweaked schnorr pubkey.
   */
  SchnorrPubkey GetTweakedPubkey(
      const SchnorrPubkey& internal_pubkey, bool* parity = nullptr) const;
  /**
   * @brief Get a tweaked privkey.
   * @param[in] internal_privkey    internal privkey
   * @param[out] parity             parity flag.
   * @return tweaked privkey.
   */
  Privkey GetTweakedPrivkey(
      const Privkey& internal_privkey, bool* parity = nullptr) const;

  /**
   * @brief Get a node list.
   * @return node list.
   */
  virtual std::vector<ByteData256> GetNodeList() const;

  /**
   * @brief Convert from string format. (cfd original)
   * @param[in] text            string format.
   * @param[in] tapscript       leaf tapscript.
   * @param[in] target_nodes    target nodes.
   * @return object
   * @see TapBranch::FromString()
   */
  static TaprootScriptTree FromString(
      const std::string& text, const Script& tapscript,
      const std::vector<ByteData256>& target_nodes =
          std::vector<ByteData256>());

 private:
  std::vector<ByteData256> nodes_;  //!< node list
};

/**
 * @brief This class contain utility functions to work with taproot.
 */
class CFD_CORE_EXPORT TaprootUtil {
 public:
  /**
   * @brief The annex tag.
   */
  static constexpr uint8_t kAnnexTag = 0x50;

  /**
   * @brief Check valid leaf version.
   * @param[in] leaf_version    leaf version
   * @retval true   valid
   * @retval false  invalid
   */
  static bool IsValidLeafVersion(uint8_t leaf_version);

  /**
   * @brief create tapscript control data.
   * @param[in] internal_pubkey     internal pubkey
   * @param[in] merkle_tree         merkle tree
   * @param[out] witness_program    witness program
   * @param[out] locking_script     taproot locking script
   * @return tapscript control data.
   */
  static ByteData CreateTapScriptControl(
      const SchnorrPubkey& internal_pubkey,
      const TaprootScriptTree& merkle_tree,
      SchnorrPubkey* witness_program = nullptr,
      Script* locking_script = nullptr);

  /**
   * @brief Verify taproot commitment.
   * @param[in] has_parity          parity flag
   * @param[in] tapleaf_bit         tapleaf bit
   * @param[in] target_taproot      witness program
   * @param[in] internal_pubkey     internal pubkey
   * @param[in] nodes               taptree node list
   * @param[in] tapscript           tapscript
   * @param[out] tapleaf_hash       tapleaf hash
   * @retval true   valid
   * @retval false  invalid
   */
  static bool VerifyTaprootCommitment(
      bool has_parity, uint8_t tapleaf_bit,
      const SchnorrPubkey& target_taproot,
      const SchnorrPubkey& internal_pubkey,
      const std::vector<ByteData256>& nodes, const Script& tapscript,
      ByteData256* tapleaf_hash = nullptr);

  /**
   * @brief Parse taproot sign (witness stack) data
   * @param[in] witness_stack       witness stack
   * @param[out] schnorr_signature  schnorr signature
   * @param[out] has_parity         parity flag
   * @param[out] tapleaf_bit        tapleaf bit
   * @param[out] internal_pubkey    internal pubkey
   * @param[out] nodes              taproot node list
   * @param[out] tapscript          tapscript
   * @param[out] stack              script stack data
   * @param[out] annex              annex data
   */
  static void ParseTaprootSignData(
      const std::vector<ByteData>& witness_stack,
      SchnorrSignature* schnorr_signature, bool* has_parity,
      uint8_t* tapleaf_bit, SchnorrPubkey* internal_pubkey,
      std::vector<ByteData256>* nodes, Script* tapscript,
      std::vector<ByteData>* stack = nullptr, ByteData* annex = nullptr);
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_TAPROOT_H_
