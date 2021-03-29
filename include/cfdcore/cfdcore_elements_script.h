// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_script.h
 *
 * @brief The script class definition file used in Elements (liquid network).
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_SCRIPT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_SCRIPT_H_
#ifndef CFD_DISABLE_ELEMENTS

#include <string>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"

namespace cfd {
namespace core {

/**
 * @class ContractHashUtil
 * @brief A class that performs ContractHash related processing of Elements.
 *
 * @details
 * In this class, only the minimum processing required as a function of cfd_core is implemented.
 * The following elements that are not covered by this class should be created separately.
 * - Privkey: private key.
 * - Pubkey: Generate using Privkey::GeneratePubkey(true).
 * - claim script: Generate a lockingScript of p2wpkh or p2pkh.
 *   - Elements default to bech32 (p2wpkh) format.
 *     (script: OP_0 <20-byte-key-hash>)
 *     - Generation: ScriptBuilder().AppendOperator(ScriptOperator::OP_0)
 *            .AppendData(AddHashUtil::hash160(pubkey)).Build()
 * - mainchain address: Generated from ContractScript.
 *   - The default for Elements is p2sh-segwit.
 *     - Generation \n
 *       1. Create a p2wsh locking Script from ContractScript.
 *          (script: OP_0 <32-byte-script-hash>) \n
 *          ScriptBuilder().AppendOperator(ScriptOperator::OP_0)
 *              .AppendData(AddHashUtil::sha256(ContractScript)).Build()
 *       2. Create a p2sh Address using 1's locking script.
 *          Address(NetType, 1's 'lockingScript)
 */
class CFD_CORE_EXPORT ContractHashUtil {
 public:
  /**
   * @brief Generate a Pay-to-Contract script.
   * @param[in] claim_script    claim script
   * @param[in] fedpeg_script   elementsd side chain configuration script
   * @return Pay-to-Contract script.
   */
  static Script GetContractScript(
      const Script& claim_script, const Script& fedpeg_script);

 private:
  /**
   * @brief Check if it is in liquidV1 watchman script format.
   * @param[in] script   script
   * @retval true   liquidV1 watchman script format
   * @retval false  other script
   */
  static bool CheckLiquidV1Watchman(const Script& script);

  /**
   * @brief constructor.
   */
  ContractHashUtil();
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_SCRIPT_H_
