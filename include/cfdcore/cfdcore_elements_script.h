// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_script.h
 *
 * @brief Elements対応したScriptクラス定義
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
 * @brief ElementsのContractHash関連処理を行うクラス.
 *
 * @details
 * 本クラスではcfd_coreの機能として必要な最小限の処理のみ実装する。
 * 本クラスの対象外である下記の要素については、別途作成すること。
 * - Privkey: Privkey::GenerageRandomKey()でランダム生成する。
 * - Pubkey: PrivkeyのGeneratePubkey(true)で生成する。
 * - claim script: p2wpkh or p2pkhのlockingScriptを生成する。
 *   - Elementsのデフォルトはbech32(p2wpkh)形式。
 *     (script: OP_0 <20-byte-key-hash>)
 *     - 生成方法: ScriptBuilder().AppendOperator(ScriptOperator::OP_0)
 *            .AppendData(AddHashUtil::hash160(pubkey)).Build()
 * - mainchain address: ContractScriptから生成する。
 *   - Elementsのデフォルトはp2sh-segwit。
 *     - 生成方法 \n
 *       1. ContractScriptから、p2wshのlockingScriptを作成。
 *          (script: OP_0 <32-byte-script-hash>) \n
 *          ScriptBuilder().AppendOperator(ScriptOperator::OP_0)
 *              .AppendData(AddHashUtil::sha256(ContractScript)).Build()
 *       2. 1を用いて、p2shのAddressを作成。
 *          Address(NetType, 1のlockingScript)
 */
class CFD_CORE_EXPORT ContractHashUtil {
 public:
  /**
   * @brief Pay-to-Contractスクリプトを生成する。
   * @param[in] claim_script    claim script
   * @param[in] fedpeg_script   elementsdのside chain設定スクリプト
   * @return Pay-to-Contract script.
   */
  static Script GetContractScript(
      const Script& claim_script, const Script& fedpeg_script);

 private:
  /**
   * @brief liquidV1 watchman script形式かどうかをチェックする。
   * @param[in] script   script
   * @retval true   liquidV1 watchman script format
   * @retval false  other script
   */
  static bool CheckLiquidV1Watchman(const Script& script);

  /**
   * @brief コンストラクタ
   */
  ContractHashUtil();
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_ELEMENTS_SCRIPT_H_
