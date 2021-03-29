// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_script.cpp
 *
 * @brief definition of script class that supports Elements
 */
#ifndef CFD_DISABLE_ELEMENTS

#include "cfdcore/cfdcore_elements_script.h"

#include <algorithm>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_iterator.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::warn;

// -----------------------------------------------------------------------------
// ContractHashUtil
// -----------------------------------------------------------------------------
Script ContractHashUtil::GetContractScript(
    const Script& claim_script, const Script& fedpeg_script) {
  bool is_liquidv1_watchman = CheckLiquidV1Watchman(fedpeg_script);

  ScriptBuilder builder;
  ByteData claim_script_data = claim_script.GetData();
  bool liquidv1_op_else = false;
  ByteData pubkey_data;
  ByteData256 tweak;
  for (const ScriptElement& element : fedpeg_script.GetElementList()) {
    if (is_liquidv1_watchman &&
        (element.GetOpCode() == ScriptOperator::OP_ELSE)) {
      liquidv1_op_else = true;
    }
    ByteData data = element.GetBinaryData();
    if ((!liquidv1_op_else) && element.IsBinary() &&
        (data.GetDataSize() == Pubkey::kCompressedPubkeySize)) {
      tweak = CryptoUtil::HmacSha256(data.GetBytes(), claim_script_data);
      pubkey_data = WallyUtil::AddTweakPubkey(data, tweak, true);
      builder.AppendData(pubkey_data);
    } else {
      builder.AppendElement(element);
    }
  }

  return builder.Build();
}

bool ContractHashUtil::CheckLiquidV1Watchman(const Script& script) {
  try {
    std::vector<ScriptElement> list = script.GetElementList();
    if (list.empty()) {
      warn(CFD_LOG_SOURCE, "script empty.");
      return false;
    }

    IteratorWrapper<ScriptElement> ite(list, "Check LiquidV1 Watchman NG");
    if (ite.next().GetOpCode() != ScriptOperator::OP_DEPTH) {
      // warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      // Does not log if it is different from the beginning of the script
      return false;
    }

    ScriptElement element(0);
    if (!ite.next().IsNumber()) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    if (ite.next().GetOpCode() != ScriptOperator::OP_EQUAL) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }

    if (ite.next().GetOpCode() != ScriptOperator::OP_IF) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }

    element = ite.next();
    if (!(element.IsOpCode() && element.IsNumber())) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    int64_t req_num = element.GetNumber();

    // check pubkey
    element = ite.next();
    while (element.GetOpCode() != ScriptOperator::OP_ELSE) {
      if ((!element.IsOpCode()) && (!element.IsBinary())) {
        warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
        return false;
      }
      element = ite.next();
    }

    if (!ite.next().IsNumber()) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    if (ite.next().GetOpCode() != ScriptOperator::OP_CHECKSEQUENCEVERIFY) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    if (ite.next().GetOpCode() != ScriptOperator::OP_DROP) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    element = ite.next();
    if (!(element.IsOpCode() && element.IsNumber())) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    int64_t req_num2 = element.GetNumber();

    if (req_num == req_num2) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }

    element = ite.next();
    while (element.GetOpCode() != ScriptOperator::OP_ENDIF) {
      if ((!element.IsOpCode()) && (!element.IsBinary())) {
        warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
        return false;
      }
      element = ite.next();
    }

    if (ite.next().GetOpCode() != ScriptOperator::OP_CHECKMULTISIG) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    if (ite.hasNext()) {
      warn(CFD_LOG_SOURCE, "LiquidV1 watchman script fail.");
      return false;
    }
    return true;
  } catch (...) {
    warn(CFD_LOG_SOURCE, "Check LiquidV1 Watchman exception.");
    return false;
  }
}

}  // namespace core
}  // namespace cfd

#endif  // CFD_DISABLE_ELEMENTS
