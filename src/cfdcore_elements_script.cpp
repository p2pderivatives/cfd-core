// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_elements_script.cpp
 *
 * @brief Elements対応したScriptクラス定義
 */
#ifndef CFD_DISABLE_ELEMENTS

#include <algorithm>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_elements_script.h"
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
  static const std::string kOpTrueHex = "51";  // OP_TRUE(HEX)
  bool is_liquidv1_watchman = false;
  if (CheckLiquidV1Watchman(fedpeg_script)) {
    is_liquidv1_watchman = true;
  } else if (fedpeg_script.GetHex() == kOpTrueHex) {
    // through
  } else if (CheckMultisigScript(fedpeg_script)) {
    // through
  } else {
    warn(CFD_LOG_SOURCE, "fedpeg script error.");
    throw CfdException(kCfdIllegalArgumentError, "fedpeg script error.");
  }

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

bool ContractHashUtil::CheckMultisigScript(const Script& script) {
  bool check_success = true;
  const ScriptOperator& kOpMultiSig = ScriptOperator::OP_CHECKMULTISIG;
  std::vector<ScriptElement> list = script.GetElementList();
  if (list.size() < 4) {
    // fail
    warn(CFD_LOG_SOURCE, "multisig format fail. scriptNum={}", list.size());
    check_success = false;
  } else if (!(list[0].IsNumber() && list[0].IsOpCode())) {
    // fail
    warn(CFD_LOG_SOURCE, "multisig format fail. (top)");
    check_success = false;
  } else if (!(list[list.size() - 2].IsNumber() &&
               list[list.size() - 2].IsOpCode())) {
    // fail
    warn(CFD_LOG_SOURCE, "multisig format fail. (last-1)");
    check_success = false;
  } else if (!list[list.size() - 1].IsOpCode()) {
    // fail
    warn(CFD_LOG_SOURCE, "multisig format fail. (last)");
    check_success = false;
  } else if (list[list.size() - 1].GetOpCode() != kOpMultiSig) {
    // fail
    warn(
        CFD_LOG_SOURCE, "multisig format fail. last opCode[{}]",
        list[list.size() - 1].GetOpCode().ToString());
    check_success = false;
  } else {
    int64_t req_num = list[0].GetNumber();
    int64_t key_num = list[list.size() - 2].GetNumber();
    for (size_t index = 1; index < (list.size() - 2); ++index) {
      if ((!list[index].IsBinary()) ||
          (!Pubkey::IsValid(list[index].GetBinaryData()))) {
        // fail
        warn(CFD_LOG_SOURCE, "multisig format fail. pubkey format[{}]", index);
        check_success = false;
        break;
      }
    }
    if (key_num < req_num) {
      warn(
          CFD_LOG_SOURCE, "multisig format fail. reqNum[{}] keyNum[{}]",
          req_num, key_num);
      check_success = false;
    }
    if (key_num != static_cast<int64_t>(list.size() - 3)) {
      warn(
          CFD_LOG_SOURCE, "multisig format fail. numatch keyNum[{}]", key_num);
      check_success = false;
    }
  }
  return check_success;
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
      // スクリプトの先頭から異なるならログ出さない
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
