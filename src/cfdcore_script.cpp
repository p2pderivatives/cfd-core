// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_script.cpp
 *
 * @brief implementation of Script related class
 */

#include "cfdcore/cfdcore_script.h"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_iterator.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::warn;

// -----------------------------------------------------------------------------
// ScriptOperator
// -----------------------------------------------------------------------------
// operator object-enum mapping
/// a map to search ScriptOperator using ScriptType.
static std::map<ScriptType, ScriptOperator> g_operator_map;
/// a map to search ScriptOperator using OP_CODE text.
static std::map<std::string, ScriptOperator> g_operator_text_map;

const ScriptOperator ScriptOperator::OP_0(kOp_0, "0");
const ScriptOperator ScriptOperator::OP_FALSE(kOpFalse, "OP_FALSE");
const ScriptOperator ScriptOperator::OP_PUSHDATA1(
    kOpPushData1, "OP_PUSHDATA1");
const ScriptOperator ScriptOperator::OP_PUSHDATA2(
    kOpPushData2, "OP_PUSHDATA2");
const ScriptOperator ScriptOperator::OP_PUSHDATA4(
    kOpPushData4, "OP_PUSHDATA4");
const ScriptOperator ScriptOperator::OP_1NEGATE(kOp1Negate, "-1");
const ScriptOperator ScriptOperator::OP_RESERVED(kOpReserved, "OP_RESERVED");
const ScriptOperator ScriptOperator::OP_1(kOp_1, "1");
const ScriptOperator ScriptOperator::OP_TRUE(kOpTrue, "OP_TRUE");
const ScriptOperator ScriptOperator::OP_2(kOp_2, "2");
const ScriptOperator ScriptOperator::OP_3(kOp_3, "3");
const ScriptOperator ScriptOperator::OP_4(kOp_4, "4");
const ScriptOperator ScriptOperator::OP_5(kOp_5, "5");
const ScriptOperator ScriptOperator::OP_6(kOp_6, "6");
const ScriptOperator ScriptOperator::OP_7(kOp_7, "7");
const ScriptOperator ScriptOperator::OP_8(kOp_8, "8");
const ScriptOperator ScriptOperator::OP_9(kOp_9, "9");
const ScriptOperator ScriptOperator::OP_10(kOp_10, "10");
const ScriptOperator ScriptOperator::OP_11(kOp_11, "11");
const ScriptOperator ScriptOperator::OP_12(kOp_12, "12");
const ScriptOperator ScriptOperator::OP_13(kOp_13, "13");
const ScriptOperator ScriptOperator::OP_14(kOp_14, "14");
const ScriptOperator ScriptOperator::OP_15(kOp_15, "15");
const ScriptOperator ScriptOperator::OP_16(kOp_16, "16");
const ScriptOperator ScriptOperator::OP_NOP(kOpNop, "OP_NOP");
const ScriptOperator ScriptOperator::OP_VER(kOpVer, "OP_VER");
const ScriptOperator ScriptOperator::OP_IF(kOpIf, "OP_IF");
const ScriptOperator ScriptOperator::OP_NOTIF(kOpNotIf, "OP_NOTIF");
const ScriptOperator ScriptOperator::OP_VERIF(kOpVerIf, "OP_VERIF");
const ScriptOperator ScriptOperator::OP_VERNOTIF(kOpVerNotIf, "OP_VERNOTIF");
const ScriptOperator ScriptOperator::OP_ELSE(kOpElse, "OP_ELSE");
const ScriptOperator ScriptOperator::OP_ENDIF(kOpEndIf, "OP_ENDIF");
const ScriptOperator ScriptOperator::OP_VERIFY(kOpVerify, "OP_VERIFY");
const ScriptOperator ScriptOperator::OP_RETURN(kOpReturn, "OP_RETURN");
const ScriptOperator ScriptOperator::OP_TOALTSTACK(
    kOpToAltStack, "OP_TOALTSTACK");
const ScriptOperator ScriptOperator::OP_FROMALTSTACK(
    kOpFromAltStack, "OP_FROMALTSTACK");
const ScriptOperator ScriptOperator::OP_2DROP(kOp2Drop, "OP_2DROP");
const ScriptOperator ScriptOperator::OP_2DUP(kOp2Dup, "OP_2DUP");
const ScriptOperator ScriptOperator::OP_3DUP(kOp3Dup, "OP_3DUP");
const ScriptOperator ScriptOperator::OP_2OVER(kOp2Over, "OP_2OVER");
const ScriptOperator ScriptOperator::OP_2ROT(kOp2Rot, "OP_2ROT");
const ScriptOperator ScriptOperator::OP_2SWAP(kOp2Swap, "OP_2SWAP");
const ScriptOperator ScriptOperator::OP_IFDUP(kOpIfDup, "OP_IFDUP");
const ScriptOperator ScriptOperator::OP_DEPTH(kOpDepth, "OP_DEPTH");
const ScriptOperator ScriptOperator::OP_DROP(kOpDrop, "OP_DROP");
const ScriptOperator ScriptOperator::OP_DUP(kOpDup, "OP_DUP");
const ScriptOperator ScriptOperator::OP_NIP(kOpNip, "OP_NIP");
const ScriptOperator ScriptOperator::OP_OVER(kOpOver, "OP_OVER");
const ScriptOperator ScriptOperator::OP_PICK(kOpPick, "OP_PICK");
const ScriptOperator ScriptOperator::OP_ROLL(kOpRoll, "OP_ROLL");
const ScriptOperator ScriptOperator::OP_ROT(kOpRot, "OP_ROT");
const ScriptOperator ScriptOperator::OP_SWAP(kOpSwap, "OP_SWAP");
const ScriptOperator ScriptOperator::OP_TUCK(kOpTuck, "OP_TUCK");
const ScriptOperator ScriptOperator::OP_CAT(kOpCat, "OP_CAT");
const ScriptOperator ScriptOperator::OP_SUBSTR(kOpSubstr, "OP_SUBSTR");
const ScriptOperator ScriptOperator::OP_LEFT(kOpLeft, "OP_LEFT");
const ScriptOperator ScriptOperator::OP_RIGHT(kOpRight, "OP_RIGHT");
const ScriptOperator ScriptOperator::OP_SIZE(kOpSize, "OP_SIZE");
const ScriptOperator ScriptOperator::OP_INVERT(kOpInvert, "OP_INVERT");
const ScriptOperator ScriptOperator::OP_AND(kOpAnd, "OP_AND");
const ScriptOperator ScriptOperator::OP_OR(kOpOr, "OP_OR");
const ScriptOperator ScriptOperator::OP_XOR(kOpXor, "OP_XOR");
const ScriptOperator ScriptOperator::OP_EQUAL(kOpEqual, "OP_EQUAL");
const ScriptOperator ScriptOperator::OP_EQUALVERIFY(
    kOpEqualVerify, "OP_EQUALVERIFY");
const ScriptOperator ScriptOperator::OP_RESERVED1(
    kOpReserved1, "OP_RESERVED1");
const ScriptOperator ScriptOperator::OP_RESERVED2(
    kOpReserved2, "OP_RESERVED2");
const ScriptOperator ScriptOperator::OP_1ADD(kOp1Add, "OP_1ADD");
const ScriptOperator ScriptOperator::OP_1SUB(kOp1Sub, "OP_1SUB");
const ScriptOperator ScriptOperator::OP_2MUL(kOp2Mul, "OP_2MUL");
const ScriptOperator ScriptOperator::OP_2DIV(kOp2Div, "OP_2DIV");
const ScriptOperator ScriptOperator::OP_NEGATE(kOpNegate, "OP_NEGATE");
const ScriptOperator ScriptOperator::OP_ABS(kOpAbs, "OP_ABS");
const ScriptOperator ScriptOperator::OP_NOT(kOpNot, "OP_NOT");
const ScriptOperator ScriptOperator::OP_0NOTEQUAL(
    kOp0NotEqual, "OP_0NOTEQUAL");
const ScriptOperator ScriptOperator::OP_ADD(kOpAdd, "OP_ADD");
const ScriptOperator ScriptOperator::OP_SUB(kOpSub, "OP_SUB");
const ScriptOperator ScriptOperator::OP_MUL(kOpMul, "OP_MUL");
const ScriptOperator ScriptOperator::OP_DIV(kOpDiv, "OP_DIV");
const ScriptOperator ScriptOperator::OP_MOD(kOpMod, "OP_MOD");
const ScriptOperator ScriptOperator::OP_LSHIFT(kOpLShift, "OP_LSHIFT");
const ScriptOperator ScriptOperator::OP_RSHIFT(kOpRShift, "OP_RSHIFT");
const ScriptOperator ScriptOperator::OP_BOOLAND(kOpBoolAnd, "OP_BOOLAND");
const ScriptOperator ScriptOperator::OP_BOOLOR(kOpBoolOr, "OP_BOOLOR");
const ScriptOperator ScriptOperator::OP_NUMEQUAL(kOpNumEqual, "OP_NUMEQUAL");
const ScriptOperator ScriptOperator::OP_NUMEQUALVERIFY(
    kOpNumEqualVerify, "OP_NUMEQUALVERIFY");
const ScriptOperator ScriptOperator::OP_NUMNOTEQUAL(
    kOpNumNotEqual, "OP_NUMNOTEQUAL");
const ScriptOperator ScriptOperator::OP_LESSTHAN(kOpLessThan, "OP_LESSTHAN");
const ScriptOperator ScriptOperator::OP_GREATERTHAN(
    kOpGreaterThan, "OP_GREATERTHAN");
const ScriptOperator ScriptOperator::OP_LESSTHANOREQUAL(
    kOpLessThanOrEqual, "OP_LESSTHANOREQUAL");
const ScriptOperator ScriptOperator::OP_GREATERTHANOREQUAL(
    kOpGreaterThanOrEqual, "OP_GREATERTHANOREQUAL");
const ScriptOperator ScriptOperator::OP_MIN(kOpMin, "OP_MIN");
const ScriptOperator ScriptOperator::OP_MAX(kOpMax, "OP_MAX");
const ScriptOperator ScriptOperator::OP_WITHIN(kOpWithIn, "OP_WITHIN");
const ScriptOperator ScriptOperator::OP_RIPEMD160(kOpRipemd, "OP_RIPEMD160");
const ScriptOperator ScriptOperator::OP_SHA1(kOpSha1, "OP_SHA1");
const ScriptOperator ScriptOperator::OP_SHA256(kOpSha256, "OP_SHA256");
const ScriptOperator ScriptOperator::OP_HASH160(kOpHash160, "OP_HASH160");
const ScriptOperator ScriptOperator::OP_HASH256(kOpHash256, "OP_HASH256");
const ScriptOperator ScriptOperator::OP_CODESEPARATOR(
    kOpCodeSeparator, "OP_CODESEPARATOR");
const ScriptOperator ScriptOperator::OP_CHECKSIG(kOpCheckSig, "OP_CHECKSIG");
const ScriptOperator ScriptOperator::OP_CHECKSIGVERIFY(
    kOpCheckSigVerify, "OP_CHECKSIGVERIFY");
const ScriptOperator ScriptOperator::OP_CHECKMULTISIG(
    kOpCheckMultiSig, "OP_CHECKMULTISIG");
const ScriptOperator ScriptOperator::OP_CHECKMULTISIGVERIFY(
    kOpCheckMultiSigVerify, "OP_CHECKMULTISIGVERIFY");
const ScriptOperator ScriptOperator::OP_NOP1(kOpNop1, "OP_NOP1");
const ScriptOperator ScriptOperator::OP_CHECKLOCKTIMEVERIFY(
    kOpCheckLockTimeVerify, "OP_CHECKLOCKTIMEVERIFY");
const ScriptOperator ScriptOperator::OP_NOP2(kOpNop2, "OP_NOP2");
const ScriptOperator ScriptOperator::OP_CHECKSEQUENCEVERIFY(
    kOpCheckSequenceVerify, "OP_CHECKSEQUENCEVERIFY");
const ScriptOperator ScriptOperator::OP_NOP3(kOpNop3, "OP_NOP3");
const ScriptOperator ScriptOperator::OP_NOP4(kOpNop4, "OP_NOP4");
const ScriptOperator ScriptOperator::OP_NOP5(kOpNop5, "OP_NOP5");
const ScriptOperator ScriptOperator::OP_NOP6(kOpNop6, "OP_NOP6");
const ScriptOperator ScriptOperator::OP_NOP7(kOpNop7, "OP_NOP7");
const ScriptOperator ScriptOperator::OP_NOP8(kOpNop8, "OP_NOP8");
const ScriptOperator ScriptOperator::OP_NOP9(kOpNop9, "OP_NOP9");
const ScriptOperator ScriptOperator::OP_NOP10(kOpNop10, "OP_NOP10");
const ScriptOperator ScriptOperator::OP_CHECKSIGADD(
    kOpCheckSigAdd, "OP_CHECKSIGADD");
const ScriptOperator ScriptOperator::OP_INVALIDOPCODE(
    kOpInvalidOpCode, "OP_INVALIDOPCODE");
#ifndef CFD_DISABLE_ELEMENTS
const ScriptOperator ScriptOperator::OP_DETERMINISTICRANDOM(
    kOpDeterministricRandom, "OP_DETERMINISTICRANDOM");
const ScriptOperator ScriptOperator::OP_CHECKSIGFROMSTACK(
    kOpCheckSigFromStack, "OP_CHECKSIGFROMSTACK");
const ScriptOperator ScriptOperator::OP_CHECKSIGFROMSTACKVERIFY(
    kOpCheckSigFromStackVerify, "OP_CHECKSIGFROMSTACKVERIFY");
const ScriptOperator ScriptOperator::OP_SMALLINTEGER(
    kOpSmallInteger, "OP_SMALLINTEGER");
const ScriptOperator ScriptOperator::OP_PUBKEYS(kOpPubkeys, "OP_PUBKEYS");
const ScriptOperator ScriptOperator::OP_PUBKEYHASH(
    kOpPubkeyHash, "OP_PUBKEYHASH");
const ScriptOperator ScriptOperator::OP_PUBKEY(kOpPubkey, "OP_PUBKEY");
#endif  // CFD_DISABLE_ELEMENTS
const ScriptOperator ScriptOperator::OP_SUCCESS80(
    kOpSuccess80, "OP_SUCCESS80");
const ScriptOperator ScriptOperator::OP_SUCCESS98(
    kOpSuccess98, "OP_SUCCESS98");
const ScriptOperator ScriptOperator::OP_SUCCESS126(
    kOpSuccess126, "OP_SUCCESS126");
const ScriptOperator ScriptOperator::OP_SUCCESS127(
    kOpSuccess127, "OP_SUCCESS127");
const ScriptOperator ScriptOperator::OP_SUCCESS128(
    kOpSuccess128, "OP_SUCCESS128");
const ScriptOperator ScriptOperator::OP_SUCCESS129(
    kOpSuccess129, "OP_SUCCESS129");
const ScriptOperator ScriptOperator::OP_SUCCESS131(
    kOpSuccess131, "OP_SUCCESS131");
const ScriptOperator ScriptOperator::OP_SUCCESS132(
    kOpSuccess132, "OP_SUCCESS132");
const ScriptOperator ScriptOperator::OP_SUCCESS133(
    kOpSuccess133, "OP_SUCCESS133");
const ScriptOperator ScriptOperator::OP_SUCCESS134(
    kOpSuccess134, "OP_SUCCESS134");
const ScriptOperator ScriptOperator::OP_SUCCESS137(
    kOpSuccess137, "OP_SUCCESS137");
const ScriptOperator ScriptOperator::OP_SUCCESS138(
    kOpSuccess138, "OP_SUCCESS138");
const ScriptOperator ScriptOperator::OP_SUCCESS141(
    kOpSuccess141, "OP_SUCCESS141");
const ScriptOperator ScriptOperator::OP_SUCCESS142(
    kOpSuccess142, "OP_SUCCESS142");
const ScriptOperator ScriptOperator::OP_SUCCESS149(
    kOpSuccess149, "OP_SUCCESS149");
const ScriptOperator ScriptOperator::OP_SUCCESS150(
    kOpSuccess150, "OP_SUCCESS150");
const ScriptOperator ScriptOperator::OP_SUCCESS151(
    kOpSuccess151, "OP_SUCCESS151");
const ScriptOperator ScriptOperator::OP_SUCCESS152(
    kOpSuccess152, "OP_SUCCESS152");
const ScriptOperator ScriptOperator::OP_SUCCESS153(
    kOpSuccess153, "OP_SUCCESS153");
const ScriptOperator ScriptOperator::OP_SUCCESS187(
    kOpSuccess187, "OP_SUCCESS187");
const ScriptOperator ScriptOperator::OP_SUCCESS188(
    kOpSuccess188, "OP_SUCCESS188");
const ScriptOperator ScriptOperator::OP_SUCCESS189(
    kOpSuccess189, "OP_SUCCESS189");
const ScriptOperator ScriptOperator::OP_SUCCESS190(
    kOpSuccess190, "OP_SUCCESS190");
const ScriptOperator ScriptOperator::OP_SUCCESS191(
    kOpSuccess191, "OP_SUCCESS191");
const ScriptOperator ScriptOperator::OP_SUCCESS192(
    kOpSuccess192, "OP_SUCCESS192");
const ScriptOperator ScriptOperator::OP_SUCCESS193(
    kOpSuccess193, "OP_SUCCESS193");
const ScriptOperator ScriptOperator::OP_SUCCESS194(
    kOpSuccess194, "OP_SUCCESS194");
const ScriptOperator ScriptOperator::OP_SUCCESS195(
    kOpSuccess195, "OP_SUCCESS195");
const ScriptOperator ScriptOperator::OP_SUCCESS196(
    kOpSuccess196, "OP_SUCCESS196");
const ScriptOperator ScriptOperator::OP_SUCCESS197(
    kOpSuccess197, "OP_SUCCESS197");
const ScriptOperator ScriptOperator::OP_SUCCESS198(
    kOpSuccess198, "OP_SUCCESS198");
const ScriptOperator ScriptOperator::OP_SUCCESS199(
    kOpSuccess199, "OP_SUCCESS199");
const ScriptOperator ScriptOperator::OP_SUCCESS200(
    kOpSuccess200, "OP_SUCCESS200");
const ScriptOperator ScriptOperator::OP_SUCCESS201(
    kOpSuccess201, "OP_SUCCESS201");
const ScriptOperator ScriptOperator::OP_SUCCESS202(
    kOpSuccess202, "OP_SUCCESS202");
const ScriptOperator ScriptOperator::OP_SUCCESS203(
    kOpSuccess203, "OP_SUCCESS203");
const ScriptOperator ScriptOperator::OP_SUCCESS204(
    kOpSuccess204, "OP_SUCCESS204");
const ScriptOperator ScriptOperator::OP_SUCCESS205(
    kOpSuccess205, "OP_SUCCESS205");
const ScriptOperator ScriptOperator::OP_SUCCESS206(
    kOpSuccess206, "OP_SUCCESS206");
const ScriptOperator ScriptOperator::OP_SUCCESS207(
    kOpSuccess207, "OP_SUCCESS207");
const ScriptOperator ScriptOperator::OP_SUCCESS208(
    kOpSuccess208, "OP_SUCCESS208");
const ScriptOperator ScriptOperator::OP_SUCCESS209(
    kOpSuccess209, "OP_SUCCESS209");
const ScriptOperator ScriptOperator::OP_SUCCESS210(
    kOpSuccess210, "OP_SUCCESS210");
const ScriptOperator ScriptOperator::OP_SUCCESS211(
    kOpSuccess211, "OP_SUCCESS211");
const ScriptOperator ScriptOperator::OP_SUCCESS212(
    kOpSuccess212, "OP_SUCCESS212");
const ScriptOperator ScriptOperator::OP_SUCCESS213(
    kOpSuccess213, "OP_SUCCESS213");
const ScriptOperator ScriptOperator::OP_SUCCESS214(
    kOpSuccess214, "OP_SUCCESS214");
const ScriptOperator ScriptOperator::OP_SUCCESS215(
    kOpSuccess215, "OP_SUCCESS215");
const ScriptOperator ScriptOperator::OP_SUCCESS216(
    kOpSuccess216, "OP_SUCCESS216");
const ScriptOperator ScriptOperator::OP_SUCCESS217(
    kOpSuccess217, "OP_SUCCESS217");
const ScriptOperator ScriptOperator::OP_SUCCESS218(
    kOpSuccess218, "OP_SUCCESS218");
const ScriptOperator ScriptOperator::OP_SUCCESS219(
    kOpSuccess219, "OP_SUCCESS219");
const ScriptOperator ScriptOperator::OP_SUCCESS220(
    kOpSuccess220, "OP_SUCCESS220");
const ScriptOperator ScriptOperator::OP_SUCCESS221(
    kOpSuccess221, "OP_SUCCESS221");
const ScriptOperator ScriptOperator::OP_SUCCESS222(
    kOpSuccess222, "OP_SUCCESS222");
const ScriptOperator ScriptOperator::OP_SUCCESS223(
    kOpSuccess223, "OP_SUCCESS223");
const ScriptOperator ScriptOperator::OP_SUCCESS224(
    kOpSuccess224, "OP_SUCCESS224");
const ScriptOperator ScriptOperator::OP_SUCCESS225(
    kOpSuccess225, "OP_SUCCESS225");
const ScriptOperator ScriptOperator::OP_SUCCESS226(
    kOpSuccess226, "OP_SUCCESS226");
const ScriptOperator ScriptOperator::OP_SUCCESS227(
    kOpSuccess227, "OP_SUCCESS227");
const ScriptOperator ScriptOperator::OP_SUCCESS228(
    kOpSuccess228, "OP_SUCCESS228");
const ScriptOperator ScriptOperator::OP_SUCCESS229(
    kOpSuccess229, "OP_SUCCESS229");
const ScriptOperator ScriptOperator::OP_SUCCESS230(
    kOpSuccess230, "OP_SUCCESS230");
const ScriptOperator ScriptOperator::OP_SUCCESS231(
    kOpSuccess231, "OP_SUCCESS231");
const ScriptOperator ScriptOperator::OP_SUCCESS232(
    kOpSuccess232, "OP_SUCCESS232");
const ScriptOperator ScriptOperator::OP_SUCCESS233(
    kOpSuccess233, "OP_SUCCESS233");
const ScriptOperator ScriptOperator::OP_SUCCESS234(
    kOpSuccess234, "OP_SUCCESS234");
const ScriptOperator ScriptOperator::OP_SUCCESS235(
    kOpSuccess235, "OP_SUCCESS235");
const ScriptOperator ScriptOperator::OP_SUCCESS236(
    kOpSuccess236, "OP_SUCCESS236");
const ScriptOperator ScriptOperator::OP_SUCCESS237(
    kOpSuccess237, "OP_SUCCESS237");
const ScriptOperator ScriptOperator::OP_SUCCESS238(
    kOpSuccess238, "OP_SUCCESS238");
const ScriptOperator ScriptOperator::OP_SUCCESS239(
    kOpSuccess239, "OP_SUCCESS239");
const ScriptOperator ScriptOperator::OP_SUCCESS240(
    kOpSuccess240, "OP_SUCCESS240");
const ScriptOperator ScriptOperator::OP_SUCCESS241(
    kOpSuccess241, "OP_SUCCESS241");
const ScriptOperator ScriptOperator::OP_SUCCESS242(
    kOpSuccess242, "OP_SUCCESS242");
const ScriptOperator ScriptOperator::OP_SUCCESS243(
    kOpSuccess243, "OP_SUCCESS243");
const ScriptOperator ScriptOperator::OP_SUCCESS244(
    kOpSuccess244, "OP_SUCCESS244");
const ScriptOperator ScriptOperator::OP_SUCCESS245(
    kOpSuccess245, "OP_SUCCESS245");
const ScriptOperator ScriptOperator::OP_SUCCESS246(
    kOpSuccess246, "OP_SUCCESS246");
const ScriptOperator ScriptOperator::OP_SUCCESS247(
    kOpSuccess247, "OP_SUCCESS247");
const ScriptOperator ScriptOperator::OP_SUCCESS248(
    kOpSuccess248, "OP_SUCCESS248");
const ScriptOperator ScriptOperator::OP_SUCCESS249(
    kOpSuccess249, "OP_SUCCESS249");
const ScriptOperator ScriptOperator::OP_SUCCESS250(
    kOpSuccess250, "OP_SUCCESS250");
const ScriptOperator ScriptOperator::OP_SUCCESS251(
    kOpSuccess251, "OP_SUCCESS251");
const ScriptOperator ScriptOperator::OP_SUCCESS252(
    kOpSuccess252, "OP_SUCCESS252");
const ScriptOperator ScriptOperator::OP_SUCCESS253(
    kOpSuccess253, "OP_SUCCESS253");
const ScriptOperator ScriptOperator::OP_SUCCESS254(
    kOpSuccess254, "OP_SUCCESS254");

ScriptOperator::ScriptOperator(ScriptType data_type)
    : ScriptOperator(data_type, "") {
  // do nothing
}

ScriptOperator::ScriptOperator(ScriptType data_type, const std::string& text)
    : data_type_(data_type), text_data_(text) {
  // map register the const definition at production timing
  if (text.empty()) {
    if (!g_operator_map.empty()) {
      text_data_ = ToString();
    }
  } else {
    if (g_operator_map.find(data_type_) == g_operator_map.end()) {
      g_operator_map.emplace(data_type_, *this);
    }
    if (g_operator_text_map.find(text_data_) == g_operator_text_map.end()) {
      g_operator_text_map.emplace(text_data_, *this);
    }
  }
}

bool ScriptOperator::Equals(const ScriptOperator& object) const {
  return (data_type_ == object.data_type_);
}

std::string ScriptOperator::ToString() const {
  if (text_data_.empty()) {
    if (!g_operator_map.empty()) {
      decltype(g_operator_map)::const_iterator ite =
          g_operator_map.find(data_type_);
      if (ite != g_operator_map.end()) {
        return ite->second.ToString();
      }
    }
    return "UNKNOWN";
  }
  return text_data_;
}

std::string ScriptOperator::ToCodeString() const {
  if (text_data_ == "0") {
    return "OP_0";
  } else if (text_data_ == "-1") {
    return "OP_1NEGATE";
  } else if (text_data_ == "1") {
    return "OP_1";
  } else if (
      (data_type_ >= ScriptType::kOp_2) &&
      (data_type_ <= ScriptType::kOp_16)) {
    int num = static_cast<int>(data_type_);
    num -= static_cast<int>(ScriptType::kOp_1);
    num += 1;
    return "OP_" + std::to_string(num);
  }
  return ToString();
}

bool ScriptOperator::IsPushOperator() const {
  // OP_RESERVED is treated as Push command (bitcoincore)
  if ((data_type_ >= ScriptType::kOp_0) &&
      (data_type_ <= ScriptType::kOp_16)) {
    return true;
  }
  return false;
}

bool ScriptOperator::IsValid(const std::string& message) {
  if (message.empty()) return false;
  if (g_operator_text_map.empty()) return false;
  if ((message == "OP_0") || (message == "OP_1NEGATE")) {
    return true;
  } else if (message.length() >= 4) {
    int num = std::atoi(message.substr(3).c_str());
    std::string opcode_text = "OP_" + std::to_string(num);
    if ((message == opcode_text) && (num >= 1) && (num <= 16)) {
      return true;
    }
  }
  return (g_operator_text_map.find(message) != g_operator_text_map.end());
}

ScriptOperator ScriptOperator::Get(const std::string& message) {
  std::string search_text = message;
  if (message == "OP_0") {
    search_text = "0";
  } else if (message == "OP_1NEGATE") {
    search_text = "-1";
  } else if (message.length() >= 4) {
    int num = std::atoi(message.substr(3).c_str());
    std::string num_str = std::to_string(num);
    std::string opcode_text = "OP_" + num_str;
    if ((message == opcode_text) && (num >= 1) && (num <= 16)) {
      search_text = num_str;
    }
  }
  decltype(g_operator_text_map)::const_iterator ite =
      g_operator_text_map.find(search_text);
  if (ite == g_operator_text_map.end()) {
    warn(CFD_LOG_SOURCE, "target op_code not found.");
    throw InvalidScriptException("target op_code not found.");
  }
  return ite->second;
}

bool ScriptOperator::IsOpSuccess(ScriptType op_code) {
  if ((op_code == kOpSuccess80) || (op_code == kOpSuccess98) ||
      ((op_code >= kOpSuccess126) && (op_code <= kOpSuccess129)) ||
      ((op_code >= kOpSuccess131) && (op_code <= kOpSuccess134)) ||
      ((op_code >= kOpSuccess137) && (op_code <= kOpSuccess138)) ||
      ((op_code >= kOpSuccess141) && (op_code <= kOpSuccess142)) ||
      ((op_code >= kOpSuccess149) && (op_code <= kOpSuccess153)) ||
      ((op_code >= kOpSuccess187) && (op_code <= kOpSuccess254))) {
    return true;
  }
  return false;
}

ScriptOperator::ScriptOperator(const ScriptOperator& object)
    : data_type_(object.data_type_), text_data_(object.text_data_) {
  // do nothing
}

ScriptOperator& ScriptOperator::operator=(const ScriptOperator& object) {
  if (this != &object) {
    data_type_ = object.data_type_;
    text_data_ = object.text_data_;
  }
  return *this;
}

bool ScriptOperator::operator==(const ScriptOperator& object) const {
  return data_type_ == object.data_type_;
}

bool ScriptOperator::operator!=(const ScriptOperator& object) const {
  return data_type_ != object.data_type_;
}

bool ScriptOperator::operator<(const ScriptOperator& object) const {
  return data_type_ < object.data_type_;
}

bool ScriptOperator::operator<=(const ScriptOperator& object) const {
  return data_type_ <= object.data_type_;
}

bool ScriptOperator::operator>(const ScriptOperator& object) const {
  return data_type_ > object.data_type_;
}

bool ScriptOperator::operator>=(const ScriptOperator& object) const {
  return data_type_ >= object.data_type_;
}

// -----------------------------------------------------------------------------
// ScriptElement
// -----------------------------------------------------------------------------
ScriptElement::ScriptElement(const ScriptElement& element)
    : type_(element.type_),
      op_code_(element.op_code_),
      binary_data_(element.binary_data_),
      value_(element.value_) {
  // do nothing
}

ScriptElement::ScriptElement(const ScriptType& type)
    : type_(kElementOpCode), op_code_(type), binary_data_(), value_(0) {
  if ((type == kOp1Negate) || ((type >= kOp_1) && (type <= kOp_16))) {
    // convert to numeric format
    int64_t base_value = static_cast<int64_t>(kOp_1) - 1;
    value_ = static_cast<int64_t>(type) - base_value;
  }
}

ScriptElement::ScriptElement(const ScriptOperator& op_code)
    : type_(kElementOpCode), op_code_(op_code), binary_data_(), value_(0) {
  ScriptType type = op_code.GetDataType();
  if ((type == kOp1Negate) || ((type >= kOp_1) && (type <= kOp_16))) {
    // convert to numeric format
    int64_t base_value = static_cast<int64_t>(kOp_1) - 1;
    value_ = static_cast<int64_t>(type) - base_value;
  }
}

ScriptElement::ScriptElement(const ByteData& binary_data)
    : type_(kElementBinary),
      op_code_(kOpInvalidOpCode),
      binary_data_(binary_data),
      value_(0) {
  // check number
  uint32_t size = static_cast<uint32_t>(binary_data.GetDataSize());
  if ((size > 0) && (size <= 5) && ConvertBinaryToNumber(&value_)) {
    type_ = kElementNumber;
  }
}

ScriptElement::ScriptElement(int64_t value)
    : type_(kElementNumber),
      op_code_(kOpInvalidOpCode),
      binary_data_(),
      value_(value) {
  if ((value >= -1) && (value <= 16)) {
    int32_t op_code = static_cast<int32_t>(kOp_0);
    if (value == -1) {
      op_code = static_cast<int32_t>(kOp1Negate);

    } else if (value >= 1) {
      op_code = static_cast<int32_t>(kOp_1);
      op_code += static_cast<int32_t>(value) - 1;
    }

    ScriptType key = static_cast<ScriptType>(op_code);
    bool is_find = false;
    if (!g_operator_map.empty()) {
      decltype(g_operator_map)::const_iterator ite = g_operator_map.find(key);
      if (ite != g_operator_map.end()) {
        op_code_ = ite->second;
        is_find = true;
      }
    }
    if (!is_find) {
      op_code_ = ScriptOperator(key);
    }
    if (op_code_.GetDataType() != kOpInvalidOpCode) {
      type_ = kElementOpCode;
    }
  }

  if (type_ == kElementNumber) {
    // set binary data
    binary_data_ = ByteData(SerializeScriptNum(value_));
  }
}

ScriptElement::ScriptElement(int64_t value, bool is_binary)
    : ScriptElement(value) {
  if (is_binary && type_ == kElementOpCode) {
    type_ = kElementNumber;
    binary_data_ = ByteData(SerializeScriptNum(value_));
  }
}

ScriptElement& ScriptElement::operator=(const ScriptElement& element) {
  if (this != &element) {
    type_ = element.type_;
    op_code_ = element.op_code_;
    binary_data_ = element.binary_data_;
    value_ = element.value_;
  }
  return *this;
}

ScriptElementType ScriptElement::GetType() const { return type_; }

const ScriptOperator& ScriptElement::GetOpCode() const { return op_code_; }

ByteData ScriptElement::GetBinaryData() const { return binary_data_; }

int64_t ScriptElement::GetNumber() const { return value_; }

ByteData ScriptElement::GetData() const {
  std::vector<uint8_t> byte_data;
  switch (type_) {
    case kElementBinary: {
      byte_data =
          WallyUtil::CreateScriptDataFromBytes(binary_data_.GetBytes());
      break;
    }
    case kElementNumber: {
      std::vector<uint8_t> byte_array = SerializeScriptNum(value_);
      byte_data = WallyUtil::CreateScriptDataFromBytes(byte_array);
      break;
    }
    case kElementOpCode:
    default: {
      ScriptType op_code = op_code_.GetDataType();
      if (op_code != kOpInvalidOpCode) {
        byte_data.push_back(static_cast<uint8_t>(op_code));
      }
      break;
    }
  }
  return ByteData(byte_data);
}

std::string ScriptElement::ToString() const {
  switch (type_) {
    case kElementBinary:
      if (binary_data_.GetDataSize() == 0) {
        return "";
      } else {
        return binary_data_.GetHex();
      }
    case kElementNumber: {
      return std::to_string(value_);
    }
    case kElementOpCode:
    default: {
      if (op_code_.GetDataType() != kOpInvalidOpCode) {
        return op_code_.ToString();
      }
      break;
    }
  }
  return "";
}

bool ScriptElement::ConvertBinaryToNumber(int64_t* int64_value) const {
  bool is_success = false;
  std::vector<uint8_t> vch = binary_data_.GetBytes();
  if (((type_ == kElementBinary) || (type_ == kElementNumber)) &&
      (vch.size() <= 5) && ((vch.back() & 0x7f) != 0)) {
    int64_t val = 0;
    for (size_t i = 0; i != vch.size(); ++i) {
      val |= static_cast<int64_t>(vch[i]) << 8 * i;
    }

    if (vch.back() & 0x80) {
      val = -((int64_t)(val & ~(0x80ULL << (8 * (vch.size() - 1)))));
    }
    is_success = true;
    if (int64_value != nullptr) {
      *int64_value = val;
    }
  }
  return is_success;
}

std::vector<uint8_t> ScriptElement::SerializeScriptNum(int64_t value) {
  if (value == 0) {
    return std::vector<uint8_t>();
  }

  std::vector<uint8_t> result;
  const bool is_negative = value < 0;
  uint64_t abstract_value = is_negative ? -value : value;

  while (abstract_value) {
    result.push_back(abstract_value & 0xff);
    abstract_value >>= 8;
  }

  if (result.back() & 0x80) {
    if (is_negative) {
      result.push_back(0x80);
    } else {
      result.push_back(0x00);
    }
  } else if (is_negative) {
    result.back() |= 0x80;
  }

  return result;
}

// -----------------------------------------------------------------------------
// ScriptHash
// -----------------------------------------------------------------------------
ScriptHash::ScriptHash(const std::string& script_hash)
    : script_hash_(StringUtil::StringToByte(script_hash)) {
  // do nothing
}

ScriptHash::ScriptHash(const Script& script, bool is_witness)
    : script_hash_() {
  std::vector<uint8_t> buffer;
  buffer.clear();

  // hash calculation
  if (is_witness) {
    ByteData256 hash256 = HashUtil::Sha256(script.GetData().GetBytes());
    const std::vector<uint8_t> byte_array = hash256.GetBytes();
    // scriptPubKey : 0 <32-byte-hash>(0x0020{32-byte-hash})
    buffer.push_back(kOp_0);
    buffer.push_back(static_cast<uint8_t>(byte_array.size()));
    std::copy(
        byte_array.begin(), byte_array.end(), std::back_inserter(buffer));

  } else {
    ByteData160 hash160 = HashUtil::Hash160(script.GetData().GetBytes());
    const std::vector<uint8_t> byte_array = hash160.GetBytes();
    // Pubkey script   : OP_HASH160 <Hash160(redeemScript)> OP_EQUAL
    buffer.push_back(kOpHash160);
    buffer.push_back(static_cast<uint8_t>(byte_array.size()));
    std::copy(
        byte_array.begin(), byte_array.end(), std::back_inserter(buffer));
    buffer.push_back(kOpEqual);
  }

  script_hash_ = ByteData(buffer);
}

const std::string ScriptHash::GetHex() const { return script_hash_.GetHex(); }

const ByteData ScriptHash::GetData() const { return script_hash_; }

// -----------------------------------------------------------------------------
// Script
// -----------------------------------------------------------------------------
const Script Script::Empty;  ///< empty script

Script::Script() : script_data_(), script_stack_() {
  // do nothing
}

Script::Script(const std::string& hex) : script_data_(), script_stack_() {
  std::vector<uint8_t> buffer = StringUtil::StringToByte(hex);
  ByteData data = ByteData(buffer);
  SetStackData(data);
  script_data_ = data;
}

Script::Script(const ByteData& bytedata)
    : script_data_(bytedata), script_stack_() {
  SetStackData(bytedata);
}

Script::Script(const Script& object) {
  script_data_ = object.script_data_;
  script_stack_ = object.script_stack_;
}

Script& Script::operator=(const Script& object) & {
  if (this != &object) {
    script_data_ = object.script_data_;
    script_stack_ = object.script_stack_;
  }
  return *this;
}

void Script::SetStackData(const ByteData& bytedata) {
  std::vector<uint8_t> buffer = bytedata.GetBytes();
  static const std::set<ScriptType> kUseScriptNum1{
      kOpCheckSequenceVerify,
      kOpCheckLockTimeVerify,
      kOp1Add,
      kOp1Sub,
      kOpNegate,
      kOpAbs,
      kOpNot,
      kOp0NotEqual,
      kOpPick,
      kOpRoll};
  static const std::set<ScriptType> kUseScriptNum2{
      kOpAdd,
      kOpSub,
      kOpGreaterThan,
      kOpBoolOr,
      kOpNumEqual,
      kOpNumEqualVerify,
      kOpNumNotEqual,
      kOpLessThan,
      kOpBoolAnd,
      kOpLessThanOrEqual,
      kOpMin,
      kOpMax,
      kOpGreaterThanOrEqual};
  static const std::set<ScriptType> kUseScriptNum3{kOpWithIn, kOpCheckSigAdd};

  // create stack
  bool is_collect_buffer = false;
  uint32_t collect_buffer_size = 0;
  std::vector<uint8_t> collect_buffer;
  uint32_t offset = 0;
  while (offset < buffer.size()) {
    uint8_t view_data = buffer[offset];
    if (kOp_0 == view_data) {
      // @formatter:off
      ScriptElement script_element = ScriptElement(ScriptOperator::OP_0);
      // @formatter:on
      script_stack_.push_back(script_element);

    } else if (view_data < kOpPushData1) {
      collect_buffer_size = view_data;
      is_collect_buffer = true;
      ++offset;

    } else if (view_data == kOpPushData1) {
      ++offset;
      if ((offset + 1) >= buffer.size()) {
        warn(CFD_LOG_SOURCE, "OP_PUSHDATA1 is incorrect size.");
        throw InvalidScriptException("OP_PUSHDATA1 is incorrect size.");
      }
      collect_buffer_size = buffer[offset];
      is_collect_buffer = true;
      ++offset;

    } else if (view_data == kOpPushData2) {
      ++offset;
      uint16_t ushort_value = 0;
      if ((offset + sizeof(uint16_t)) >= buffer.size()) {
        warn(CFD_LOG_SOURCE, "OP_PUSHDATA2 is incorrect size.");
        throw InvalidScriptException("OP_PUSHDATA2 is incorrect size.");
      }
      // process under LittleEndian
      memcpy(&ushort_value, &buffer[offset], sizeof(ushort_value));
      collect_buffer_size = ushort_value;
      offset += sizeof(ushort_value);
      is_collect_buffer = true;

    } else if (view_data == kOpPushData4) {
      ++offset;
      uint32_t uint_value = 0;
      if ((offset + sizeof(uint_value)) >= buffer.size()) {
        warn(CFD_LOG_SOURCE, "OP_PUSHDATA4 is incorrect size.");
        throw InvalidScriptException("OP_PUSHDATA4 is incorrect size.");
      }
      // process under LittleEndian
      memcpy(&uint_value, &buffer[offset], sizeof(uint_value));
      collect_buffer_size = uint_value;
      offset += sizeof(uint_value);
      is_collect_buffer = true;

    } else {
      // if ((bytedata == OP_0) || ((byteadata >= OP_PUSHDATA1)
      //     && (byteadata <= OP_NOP10)))
      // TODO(k-matsuzawa): Considering script extension, do not perform strict check of OP value.  // NOLINT

      // Setting for ScriptOperator
      ScriptType type = (ScriptType)view_data;
      if (!g_operator_map.empty()) {
        decltype(g_operator_map)::const_iterator ite =
            g_operator_map.find(type);
        if (ite != g_operator_map.end()) {
          ScriptElement script_element = ScriptElement(ite->second);
          script_stack_.push_back(script_element);

          // Since bytedata is stored as numerica type, after decoding bytedata
          // Re-convert to numeric type based on the contents of OP_CODE.
          /// Since OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY are
          // in the range of OP_1-OP_16, they are excluded from
          // this conversion process.
          uint32_t convert_count = 0;
          if (kUseScriptNum1.count(type) > 0) {
            if (script_stack_.size() > 1) {
              convert_count = 1;
            }
          } else if (kUseScriptNum2.count(type) > 0) {
            if (script_stack_.size() > 2) {
              convert_count = 2;
            }
          } else if (kUseScriptNum3.count(type) > 0) {
            if (script_stack_.size() > 3) {
              convert_count = 3;
            }
          }

          static constexpr uint32_t kMaxArray = 5;
          if ((convert_count != 0) && (convert_count <= kMaxArray)) {
            int64_t values[kMaxArray];
            uint32_t stack_offset =
                static_cast<uint32_t>(script_stack_.size());
            stack_offset -= convert_count + 1;
            uint32_t check_count = 0;
            for (uint32_t index = 0; index < convert_count; ++index) {
              if (script_stack_[stack_offset + index].ConvertBinaryToNumber(
                      &values[index])) {
                ++check_count;
              }
            }
            if (check_count == convert_count) {
              ScriptElement* pointer = script_stack_.data();
              for (uint32_t index = 0; index < convert_count; ++index) {
                pointer[stack_offset + index] = ScriptElement(values[index]);
              }
            }
          }
        }
      }
    }

    if (is_collect_buffer) {
      collect_buffer.clear();
      collect_buffer.resize(collect_buffer_size);
      if ((offset + collect_buffer_size) > buffer.size()) {
        warn(CFD_LOG_SOURCE, "buffer is incorrect size.");
        throw InvalidScriptException("buffer is incorrect size.");
      }

      // OK
      collect_buffer.assign(
          buffer.begin() + offset,
          buffer.begin() + offset + collect_buffer_size);

      if (collect_buffer_size <= kMaxScriptNumSize) {
        ScriptElement script_element =
            ScriptElement(ConvertToNumber(collect_buffer), true);
        script_stack_.push_back(script_element);
      } else {
        ByteData byte_array = ByteData(collect_buffer);
        ScriptElement script_element = ScriptElement(byte_array);
        script_stack_.push_back(script_element);
      }
      offset += collect_buffer_size;
      is_collect_buffer = false;
    } else {
      ++offset;
    }
  }
  if (is_collect_buffer) {
    // incorrect script
    warn(CFD_LOG_SOURCE, "incorrect script data.");
    throw InvalidScriptException("incorrect script data.");
  }
}

int64_t Script::ConvertToNumber(const std::vector<uint8_t> bytes) {
  if (bytes.empty()) {
    return 0;
  }

  int64_t result = 0;
  for (size_t i = 0; i < bytes.size(); ++i) {
    result |= static_cast<int64_t>(bytes[i]) << 8 * i;
  }

  if (bytes.back() & 0x80) {
    return -(
        static_cast<int64_t>(result & ~(0x80ULL << (8 * (bytes.size() - 1)))));
  }

  return result;
}

Script Script::GetScript() const { return Script(script_data_); }

ScriptHash Script::GetScriptHash() const { return ScriptHash(*this, false); }

ScriptHash Script::GetWitnessScriptHash() const {
  return ScriptHash(*this, true);
}

const ByteData Script::GetData() const { return script_data_; }

const std::string Script::GetHex() const { return script_data_.GetHex(); }

bool Script::IsEmpty() const { return script_data_.GetBytes().empty(); }

bool Script::Equals(const Script& object) const {
  return script_data_.Equals(object.script_data_);
}

std::vector<ScriptElement> Script::GetElementList() const {
  return script_stack_;
}

std::string Script::ToString() const {
  if (script_stack_.empty()) {
    return "";
  }

  std::vector<std::string> str_list;
  for (const ScriptElement& element : script_stack_) {
    str_list.push_back(element.ToString());
  }

  const char* delimiter = " ";
  std::ostringstream os;
  std::copy(
      str_list.begin(), str_list.end(),
      std::ostream_iterator<std::string>(os, delimiter));
  std::string result = os.str();  // "a,b,c,"
  result.erase(result.size() - std::char_traits<char>::length(delimiter));
  return result;
}

bool Script::IsPushOnly() const {
  bool is_push_only = true;
  for (const ScriptElement& element : script_stack_) {
    if (element.IsOpCode()) {
      if (!element.GetOpCode().IsPushOperator()) {
        is_push_only = false;
        break;
      }
    }
  }
  return is_push_only;
}

bool Script::IsP2pkScript() const {
  return (
      script_stack_.size() == 2 && script_stack_[0].IsBinary() &&
      Pubkey::IsValid(script_stack_[0].GetBinaryData()) &&
      script_stack_[1].GetOpCode() == ScriptOperator::OP_CHECKSIG);
}

bool Script::IsP2pkhScript() const {
  return (
      script_data_.GetDataSize() == kScriptHashP2pkhLength &&
      script_stack_.size() == 5 &&
      script_stack_[0].GetOpCode() == ScriptOperator::OP_DUP &&
      script_stack_[1].GetOpCode() == ScriptOperator::OP_HASH160 &&
      script_stack_[2].IsBinary() &&
      script_stack_[3].GetOpCode() == ScriptOperator::OP_EQUALVERIFY &&
      script_stack_[4].GetOpCode() == ScriptOperator::OP_CHECKSIG);
}

bool Script::IsP2shScript() const {
  return (
      script_data_.GetDataSize() == kScriptHashP2shLength &&
      script_stack_.size() == 3 &&
      script_stack_[0].GetOpCode() == ScriptOperator::OP_HASH160 &&
      script_stack_[1].IsBinary() &&
      script_stack_[2].GetOpCode() == ScriptOperator::OP_EQUAL);
}

bool Script::IsMultisigScript() const {
  if (script_stack_.size() < 4 || !script_stack_[0].IsNumber() ||
      !script_stack_[(script_stack_.size() - 2)].IsNumber() ||
      script_stack_[(script_stack_.size() - 1)].GetOpCode() !=
          ScriptOperator::OP_CHECKMULTISIG) {
    return false;
  }
  int64_t req_num = script_stack_[0].GetNumber();
  int64_t num = script_stack_[(script_stack_.size() - 2)].GetNumber();
  if (req_num <= 16 && !script_stack_[0].IsOpCode()) {
    return false;
  }
  if (num <= 16 && !script_stack_[(script_stack_.size() - 2)].IsOpCode()) {
    return false;
  }

  if (req_num > num || req_num == 0 ||
      num != static_cast<int64_t>(script_stack_.size() - 3)) {
    return false;
  }

  for (size_t i = 1; i < (script_stack_.size() - 2); ++i) {
    if (!script_stack_[i].IsBinary() ||
        !Pubkey::IsValid(script_stack_[i].GetBinaryData())) {
      return false;
    }
  }
  return true;
}

bool Script::IsWitnessProgram() const {
  if ((script_data_.GetDataSize() < kMinWitnessProgramLength) ||
      (kMaxWitnessProgramLength < script_data_.GetDataSize()) ||
      (script_stack_.size() != 2) || (!script_stack_[0].IsOpCode()) ||
      (!script_stack_[1].IsBinary())) {
    return false;
  }
  auto op_code = script_stack_[0].GetOpCode().GetDataType();
  if ((op_code != ScriptType::kOp_0) &&
      ((op_code < ScriptType::kOp_1) || (op_code > ScriptType::kOp_16))) {
    return false;
  }

  auto hash_size = script_stack_[1].GetBinaryData().GetDataSize();
  if (op_code == ScriptType::kOp_0) {
    if ((hash_size != 0x14) && (hash_size != 0x20)) return false;
  } else if (op_code == ScriptType::kOp_1) {
    if (hash_size != 0x20) return false;
  }
  return true;
}

WitnessVersion Script::GetWitnessVersion() const {
  if (IsWitnessProgram()) {
    auto val = script_stack_[0].GetOpCode().GetDataType();
    if (kOp_0 == val) {
      return WitnessVersion::kVersion0;
    } else if ((kOp_1 <= val) && (val <= kOp_16)) {
      auto num = val - kOp_1;
      auto version = WitnessVersion::kVersion1 + num;
      return static_cast<WitnessVersion>(version);
    }
  }
  return WitnessVersion::kVersionNone;
}

bool Script::IsP2wpkhScript() const {
  return (
      script_data_.GetDataSize() == kScriptHashP2wpkhLength &&
      script_stack_.size() == 2 &&
      script_stack_[0].GetOpCode() == ScriptOperator::OP_0 &&
      script_stack_[1].IsBinary() &&
      script_stack_[1].GetBinaryData().GetDataSize() == kByteData160Length);
}

bool Script::IsP2wshScript() const {
  return (
      script_data_.GetDataSize() == kScriptHashP2wshLength &&
      script_stack_.size() == 2 &&
      script_stack_[0].GetOpCode() == ScriptOperator::OP_0 &&
      script_stack_[1].IsBinary() &&
      script_stack_[1].GetBinaryData().GetDataSize() == kByteData256Length);
}

bool Script::IsTaprootScript() const {
  return (
      script_data_.GetDataSize() == kScriptHashTaprootLength &&
      script_stack_.size() == 2 &&
      script_stack_[0].GetOpCode() == ScriptOperator::OP_1 &&
      script_stack_[1].IsBinary() &&
      script_stack_[1].GetBinaryData().GetDataSize() == kByteData256Length);
}

bool Script::IsPegoutScript() const {
  if ((script_data_.GetDataSize() < 2) ||
      (script_stack_[0].GetOpCode() != ScriptOperator::OP_RETURN)) {
    return false;
  }

  if (!script_stack_[1].IsBinary() ||
      script_stack_[1].GetBinaryData().GetDataSize() != kByteData256Length) {
    return false;
  }

  for (size_t i = 2; i < script_stack_.size(); ++i) {
    if (!script_stack_[i].IsBinary()) {
      return false;
    }
  }

  return true;
}

// -----------------------------------------------------------------------------
// ScriptBuilder
// -----------------------------------------------------------------------------
ScriptBuilder& ScriptBuilder::AppendString(const std::string& message) {
  if (ScriptOperator::IsValid(message)) {
    return AppendOperator(ScriptOperator::Get(message));
  } else if ((message.length() > 2) && (message.substr(0, 2) == "0x")) {
    // to hex
    return AppendData(ByteData(message.substr(2)));
  } else {
    if (std::atoi(message.c_str()) != 0) {  // check number
      int int_value = std::atoi(message.c_str());
      std::string str = std::to_string(int_value);
      if (str == message) {
        return AppendData(static_cast<int64_t>(int_value));
      }
    }
    // hex string check (force)
    return AppendData(ByteData(message));
  }
}

ScriptBuilder& ScriptBuilder::AppendOperator(ScriptType type) {
  script_byte_array_.push_back(type);
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendOperator(
    const ScriptOperator& operate_object) {
  script_byte_array_.push_back(
      static_cast<uint8_t>(operate_object.GetDataType()));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendData(const std::string& hex_str) {
  const std::vector<uint8_t>& byte_array = StringUtil::StringToByte(hex_str);
  std::vector<uint8_t> byte_datas =
      WallyUtil::CreateScriptDataFromBytes(byte_array);
  std::copy(
      byte_datas.begin(), byte_datas.end(),
      std::back_inserter(script_byte_array_));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendData(const ByteData& data) {
  const std::vector<uint8_t>& byte_array = data.GetBytes();
  std::vector<uint8_t> byte_datas =
      WallyUtil::CreateScriptDataFromBytes(byte_array);
  std::copy(
      byte_datas.begin(), byte_datas.end(),
      std::back_inserter(script_byte_array_));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendData(const ByteData160& data) {
  const std::vector<uint8_t>& byte_array = data.GetBytes();
  std::vector<uint8_t> byte_datas =
      WallyUtil::CreateScriptDataFromBytes(byte_array);
  std::copy(
      byte_datas.begin(), byte_datas.end(),
      std::back_inserter(script_byte_array_));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendData(const ByteData256& data) {
  const std::vector<uint8_t>& byte_array = data.GetBytes();
  std::vector<uint8_t> byte_datas =
      WallyUtil::CreateScriptDataFromBytes(byte_array);
  std::copy(
      byte_datas.begin(), byte_datas.end(),
      std::back_inserter(script_byte_array_));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendData(const Pubkey& pubkey) {
  const std::vector<uint8_t>& byte_array = pubkey.GetData().GetBytes();
  std::vector<uint8_t> byte_datas =
      WallyUtil::CreateScriptDataFromBytes(byte_array);
  std::copy(
      byte_datas.begin(), byte_datas.end(),
      std::back_inserter(script_byte_array_));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendData(const Script& script) {
  const std::vector<uint8_t>& byte_array = script.GetData().GetBytes();
  std::vector<uint8_t> byte_datas =
      WallyUtil::CreateScriptDataFromBytes(byte_array);
  std::copy(
      byte_datas.begin(), byte_datas.end(),
      std::back_inserter(script_byte_array_));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendData(const int64_t& data) {
  ScriptElement element(data);
  std::vector<uint8_t> byte_datas = element.GetData().GetBytes();
  std::copy(
      byte_datas.begin(), byte_datas.end(),
      std::back_inserter(script_byte_array_));
  return *this;
}

ScriptBuilder& ScriptBuilder::AppendElement(const ScriptElement& element) {
  std::vector<uint8_t> byte_datas = element.GetData().GetBytes();
  if (!byte_datas.empty()) {
    std::copy(
        byte_datas.begin(), byte_datas.end(),
        std::back_inserter(script_byte_array_));
  }
  return *this;
}

ScriptBuilder& ScriptBuilder::operator<<(const std::string& message) {
  return AppendString(message);
}

ScriptBuilder& ScriptBuilder::operator<<(ScriptType type) {
  return AppendOperator(type);
}

ScriptBuilder& ScriptBuilder::operator<<(
    const ScriptOperator& operate_object) {
  return AppendOperator(operate_object);
}

ScriptBuilder& ScriptBuilder::operator<<(const ByteData& data) {
  return AppendData(data);
}

ScriptBuilder& ScriptBuilder::operator<<(const ByteData160& data) {
  return AppendData(data);
}

ScriptBuilder& ScriptBuilder::operator<<(const ByteData256& data) {
  return AppendData(data);
}

ScriptBuilder& ScriptBuilder::operator<<(const Pubkey& pubkey) {
  return AppendData(pubkey);
}

ScriptBuilder& ScriptBuilder::operator<<(const Script& script) {
  return AppendData(script);
}

ScriptBuilder& ScriptBuilder::operator<<(const int64_t& data) {
  return AppendData(data);
}

ScriptBuilder& ScriptBuilder::operator<<(const ScriptElement& element) {
  return AppendElement(element);
}

Script ScriptBuilder::Build() {
  ByteData data(script_byte_array_);
  if (data.GetDataSize() > Script::kMaxScriptSize) {
    warn(CFD_LOG_SOURCE, "Script size is over.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Script size is over.");
  }

  return Script(data);
}

// -----------------------------------------------------------------------------
// ScriptUtil
// -----------------------------------------------------------------------------

// <pubkey> OP_CHECKSIG
Script ScriptUtil::CreateP2pkLockingScript(const Pubkey& pubkey) {
  // script作成
  ScriptBuilder builder;
  builder.AppendData(pubkey);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);

  return builder.Build();
}

// OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
Script ScriptUtil::CreateP2pkhLockingScript(const ByteData160& pubkey_hash) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(pubkey_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);

  return builder.Build();
}

// OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
Script ScriptUtil::CreateP2pkhLockingScript(const Pubkey& pubkey) {
  // create pubkey hash
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);

  return CreateP2pkhLockingScript(pubkey_hash);
}

// OP_HASH160 <hash160(redeem_script)> OP_EQUAL
Script ScriptUtil::CreateP2shLockingScript(const ByteData160& script_hash) {
  // script作成
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(script_hash);
  builder.AppendOperator(ScriptOperator::OP_EQUAL);

  return builder.Build();
}

// OP_HASH160 <hash160(redeem_script)> OP_EQUAL
Script ScriptUtil::CreateP2shLockingScript(const Script& redeem_script) {
  // script hash作成
  ByteData160 script_hash = HashUtil::Hash160(redeem_script);

  return CreateP2shLockingScript(script_hash);
}

// OP_0 <hash160(pubkey)>
Script ScriptUtil::CreateP2wpkhLockingScript(const ByteData160& pubkey_hash) {
  // create script
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(pubkey_hash);

  return builder.Build();
}

// OP_0 <hash160(pubkey)>
Script ScriptUtil::CreateP2wpkhLockingScript(const Pubkey& pubkey) {
  // create pubkey hash
  ByteData160 pubkey_hash = HashUtil::Hash160(pubkey);

  return CreateP2wpkhLockingScript(pubkey_hash);
}

// OP_0 <sha256(redeem_script)>
Script ScriptUtil::CreateP2wshLockingScript(const ByteData256& script_hash) {
  // create script
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_0);
  builder.AppendData(script_hash);

  return builder.Build();
}

// OP_0 <sha256(redeem_script)>
Script ScriptUtil::CreateP2wshLockingScript(const Script& redeem_script) {
  // create script hash
  ByteData256 script_hash = HashUtil::Sha256(redeem_script);

  return CreateP2wshLockingScript(script_hash);
}

Script ScriptUtil::CreateTaprootLockingScript(const ByteData256& data) {
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_1);
  builder.AppendData(data);
  return builder.Build();
}

bool ScriptUtil::IsValidRedeemScript(const Script& redeem_script) {
  size_t script_buf_size = redeem_script.GetData().GetDataSize();
  if (script_buf_size > Script::kMaxRedeemScriptSize) {
    warn(
        CFD_LOG_SOURCE, "Redeem script size is over the limit. script size={}",
        script_buf_size);
    return false;
  }
  return true;
}

// OP_n <pubkey> ... OP_<requireSigNum> OP_CHECKMULTISIG
Script ScriptUtil::CreateMultisigRedeemScript(
    uint32_t require_signature_num, const std::vector<Pubkey>& pubkeys,
    bool has_witness) {
  if (require_signature_num == 0) {
    warn(CFD_LOG_SOURCE, "Invalid require_sig_num. require_sig_num = 0");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "CreateMultisigScript require_num is 0.");
  }
  if (pubkeys.empty()) {
    warn(CFD_LOG_SOURCE, "pubkey array is empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "CreateMultisigScript empty pubkey array.");
  }
  if (require_signature_num > pubkeys.size()) {
    warn(
        CFD_LOG_SOURCE,
        "Invalid require_sig_num. require_sig_num={0}, pubkey size={1}.",
        require_signature_num, pubkeys.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "CreateMultisigScript require_num is over.");
  }
  size_t max_num = (has_witness) ? Script::kMaxMultisigPubkeyNum : 15;
  if (pubkeys.size() > max_num) {
    warn(CFD_LOG_SOURCE, "pubkey array size is over.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "CreateMultisigScript pubkeys array size is over.");
  }

  ScriptElement op_require_num(static_cast<int64_t>(require_signature_num));
  ScriptElement op_pubkey_num(static_cast<int64_t>(pubkeys.size()));

  // create script
  ScriptBuilder builder;
  builder << op_require_num;
  for (const Pubkey& pubkey : pubkeys) builder << pubkey;
  builder << op_pubkey_num << ScriptOperator::OP_CHECKMULTISIG;
  Script redeem_script = builder.Build();

  if ((!has_witness) && (!IsValidRedeemScript(redeem_script))) {
    warn(CFD_LOG_SOURCE, "Multisig script size is over.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "CreateMultisigScript multisig script size is over.");
  }
  return redeem_script;
}

#ifndef CFD_DISABLE_ELEMENTS
Script ScriptUtil::CreatePegoutLogkingScript(
    const BlockHash& genesisblock_hash, const Script& parent_locking_script,
    const Pubkey& btc_pubkey_bytes, const ByteData& whitelist_proof) {
  // create script
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_RETURN);
  builder.AppendData(genesisblock_hash.GetData());
  builder.AppendData(parent_locking_script);
  if (btc_pubkey_bytes.IsValid() && (whitelist_proof.GetDataSize() > 0)) {
    builder.AppendData(btc_pubkey_bytes);
    builder.AppendData(whitelist_proof);
  }
  Script locking_script = builder.Build();
  return locking_script;
}
#endif  // CFD_DISABLE_ELEMENTS

std::vector<Pubkey> ScriptUtil::ExtractPubkeysFromMultisigScript(
    const Script& multisig_script, uint32_t* require_num) {
  std::vector<Pubkey> pubkeys;
  const std::vector<ScriptElement> elements = multisig_script.GetElementList();

  // find OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY
  IteratorWrapper<ScriptElement> itr = IteratorWrapper<ScriptElement>(
      elements, "Invalid script element access", true);
  // search OP_CHECKMULTISIG(or VERIFY)
  while (itr.hasNext()) {
    ScriptElement element = itr.next();
    if (!element.IsOpCode()) {
      continue;
    }
    if (element.GetOpCode() == ScriptOperator::OP_CHECKMULTISIG ||
        element.GetOpCode() == ScriptOperator::OP_CHECKMULTISIGVERIFY) {
      break;
    }
  }
  // target opcode not found
  if (!itr.hasNext()) {
    warn(
        CFD_LOG_SOURCE,
        "Multisig opcode (OP_CHECKMULTISIG|VERIFY) not found"
        " in redeem script: script={}",
        multisig_script.ToString());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "OP_CHCKMULTISIG(OP_CHECKMULTISIGVERIFY) not found"
        " in redeem script.");
  }

  // get contain pubkey num
  const ScriptElement& op_m = itr.next();
  if (!op_m.IsNumber()) {
    warn(
        CFD_LOG_SOURCE,
        "Invalid OP_CHECKMULTISIG(VERIFY) input in redeem script."
        " Missing contain pubkey number.: script={}",
        multisig_script.ToString());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid OP_CHCKMULTISIG(OP_CHECKMULTISIGVERIFY) input"
        " in redeem script. Missing contain pubkey number.");
  }

  // set pubkey to vector(reverse data)
  int64_t contain_pubkey_num = op_m.GetNumber();
  for (int64_t i = 0; i < contain_pubkey_num; ++i) {
    if (!itr.hasNext()) {
      warn(
          CFD_LOG_SOURCE,
          "Not found enough pubkeys in redeem script.: "
          "require_pubkey_num={}, script={}",
          contain_pubkey_num, multisig_script.ToString());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Not found enough pubkeys in redeem script.");
    }

    const ScriptElement& pubkey_element = itr.next();
    // check script element type
    if (!pubkey_element.IsBinary()) {
      warn(
          CFD_LOG_SOURCE,
          "Invalid script element. Not binary element.: "
          "ScriptElementType={}, data={}",
          pubkey_element.GetType(), pubkey_element.ToString());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Invalid ScriptElementType.(not binary)");
    }

    // push pubkey data
    pubkeys.push_back(Pubkey(pubkey_element.GetBinaryData()));
  }

  // check opcode(require signature num)
  ScriptElement require_num_element(ScriptType::kOpInvalidOpCode);
  if (itr.hasNext()) {
    require_num_element = itr.next();
  }
  if (!(require_num_element.IsNumber() && require_num_element.IsOpCode()) ||
      (require_num_element.GetNumber() <= 0)) {
    warn(
        CFD_LOG_SOURCE,
        "Invalid OP_CHECKMULTISIG(VERIFY) input in redeem script."
        " Missing require signature number.: script={}",
        multisig_script.ToString());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Invalid OP_CHCKMULTISIG(OP_CHECKMULTISIGVERIFY) input"
        " in redeem script. Missing require signature number.");
  }

  if (require_num) {
    *require_num = static_cast<uint32_t>(require_num_element.GetNumber());
  }
  // return reverse pubkey vector
  std::reverse(std::begin(pubkeys), std::end(pubkeys));
  return pubkeys;
}

}  // namespace core
}  // namespace cfd
