// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_script.h
 *
 * @brief The script related class definition.
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCRIPT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCRIPT_H_

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"

namespace cfd {
namespace core {

/// Script size on P2PKH.
constexpr size_t kScriptHashP2pkhLength = 25;
/// Script size on P2SH.
constexpr size_t kScriptHashP2shLength = 23;
/// Script size on P2WPKH.
constexpr size_t kScriptHashP2wpkhLength = 22;
/// Script size on P2WSH.
constexpr size_t kScriptHashP2wshLength = 34;
/// Script size on Taproot.
constexpr size_t kScriptHashTaprootLength = 34;
/// WitnessProgram's minimum size.
constexpr size_t kMinWitnessProgramLength = 4;
/// WitnessProgram's maximum size.
constexpr size_t kMaxWitnessProgramLength = 42;

/**
 * @typedef WitnessVersion
 * @brief Witness version
 */
enum WitnessVersion {
  kVersionNone = -1,  //!< Missing WitnessVersion
  kVersion0 = 0,      //!< version 0
  kVersion1,          //!< version 1 (for future use)
  kVersion2,          //!< version 2 (for future use)
  kVersion3,          //!< version 3 (for future use)
  kVersion4,          //!< version 4 (for future use)
  kVersion5,          //!< version 5 (for future use)
  kVersion6,          //!< version 6 (for future use)
  kVersion7,          //!< version 7 (for future use)
  kVersion8,          //!< version 8 (for future use)
  kVersion9,          //!< version 9 (for future use)
  kVersion10,         //!< version 10 (for future use)
  kVersion11,         //!< version 11 (for future use)
  kVersion12,         //!< version 12 (for future use)
  kVersion13,         //!< version 13 (for future use)
  kVersion14,         //!< version 14 (for future use)
  kVersion15,         //!< version 15 (for future use)
  kVersion16          //!< version 16 (for future use)
};

/**
 * @brief script element type
 */
enum ScriptElementType {
  kElementOpCode,  //!< OP_CODE
  kElementBinary,  //!< Binary data
  kElementNumber   //!< number
};

// clang-format off
// @formatter:off
/**
 * @brief script type.
 */
enum ScriptType {
  kOp_0 = 0,                      //!< kOp_0
  kOpFalse = 0,                   //!< kOpFalse
  kOpPushData1 = 0x4c,            //!< kOpPushData1
  kOpPushData2 = 0x4d,            //!< kOpPushData2
  kOpPushData4 = 0x4e,            //!< kOpPushData4
  kOp1Negate = 0x4f,              //!< kOp1Negate
  kOpReserved = 0x50,             //!< kOpReserved
  kOpSuccess80 = 0x50,            //!< kOpSuccess80 (BIP-342)
  kOp_1 = 0x51,                   //!< kOp_1
  kOpTrue = 0x51,                 //!< kOpTrue
  kOp_2 = 0x52,                   //!< kOp_2
  kOp_3 = 0x53,                   //!< kOp_3
  kOp_4 = 0x54,                   //!< kOp_4
  kOp_5 = 0x55,                   //!< kOp_5
  kOp_6 = 0x56,                   //!< kOp_6
  kOp_7 = 0x57,                   //!< kOp_7
  kOp_8 = 0x58,                   //!< kOp_8
  kOp_9 = 0x59,                   //!< kOp_9
  kOp_10 = 0x5a,                  //!< kOp_10
  kOp_11 = 0x5b,                  //!< kOp_11
  kOp_12 = 0x5c,                  //!< kOp_12
  kOp_13 = 0x5d,                  //!< kOp_13
  kOp_14 = 0x5e,                  //!< kOp_14
  kOp_15 = 0x5f,                  //!< kOp_15
  kOp_16 = 0x60,                  //!< kOp_16
  kOpNop = 0x61,                  //!< kOpNop
  kOpVer = 0x62,                  //!< kOpVer
  kOpSuccess98 = 0x62,            //!< kOpSuccess98 (BIP-342)
  kOpIf = 0x63,                   //!< kOpIf
  kOpNotIf = 0x64,                //!< kOpNotIf
  kOpVerIf = 0x65,                //!< kOpVerIf
  kOpVerNotIf = 0x66,             //!< kOpVerNotIf
  kOpElse = 0x67,                 //!< kOpElse
  kOpEndIf = 0x68,                //!< kOpEndIf
  kOpVerify = 0x69,               //!< kOpVerify
  kOpReturn = 0x6a,               //!< kOpReturn
  kOpToAltStack = 0x6b,           //!< kOpToAltStack
  kOpFromAltStack = 0x6c,         //!< kOpFromAltStack
  kOp2Drop = 0x6d,                //!< kOp2Drop
  kOp2Dup = 0x6e,                 //!< kOp2Dup
  kOp3Dup = 0x6f,                 //!< kOp3Dup
  kOp2Over = 0x70,                //!< kOp2Over
  kOp2Rot = 0x71,                 //!< kOp2Rot
  kOp2Swap = 0x72,                //!< kOp2Swap
  kOpIfDup = 0x73,                //!< kOpIfDup
  kOpDepth = 0x74,                //!< kOpDepth
  kOpDrop = 0x75,                 //!< kOpDrop
  kOpDup = 0x76,                  //!< kOpDup
  kOpNip = 0x77,                  //!< kOpNip
  kOpOver = 0x78,                 //!< kOpOver
  kOpPick = 0x79,                 //!< kOpPick
  kOpRoll = 0x7a,                 //!< kOpRoll
  kOpRot = 0x7b,                  //!< kOpRot
  kOpSwap = 0x7c,                 //!< kOpSwap
  kOpTuck = 0x7d,                 //!< kOpTuck
  kOpCat = 0x7e,                  //!< kOpCat
  kOpSubstr = 0x7f,               //!< kOpSubstr
  kOpLeft = 0x80,                 //!< kOpLeft
  kOpRight = 0x81,                //!< kOpRight
  kOpSuccess126 = 0x7e,           //!< kOpSuccess126 (BIP-342)
  kOpSuccess127 = 0x7f,           //!< kOpSuccess127 (BIP-342)
  kOpSuccess128 = 0x80,           //!< kOpSuccess128 (BIP-342)
  kOpSuccess129 = 0x81,           //!< kOpSuccess129 (BIP-342)
  kOpSize = 0x82,                 //!< kOpSize
  kOpInvert = 0x83,               //!< kOpInvert
  kOpAnd = 0x84,                  //!< kOpAnd
  kOpOr = 0x85,                   //!< kOpOr
  kOpXor = 0x86,                  //!< kOpXor
  kOpSuccess131 = 0x83,           //!< kOpSuccess131 (BIP-342)
  kOpSuccess132 = 0x84,           //!< kOpSuccess132 (BIP-342)
  kOpSuccess133 = 0x85,           //!< kOpSuccess133 (BIP-342)
  kOpSuccess134 = 0x86,           //!< kOpSuccess134 (BIP-342)
  kOpEqual = 0x87,                //!< kOpEqual
  kOpEqualVerify = 0x88,          //!< kOpEqualVerify
  kOpReserved1 = 0x89,            //!< kOpReserved1
  kOpReserved2 = 0x8a,            //!< kOpReserved2
  kOpSuccess137 = 0x89,           //!< kOpSuccess137 (BIP-342)
  kOpSuccess138 = 0x8a,           //!< kOpSuccess138 (BIP-342)
  kOp1Add = 0x8b,                 //!< kOp1Add
  kOp1Sub = 0x8c,                 //!< kOp1Sub
  kOp2Mul = 0x8d,                 //!< kOp2Mul
  kOp2Div = 0x8e,                 //!< kOp2Div
  kOpSuccess141 = 0x8d,           //!< kOpSuccess141 (BIP-342)
  kOpSuccess142 = 0x8e,           //!< kOpSuccess142 (BIP-342)
  kOpNegate = 0x8f,               //!< kOpNegate
  kOpAbs = 0x90,                  //!< kOpAbs
  kOpNot = 0x91,                  //!< kOpNot
  kOp0NotEqual = 0x92,            //!< kOp0NotEqual
  kOpAdd = 0x93,                  //!< kOpAdd
  kOpSub = 0x94,                  //!< kOpSub
  kOpMul = 0x95,                  //!< kOpMul
  kOpDiv = 0x96,                  //!< kOpDiv
  kOpMod = 0x97,                  //!< kOpMod
  kOpLShift = 0x98,               //!< kOpLShift
  kOpRShift = 0x99,               //!< kOpRShift
  kOpSuccess149 = 0x95,           //!< kOpSuccess149 (BIP-342)
  kOpSuccess150 = 0x96,           //!< kOpSuccess150 (BIP-342)
  kOpSuccess151 = 0x97,           //!< kOpSuccess151 (BIP-342)
  kOpSuccess152 = 0x98,           //!< kOpSuccess152 (BIP-342)
  kOpSuccess153 = 0x99,           //!< kOpSuccess153 (BIP-342)
  kOpBoolAnd = 0x9a,              //!< kOpBoolAnd
  kOpBoolOr = 0x9b,               //!< kOpBoolOr
  kOpNumEqual = 0x9c,             //!< kOpNumEqual
  kOpNumEqualVerify = 0x9d,       //!< kOpNumEqualVerify
  kOpNumNotEqual = 0x9e,          //!< kOpNumNotEqual
  kOpLessThan = 0x9f,             //!< kOpLessThan
  kOpGreaterThan = 0xa0,          //!< kOpGreaterThan
  kOpLessThanOrEqual = 0xa1,      //!< kOpLessThanOrEqual
  kOpGreaterThanOrEqual = 0xa2,   //!< kOpGreaterThanOrEqual
  kOpMin = 0xa3,                  //!< kOpMin
  kOpMax = 0xa4,                  //!< kOpMax
  kOpWithIn = 0xa5,               //!< kOpWithIn
  kOpRipemd = 0xa6,               //!< kOpRipemd
  kOpSha1 = 0xa7,                 //!< kOpSha1
  kOpSha256 = 0xa8,               //!< kOpSha256
  kOpHash160 = 0xa9,              //!< kOpHash160
  kOpHash256 = 0xaa,              //!< kOpHash256
  kOpCodeSeparator = 0xab,        //!< kOpCodeSeparator
  kOpCheckSig = 0xac,             //!< kOpCheckSig
  kOpCheckSigVerify = 0xad,       //!< kOpCheckSigVerify
  kOpCheckMultiSig = 0xae,        //!< kOpCheckMultiSig
  kOpCheckMultiSigVerify = 0xaf,  //!< kOpCheckMultiSigVerify
  kOpNop1 = 0xb0,                 //!< kOpNop1
  kOpCheckLockTimeVerify = 0xb1,  //!< kOpCheckLockTimeVerify
  kOpNop2 = 0xb1,                 //!< kOpNop2
  kOpCheckSequenceVerify = 0xb2,  //!< kOpCheckSequenceVerify
  kOpNop3 = 0xb2,                 //!< kOpNop3
  kOpNop4 = 0xb3,                 //!< kOpNop4
  kOpNop5 = 0xb4,                 //!< kOpNop5
  kOpNop6 = 0xb5,                 //!< kOpNop6
  kOpNop7 = 0xb6,                 //!< kOpNop7
  kOpNop8 = 0xb7,                 //!< kOpNop8
  kOpNop9 = 0xb8,                 //!< kOpNop9
  kOpNop10 = 0xb9,                //!< kOpNop10
  kOpCheckSigAdd = 0xba,          //!< kOpCheckSigAdd (BIP-342)
  kOpSuccess187 = 0xbb,           //!< kOpSuccess187 (BIP-342)
  kOpSuccess188 = 0xbc,           //!< kOpSuccess188 (BIP-342)
  kOpSuccess189 = 0xbd,           //!< kOpSuccess189 (BIP-342)
  kOpSuccess190 = 0xbe,           //!< kOpSuccess190 (BIP-342)
  kOpSuccess191 = 0xbf,           //!< kOpSuccess191 (BIP-342)
  kOpSuccess192 = 0xc0,           //!< kOpSuccess192 (BIP-342)
  kOpSuccess193 = 0xc1,           //!< kOpSuccess193 (BIP-342)
  kOpSuccess194 = 0xc2,           //!< kOpSuccess194 (BIP-342)
  kOpSuccess195 = 0xc3,           //!< kOpSuccess195 (BIP-342)
  kOpSuccess196 = 0xc4,           //!< kOpSuccess196 (BIP-342)
  kOpSuccess197 = 0xc5,           //!< kOpSuccess197 (BIP-342)
  kOpSuccess198 = 0xc6,           //!< kOpSuccess198 (BIP-342)
  kOpSuccess199 = 0xc7,           //!< kOpSuccess199 (BIP-342)
  kOpSuccess200 = 0xc8,           //!< kOpSuccess200 (BIP-342)
  kOpSuccess201 = 0xc9,           //!< kOpSuccess201 (BIP-342)
  kOpSuccess202 = 0xca,           //!< kOpSuccess202 (BIP-342)
  kOpSuccess203 = 0xcb,           //!< kOpSuccess203 (BIP-342)
  kOpSuccess204 = 0xcc,           //!< kOpSuccess204 (BIP-342)
  kOpSuccess205 = 0xcd,           //!< kOpSuccess205 (BIP-342)
  kOpSuccess206 = 0xce,           //!< kOpSuccess206 (BIP-342)
  kOpSuccess207 = 0xcf,           //!< kOpSuccess207 (BIP-342)
  kOpSuccess208 = 0xd0,           //!< kOpSuccess208 (BIP-342)
  kOpSuccess209 = 0xd1,           //!< kOpSuccess209 (BIP-342)
  kOpSuccess210 = 0xd2,           //!< kOpSuccess210 (BIP-342)
  kOpSuccess211 = 0xd3,           //!< kOpSuccess211 (BIP-342)
  kOpSuccess212 = 0xd4,           //!< kOpSuccess212 (BIP-342)
  kOpSuccess213 = 0xd5,           //!< kOpSuccess213 (BIP-342)
  kOpSuccess214 = 0xd6,           //!< kOpSuccess214 (BIP-342)
  kOpSuccess215 = 0xd7,           //!< kOpSuccess215 (BIP-342)
  kOpSuccess216 = 0xd8,           //!< kOpSuccess216 (BIP-342)
  kOpSuccess217 = 0xd9,           //!< kOpSuccess217 (BIP-342)
  kOpSuccess218 = 0xda,           //!< kOpSuccess218 (BIP-342)
  kOpSuccess219 = 0xdb,           //!< kOpSuccess219 (BIP-342)
  kOpSuccess220 = 0xdc,           //!< kOpSuccess220 (BIP-342)
  kOpSuccess221 = 0xdd,           //!< kOpSuccess221 (BIP-342)
  kOpSuccess222 = 0xde,           //!< kOpSuccess222 (BIP-342)
  kOpSuccess223 = 0xdf,           //!< kOpSuccess223 (BIP-342)
  kOpSuccess224 = 0xe0,           //!< kOpSuccess224 (BIP-342)
  kOpSuccess225 = 0xe1,           //!< kOpSuccess225 (BIP-342)
  kOpSuccess226 = 0xe2,           //!< kOpSuccess226 (BIP-342)
  kOpSuccess227 = 0xe3,           //!< kOpSuccess227 (BIP-342)
  kOpSuccess228 = 0xe4,           //!< kOpSuccess228 (BIP-342)
  kOpSuccess229 = 0xe5,           //!< kOpSuccess229 (BIP-342)
  kOpSuccess230 = 0xe6,           //!< kOpSuccess230 (BIP-342)
  kOpSuccess231 = 0xe7,           //!< kOpSuccess231 (BIP-342)
  kOpSuccess232 = 0xe8,           //!< kOpSuccess232 (BIP-342)
  kOpSuccess233 = 0xe9,           //!< kOpSuccess233 (BIP-342)
  kOpSuccess234 = 0xea,           //!< kOpSuccess234 (BIP-342)
  kOpSuccess235 = 0xeb,           //!< kOpSuccess235 (BIP-342)
  kOpSuccess236 = 0xec,           //!< kOpSuccess236 (BIP-342)
  kOpSuccess237 = 0xed,           //!< kOpSuccess237 (BIP-342)
  kOpSuccess238 = 0xee,           //!< kOpSuccess238 (BIP-342)
  kOpSuccess239 = 0xef,           //!< kOpSuccess239 (BIP-342)
  kOpSuccess240 = 0xf0,           //!< kOpSuccess240 (BIP-342)
  kOpSuccess241 = 0xf1,           //!< kOpSuccess241 (BIP-342)
  kOpSuccess242 = 0xf2,           //!< kOpSuccess242 (BIP-342)
  kOpSuccess243 = 0xf3,           //!< kOpSuccess243 (BIP-342)
  kOpSuccess244 = 0xf4,           //!< kOpSuccess244 (BIP-342)
  kOpSuccess245 = 0xf5,           //!< kOpSuccess245 (BIP-342)
  kOpSuccess246 = 0xf6,           //!< kOpSuccess246 (BIP-342)
  kOpSuccess247 = 0xf7,           //!< kOpSuccess247 (BIP-342)
  kOpSuccess248 = 0xf8,           //!< kOpSuccess248 (BIP-342)
  kOpSuccess249 = 0xf9,           //!< kOpSuccess249 (BIP-342)
  kOpSuccess250 = 0xfa,           //!< kOpSuccess250 (BIP-342)
  kOpSuccess251 = 0xfb,           //!< kOpSuccess251 (BIP-342)
  kOpSuccess252 = 0xfc,           //!< kOpSuccess252 (BIP-342)
  kOpSuccess253 = 0xfd,           //!< kOpSuccess253 (BIP-342)
  kOpSuccess254 = 0xfe,           //!< kOpSuccess254 (BIP-342)
  kOpInvalidOpCode = 0xff,        //!< kOpInvalidOpCode
#ifndef CFD_DISABLE_ELEMENTS
  kOpDeterministricRandom = 0xc0,     //!< kOpDeterministricRandom
  kOpCheckSigFromStack = 0xc1,        //!< kOpCheckSigFromStack
  kOpCheckSigFromStackVerify = 0xc2,  //!< kOpCheckSigFromStackVerify
  kOpSmallInteger = 0xfa,             //!< kOpSmallInteger
  kOpPubkeys = 0xfb,                  //!< kOpPubkeys
  kOpPubkeyHash = 0xfd,               //!< kOpPubkeyHash
  kOpPubkey = 0xfe,                   //!< kOpPubkey
#endif  // CFD_DISABLE_ELEMENTS
};
// @formatter:on
// clang-format on

class Script;

/**
 * @brief Script Operation definition class.
 * @details
 * Regarding the definition value of OP_XXXX, please note the following when using it.
 * - When statically linking, do not use it as the initial value of global variables.
 *   - Due to the initialization order, it may be set in the uninitialized state.
 *   - When using it as the initial value of a global variable, \
 *     use ScriptType instead of ScriptOperator.
 */
class CFD_CORE_EXPORT ScriptOperator {
 public:
  // clang-format off
  // @formatter:off
  static const ScriptOperator OP_0;                //!< OP_0
  static const ScriptOperator OP_FALSE;            //!< OP_FALSE
  static const ScriptOperator OP_PUSHDATA1;        //!< OP_PUSHDATA1
  static const ScriptOperator OP_PUSHDATA2;        //!< OP_PUSHDATA2
  static const ScriptOperator OP_PUSHDATA4;        //!< OP_PUSHDATA4
  static const ScriptOperator OP_1NEGATE;          //!< OP_1NEGATE
  static const ScriptOperator OP_RESERVED;         //!< OP_RESERVED
  static const ScriptOperator OP_1;                //!< OP_1
  static const ScriptOperator OP_TRUE;             //!< OP_TRUE
  static const ScriptOperator OP_2;                //!< OP_2
  static const ScriptOperator OP_3;                //!< OP_3
  static const ScriptOperator OP_4;                //!< OP_4
  static const ScriptOperator OP_5;                //!< OP_5
  static const ScriptOperator OP_6;                //!< OP_6
  static const ScriptOperator OP_7;                //!< OP_7
  static const ScriptOperator OP_8;                //!< OP_8
  static const ScriptOperator OP_9;                //!< OP_9
  static const ScriptOperator OP_10;               //!< OP_10
  static const ScriptOperator OP_11;               //!< OP_11
  static const ScriptOperator OP_12;               //!< OP_12
  static const ScriptOperator OP_13;               //!< OP_13
  static const ScriptOperator OP_14;               //!< OP_14
  static const ScriptOperator OP_15;               //!< OP_15
  static const ScriptOperator OP_16;               //!< OP_16
  static const ScriptOperator OP_NOP;              //!< OP_NOP
  static const ScriptOperator OP_VER;              //!< OP_VER
  static const ScriptOperator OP_IF;               //!< OP_IF
  static const ScriptOperator OP_NOTIF;            //!< OP_NOTIF
  static const ScriptOperator OP_VERIF;            //!< OP_VERIF
  static const ScriptOperator OP_VERNOTIF;         //!< OP_VERNOTIF
  static const ScriptOperator OP_ELSE;             //!< OP_ELSE
  static const ScriptOperator OP_ENDIF;            //!< OP_ENDIF
  static const ScriptOperator OP_VERIFY;           //!< OP_VERIFY
  static const ScriptOperator OP_RETURN;           //!< OP_RETURN
  static const ScriptOperator OP_TOALTSTACK;       //!< OP_TOALTSTACK
  static const ScriptOperator OP_FROMALTSTACK;     //!< OP_FROMALTSTACK
  static const ScriptOperator OP_2DROP;            //!< OP_2DROP
  static const ScriptOperator OP_2DUP;             //!< OP_2DUP
  static const ScriptOperator OP_3DUP;             //!< OP_3DUP
  static const ScriptOperator OP_2OVER;            //!< OP_2OVER
  static const ScriptOperator OP_2ROT;             //!< OP_2ROT
  static const ScriptOperator OP_2SWAP;            //!< OP_2SWAP
  static const ScriptOperator OP_IFDUP;            //!< OP_IFDUP
  static const ScriptOperator OP_DEPTH;            //!< OP_DEPTH
  static const ScriptOperator OP_DROP;             //!< OP_DROP
  static const ScriptOperator OP_DUP;              //!< OP_DUP
  static const ScriptOperator OP_NIP;              //!< OP_NIP
  static const ScriptOperator OP_OVER;             //!< OP_OVER
  static const ScriptOperator OP_PICK;             //!< OP_PICK
  static const ScriptOperator OP_ROLL;             //!< OP_ROLL
  static const ScriptOperator OP_ROT;              //!< OP_ROT
  static const ScriptOperator OP_SWAP;             //!< OP_SWAP
  static const ScriptOperator OP_TUCK;             //!< OP_TUCK
  static const ScriptOperator OP_CAT;              //!< OP_CAT
  static const ScriptOperator OP_SUBSTR;           //!< OP_SUBSTR
  static const ScriptOperator OP_LEFT;             //!< OP_LEFT
  static const ScriptOperator OP_RIGHT;            //!< OP_RIGHT
  static const ScriptOperator OP_SIZE;             //!< OP_SIZE
  static const ScriptOperator OP_INVERT;           //!< OP_INVERT
  static const ScriptOperator OP_AND;              //!< OP_AND
  static const ScriptOperator OP_OR;               //!< OP_OR
  static const ScriptOperator OP_XOR;              //!< OP_XOR
  static const ScriptOperator OP_EQUAL;            //!< OP_EQUAL
  static const ScriptOperator OP_EQUALVERIFY;      //!< OP_EQUALVERIFY
  static const ScriptOperator OP_RESERVED1;        //!< OP_RESERVED1
  static const ScriptOperator OP_RESERVED2;        //!< OP_RESERVED2
  static const ScriptOperator OP_1ADD;             //!< OP_1ADD
  static const ScriptOperator OP_1SUB;             //!< OP_1SUB
  static const ScriptOperator OP_2MUL;             //!< OP_2MUL
  static const ScriptOperator OP_2DIV;             //!< OP_2DIV
  static const ScriptOperator OP_NEGATE;           //!< OP_NEGATE
  static const ScriptOperator OP_ABS;              //!< OP_ABS
  static const ScriptOperator OP_NOT;              //!< OP_NOT
  static const ScriptOperator OP_0NOTEQUAL;        //!< OP_0NOTEQUAL
  static const ScriptOperator OP_ADD;              //!< OP_ADD
  static const ScriptOperator OP_SUB;              //!< OP_SUB
  static const ScriptOperator OP_MUL;              //!< OP_MUL
  static const ScriptOperator OP_DIV;              //!< OP_DIV
  static const ScriptOperator OP_MOD;              //!< OP_MOD
  static const ScriptOperator OP_LSHIFT;           //!< OP_LSHIFT
  static const ScriptOperator OP_RSHIFT;           //!< OP_RSHIFT
  static const ScriptOperator OP_BOOLAND;          //!< OP_BOOLAND
  static const ScriptOperator OP_BOOLOR;           //!< OP_BOOLOR
  static const ScriptOperator OP_NUMEQUAL;         //!< OP_NUMEQUAL
  static const ScriptOperator OP_NUMEQUALVERIFY;   //!< OP_NUMEQUALVERIFY
  static const ScriptOperator OP_NUMNOTEQUAL;      //!< OP_NUMNOTEQUAL
  static const ScriptOperator OP_LESSTHAN;         //!< OP_LESSTHAN
  static const ScriptOperator OP_GREATERTHAN;      //!< OP_GREATERTHAN
  static const ScriptOperator OP_LESSTHANOREQUAL;  //!< OP_LESSTHANOREQUAL
  static const ScriptOperator OP_GREATERTHANOREQUAL;  //!< OP_GREATERTHANOREQUAL  //NOLINT
  static const ScriptOperator OP_MIN;     //!< OP_MIN
  static const ScriptOperator OP_MAX;     //!< OP_MAX
  static const ScriptOperator OP_WITHIN;  //!< OP_WITHIN
  static const ScriptOperator OP_RIPEMD160;       //!< OP_RIPEMD160
  static const ScriptOperator OP_SHA1;            //!< OP_SHA1
  static const ScriptOperator OP_SHA256;          //!< OP_SHA256
  static const ScriptOperator OP_HASH160;         //!< OP_HASH160
  static const ScriptOperator OP_HASH256;         //!< OP_HASH256
  static const ScriptOperator OP_CODESEPARATOR;   //!< OP_CODESEPARATOR
  static const ScriptOperator OP_CHECKSIG;        //!< OP_CHECKSIG
  static const ScriptOperator OP_CHECKSIGVERIFY;  //!< OP_CHECKSIGVERIFY
  static const ScriptOperator OP_CHECKMULTISIG;   //!< OP_CHECKMULTISIG
  static const ScriptOperator OP_CHECKMULTISIGVERIFY;  //!< OP_CHECKMULTISIGVERIFY  //NOLINT
  static const ScriptOperator OP_NOP1;  //!< OP_NOP1
  static const ScriptOperator OP_CHECKLOCKTIMEVERIFY;  //!< OP_CHECKLOCKTIMEVERIFY  //NOLINT
  static const ScriptOperator OP_NOP2;  //!< OP_NOP2
  static const ScriptOperator OP_CHECKSEQUENCEVERIFY;  //!< OP_CHECKSEQUENCEVERIFY  //NOLINT
  static const ScriptOperator OP_NOP3;   //!< OP_NOP3
  static const ScriptOperator OP_NOP4;   //!< OP_NOP4
  static const ScriptOperator OP_NOP5;   //!< OP_NOP5
  static const ScriptOperator OP_NOP6;   //!< OP_NOP6
  static const ScriptOperator OP_NOP7;   //!< OP_NOP7
  static const ScriptOperator OP_NOP8;   //!< OP_NOP8
  static const ScriptOperator OP_NOP9;   //!< OP_NOP9
  static const ScriptOperator OP_NOP10;  //!< OP_NOP10
  static const ScriptOperator OP_CHECKSIGADD;    //!< OP_CHECKSIGADD
  static const ScriptOperator OP_INVALIDOPCODE;  //!< OP_INVALIDOPCODE
#ifndef CFD_DISABLE_ELEMENTS
  static const ScriptOperator
      OP_DETERMINISTICRANDOM;  //!< OP_DETERMINISTICRANDOM      // NOLINT
  static const ScriptOperator
      OP_CHECKSIGFROMSTACK;  //!< OP_CHECKSIGFROMSTACK        // NOLINT
  static const ScriptOperator
      OP_CHECKSIGFROMSTACKVERIFY;  //!< OP_CHECKSIGFROMSTACKVERIFY  // NOLINT
  static const ScriptOperator OP_SMALLINTEGER;  //!< OP_SMALLINTEGER
  static const ScriptOperator OP_PUBKEYS;       //!< OP_PUBKEYS
  static const ScriptOperator OP_PUBKEYHASH;    //!< OP_PUBKEYHASH
  static const ScriptOperator OP_PUBKEY;        //!< OP_PUBKEY
#endif  // CFD_DISABLE_ELEMENTS
  static const ScriptOperator OP_SUCCESS80;   //!< OP_SUCCESS80 (BIP-342)
  static const ScriptOperator OP_SUCCESS98;   //!< OP_SUCCESS98 (BIP-342)
  static const ScriptOperator OP_SUCCESS126;  //!< OP_SUCCESS126 (BIP-342)
  static const ScriptOperator OP_SUCCESS127;  //!< OP_SUCCESS127 (BIP-342)
  static const ScriptOperator OP_SUCCESS128;  //!< OP_SUCCESS128 (BIP-342)
  static const ScriptOperator OP_SUCCESS129;  //!< OP_SUCCESS129 (BIP-342)
  static const ScriptOperator OP_SUCCESS131;  //!< OP_SUCCESS131 (BIP-342)
  static const ScriptOperator OP_SUCCESS132;  //!< OP_SUCCESS132 (BIP-342)
  static const ScriptOperator OP_SUCCESS133;  //!< OP_SUCCESS133 (BIP-342)
  static const ScriptOperator OP_SUCCESS134;  //!< OP_SUCCESS134 (BIP-342)
  static const ScriptOperator OP_SUCCESS137;  //!< OP_SUCCESS137 (BIP-342)
  static const ScriptOperator OP_SUCCESS138;  //!< OP_SUCCESS138 (BIP-342)
  static const ScriptOperator OP_SUCCESS141;  //!< OP_SUCCESS141 (BIP-342)
  static const ScriptOperator OP_SUCCESS142;  //!< OP_SUCCESS142 (BIP-342)
  static const ScriptOperator OP_SUCCESS149;  //!< OP_SUCCESS149 (BIP-342)
  static const ScriptOperator OP_SUCCESS150;  //!< OP_SUCCESS150 (BIP-342)
  static const ScriptOperator OP_SUCCESS151;  //!< OP_SUCCESS151 (BIP-342)
  static const ScriptOperator OP_SUCCESS152;  //!< OP_SUCCESS152 (BIP-342)
  static const ScriptOperator OP_SUCCESS153;  //!< OP_SUCCESS153 (BIP-342)
  static const ScriptOperator OP_SUCCESS187;  //!< OP_SUCCESS187 (BIP-342)
  static const ScriptOperator OP_SUCCESS188;  //!< OP_SUCCESS188 (BIP-342)
  static const ScriptOperator OP_SUCCESS189;  //!< OP_SUCCESS189 (BIP-342)
  static const ScriptOperator OP_SUCCESS190;  //!< OP_SUCCESS190 (BIP-342)
  static const ScriptOperator OP_SUCCESS191;  //!< OP_SUCCESS191 (BIP-342)
  static const ScriptOperator OP_SUCCESS192;  //!< OP_SUCCESS192 (BIP-342)
  static const ScriptOperator OP_SUCCESS193;  //!< OP_SUCCESS193 (BIP-342)
  static const ScriptOperator OP_SUCCESS194;  //!< OP_SUCCESS194 (BIP-342)
  static const ScriptOperator OP_SUCCESS195;  //!< OP_SUCCESS195 (BIP-342)
  static const ScriptOperator OP_SUCCESS196;  //!< OP_SUCCESS196 (BIP-342)
  static const ScriptOperator OP_SUCCESS197;  //!< OP_SUCCESS197 (BIP-342)
  static const ScriptOperator OP_SUCCESS198;  //!< OP_SUCCESS198 (BIP-342)
  static const ScriptOperator OP_SUCCESS199;  //!< OP_SUCCESS199 (BIP-342)
  static const ScriptOperator OP_SUCCESS200;  //!< OP_SUCCESS200 (BIP-342)
  static const ScriptOperator OP_SUCCESS201;  //!< OP_SUCCESS201 (BIP-342)
  static const ScriptOperator OP_SUCCESS202;  //!< OP_SUCCESS202 (BIP-342)
  static const ScriptOperator OP_SUCCESS203;  //!< OP_SUCCESS203 (BIP-342)
  static const ScriptOperator OP_SUCCESS204;  //!< OP_SUCCESS204 (BIP-342)
  static const ScriptOperator OP_SUCCESS205;  //!< OP_SUCCESS205 (BIP-342)
  static const ScriptOperator OP_SUCCESS206;  //!< OP_SUCCESS206 (BIP-342)
  static const ScriptOperator OP_SUCCESS207;  //!< OP_SUCCESS207 (BIP-342)
  static const ScriptOperator OP_SUCCESS208;  //!< OP_SUCCESS208 (BIP-342)
  static const ScriptOperator OP_SUCCESS209;  //!< OP_SUCCESS209 (BIP-342)
  static const ScriptOperator OP_SUCCESS210;  //!< OP_SUCCESS210 (BIP-342)
  static const ScriptOperator OP_SUCCESS211;  //!< OP_SUCCESS211 (BIP-342)
  static const ScriptOperator OP_SUCCESS212;  //!< OP_SUCCESS212 (BIP-342)
  static const ScriptOperator OP_SUCCESS213;  //!< OP_SUCCESS213 (BIP-342)
  static const ScriptOperator OP_SUCCESS214;  //!< OP_SUCCESS214 (BIP-342)
  static const ScriptOperator OP_SUCCESS215;  //!< OP_SUCCESS215 (BIP-342)
  static const ScriptOperator OP_SUCCESS216;  //!< OP_SUCCESS216 (BIP-342)
  static const ScriptOperator OP_SUCCESS217;  //!< OP_SUCCESS217 (BIP-342)
  static const ScriptOperator OP_SUCCESS218;  //!< OP_SUCCESS218 (BIP-342)
  static const ScriptOperator OP_SUCCESS219;  //!< OP_SUCCESS219 (BIP-342)
  static const ScriptOperator OP_SUCCESS220;  //!< OP_SUCCESS220 (BIP-342)
  static const ScriptOperator OP_SUCCESS221;  //!< OP_SUCCESS221 (BIP-342)
  static const ScriptOperator OP_SUCCESS222;  //!< OP_SUCCESS222 (BIP-342)
  static const ScriptOperator OP_SUCCESS223;  //!< OP_SUCCESS223 (BIP-342)
  static const ScriptOperator OP_SUCCESS224;  //!< OP_SUCCESS224 (BIP-342)
  static const ScriptOperator OP_SUCCESS225;  //!< OP_SUCCESS225 (BIP-342)
  static const ScriptOperator OP_SUCCESS226;  //!< OP_SUCCESS226 (BIP-342)
  static const ScriptOperator OP_SUCCESS227;  //!< OP_SUCCESS227 (BIP-342)
  static const ScriptOperator OP_SUCCESS228;  //!< OP_SUCCESS228 (BIP-342)
  static const ScriptOperator OP_SUCCESS229;  //!< OP_SUCCESS229 (BIP-342)
  static const ScriptOperator OP_SUCCESS230;  //!< OP_SUCCESS230 (BIP-342)
  static const ScriptOperator OP_SUCCESS231;  //!< OP_SUCCESS231 (BIP-342)
  static const ScriptOperator OP_SUCCESS232;  //!< OP_SUCCESS232 (BIP-342)
  static const ScriptOperator OP_SUCCESS233;  //!< OP_SUCCESS233 (BIP-342)
  static const ScriptOperator OP_SUCCESS234;  //!< OP_SUCCESS234 (BIP-342)
  static const ScriptOperator OP_SUCCESS235;  //!< OP_SUCCESS235 (BIP-342)
  static const ScriptOperator OP_SUCCESS236;  //!< OP_SUCCESS236 (BIP-342)
  static const ScriptOperator OP_SUCCESS237;  //!< OP_SUCCESS237 (BIP-342)
  static const ScriptOperator OP_SUCCESS238;  //!< OP_SUCCESS238 (BIP-342)
  static const ScriptOperator OP_SUCCESS239;  //!< OP_SUCCESS239 (BIP-342)
  static const ScriptOperator OP_SUCCESS240;  //!< OP_SUCCESS240 (BIP-342)
  static const ScriptOperator OP_SUCCESS241;  //!< OP_SUCCESS241 (BIP-342)
  static const ScriptOperator OP_SUCCESS242;  //!< OP_SUCCESS242 (BIP-342)
  static const ScriptOperator OP_SUCCESS243;  //!< OP_SUCCESS243 (BIP-342)
  static const ScriptOperator OP_SUCCESS244;  //!< OP_SUCCESS244 (BIP-342)
  static const ScriptOperator OP_SUCCESS245;  //!< OP_SUCCESS245 (BIP-342)
  static const ScriptOperator OP_SUCCESS246;  //!< OP_SUCCESS246 (BIP-342)
  static const ScriptOperator OP_SUCCESS247;  //!< OP_SUCCESS247 (BIP-342)
  static const ScriptOperator OP_SUCCESS248;  //!< OP_SUCCESS248 (BIP-342)
  static const ScriptOperator OP_SUCCESS249;  //!< OP_SUCCESS249 (BIP-342)
  static const ScriptOperator OP_SUCCESS250;  //!< OP_SUCCESS250 (BIP-342)
  static const ScriptOperator OP_SUCCESS251;  //!< OP_SUCCESS251 (BIP-342)
  static const ScriptOperator OP_SUCCESS252;  //!< OP_SUCCESS252 (BIP-342)
  static const ScriptOperator OP_SUCCESS253;  //!< OP_SUCCESS253 (BIP-342)
  static const ScriptOperator OP_SUCCESS254;  //!< OP_SUCCESS254 (BIP-342)
// @formatter:on
  // clang-format on

  /**
   * @brief check valid.
   * @param[in] message   text message
   * @retval true valid
   * @retval false invalid
   */
  static bool IsValid(const std::string &message);

  /**
   * @brief get object.
   * @param[in] message   text message
   * @return script operator.
   */
  static ScriptOperator Get(const std::string &message);

  /**
   * @brief Check if it is OP_SUCCESSxx.
   * @param[in] op_code   OP Code
   * @retval true   OP_SUCCESSxx
   * @retval false  other
   */
  static bool IsOpSuccess(ScriptType op_code);

  /**
   * @brief get data type.
   * @return script data type
   */
  ScriptType GetDataType() const { return data_type_; }

  /**
   * @brief get string text.
   * @return string text
   */
  std::string ToString() const;
  /**
   * @brief get op_code string text.
   * @return string text
   */
  std::string ToCodeString() const;

  /**
   * @brief Check if the script is push operator.
   * @retval true   push operator.
   * @retval false  contain other operator.
   */
  bool IsPushOperator() const;

  /**
   * @brief check equal object.
   * @param[in] object     check target,
   * @retval true   equal
   * @retval false  differ
   */
  bool Equals(const ScriptOperator &object) const;

  /**
   * @brief destructor.
   */
  virtual ~ScriptOperator() {
    // do nothing
  }

  /**
   * @brief constructor.
   * @param[in] object     object
   */
  ScriptOperator(const ScriptOperator &object);

  // operator overloading
  /**
   * @brief copy constructor.
   * @param[in] object     object
   * @return current object
   */
  ScriptOperator &operator=(const ScriptOperator &object);

  /**
   * @brief Equals operator.
   * @param[in] object     object
   * @retval true   equals
   * @retval false  not equals
   */
  bool operator==(const ScriptOperator &object) const;
  /**
   * @brief Not Equals operator.
   * @param[in] object     object
   * @retval true   not equals
   * @retval false  equals
   */
  bool operator!=(const ScriptOperator &object) const;
  /**
   * @brief Compare operator.
   * @param[in] object     object
   * @retval true   match
   * @retval false  unmatch
   */
  bool operator<(const ScriptOperator &object) const;
  /**
   * @brief Compare operator.
   * @param[in] object     object
   * @retval true   match
   * @retval false  unmatch
   */
  bool operator<=(const ScriptOperator &object) const;
  /**
   * @brief Compare operator.
   * @param[in] object     object
   * @retval true   match
   * @retval false  unmatch
   */
  bool operator>(const ScriptOperator &object) const;
  /**
   * @brief Compare operator.
   * @param[in] object     object
   * @retval true   match
   * @retval false  unmatch
   */
  bool operator>=(const ScriptOperator &object) const;

  /**
   * @brief default constructor.
   */
  ScriptOperator()
      : data_type_(kOpInvalidOpCode), text_data_("OP_INVALIDOPCODE") {
    // do nothing
  }

  /**
   * @brief constructor.
   * @param[in] data_type     script data type
   */
  explicit ScriptOperator(ScriptType data_type);

 private:
  ScriptType data_type_;   ///< script operation type
  std::string text_data_;  ///< script operation code text

  /**
   * @brief constructor.
   * @param[in] data_type     script data type
   * @param[in] text          script operation code text
   */
  explicit ScriptOperator(ScriptType data_type, const std::string &text);
};

/**
 * @brief Script element class.
 */
class CFD_CORE_EXPORT ScriptElement {
 public:
  /**
   * @brief constructor.
   * @param[in] element     object
   */
  ScriptElement(const ScriptElement &element);
  /**
   * @brief constructor.
   * @param[in] type     OP_CODE
   */
  explicit ScriptElement(const ScriptType &type);
  /**
   * @brief constructor.
   * @param[in] op_code     OP_CODE
   */
  explicit ScriptElement(const ScriptOperator &op_code);
  /**
   * @brief constructor.
   * @param[in] binary_data   binary data
   */
  explicit ScriptElement(const ByteData &binary_data);
  /**
   * @brief constructor.
   * @param[in] value       script number.
   */
  explicit ScriptElement(int64_t value);
  /**
   * @brief constructor.
   * @param[in] value       script number.
   * @param[in] is_binary   binary mode.
   */
  explicit ScriptElement(int64_t value, bool is_binary);
  /**
   * @brief destructor.
   */
  virtual ~ScriptElement() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] element     object
   * @return object
   */
  ScriptElement &operator=(const ScriptElement &element);

  /**
   * @brief Get the element type.
   * @return element type.
   */
  ScriptElementType GetType() const;
  /**
   * @brief Get the OP_CODE.
   * @return OP_CODE
   */
  const ScriptOperator &GetOpCode() const;
  /**
   * @brief Get a binary data.
   * @return binary data.
   */
  ByteData GetBinaryData() const;
  /**
   * @brief Get a numeric value.
   * @return numeric value.
   */
  int64_t GetNumber() const;

  /**
   * @brief Get a byte array.
   * @return byte array.
   */
  ByteData GetData() const;
  /**
   * @brief Get a stirng data.
   * @return string data.
   */
  std::string ToString() const;

  /**
   * @brief Determine if it is OP_CODE type information.
   * @retval true   OP_CODE
   * @retval false  other
   */
  bool IsOpCode() const { return type_ == kElementOpCode; }

  /**
   * @brief Determine if it is numeric type information.
   * @retval true   Numeric type
   * @retval false  other type
   */
  bool IsNumber() const {
    // If either the numeric type is specified, the number is included,
    // or OP_0 is specified, it is regarded as a number.
    return (type_ == kElementNumber) || (value_ != 0) ||
           (op_code_.GetDataType() == kOp_0);
  }

  /**
   * @brief Determine if it is binary information.
   * @retval true   Binary information
   * @retval false  other
   */
  bool IsBinary() const { return type_ == kElementBinary; }

  /**
   * @brief Convert from a binary value to a numeric type.
   * @param[out] int64_value    numeric
   * @retval true   conversion OK
   * @retval false  conversion fail.
   */
  bool ConvertBinaryToNumber(int64_t *int64_value = nullptr) const;

  /**
   * @brief default constructor.
   */
  ScriptElement()
      : type_(kElementOpCode), op_code_(), binary_data_(), value_(0) {
    // do nothing
  }

 private:
  ScriptElementType type_;  ///< element type
  ScriptOperator op_code_;  ///< OP_CODE
  ByteData binary_data_;    ///< binary data
  int64_t value_;           ///< numeric value

  /**
   * @brief Convert the numerical value to be added to Script to byte data.
   * @param[in] value   Numerical value to add to script
   * @return Byte data with serialized number
   */
  static std::vector<uint8_t> SerializeScriptNum(int64_t value);
};

/**
 * @brief script hash data class.
 */
class CFD_CORE_EXPORT ScriptHash {
 public:
  /**
   * @brief constructor.
   * @param[in] script_hash   script hash.
   */
  explicit ScriptHash(const std::string &script_hash);
  /**
   * @brief constructor.
   * @param[in] script      script data.
   * @param[in] is_witness  witness data flag.
   */
  explicit ScriptHash(const Script &script, bool is_witness);
  /**
   * @brief destructor.
   */
  virtual ~ScriptHash() {
    // do nothing
  }
  /**
   * @brief get hex data.
   * @return hex string.
   */
  const std::string GetHex() const;
  /**
   * @brief get byte data.
   * @return byte data.
   */
  const ByteData GetData() const;

 private:
  ByteData script_hash_;  ///< script hash
};

/**
 * @brief script data.
 */
class CFD_CORE_EXPORT Script {
 public:
  //! empty script
  static const Script Empty;
  //! maximum size of script
  static constexpr uint32_t kMaxScriptSize = 10000;
  //! maximum size of RedeemScript
  static constexpr uint32_t kMaxRedeemScriptSize = 520;
  //! maximum size of multisig
  static constexpr uint32_t kMaxMultisigPubkeyNum = 20;

  /**
   * @brief constructor.
   */
  Script();
  /**
   * @brief constructor.
   * @param[in] hex     hex string.
   */
  explicit Script(const std::string &hex);
  /**
   * @brief constructor.
   * @param[in] bytedata  byte data.
   */
  explicit Script(const ByteData &bytedata);
  /**
   * @brief destructor.
   */
  virtual ~Script() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  Script(const Script &object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  Script &operator=(const Script &object) &;
  /**
   * @brief get script.
   * @return script
   */
  Script GetScript() const;
  /**
   * @brief get script hash.
   * @return script hash
   */
  ScriptHash GetScriptHash() const;
  /**
   * @brief get witness script hash.
   * @return witness script hash
   */
  ScriptHash GetWitnessScriptHash() const;
  /**
   * @brief get script byte data.
   * @return script byte data.
   */
  const ByteData GetData() const;
  /**
   * @brief get script hex string.
   * @return script hex string.
   */
  const std::string GetHex() const;
  /**
   * @brief empty check.
   * @retval true   empty.
   * @retval false  data exist.
   */
  bool IsEmpty() const;
  /**
   * @brief check equal object.
   * @param[in] script     check target,
   * @retval true   equal
   * @retval false  differ
   */
  bool Equals(const Script &script) const;
  /**
   * @brief get element list.
   * @return element list
   */
  std::vector<ScriptElement> GetElementList() const;
  /**
   * @brief get script text string.
   * @return script text.
   */
  std::string ToString() const;
  /**
   * @brief Check if the script is push operator only.
   * @retval true   push operator only.
   * @retval false  contain other operator.
   */
  bool IsPushOnly() const;

  /**
   * @brief Check if the script is pay to pubkey script.
   * @retval true   script is pay to pubkey.
   * @retval false  not pay to pubkey.
   */
  bool IsP2pkScript() const;

  /**
   * @brief Check if the script is pay to pubkey hash script.
   * @retval true   script is pay to pubkey hash.
   * @retval false  not pay to pubkey hash.
   */
  bool IsP2pkhScript() const;

  /**
   * @brief Check if the script is pay to script hash script.
   * @retval true   script is pay to script hash.
   * @retval false  not pay to script hash.
   */
  bool IsP2shScript() const;

  /**
   * @brief Check if the script is pay to multi-sig script.
   * @retval true   script is pay to multi-sig.
   * @retval false  not pay to multi-sig.
   */
  bool IsMultisigScript() const;

  /**
   * @brief Check if the script is pay to WitnessProgram script.
   * @retval true   script is pay to WitnessProgram.
   * @retval false  not pay to WitnessProgram.
   */
  bool IsWitnessProgram() const;

  /**
   * @brief Check if the script is pay to witness pubkey hash script.
   * @retval true   script is pay to witness pubkey hash.
   * @retval false  not pay to witness pubkey hash.
   */
  bool IsP2wpkhScript() const;

  /**
   * @brief Check if the script is pay to witness script hash script.
   * @retval true   script is pay to witness script hash.
   * @retval false  not pay to witness script hash.
   */
  bool IsP2wshScript() const;

  /**
   * @brief Check if the script is taproot script.
   * @retval true   script is taproot.
   * @retval false  not taproot.
   */
  bool IsTaprootScript() const;

  /**
   * @brief Check if the script is pegout script.
   * @retval true   script is pegout script.
   * @retval false  not pegout script.
   */
  bool IsPegoutScript() const;

  /**
   * @brief get witness version on locking script.
   * @return witness version.
   */
  WitnessVersion GetWitnessVersion() const;

 private:
  /// script byte data
  ByteData script_data_;

  /// script stack
  std::vector<ScriptElement> script_stack_;

  /// max byte size of script number
  static constexpr size_t kMaxScriptNumSize = 4;

  /**
   * @brief set stack data.
   * @param[in] bytedata    script byte array.
   */
  void SetStackData(const ByteData &bytedata);

  /**
   * @brief Convert byte array to number.
   * @param[in] bytes original byte array.
   * @return converted number value
   * @see https://github.com/bitcoin/bitcoin/blob/c799976c86e2d65f129d106724fbefbf665d63d4/src/script/script.h#L359 // NOLINT
   */
  int64_t ConvertToNumber(const std::vector<uint8_t> bytes);
};

/**
 * @brief script builder class.
 */
class CFD_CORE_EXPORT ScriptBuilder {
 public:
  /**
   * @brief constructor.
   */
  ScriptBuilder() {
    // do nothing
  }
  /**
   * @brief destructor.
   */
  virtual ~ScriptBuilder() {
    // do nothing
  }

  /**
   * @brief append string data.
   * @param[in] message  string data.
   * @return script builder object.
   */
  ScriptBuilder &AppendString(const std::string &message);
  /**
   * @brief append script operator.
   * @param[in] type      ScriptType.
   * @return script builder object.
   */
  ScriptBuilder &AppendOperator(ScriptType type);
  /**
   * @brief append script operator.
   * @param[in] operate_object     operator object.
   * @return script builder object.
   */
  ScriptBuilder &AppendOperator(const ScriptOperator &operate_object);
  /**
   * @brief append script data.
   * @param[in] hex_str   script data.
   * @return script builder object.
   */
  ScriptBuilder &AppendData(const std::string &hex_str);
  /**
   * @brief             append script data.
   * @param[in] data    script data.
   * @return            script builder object.
   */
  ScriptBuilder &AppendData(const ByteData &data);
  /**
   * @brief             append script data.
   * @param[in] data    script data.
   * @return            script builder object.
   */
  ScriptBuilder &AppendData(const ByteData160 &data);
  /**
   * @brief             append script data.
   * @param[in] data    script data.
   * @return            script builder object.
   */
  ScriptBuilder &AppendData(const ByteData256 &data);
  /**
   * @brief               append script data.
   * @param[in] pubkey   public key.
   * @return              script builder object.
   */
  ScriptBuilder &AppendData(const Pubkey &pubkey);
  /**
   * @brief               append script data.
   * @param[in] script    script data.
   * @return              script builder object.
   */
  ScriptBuilder &AppendData(const Script &script);
  /**
   * @brief           append script data.
   * @param[in] data  script number.
   * @return          script builder object.
   */
  ScriptBuilder &AppendData(const int64_t &data);
  /**
   * @brief             append script element data.
   * @param[in] element element data.
   * @return            script builder object.
   */
  ScriptBuilder &AppendElement(const ScriptElement &element);

  // ScriptBuilder& AppendData(const ByteData& data, bool is_template);

  /**
   * @brief append string data.
   * @param[in] message  string data.
   * @return script builder object.
   */
  ScriptBuilder &operator<<(const std::string &message);
  /**
   * @brief append script operator.
   * @param[in] type      ScriptType.
   * @return script builder object.
   */
  ScriptBuilder &operator<<(ScriptType type);
  /**
   * @brief append script operator.
   * @param[in] operate_object     operator object.
   * @return script builder object.
   */
  ScriptBuilder &operator<<(const ScriptOperator &operate_object);
  /**
   * @brief             append script data.
   * @param[in] data    script data.
   * @return            script builder object.
   */
  ScriptBuilder &operator<<(const ByteData &data);
  /**
   * @brief             append script data.
   * @param[in] data    script data.
   * @return            script builder object.
   */
  ScriptBuilder &operator<<(const ByteData160 &data);
  /**
   * @brief             append script data.
   * @param[in] data    script data.
   * @return            script builder object.
   */
  ScriptBuilder &operator<<(const ByteData256 &data);
  /**
   * @brief               append script data.
   * @param[in] pubkey   public key.
   * @return              script builder object.
   */
  ScriptBuilder &operator<<(const Pubkey &pubkey);
  /**
   * @brief               append script data.
   * @param[in] script    script data.
   * @return              script builder object.
   */
  ScriptBuilder &operator<<(const Script &script);
  /**
   * @brief           append script data.
   * @param[in] data  script number.
   * @return          script builder object.
   */
  ScriptBuilder &operator<<(const int64_t &data);
  /**
   * @brief             append script element data.
   * @param[in] element element data.
   * @return            script builder object.
   */
  ScriptBuilder &operator<<(const ScriptElement &element);

  /**
   * @brief   build script.
   * @return  script
   */
  Script Build();

 private:
  std::vector<uint8_t> script_byte_array_;  ///< byte array
};

/**
 * @brief Utility class that creates Script.
 */
class CFD_CORE_EXPORT ScriptUtil {
 public:
  /**
   * @brief Create a P2PK locking script.
   * @param[in] pubkey Pubkey
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * <pubkey> OP_CHECKSIG
   * @endcode
   */
  static Script CreateP2pkLockingScript(const Pubkey &pubkey);
  /**
   * @brief Create a P2PKH locking script.
   * @param[in] pubkey_hash pubkey hash
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
   * @endcode
   */
  static Script CreateP2pkhLockingScript(const ByteData160 &pubkey_hash);
  /**
   * @brief Create a P2PKH locking script.
   * @param[in] pubkey Pubkey
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
   * @endcode
   */
  static Script CreateP2pkhLockingScript(const Pubkey &pubkey);
  /**
   * @brief Create a P2SH locking script.
   * @param[in] script_hash script hash
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_HASH160 <hash160(redeemScript)> OP_EQUAL
   * @endcode
   */
  static Script CreateP2shLockingScript(const ByteData160 &script_hash);
  /**
   * @brief Create a P2SH locking script.
   * @param[in] redeem_script redeem script
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_HASH160 <hash160(redeemScript)> OP_EQUAL
   * @endcode
   */
  static Script CreateP2shLockingScript(const Script &redeem_script);
  /**
   * @brief Create a P2WPKH locking script.
   * @param[in] pubkey_hash pubkey hash
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_0 <hash160(pubkey)>
   * @endcode
   */
  static Script CreateP2wpkhLockingScript(const ByteData160 &pubkey_hash);
  /**
   * @brief Create a P2WPKH locking script.
   * @param[in] pubkey Pubkey
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_0 <hash160(pubkey)>
   * @endcode
   */
  static Script CreateP2wpkhLockingScript(const Pubkey &pubkey);
  /**
   * @brief Create a P2WSH locking script.
   * @param[in] script_hash  script hash
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_0 <sha256(redeemScript)>
   * @endcode
   */
  static Script CreateP2wshLockingScript(const ByteData256 &script_hash);
  /**
   * @brief Create a P2WSH locking script.
   * @param[in] redeem_script redeem script
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_0 <sha256(redeemScript)>
   * @endcode
   */
  static Script CreateP2wshLockingScript(const Script &redeem_script);
  /**
   * @brief Create locking script for taproot.
   * @param[in] data  witness program
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_1 <32-byte>
   * @endcode
   */
  static Script CreateTaprootLockingScript(const ByteData256 &data);
  /**
   * @brief Check if Redeem Script is valid.
   * @param[in] redeem_script redeem script
   * @retval true   valid
   * @retval false  invalid
   */
  static bool IsValidRedeemScript(const Script &redeem_script);
  /**
   * @brief Create redeem script of the M-of-N Multisig.
   * @param[in] require_sig_num \
   *    Number of Signatures required for unlocking (equivalent to M)
   * @param[in] pubkeys   Pubkey array corresponding to the signature. \
   *    (equivalent to N)
   * @param[in] has_witness   target is witness script.
   * @return Script
   * @details Create a Script with the following content.
   * @code{.unparse}
   * OP_<requireSigNum> <pubkey> ... OP_n OP_CHECKMULTISIG
   * @endcode
   */
  static Script CreateMultisigRedeemScript(
      uint32_t require_sig_num, const std::vector<Pubkey> &pubkeys,
      bool has_witness = true);

#ifndef CFD_DISABLE_ELEMENTS
  /**
   * @brief Create a Pegout locking script.
   * @param[in] genesisblock_hash   mainchain genesis block hash
   * @param[in] parent_locking_script  \
   *    Destination bitcoin address locking script
   * @param[in] btc_pubkey_bytes  \
   *    Pubkey information created by the DerivePubTweak function
   * @param[in] whitelist_proof   Proof of whitelist
   * @return Script
   * @code{.unparse}
   * OP_RETURN <genesis block hash> <bitcoin address lockingScript> <tweaked pubkey bytes> <whitelistproof>
   * @endcode
   */
  static Script CreatePegoutLogkingScript(
      const BlockHash &genesisblock_hash, const Script &parent_locking_script,
      const Pubkey &btc_pubkey_bytes, const ByteData &whitelist_proof);
#endif  // CFD_DISABLE_ELEMENTS

  /**
   * @brief Get the set of public keys contained in a multisig script.
   * @details if the redeem script contains multiple OP_CHECKMULTISIG(VERIFY),
   * returns only the public keys required for the last one.
   * @param[in] multisig_script the multisig redeem script.
   * @param[out] require_num the multisig require number.
   * @return an array of public keys.
   */
  static std::vector<Pubkey> ExtractPubkeysFromMultisigScript(
      const Script &multisig_script, uint32_t *require_num = nullptr);

 private:
  ScriptUtil();
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_SCRIPT_H_
