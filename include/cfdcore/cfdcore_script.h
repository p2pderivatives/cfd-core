// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_script.h
 *
 * @brief Script関連クラス定義
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

/// P2PKHのScriptサイズ（WALLY_SCRIPTPUBKEY_P2PKH_LEN）
constexpr size_t kScriptHashP2pkhLength = 25;
/// P2SHのScriptサイズ（WALLY_SCRIPTPUBKEY_P2SH_LEN）
constexpr size_t kScriptHashP2shLength = 23;
/// P2WPKHのScriptサイズ（WALLY_SCRIPTPUBKEY_P2WPKH_LEN）
constexpr size_t kScriptHashP2wpkhLength = 22;
/// P2WSHのScriptサイズ（WALLY_SCRIPTPUBKEY_P2WSH_LEN）
constexpr size_t kScriptHashP2wshLength = 34;
/// WitnessProgramの最小サイズ
constexpr size_t kMinWitnessProgramLength = 4;
/// WitnessProgramの最大サイズ
constexpr size_t kMaxWitnessProgramLength = 42;

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
  kOpSize = 0x82,                 //!< kOpSize
  kOpInvert = 0x83,               //!< kOpInvert
  kOpAnd = 0x84,                  //!< kOpAnd
  kOpOr = 0x85,                   //!< kOpOr
  kOpXor = 0x86,                  //!< kOpXor
  kOpEqual = 0x87,                //!< kOpEqual
  kOpEqualVerify = 0x88,          //!< kOpEqualVerify
  kOpReserved1 = 0x89,            //!< kOpReserved1
  kOpReserved2 = 0x8a,            //!< kOpReserved2
  kOp1Add = 0x8b,                 //!< kOp1Add
  kOp1Sub = 0x8c,                 //!< kOp1Sub
  kOp2Mul = 0x8d,                 //!< kOp2Mul
  kOp2Div = 0x8e,                 //!< kOp2Div
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
 * @brief Script操作定義クラス。
 * @details
 * OP_XXXXの定義値についてですが、使用時は以下に注意してください。
 * - static linkする場合は、グローバル変数の初期値に使用しないこと。
 *   - 初期化順序の関係で、未初期化状態で設定されることがあります。
 *   - グローバル変数の初期値に使う場合、
 *     ScriptOperatorではなくScriptTypeを使用して下さい。
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
  static const ScriptOperator
      OP_GREATERTHANOREQUAL;              //!< OP_GREATERTHANOREQUAL  //NOLINT
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
  static const ScriptOperator
      OP_CHECKMULTISIGVERIFY;           //!< OP_CHECKMULTISIGVERIFY  //NOLINT
  static const ScriptOperator OP_NOP1;  //!< OP_NOP1
  static const ScriptOperator
      OP_CHECKLOCKTIMEVERIFY;           //!< OP_CHECKLOCKTIMEVERIFY  //NOLINT
  static const ScriptOperator OP_NOP2;  //!< OP_NOP2
  static const ScriptOperator
      OP_CHECKSEQUENCEVERIFY;            //!< OP_CHECKSEQUENCEVERIFY  //NOLINT
  static const ScriptOperator OP_NOP3;   //!< OP_NOP3
  static const ScriptOperator OP_NOP4;   //!< OP_NOP4
  static const ScriptOperator OP_NOP5;   //!< OP_NOP5
  static const ScriptOperator OP_NOP6;   //!< OP_NOP6
  static const ScriptOperator OP_NOP7;   //!< OP_NOP7
  static const ScriptOperator OP_NOP8;   //!< OP_NOP8
  static const ScriptOperator OP_NOP9;   //!< OP_NOP9
  static const ScriptOperator OP_NOP10;  //!< OP_NOP10
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
   * @brief 等価比較オペレータ
   * @param[in] object     比較対象
   * @retval true 等価
   * @retval false 不等価
   * @return 等価であればtrue, それ以外はfalse
   */
  bool operator==(const ScriptOperator &object) const;
  /**
   * @brief 不等価比較オペレータ
   * @param[in] object     比較対象
   * @retval true 不等価
   * @retval false 等価
   * @return 不等価であればtrue, それ以外はfalse
   */
  bool operator!=(const ScriptOperator &object) const;
  /**
   * @brief 比較オペレータ
   * @param[in] object     比較対象
   * @retval true 条件に合致
   * @retval false 条件に合致せず
   */
  bool operator<(const ScriptOperator &object) const;
  /**
   * @brief 比較オペレータ
   * @param[in] object     比較対象
   * @retval true 条件に合致
   * @retval false 条件に合致せず
   */
  bool operator<=(const ScriptOperator &object) const;
  /**
   * @brief 比較オペレータ
   * @param[in] object     比較対象
   * @retval true 条件に合致
   * @retval false 条件に合致せず
   */
  bool operator>(const ScriptOperator &object) const;
  /**
   * @brief 比較オペレータ
   * @param[in] object     比較対象
   * @retval true 条件に合致
   * @retval false 条件に合致せず
   */
  bool operator>=(const ScriptOperator &object) const;

  /**
   * @brief default constructor.
   *
   * リスト型使用時のため.
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
 * @brief Script要素保持クラス。
 */
class CFD_CORE_EXPORT ScriptElement {
 public:
  /**
   * @brief コンストラクタ.
   * @param[in] element     オブジェクト
   */
  ScriptElement(const ScriptElement &element);
  /**
   * @brief コンストラクタ.
   * @param[in] type     OP_CODE
   */
  explicit ScriptElement(const ScriptType &type);
  /**
   * @brief コンストラクタ.
   * @param[in] op_code     OP_CODE
   */
  explicit ScriptElement(const ScriptOperator &op_code);
  /**
   * @brief コンストラクタ.
   * @param[in] binary_data   binary data
   */
  explicit ScriptElement(const ByteData &binary_data);
  /**
   * @brief コンストラクタ.
   * @param[in] value       script number.
   */
  explicit ScriptElement(int64_t value);
  /**
   * @brief デストラクタ.
   */
  virtual ~ScriptElement() {
    // do nothing
  }
  /**
   * @brief コピーコンストラクタ.
   * @param[in] element     オブジェクト
   * @return オブジェクト
   */
  ScriptElement &operator=(const ScriptElement &element);

  /**
   * @brief 要素種別を取得する.
   * @return 要素種別.
   */
  ScriptElementType GetType() const;
  /**
   * @brief OP_CODEを取得する.
   * @return OP_CODE
   */
  const ScriptOperator &GetOpCode() const;
  /**
   * @brief バイナリ値を取得する.
   * @return バイナリ値
   */
  ByteData GetBinaryData() const;
  /**
   * @brief 数値情報を取得する.
   * @return 数値情報
   */
  int64_t GetNumber() const;

  /**
   * @brief バイト配列を取得する.
   * @return バイト配列
   */
  ByteData GetData() const;
  /**
   * @brief 文字列情報を取得する.
   * @return 文字列情報
   */
  std::string ToString() const;

  /**
   * @brief OP_CODE型の情報かどうか判定する.
   * @retval true   OP_CODE
   * @retval false  その他
   */
  bool IsOpCode() const { return type_ == kElementOpCode; }

  /**
   * @brief 数値型の情報かどうか判定する.
   * @retval true   数値型
   * @retval false  その他
   */
  bool IsNumber() const {
    // 数値型明示 or 数値が入っている or OP_0 の何れかなら数値とみなす
    return (type_ == kElementNumber) || (value_ != 0) ||
           (op_code_.GetDataType() == kOp_0);
  }

  /**
   * @brief バイナリ情報かどうか判定する.
   * @retval true   バイナリ情報
   * @retval false  その他
   */
  bool IsBinary() const { return type_ == kElementBinary; }

  /**
   * @brief バイナリ値から数値型に変換する.
   * @param[out] int64_value    数値
   * @retval true   数値型変換OK
   * @retval false  数値型変換NG
   */
  bool ConvertBinaryToNumber(int64_t *int64_value = nullptr) const;

  /**
   * @brief デフォルトコンストラクタ.
   *
   * リスト作成のため.
   */
  ScriptElement()
      : type_(kElementOpCode), op_code_(), binary_data_(), value_(0) {
    // do nothing
  }

 private:
  ScriptElementType type_;  ///< 要素種別
  ScriptOperator op_code_;  ///< OP_CODE
  ByteData binary_data_;    ///< バイナリ情報
  int64_t value_;           ///< 数値

  /**
   * @brief             Scriptに追加する数値をbyteデータに変換する
   * @param[in] value   scriptに追加する数値
   * @return            numberをserializeしたbyteデータ
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
   * @brief Check if the script is pegout script.
   * @retval true   script is pegout script.
   * @retval false  not pegout script.
   */
  bool IsPegoutScript() const;

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
 * @brief script builderクラス.
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
   * @brief   build script.
   * @return  script
   */
  Script Build();

 private:
  std::vector<uint8_t> script_byte_array_;  ///< byte array
};

/**
 * @brief Scriptを作成する関数群クラス
 */
class CFD_CORE_EXPORT ScriptUtil {
 public:
  /**
   * @brief P2PKのlocking scriptを作成する.
   * @param[in] pubkey Pubkeyインスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * <pubkey> OP_CHECKSIG
   * @endcode
   */
  static Script CreateP2pkLockingScript(const Pubkey &pubkey);
  /**
   * @brief P2PKHのlocking scriptを作成する.
   * @param[in] pubkey_hash pubkey hashが格納されたByteData160インスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
   * @endcode
   */
  static Script CreateP2pkhLockingScript(const ByteData160 &pubkey_hash);
  /**
   * @brief P2PKHのlocking scriptを作成する.
   * @param[in] pubkey Pubkeyインスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
   * @endcode
   */
  static Script CreateP2pkhLockingScript(const Pubkey &pubkey);
  /**
   * @brief P2SHのlocking scriptを作成する.
   * @param[in] script_hash script hashが格納されたByteData160インスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_HASH160 <hash160(redeemScript)> OP_EQUAL
   * @endcode
   */
  static Script CreateP2shLockingScript(const ByteData160 &script_hash);
  /**
   * @brief P2SHのlocking scriptを作成する.
   * @param[in] redeem_script redeem scriptのScriptインスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_HASH160 <hash160(redeemScript)> OP_EQUAL
   * @endcode
   */
  static Script CreateP2shLockingScript(const Script &redeem_script);
  /**
   * @brief P2WPKHのlocking scriptを作成する.
   * @param[in] pubkey_hash pubkey hashが格納されたByteData160インスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_0 <hash160(pubkey)>
   * @endcode
   */
  static Script CreateP2wpkhLockingScript(const ByteData160 &pubkey_hash);
  /**
   * @brief P2WPKHのlocking scriptを作成する.
   * @param[in] pubkey Pubkeyインスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_0 <hash160(pubkey)>
   * @endcode
   */
  static Script CreateP2wpkhLockingScript(const Pubkey &pubkey);
  /**
   * @brief P2WSHのlocking scriptを作成する.
   * @param[in] script_hash script hashのByteData256インスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_0 <sha256(redeemScript)>
   * @endcode
   */
  static Script CreateP2wshLockingScript(const ByteData256 &script_hash);
  /**
   * @brief P2WSHのlocking scriptを作成する.
   * @param[in] redeem_script redeem scriptのScriptインスタンス
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_0 <sha256(redeemScript)>
   * @endcode
   */
  static Script CreateP2wshLockingScript(const Script &redeem_script);
  /**
   * @brief RedeemScriptが有効なものであるかをチェックする.
   * @param[in] redeem_script redeem script
   * @retval true 有効なredeem script
   * @retval false 有効でないredeem script
   */
  static bool IsValidRedeemScript(const Script &redeem_script);
  /**
   * @brief M-of-N Multisigのredeem scriptを作成する.
   * @param[in] require_sig_num unlockingに必要なSignature数（Mに相当）
   * @param[in] pubkeys 署名に対応するPubkey配列（Nに相当）
   * @return Scriptインスタンス
   * @details 下記の内容のScriptを作成する.
   * @code{.unparse}
   * OP_<requireSigNum> <pubkey> ... OP_n OP_CHECKMULTISIG
   * @endcode
   */
  static Script CreateMultisigRedeemScript(
      uint32_t require_sig_num, const std::vector<Pubkey> &pubkeys);
#ifndef CFD_DISABLE_ELEMENTS
  /**
   * @brief Pegoutのlocking scriptを作成する.
   * @param[in] genesisblock_hash mainchainのgenesisblock hash
   * @param[in] parent_locking_script 送り先 bitcoin address の locking script
   * @param[in] btc_pubkey_bytes DerivePubTweak関数で作られたpubkey情報
   * @param[in] whitelist_proof whitelistの証明
   * @return Scriptインスタンス
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
