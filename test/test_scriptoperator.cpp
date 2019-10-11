#include "gtest/gtest.h"

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_script.h"

using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptElement;
using cfd::core::ScriptOperator;
using cfd::core::ScriptType;

TEST(ScriptOperator, GetDataType) {
  ScriptType scriptType = ScriptOperator::OP_DUP.GetDataType();
  EXPECT_EQ(scriptType, ScriptType::kOpDup);
}

TEST(ScriptOperator, ToString) {
  std::string str = ScriptOperator::OP_SUBSTR.ToString();
  EXPECT_STREQ(str.c_str(), "OP_SUBSTR");
}

TEST(ScriptOperator, Equals) {
  ScriptOperator script_op(ScriptOperator::OP_VERIFY);

  EXPECT_EQ(script_op.GetDataType(), ScriptType::kOpVerify);
  EXPECT_STREQ(script_op.ToString().c_str(), "OP_VERIFY");
  EXPECT_TRUE(script_op.Equals(ScriptOperator::OP_VERIFY));
  EXPECT_FALSE(script_op.Equals(ScriptOperator::OP_RETURN));
}

TEST(ScriptOperator, operator_1) {
  ScriptOperator script_op = ScriptOperator::OP_1ADD;

  EXPECT_EQ(script_op.GetDataType(), ScriptType::kOp1Add);
  EXPECT_STREQ(script_op.ToString().c_str(), "OP_1ADD");
  EXPECT_FALSE(script_op.Equals(ScriptOperator::OP_XOR));
  EXPECT_TRUE(script_op.Equals(ScriptOperator::OP_1ADD));
}

TEST(ScriptOperator, operator_2) {
  ScriptOperator script_op(ScriptOperator::OP_ROLL);

  EXPECT_FALSE(script_op == ScriptOperator::OP_WITHIN);
  EXPECT_TRUE(script_op == ScriptOperator::OP_ROLL);
}

TEST(ScriptOperator, operator_3) {
  ScriptOperator script_op(ScriptOperator::OP_NEGATE);

  EXPECT_FALSE(script_op != ScriptOperator::OP_NEGATE);
  EXPECT_TRUE(script_op != ScriptOperator::OP_SHA1);
}

TEST(ScriptOperator, operator_4) {
  ScriptOperator script_op(ScriptOperator::OP_12);
  EXPECT_FALSE(script_op < ScriptOperator::OP_PUSHDATA2);
  EXPECT_FALSE(script_op < ScriptOperator::OP_1);
  EXPECT_FALSE(script_op < ScriptOperator::OP_12);
  EXPECT_TRUE(script_op < ScriptOperator::OP_15);
  EXPECT_TRUE(script_op < ScriptOperator::OP_NOP);
}

TEST(ScriptOperator, operator_5) {
  ScriptOperator script_op(ScriptOperator::OP_12);
  EXPECT_FALSE(script_op <= ScriptOperator::OP_RESERVED);
  EXPECT_FALSE(script_op <= ScriptOperator::OP_1);
  EXPECT_TRUE(script_op <= ScriptOperator::OP_12);
  EXPECT_TRUE(script_op <= ScriptOperator::OP_LEFT);
}

TEST(ScriptOperator, operator_6) {
  ScriptOperator script_op(ScriptOperator::OP_3);
  EXPECT_FALSE(script_op > ScriptOperator::OP_RIGHT);
  EXPECT_FALSE(script_op > ScriptOperator::OP_10);
  EXPECT_FALSE(script_op > ScriptOperator::OP_3);
  EXPECT_TRUE(script_op > ScriptOperator::OP_0);
  EXPECT_TRUE(script_op > ScriptOperator::OP_1NEGATE);
}

TEST(ScriptOperator, operator_7) {
  ScriptOperator script_op(ScriptOperator::OP_3);
  EXPECT_FALSE(script_op >= ScriptOperator::OP_MIN);
  EXPECT_FALSE(script_op >= ScriptOperator::OP_10);
  EXPECT_TRUE(script_op >= ScriptOperator::OP_3);
  EXPECT_TRUE(script_op >= ScriptOperator::OP_0);
  EXPECT_TRUE(script_op >= ScriptOperator::OP_PUSHDATA4);
}

