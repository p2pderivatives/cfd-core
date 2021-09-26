#include "gtest/gtest.h"

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_script.h"

using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::Script;
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
  EXPECT_FALSE(script_op.IsPushOperator());
}

TEST(ScriptOperator, operator_2) {
  ScriptOperator script_op(ScriptOperator::OP_ROLL);

  EXPECT_FALSE(script_op == ScriptOperator::OP_WITHIN);
  EXPECT_TRUE(script_op == ScriptOperator::OP_ROLL);
  EXPECT_FALSE(script_op.IsPushOperator());
}

TEST(ScriptOperator, operator_3) {
  ScriptOperator script_op(ScriptOperator::OP_NEGATE);

  EXPECT_FALSE(script_op != ScriptOperator::OP_NEGATE);
  EXPECT_TRUE(script_op != ScriptOperator::OP_SHA1);
  EXPECT_FALSE(script_op.IsPushOperator());
}

TEST(ScriptOperator, operator_4) {
  ScriptOperator script_op(ScriptOperator::OP_12);
  EXPECT_FALSE(script_op < ScriptOperator::OP_PUSHDATA2);
  EXPECT_FALSE(script_op < ScriptOperator::OP_1);
  EXPECT_FALSE(script_op < ScriptOperator::OP_12);
  EXPECT_TRUE(script_op < ScriptOperator::OP_15);
  EXPECT_TRUE(script_op < ScriptOperator::OP_NOP);
  EXPECT_TRUE(script_op.IsPushOperator());
}

TEST(ScriptOperator, operator_5) {
  ScriptOperator script_op(ScriptOperator::OP_12);
  EXPECT_FALSE(script_op <= ScriptOperator::OP_RESERVED);
  EXPECT_FALSE(script_op <= ScriptOperator::OP_1);
  EXPECT_TRUE(script_op <= ScriptOperator::OP_12);
  EXPECT_TRUE(script_op <= ScriptOperator::OP_LEFT);
  EXPECT_STREQ(script_op.ToString().c_str(), "12");
  EXPECT_STREQ(script_op.ToCodeString().c_str(), "OP_12");
  EXPECT_TRUE(script_op.IsPushOperator());
}

TEST(ScriptOperator, operator_6) {
  ScriptOperator script_op(ScriptOperator::OP_3);
  EXPECT_FALSE(script_op > ScriptOperator::OP_RIGHT);
  EXPECT_FALSE(script_op > ScriptOperator::OP_10);
  EXPECT_FALSE(script_op > ScriptOperator::OP_3);
  EXPECT_TRUE(script_op > ScriptOperator::OP_0);
  EXPECT_TRUE(script_op > ScriptOperator::OP_1NEGATE);
  EXPECT_STREQ(script_op.ToString().c_str(), "3");
  EXPECT_STREQ(script_op.ToCodeString().c_str(), "OP_3");
  EXPECT_TRUE(script_op.IsPushOperator());
}

TEST(ScriptOperator, operator_7) {
  ScriptOperator script_op(ScriptOperator::OP_3);
  EXPECT_FALSE(script_op >= ScriptOperator::OP_MIN);
  EXPECT_FALSE(script_op >= ScriptOperator::OP_10);
  EXPECT_TRUE(script_op >= ScriptOperator::OP_3);
  EXPECT_TRUE(script_op >= ScriptOperator::OP_0);
  EXPECT_TRUE(script_op >= ScriptOperator::OP_PUSHDATA4);
  EXPECT_TRUE(script_op.IsPushOperator());
}

TEST(ScriptOperator, ToCodeString) {
  EXPECT_STREQ(ScriptOperator::OP_MIN.ToCodeString().c_str(), "OP_MIN");
  EXPECT_STREQ(ScriptOperator::OP_3.ToCodeString().c_str(), "OP_3");
  EXPECT_STREQ(ScriptOperator::OP_0.ToCodeString().c_str(), "OP_0");
  EXPECT_STREQ(ScriptOperator::OP_1.ToCodeString().c_str(), "OP_1");
  EXPECT_STREQ(ScriptOperator::OP_16.ToCodeString().c_str(), "OP_16");
  EXPECT_STREQ(ScriptOperator::OP_TRUE.ToCodeString().c_str(), "OP_TRUE");
  EXPECT_STREQ(ScriptOperator::OP_FALSE.ToCodeString().c_str(), "OP_FALSE");
  EXPECT_STREQ(ScriptOperator::OP_1NEGATE.ToCodeString().c_str(), "OP_1NEGATE");
}

TEST(ScriptOperator, IsValid) {
  EXPECT_TRUE(ScriptOperator::IsValid("OP_MIN"));
  EXPECT_TRUE(ScriptOperator::IsValid("OP_3"));
  EXPECT_TRUE(ScriptOperator::IsValid("OP_0"));
  EXPECT_TRUE(ScriptOperator::IsValid("OP_1"));
  EXPECT_TRUE(ScriptOperator::IsValid("OP_16"));
  EXPECT_TRUE(ScriptOperator::IsValid("OP_TRUE"));
  EXPECT_TRUE(ScriptOperator::IsValid("OP_FALSE"));
  EXPECT_TRUE(ScriptOperator::IsValid("OP_1NEGATE"));
  EXPECT_FALSE(ScriptOperator::IsValid("OP_xxxx"));
}

TEST(ScriptOperator, GetOperator) {
  ScriptOperator ope;
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_MIN"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_MIN");
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_3"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_3");
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_0"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_0");
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_1"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_1");
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_16"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_16");
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_TRUE"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_TRUE");
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_FALSE"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_FALSE");
  EXPECT_NO_THROW(ope = ScriptOperator::Get("OP_1NEGATE"));
  EXPECT_STREQ(ope.ToCodeString().c_str(), "OP_1NEGATE");
  EXPECT_THROW((ope = ScriptOperator::Get("OP_xxxx")), CfdException);
}

TEST(ScriptOperator, IsOpSuccess) {
  EXPECT_TRUE(ScriptOperator::IsOpSuccess(ScriptType::kOpSuccess137));
  EXPECT_TRUE(ScriptOperator::IsOpSuccess(ScriptType::kOpSuccess137, true));
  EXPECT_TRUE(ScriptOperator::IsOpSuccess(ScriptType::kOpSuccess192));
  EXPECT_FALSE(ScriptOperator::IsOpSuccess(ScriptType::kOpSuccess192, true));
  EXPECT_TRUE(ScriptOperator::IsOpSuccess(ScriptType::kOpSuccess195));
  EXPECT_TRUE(ScriptOperator::IsOpSuccess(ScriptType::kOpSuccess195, true));
}
