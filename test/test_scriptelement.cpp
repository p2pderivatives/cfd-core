#include "gtest/gtest.h"

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_script.h"

using cfd::core::ByteData;
using cfd::core::ScriptElement;
using cfd::core::ScriptElementType;
using cfd::core::ScriptOperator;
using cfd::core::ScriptType;

TEST(ScriptElement, OpTypeConstructor) {
  ScriptElement op_elem = ScriptElement(ScriptOperator::OP_CHECKSIG);

  EXPECT_EQ(ScriptElementType::kElementOpCode, op_elem.GetType());
  EXPECT_EQ(ScriptOperator::OP_CHECKSIG, op_elem.GetOpCode());
  EXPECT_EQ(ByteData().GetBytes(), op_elem.GetBinaryData().GetBytes());
  EXPECT_EQ(0, op_elem.GetNumber());
  EXPECT_EQ(ByteData("ac").GetBytes(), op_elem.GetData().GetBytes());
  EXPECT_STREQ("OP_CHECKSIG", op_elem.ToString().c_str());
  EXPECT_FALSE(op_elem.IsBinary());
  EXPECT_FALSE(op_elem.IsNumber());
  EXPECT_TRUE(op_elem.IsOpCode());
}

TEST(ScriptElement, OpNumTypeConstructor) {
  ScriptElement op_elem = ScriptElement(ScriptOperator::OP_12);

  EXPECT_EQ(ScriptElementType::kElementOpCode, op_elem.GetType());
  EXPECT_EQ(ScriptOperator::OP_12, op_elem.GetOpCode());
  EXPECT_EQ(ByteData().GetBytes(), op_elem.GetBinaryData().GetBytes());
  EXPECT_EQ(12, op_elem.GetNumber());
  EXPECT_EQ(ByteData("5c").GetBytes(), op_elem.GetData().GetBytes());
  EXPECT_STREQ("12", op_elem.ToString().c_str());
  EXPECT_FALSE(op_elem.IsBinary());
  EXPECT_TRUE(op_elem.IsNumber());
  EXPECT_TRUE(op_elem.IsOpCode());
}

TEST(ScriptElement, ByteTypeConstructor) {
  ScriptElement byte_elem = ScriptElement(ByteData("1234567890abcdef"));

  EXPECT_EQ(ScriptElementType::kElementBinary, byte_elem.GetType());
  EXPECT_EQ(ScriptOperator::OP_INVALIDOPCODE, byte_elem.GetOpCode());
  EXPECT_EQ(ByteData("1234567890abcdef").GetBytes(),
            byte_elem.GetBinaryData().GetBytes());
  EXPECT_EQ(0, byte_elem.GetNumber());
  EXPECT_EQ(ByteData("081234567890abcdef").GetBytes(),
            byte_elem.GetData().GetBytes());
  EXPECT_STREQ("1234567890abcdef", byte_elem.ToString().c_str());
  EXPECT_TRUE(byte_elem.IsBinary());
  EXPECT_FALSE(byte_elem.IsNumber());
  EXPECT_FALSE(byte_elem.IsOpCode());
}

TEST(ScriptElement, NumTypeConstructor) {
  ScriptElement num_elem = ScriptElement(144);

  EXPECT_EQ(ScriptElementType::kElementNumber, num_elem.GetType());
  EXPECT_EQ(ScriptOperator::OP_INVALIDOPCODE, num_elem.GetOpCode());
  EXPECT_EQ(ByteData().GetBytes(), num_elem.GetBinaryData().GetBytes());
  EXPECT_EQ(144, num_elem.GetNumber());
  EXPECT_EQ(ByteData("029000").GetBytes(), num_elem.GetData().GetBytes());
  EXPECT_STREQ("144", num_elem.ToString().c_str());
  EXPECT_FALSE(num_elem.IsBinary());
  EXPECT_TRUE(num_elem.IsNumber());
  EXPECT_FALSE(num_elem.IsOpCode());
}

TEST(ScriptElement, CopyConstructor) {
  ScriptElement op_elem = ScriptElement(ScriptOperator::OP_DUP);
  ScriptElement copied_elem = ScriptElement(op_elem);

  EXPECT_EQ(op_elem.GetType(), copied_elem.GetType());
  EXPECT_EQ(op_elem.GetOpCode(), copied_elem.GetOpCode());
  EXPECT_EQ(op_elem.GetBinaryData().GetBytes(),
            copied_elem.GetBinaryData().GetBytes());
  EXPECT_EQ(op_elem.GetNumber(), copied_elem.GetNumber());
  EXPECT_EQ(op_elem.GetData().GetBytes(), copied_elem.GetData().GetBytes());
  EXPECT_STREQ(op_elem.ToString().c_str(), copied_elem.ToString().c_str());
}

TEST(ScriptElement, CopyOperator) {
  ScriptElement op_elem = ScriptElement(ScriptOperator::OP_NOP);
  ScriptElement copied_elem = op_elem;

  EXPECT_EQ(op_elem.GetType(), copied_elem.GetType());
  EXPECT_EQ(op_elem.GetOpCode(), copied_elem.GetOpCode());
  EXPECT_EQ(op_elem.GetBinaryData().GetBytes(),
            copied_elem.GetBinaryData().GetBytes());
  EXPECT_EQ(op_elem.GetNumber(), copied_elem.GetNumber());
  EXPECT_EQ(op_elem.GetData().GetBytes(), copied_elem.GetData().GetBytes());
  EXPECT_STREQ(op_elem.ToString().c_str(), copied_elem.ToString().c_str());
}

TEST(ScriptElement, ConvertBinaryToNumber) {
  ScriptElement bi_num_elem = ScriptElement(ByteData("ff7f"));
  int64_t converted;
  EXPECT_TRUE(bi_num_elem.ConvertBinaryToNumber(&converted));
  EXPECT_EQ(32767, converted);

  bi_num_elem = ScriptElement(ByteData("ffffffffffff"));
  converted = 0;
  EXPECT_FALSE(bi_num_elem.ConvertBinaryToNumber(&converted));
  EXPECT_EQ(0, converted);

  bi_num_elem = ScriptElement(ScriptOperator::OP_12);
  converted = 0;
  EXPECT_FALSE(bi_num_elem.ConvertBinaryToNumber(&converted));
  EXPECT_EQ(0, converted);
}

typedef struct {
  int64_t input;
  ScriptOperator expect_op_code;
  std::string expect_data;
} NumberElementTestCase;

// @formatter:off
static const std::vector<NumberElementTestCase> test_vector = {
    {
        -129,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "028180"
    },
    {
        -128,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "028080"
    },
    {
        -127,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "01ff"
    },
    {
        -126,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "01fe"
    },
    {
        -2,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "0182"
    },
    {
        -1,
        ScriptOperator(ScriptType::kOp1Negate),
        "4f"
    },
    {
        0,
        ScriptOperator(ScriptType::kOp_0),
        "00"
    },
    {
        1,
        ScriptOperator(ScriptType::kOp_1),
        "51"
    },
    {
        15,
        ScriptOperator(ScriptType::kOp_15),
        "5f"
    },
    {
        16,
        ScriptOperator(ScriptType::kOp_16),
        "60"
    },
    {
        17,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "0111"
    },
    {
        126,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "017e"
    },
    {
        127,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "017f"
    },
    {
        128,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "028000"
    },
    {
        129,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "028100"
    },
    {
        32766,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "02fe7f"
    },
    {
        32767,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "02ff7f"
    },
    {
        32768,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "03008000"
    },
    {
        32769,
        ScriptOperator(ScriptType::kOpInvalidOpCode),
        "03018000"
    },
};
// @formatter:on

TEST(ScriptElement, NumConstructorWitTestVector) {
  for (const NumberElementTestCase& test_case : test_vector) {
    ScriptElement elem = ScriptElement(test_case.input);

    EXPECT_TRUE(elem.IsNumber());
    EXPECT_EQ(test_case.input, elem.GetNumber());
    EXPECT_EQ(test_case.expect_op_code, elem.GetOpCode());
    EXPECT_STREQ(test_case.expect_data.c_str(),
                 elem.GetData().GetHex().c_str());
  }
}

