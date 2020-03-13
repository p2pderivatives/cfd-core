#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::SigHashType;
using cfd::core::SigHashAlgorithm;

TEST(SigHashType, Constructor_GetSigHashFlag) {
  SigHashType type;
  SigHashType type2;
  EXPECT_NO_THROW(type = SigHashType());
  EXPECT_EQ(type.GetSigHashFlag(), 1);

  EXPECT_NO_THROW(type2 = SigHashType(SigHashAlgorithm::kSigHashNone, true, false));
  EXPECT_EQ(type2.GetSigHashFlag(), 0x82);
  EXPECT_TRUE(type2.IsAnyoneCanPay());
  EXPECT_FALSE(type2.IsForkId());

  EXPECT_NO_THROW(type = type2);
  EXPECT_EQ(type.GetSigHashFlag(), 0x82);
}

TEST(SigHashType, SetFromSigHashFlag) {
  SigHashType type;
  EXPECT_NO_THROW(type.SetFromSigHashFlag(0x82));
  EXPECT_EQ(type.GetSigHashAlgorithm(), SigHashAlgorithm::kSigHashNone);
  EXPECT_TRUE(type.IsAnyoneCanPay());
  EXPECT_FALSE(type.IsForkId());

  EXPECT_NO_THROW(type.SetFromSigHashFlag(0x41));
  EXPECT_EQ(type.GetSigHashAlgorithm(), SigHashAlgorithm::kSigHashAll);
  EXPECT_FALSE(type.IsAnyoneCanPay());
  EXPECT_TRUE(type.IsForkId());

  EXPECT_NO_THROW(type.SetFromSigHashFlag(0x03));
  EXPECT_EQ(type.GetSigHashAlgorithm(), SigHashAlgorithm::kSigHashSingle);
  EXPECT_FALSE(type.IsAnyoneCanPay());
  EXPECT_FALSE(type.IsForkId());
}
