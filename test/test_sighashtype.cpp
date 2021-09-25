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
  EXPECT_STREQ(type.ToString().c_str(), "ALL");

  EXPECT_NO_THROW(type2 = SigHashType(SigHashAlgorithm::kSigHashNone, true, false));
  EXPECT_EQ(type2.GetSigHashFlag(), 0x82);
  EXPECT_TRUE(type2.IsAnyoneCanPay());
  EXPECT_FALSE(type2.IsForkId());
  EXPECT_STREQ(type2.ToString().c_str(), "NONE|ANYONECANPAY");

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

TEST(SigHashType, CheckFlag) {
  SigHashType sighash = SigHashType(SigHashAlgorithm::kSigHashUnknown);
  EXPECT_FALSE(sighash.IsValid());

  sighash = SigHashType(SigHashAlgorithm::kSigHashAll);
  sighash.SetRangeproof(true);
  EXPECT_FALSE(sighash.IsAnyoneCanPay());
  EXPECT_TRUE(sighash.IsRangeproof());
  sighash.SetAnyoneCanPay(true);
  EXPECT_TRUE(sighash.IsAnyoneCanPay());
  EXPECT_TRUE(sighash.IsRangeproof());
}

TEST(SigHashType, Create) {
  auto sighash = SigHashType::Create(0x41);
  EXPECT_EQ(SigHashAlgorithm::kSigHashAll, sighash.GetSigHashAlgorithm());
  EXPECT_FALSE(sighash.IsAnyoneCanPay());
  EXPECT_TRUE(sighash.IsRangeproof());
}
