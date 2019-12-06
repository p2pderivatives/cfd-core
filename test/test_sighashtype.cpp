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

  EXPECT_NO_THROW(type = type2);
  EXPECT_EQ(type.GetSigHashFlag(), 0x82);
}
