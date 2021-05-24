#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_logger.h"

using cfd::core::logger::IsEnableLogLevel;
using cfd::core::logger::WriteLog;
using cfd::core::logger::CfdLogLevel;
using cfd::core::logger::CfdLogger;
using cfd::core::logger::CfdSourceLocation;
using cfd::core::InitializeLogger;
using cfd::core::FinalizeLogger;
using cfd::core::SetLogger;

TEST(CfdLogger, IsEnableLogLevel) {
  EXPECT_FALSE(IsEnableLogLevel(CfdLogLevel::kCfdLogLevelTrace));
}

TEST(CfdLogger, WriteLog) {
  CfdSourceLocation loc {"", 0, ""};
  EXPECT_NO_THROW((WriteLog(loc, CfdLogLevel::kCfdLogLevelInfo, "")));
}


TEST(CfdLogger, FinalizeLogger) {
  EXPECT_NO_THROW((FinalizeLogger()));
}

TEST(CfdLogger, InitializeLogger) {
  EXPECT_NO_THROW((InitializeLogger()));
}

TEST(CfdLogger, SetLogger) {
  EXPECT_NO_THROW((SetLogger(nullptr)));
}

TEST(CfdLogger, Destructor) {
  CfdLogger logger;
  EXPECT_NO_THROW((logger = CfdLogger()));
}
