#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_logger.h"

using cfd::core::logger::IsEnableLogLevel;
using cfd::core::logger::WriteLog;
using cfd::core::logger::CfdLogLevel;
using cfd::core::logger::CfdLogger;
using cfd::core::InitializeLogger;
using cfd::core::FinalizeLogger;
using cfd::core::SetLogger;
using spdlog::details::log_msg;

TEST(CfdLogger, IsEnableLogLevel) {
  EXPECT_FALSE(IsEnableLogLevel(CfdLogLevel::kCfdLogLevelTrace));
}

TEST(CfdLogger, WriteLog) {
  spdlog::source_loc source;
  using spdlog::details::fmt_helper::to_string_view;
  fmt::memory_buffer buf;
  std::string log_name = "cfd";
  spdlog::details::log_msg log_msg(source, &log_name,
                                   (spdlog::level::level_enum) CfdLogLevel::kCfdLogLevelTrace,
                                   to_string_view(buf));
  EXPECT_NO_THROW((WriteLog(log_msg)));
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
