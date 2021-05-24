// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_logger.cpp
 * @brief implementation of logger
 */
#include <iostream>
#include <memory>
#include <string>
#include <vector>

// clang-format off
#include "quill/LogLevel.h"
#ifdef CFDCORE_LOGGING
#include "quill/Logger.h"
#include "quill/Fmt.h"
#include "quill/Quill.h"
#include "quill/LogMacroMetadata.h"
#ifdef CFDCORE_LOG_CONSOLE
#include "quill/handlers/ConsoleHandler.h"
#endif  // CFDCORE_LOG_CONSOLE
#endif  // CFDCORE_LOGGING
// clang-format on

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_logger_interface.h"
#include "cfdcore/cfdcore_util.h"

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------
/// instance of CfdLogger class
static cfd::core::logger::CfdLogger logger_instance;

void cfd::core::InitializeLogger(void) { logger_instance.Initialize(); }

void cfd::core::FinalizeLogger(bool is_finish_process) {
  logger_instance.Finalize(is_finish_process);
}

void cfd::core::SetLogger(void* function_address) {
  logger_instance.SetLogger(function_address);
}

// -----------------------------------------------------------------------------
// Internal API
// -----------------------------------------------------------------------------
namespace cfd {
namespace core {
namespace logger {

/// Debug Flag
#if defined(DEBUG) || defined(CFDCORE_DEBUG)
static bool cfdcore_logger_is_debug = true;
#else
static bool cfdcore_logger_is_debug = false;
#endif

bool IsEnableLogLevel(cfd::core::logger::CfdLogLevel level) {
  return logger_instance.IsEnableLogLevel(level);
}

void WriteLog(
    const CfdSourceLocation& location, cfd::core::logger::CfdLogLevel level,
    const std::string& log_message) {
  logger_instance.WriteLog(location, level, log_message);
}

#if defined(CFDCORE_LOGGING) && (defined(DEBUG) || defined(CFDCORE_DEBUG))
/**
 * @brief convert log level.
 * @param[in] log_level     cfd log level
 * @return convert log level.
 */
static quill::LogLevel ConvertLogLevel(CfdLogLevel log_level) {
  switch (log_level) {
    case CfdLogLevel::kCfdLogLevelOff:
      return quill::LogLevel::None;
    case CfdLogLevel::kCfdLogLevelTrace:
      return quill::LogLevel::TraceL1;
    case CfdLogLevel::kCfdLogLevelDebug:
      return quill::LogLevel::Debug;
    case CfdLogLevel::kCfdLogLevelWarning:
      return quill::LogLevel::Warning;
    case CfdLogLevel::kCfdLogLevelError:
      return quill::LogLevel::Error;
    case CfdLogLevel::kCfdLogLevelCritical:
      return quill::LogLevel::Critical;
    case CfdLogLevel::kCfdLogLevelInfo:
    default:
      return quill::LogLevel::Info;
  }
}
#endif  // CFDCORE_LOGGING

// -----------------------------------------------------------------------------
// CfdLogger
// -----------------------------------------------------------------------------
cfd::core::logger::CfdLogger::CfdLogger(void) {
  // do nothing
}

cfd::core::logger::CfdLogger::~CfdLogger(void) { Finalize(true); }

cfd::core::CfdError cfd::core::logger::CfdLogger::Initialize(void) {
  if (is_initialized_) {
    // do nothing
  } else {
    is_initialized_ = true;
    is_alive_ = true;

    if ((!is_extend_log_) && cfdcore_logger_is_debug) {
#if defined(CFDCORE_LOGGING) && (defined(DEBUG) || defined(CFDCORE_DEBUG))
#ifndef CFDCORE_LOG_CONSOLE
      const size_t kRotateFileSize = 1024 * 1024 * 256;
      const std::string filepath = "cfd_debug.txt";
#endif

      std::string kDefaultLogLevel = "info";
#ifdef CFDCORE_LOG_LEVEL
      int level_val = CFDCORE_LOG_LEVEL;
      if (level_val == 1) {
        kDefaultLogLevel = "trace";
      } else if (level_val == 2) {
        kDefaultLogLevel = "debug";
      } else if (level_val == 4) {
        kDefaultLogLevel = "warn";
      }
#endif

      // TODO(k-matsuzawa): only used for debugging
      auto log_level = StringUtil::ToLower(kDefaultLogLevel);
      if (log_level == "trace") {
        log_level_ = kCfdLogLevelTrace;
      } else if (log_level == "debug") {
        log_level_ = kCfdLogLevelDebug;
      } else if ((log_level == "warn") || (log_level == "warning")) {
        log_level_ = kCfdLogLevelWarning;
      } else {
        log_level_ = kCfdLogLevelInfo;
      }
      // is_async_ = true;

      is_use_default_logger_ = true;
      // spdlog::init_thread_pool(1024 * 128, 5);  // For Initalization
#ifdef CFDCORE_LOG_CONSOLE
      // quill::enable_console_colours();
      quill::ConsoleColours console_colours;
      console_colours.set_default_colours();
      quill::Handler* handler =
          quill::stdout_handler("stdout_colours", console_colours);
      handler->set_pattern(
          QUILL_STRING("%(ascii_time) [%(process):%(thread)] %(level_name) "
                       "%(logger_name) - %(message)"),  // NOLINT
          "%D %H:%M:%S.%Qms", quill::Timezone::LocalTime);
      quill::set_default_logger_handler(handler);
      quill::start();
      quill::Logger* logger = quill::get_logger();
#else
      quill::start();
      quill::Handler* handler =
          quill::rotating_file_handler(filepath, "w", kRotateFileSize, 3);
      handler->set_pattern(
          QUILL_STRING("%(ascii_time) [%(process):%(thread)] %(level_name) "
                       "%(logger_name) - %(message)"),  // NOLINT
          "%D %H:%M:%S.%Qms", quill::Timezone::LocalTime);
      quill::Logger* logger = quill::create_logger("cfd", handler);
#endif
      logger->set_log_level(ConvertLogLevel(log_level_));
      default_logger_ = logger;

#else   // CFDCORE_LOGGING
      std::cout << "default logger is not support on C++11." << std::endl;
#endif  // CFDCORE_LOGGING
    }
  }
  return kCfdSuccess;
}

void cfd::core::logger::CfdLogger::Finalize(bool is_finish_process) {
  if (is_alive_) {
    is_alive_ = false;
    if (is_use_default_logger_ && (!is_finish_process)) {
      // quill is not found finalize function.
    }
  }
}

void cfd::core::logger::CfdLogger::SetLogger(void* function_address) {
  this->function_address_ = function_address;
  is_extend_log_ = true;
}

bool cfd::core::logger::CfdLogger::IsEnableLogLevel(CfdLogLevel level) {
  if (log_level_ == kCfdLogLevelOff) return false;
  if (is_initialized_ && is_alive_ && (level >= log_level_)) return true;
  return false;
}

void cfd::core::logger::CfdLogger::WriteLog(
    const CfdSourceLocation& location, cfd::core::logger::CfdLogLevel level,
    const std::string& log_message) {
  if (is_initialized_ && is_alive_) {
    if (function_address_ != nullptr) {
      // extend log
    } else if (default_logger_ != nullptr) {
#if defined(CFDCORE_LOGGING) && (defined(DEBUG) || defined(CFDCORE_DEBUG))
      auto logger = static_cast<quill::Logger*>(default_logger_);
      if (level == CfdLogLevel::kCfdLogLevelCritical) {
        LOG_CRITICAL(
            logger, "[{}:{}] {}", location.filename, location.line,
            log_message);
      } else if (level == CfdLogLevel::kCfdLogLevelError) {
        LOG_ERROR(
            logger, "[{}:{}] {}", location.filename, location.line,
            log_message);
      } else if (level == CfdLogLevel::kCfdLogLevelWarning) {
        LOG_WARNING(
            logger, "[{}:{}] {}", location.filename, location.line,
            log_message);
      } else if (level == CfdLogLevel::kCfdLogLevelInfo) {
        LOG_INFO(
            logger, "[{}:{}] {}: {}", location.filename, location.line,
            location.funcname, log_message);
      } else if (level == CfdLogLevel::kCfdLogLevelDebug) {
        LOG_DEBUG(
            logger, "[{}:{}] {}: {}", location.filename, location.line,
            location.funcname, log_message);
      } else if (level == CfdLogLevel::kCfdLogLevelTrace) {
        LOG_TRACE_L1(
            logger, "[{}:{}] {}: {}", location.filename, location.line,
            location.funcname, log_message);
      }
#else
      printf(
          "[%s:%d](%d) %s: %s", location.filename, location.line, level,
          location.funcname, log_message.c_str());
#endif  // CFDCORE_LOGGING
    }
  }
}

}  // namespace logger
}  // namespace core
}  // namespace cfd
