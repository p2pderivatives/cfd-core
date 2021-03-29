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
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/fmt/fmt.h"
#include "spdlog/details/pattern_formatter.h"
#include "spdlog/async.h"
#include "spdlog/async_logger.h"
#ifdef CFDCORE_LOG_CONSOLE
#include "spdlog/sinks/stdout_sinks.h"
#endif
// clang-format on

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_logger_interface.h"

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
void WriteLog(const spdlog::details::log_msg& log_message) {
  logger_instance.WriteLog(log_message);
}

// -----------------------------------------------------------------------------
// CfdLogger
// -----------------------------------------------------------------------------
cfd::core::logger::CfdLogger::CfdLogger(void) {
  // do nothing
}

cfd::core::logger::CfdLogger::~CfdLogger(void) { Finalize(true); }

cfd::core::CfdError cfd::core::logger::CfdLogger::Initialize(void) {
#ifndef CFDCORE_LOG_CONSOLE
  const size_t kRotateFileSize = 1024 * 1024 * 256;
  std::string filepath = "./cfd_debug.log";
#endif

  if (is_initialized_) {
    // do nothing
  } else {
    is_alive_ = true;
    is_initialized_ = true;

    if ((!is_extend_log_) && cfdcore_logger_is_debug) {
      // TODO(k-matsuzawa): only used for debugging
      log_level_ = kCfdLogLevelTrace;
      is_async_ = true;

      is_use_default_logger_ = true;
      std::string cfd_log_name = "cfd";
      spdlog::init_thread_pool(1024 * 128, 5);  // For Initalization
#ifdef CFDCORE_LOG_CONSOLE
      auto stdout_sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
      std::vector<spdlog::sink_ptr> sinks{stdout_sink};
#else
      auto rotating_sink =
          std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
              filepath, kRotateFileSize, 3);
      std::vector<spdlog::sink_ptr> sinks{rotating_sink};
#endif
      auto logger = std::make_shared<spdlog::async_logger>(
          cfd_log_name, sinks.begin(), sinks.end(), spdlog::thread_pool(),
          spdlog::async_overflow_policy::block);
      spdlog::register_logger(logger);
      spdlog::set_level((spdlog::level::level_enum)log_level_);
      default_logger_ = spdlog::get(cfd_log_name);
    }
  }
  return kCfdSuccess;
}

void cfd::core::logger::CfdLogger::Finalize(bool is_finish_process) {
  if (is_alive_) {
    is_alive_ = false;
    if (is_use_default_logger_ && (!is_finish_process)) {
      spdlog::set_level(spdlog::level::level_enum::off);
      try {
        spdlog::shutdown();
      } catch (...) {
        std::cout << "spdlog::shutdown exception." << std::endl;
      }
    }
  }
}

void cfd::core::logger::CfdLogger::SetLogger(void* function_address) {
  this->function_address_ = function_address;
  is_extend_log_ = true;
}

bool cfd::core::logger::CfdLogger::IsEnableLogLevel(CfdLogLevel level) {
  if (is_initialized_ && is_alive_ && (level >= log_level_)) {
    return true;
  }
  return false;
}

void cfd::core::logger::CfdLogger::WriteLog(
    const spdlog::details::log_msg& log_message) {
  if (is_initialized_ && is_alive_) {
    if (function_address_ != nullptr) {
      // extend log
    } else if (default_logger_) {
      // spdlog
      fmt::memory_buffer formatted;
      // spdlog::pattern_formatter formatter;
      spdlog::details::padding_info pad_info;
      spdlog::details::v_formatter formatter(pad_info);
      std::tm tm;
      formatter.format(log_message, tm, formatted);

      default_logger_->log(
          log_message.source, log_message.level, formatted.data());
      // std::cout << "CfdLogger::writeLog OK" << std::endl;
    }
  }
}

}  // namespace logger
}  // namespace core
}  // namespace cfd
