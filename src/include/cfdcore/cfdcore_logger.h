// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_logger.h
 * @brief definition file for logger
 */
#ifndef CFD_CORE_SRC_INCLUDE_CFDCORE_CFDCORE_LOGGER_H_
#define CFD_CORE_SRC_INCLUDE_CFDCORE_CFDCORE_LOGGER_H_
#if defined(CFD_CORE_SHARED) && !defined(FMT_SHARED)
#define FMT_SHARED
#endif

#include <memory>
#include <string>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger_interface.h"
#include "fmt/core.h"

namespace cfd {
namespace core {
/**
 * @brief cfd::core::logger namespace
 */
namespace logger {

/**
 * @brief cfd log level
 */
typedef enum {
  kCfdLogLevelOff,       //!< off
  kCfdLogLevelCritical,  //!< Critical
  kCfdLogLevelError,     //!< Error
  kCfdLogLevelWarning,   //!< Warning
  kCfdLogLevelInfo,      //!< Information
  kCfdLogLevelDebug,     //!< Debug
  kCfdLogLevelTrace      //!< Trace
} CfdLogLevel;

/**
 * @brief Get the basename of __FILE__ (at compile time if possible)
 */
#if FMT_HAS_FEATURE(__builtin_strrchr)
#define LOG_STRRCHR(str, sep) __builtin_strrchr(str, sep)
#else
#define LOG_STRRCHR(str, sep) strrchr(str, sep)
#endif  // __builtin_strrchr

/**
 * @brief get basename macro.
 */
#ifdef _WIN32
#define LOG_FILE_BASENAME(file) LOG_STRRCHR("\\" file, '\\') + 1
#else
#define LOG_FILE_BASENAME(file) LOG_STRRCHR("/" file, '/') + 1
#endif

/**
 * @brief source location.
 */
struct CfdSourceLocation {
  const char *filename;  //!< file name
  int line;              //!< file line
  const char *funcname;  //!< function name
};

/**
 * @brief source position macro
 */
#define CFD_LOG_SOURCE \
  cfd::core::logger::CfdSourceLocation { \
    LOG_FILE_BASENAME(__FILE__), __LINE__, __FUNCTION__ \
  }

/**
 * @brief file position macro
 */
#define CFD_LOG_FILE LOG_FILE_BASENAME(__FILE__)

/**
 * @brief Checks if the log level is valid or not.
 * @param[in] level   log level
 * @retval true   valid
 * @retval false  invalid
 */
CFD_CORE_API bool IsEnableLogLevel(cfd::core::logger::CfdLogLevel level);
/**
 * @brief Write log message.
 * @param[in] location        location.
 * @param[in] level           log level
 * @param[in] log_message     logging message.
 */
CFD_CORE_API void WriteLog(
    const CfdSourceLocation &location, cfd::core::logger::CfdLogLevel level,
    const std::string &log_message);

/**
 * @brief ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] lvl         ログレベル
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void log(
    const CfdSourceLocation &source, cfd::core::logger::CfdLogLevel lvl,
    const char *fmt, Args &&...args) {
  if (cfd::core::logger::IsEnableLogLevel(lvl)) {
    auto message = fmt::format(fmt, args...);
    // std::string message = fmt::format(std::locale::messages, fmt, args...);
    cfd::core::logger::WriteLog(source, lvl, message);
  }
}

/**
 * @brief ログ出力を行う。
 * @param[in] lvl         ログレベル
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void log(cfd::core::logger::CfdLogLevel lvl, const char *fmt, Args &&...args) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, "log"};
  log(location, lvl, fmt, args...);
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void trace(const CfdSourceLocation &source, const char *fmt, Args &&...args) {
  log(source, kCfdLogLevelTrace, fmt, args...);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void debug(const CfdSourceLocation &source, const char *fmt, Args &&...args) {
  log(source, cfd::core::logger::kCfdLogLevelDebug, fmt, args...);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void info(const CfdSourceLocation &source, const char *fmt, Args &&...args) {
  log(source, cfd::core::logger::kCfdLogLevelInfo, fmt, args...);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void warn(const CfdSourceLocation &source, const char *fmt, Args &&...args) {
  log(source, cfd::core::logger::kCfdLogLevelWarning, fmt, args...);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void error(const CfdSourceLocation &source, const char *fmt, Args &&...args) {
  log(source, cfd::core::logger::kCfdLogLevelError, fmt, args...);
}

/**
 * @brief クリティカルログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void critical(
    const CfdSourceLocation &source, const char *fmt, Args &&...args) {
  log(source, cfd::core::logger::kCfdLogLevelCritical, fmt, args...);
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void trace(const char *fmt, Args &&...args) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelTrace, fmt, args...);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void debug(const char *fmt, Args &&...args) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelDebug, fmt, args...);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void info(const char *fmt, Args &&...args) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelInfo, fmt, args...);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void warn(const char *fmt, Args &&...args) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelWarning, fmt, args...);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void error(const char *fmt, Args &&...args) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelError, fmt, args...);
}

/**
 * @brief クリティカルログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void critical(const char *fmt, Args &&...args) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelCritical, fmt, args...);
}

/**
 * @brief ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] lvl         ログレベル
 * @param[in] fmt         出力フォーマット
 */
template <typename... Args>
void log(
    const CfdSourceLocation &source, cfd::core::logger::CfdLogLevel lvl,
    const char *fmt) {
  if (cfd::core::logger::IsEnableLogLevel(lvl)) {
    cfd::core::logger::WriteLog(source, lvl, fmt);
  }
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void trace(const CfdSourceLocation &source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelTrace, msg);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void debug(const CfdSourceLocation &source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelDebug, msg);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void info(const CfdSourceLocation &source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelInfo, msg);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void warn(const CfdSourceLocation &source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelWarning, msg);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void error(const CfdSourceLocation &source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelError, msg);
}

/**
 * @brief クリティカルログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void critical(const CfdSourceLocation &source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelCritical, msg);
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void trace(const T &msg) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelTrace, msg);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void debug(const T &msg) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelDebug, msg);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void info(const T &msg) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelInfo, msg);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void warn(const T &msg) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelWarning, msg);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void error(const T &msg) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelError, msg);
}

/**
 * @brief クリティカルログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void critical(const T &msg) {
  CfdSourceLocation location{"cfdcore_logger.h", __LINE__, __FUNCTION__};
  log(location, cfd::core::logger::kCfdLogLevelCritical, msg);
}

/**
 * @brief ログ制御を行う。
 */
class CfdLogger {
 public:
  /**
   * @brief コンストラクタ
   */
  CfdLogger();
  /**
   * @brief デストラクタ
   */
  ~CfdLogger();
  /**
   * @brief 初期化処理を行う。
   * @return エラーコード
   */
  cfd::core::CfdError Initialize(void);
  /**
   * @brief 終了処理を行う。
   * @param[in] is_finish_process プロセス終了するかどうか
   */
  void Finalize(bool is_finish_process);
  /**
   * @brief Loggerを設定する。
   * @param[in] function_address 関数ポインタ
   */
  void SetLogger(void *function_address);
  /**
   * @brief 出力有無を判定する。
   * @param[in] level ログレベル
   * @return ログ出力有無
   */
  bool IsEnableLogLevel(cfd::core::logger::CfdLogLevel level);
  /**
   * @brief Write log message.
   * @param[in] location        location.
   * @param[in] level           log level
   * @param[in] log_message     logging message.
   */
  void WriteLog(
      const CfdSourceLocation &location, cfd::core::logger::CfdLogLevel level,
      const std::string &log_message);

 private:
  /// aliveフラグ
  bool is_alive_ = false;

  /// ログレベル
  cfd::core::logger::CfdLogLevel log_level_ = kCfdLogLevelOff;

  /// 初期化済みかどうか
  bool is_initialized_ = false;

  // async flag
  // bool is_async_ = false;

  /// 拡張ログフラグ
  bool is_extend_log_ = false;

  /// defaultロガーの使用有無
  bool is_use_default_logger_ = false;

  /// defaultロガー
  void *default_logger_ = nullptr;

  /// 関数ポインタ
  void *function_address_ = nullptr;
};

}  // namespace logger
}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_SRC_INCLUDE_CFDCORE_CFDCORE_LOGGER_H_
