// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_logger.h
 * @brief definition file for logger
 */
#ifndef CFD_CORE_SRC_INCLUDE_CFDCORE_CFDCORE_LOGGER_H_
#define CFD_CORE_SRC_INCLUDE_CFDCORE_CFDCORE_LOGGER_H_

#include <memory>
#include <string>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger_interface.h"
#include "spdlog/spdlog.h"

namespace cfd {
namespace core {
/**
 * @brief cfd::core::logger名前空間
 */
namespace logger {

/**
 * @brief cfdのログレベル定義
 */
typedef enum {
  kCfdLogLevelOff = SPDLOG_LEVEL_OFF,            //!< ログ機能OFF
  kCfdLogLevelCritical = SPDLOG_LEVEL_CRITICAL,  //!< Criticalログ
  kCfdLogLevelError = SPDLOG_LEVEL_ERROR,        //!< Errorログ
  kCfdLogLevelWarning = SPDLOG_LEVEL_WARN,       //!< Warningログ
  kCfdLogLevelInfo = SPDLOG_LEVEL_INFO,          //!< Informationログ
  kCfdLogLevelDebug = SPDLOG_LEVEL_DEBUG,        //!< Debugログ
  kCfdLogLevelTrace = SPDLOG_LEVEL_TRACE         //!< Traceログ
} CfdLogLevel;

/**
 * @brief ソース位置情報定義マクロ
 */
#define CFD_LOG_SOURCE \
  spdlog::source_loc { SPDLOG_FILE_BASENAME(__FILE__), __LINE__, __FUNCTION__ }
/**
 * @brief ファイル位置情報定義マクロ
 */
#define CFD_LOG_FILE SPDLOG_FILE_BASENAME(__FILE__)

/**
 * @brief ログレベル有効可否をチェックします。
 * @param[in] level   チェックするログレベル
 * @retval true   有効
 * @retval false  無効
 */
CFD_CORE_API bool IsEnableLogLevel(cfd::core::logger::CfdLogLevel level);
/**
 * @brief ログを書き込みます。
 * @param[in] log_message     ログ出力情報
 */
CFD_CORE_API void WriteLog(const spdlog::details::log_msg &log_message);

/**
 * @brief ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] lvl         ログレベル
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void log(
    spdlog::source_loc source, cfd::core::logger::CfdLogLevel lvl,
    const char *fmt, const Args &... args) {
  if (cfd::core::logger::IsEnableLogLevel(lvl)) {
    using spdlog::details::fmt_helper::to_string_view;
    fmt::memory_buffer buf;
    fmt::format_to(buf, fmt, args...);
    std::string log_name = "cfd";
    spdlog::details::log_msg log_msg(
        source, &log_name, (spdlog::level::level_enum)lvl,
        to_string_view(buf));

    // 書き込みは下回りで行う。
    // spdlogのヘッダを使うのは致し方なし
    cfd::core::logger::WriteLog(log_msg);
  }
}

/**
 * @brief ログ出力を行う。
 * @param[in] lvl         ログレベル
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void log(
    cfd::core::logger::CfdLogLevel lvl, const char *fmt,
    const Args &... args) {
  log(spdlog::source_loc{}, lvl, fmt, args...);
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void trace(spdlog::source_loc source, const char *fmt, const Args &... args) {
  log(source, kCfdLogLevelTrace, fmt, args...);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void debug(spdlog::source_loc source, const char *fmt, const Args &... args) {
  log(source, cfd::core::logger::kCfdLogLevelDebug, fmt, args...);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void info(spdlog::source_loc source, const char *fmt, const Args &... args) {
  log(source, cfd::core::logger::kCfdLogLevelInfo, fmt, args...);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void warn(spdlog::source_loc source, const char *fmt, const Args &... args) {
  log(source, cfd::core::logger::kCfdLogLevelWarning, fmt, args...);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void error(spdlog::source_loc source, const char *fmt, const Args &... args) {
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
    spdlog::source_loc source, const char *fmt, const Args &... args) {
  log(source, cfd::core::logger::kCfdLogLevelCritical, fmt, args...);
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void trace(const char *fmt, const Args &... args) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelTrace, fmt,
      args...);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void debug(const char *fmt, const Args &... args) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelDebug, fmt,
      args...);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void info(const char *fmt, const Args &... args) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelInfo, fmt, args...);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void warn(const char *fmt, const Args &... args) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelWarning, fmt,
      args...);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void error(const char *fmt, const Args &... args) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelError, fmt,
      args...);
}

/**
 * @brief クリティカルログ出力を行う。
 * @param[in] fmt         出力フォーマット
 * @param[in] args        引数
 */
template <typename... Args>
void critical(const char *fmt, const Args &... args) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelCritical, fmt,
      args...);
}

/**
 * @brief ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] lvl         ログレベル
 * @param[in] fmt         出力フォーマット
 */
template <typename... Args>
void log(
    spdlog::source_loc source, cfd::core::logger::CfdLogLevel lvl,
    const char *fmt) {
  if (cfd::core::logger::IsEnableLogLevel(lvl)) {
    using spdlog::details::fmt_helper::to_string_view;
    fmt::memory_buffer buf;
    fmt::format_to(buf, fmt);
    std::string log_name = "cfd";
    spdlog::details::log_msg log_msg(
        source, &log_name, (spdlog::level::level_enum)lvl,
        to_string_view(buf));

    // 書き込みは下回りで行う。
    // spdlogのヘッダを使うのは致し方なし
    cfd::core::logger::WriteLog(log_msg);
  }
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void trace(spdlog::source_loc source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelTrace, msg);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void debug(spdlog::source_loc source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelDebug, msg);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void info(spdlog::source_loc source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelInfo, msg);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void warn(spdlog::source_loc source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelWarning, msg);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void error(spdlog::source_loc source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelError, msg);
}

/**
 * @brief クリティカルログ出力を行う。
 * @param[in] source      ソース位置
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void critical(spdlog::source_loc source, const T &msg) {
  log(source, cfd::core::logger::kCfdLogLevelCritical, msg);
}

/**
 * @brief トレースログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void trace(const T &msg) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelTrace, msg);
}

/**
 * @brief デバッグログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void debug(const T &msg) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelDebug, msg);
}

/**
 * @brief 情報ログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void info(const T &msg) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelInfo, msg);
}

/**
 * @brief ワーニングログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void warn(const T &msg) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelWarning, msg);
}

/**
 * @brief エラーログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void error(const T &msg) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelError, msg);
}

/**
 * @brief クリティカルログ出力を行う。
 * @param[in] msg         出力フォーマット
 */
template <typename T>
void critical(const T &msg) {
  log(spdlog::source_loc{}, cfd::core::logger::kCfdLogLevelCritical, msg);
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
   * @brief ログを出力する。
   * @param[in] log_message ログメッセージ
   */
  void WriteLog(const spdlog::details::log_msg &log_message);

 private:
  /// aliveフラグ
  bool is_alive_ = false;

  /// ログレベル
  cfd::core::logger::CfdLogLevel log_level_ = kCfdLogLevelOff;

  /// 初期化済みかどうか
  bool is_initialized_ = false;

  /// 同期フラグ
  bool is_async_ = false;

  /// 拡張ログフラグ
  bool is_extend_log_ = false;

  /// defaultロガーの使用有無
  bool is_use_default_logger_ = false;

  /// defaultロガー
  std::shared_ptr<spdlog::logger> default_logger_ = nullptr;

  /// 関数ポインタ
  void *function_address_ = nullptr;
};

}  // namespace logger
}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_SRC_INCLUDE_CFDCORE_CFDCORE_LOGGER_H_
