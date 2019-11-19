// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_exception.h
 * @brief cfdの例外クラス定義ファイルです。
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_EXCEPTION_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_EXCEPTION_H_
#ifdef __cplusplus

#include <exception>
#include <map>
#include <string>

#include "cfdcore/cfdcore_common.h"

#ifndef _GLIBCXX_TXN_SAFE_DYN
/// インクルードガード(_GLIBCXX_TXN_SAFE_DYN)
#define _GLIBCXX_TXN_SAFE_DYN
#endif
#ifndef _GLIBCXX_USE_NOEXCEPT
/// インクルードガード(_GLIBCXX_USE_NOEXCEPT)
#define _GLIBCXX_USE_NOEXCEPT noexcept
#endif

namespace cfd {
namespace core {

/**
 * @brief エラーコード定義
 */
typedef enum {
  kCfdSuccess = 0,               //!< 正常終了
  kCfdUnknownError = -1,         //!< 不明なエラー
  kCfdInternalError = -2,        //!< 内部エラー
  kCfdMemoryFullError = -3,      //!< メモリ確保エラー
  kCfdIllegalArgumentError = 1,  //!< 引数不正
  kCfdIllegalStateError = 2,     //!< 状態不正
  kCfdOutOfRangeError = 3,       //!< 範囲外の値
  kCfdInvalidSettingError = 4,   //!< 設定不正
  kCfdConnectionError = 5,       //!< 接続エラー
  kCfdDiskAccessError = 6        //!< ディスクアクセスエラー
} CfdError;

/// @brief エラーメッセージ：不明なエラー
const char kCfdUnknownErrorMessage[] = "Unknown error occurred.";

/**
 * @brief CFD例外クラス
 */
class CfdException : public std::exception {
 public:
  /**
   * @brief コンストラクタ
   */
  CfdException()
      : error_code_(kCfdUnknownError), message_(kCfdUnknownErrorMessage) {}
  /**
   * @brief コンストラクタ
   * @param[in] message   エラーメッセージ
   */
  explicit CfdException(const std::string& message)
      : error_code_(kCfdUnknownError), message_(message) {}
  /**
   * @brief コンストラクタ
   * @param[in] error_code    エラーコード
   */
  explicit CfdException(CfdError error_code)
      : error_code_(error_code), message_(kCfdUnknownErrorMessage) {}
  /**
   * @brief コンストラクタ
   * @param[in] error_code    エラーコード
   * @param[in] message       エラーメッセージ
   */
  CfdException(CfdError error_code, const std::string& message)
      : error_code_(error_code), message_(message) {}
  /**
   * @brief デストラクタ
   */
  virtual ~CfdException(void) _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_USE_NOEXCEPT {
    // do nothing
  }
  /**
   * @brief エラーメッセージを取得する.
   * @return エラーメッセージ
   */
  virtual const char* what() const _GLIBCXX_TXN_SAFE_DYN
      _GLIBCXX_USE_NOEXCEPT {
    return message_.c_str();
  }
  /**
   * @brief エラーコードを取得する.
   * @return エラーコード
   */
  virtual CfdError GetErrorCode() const _GLIBCXX_TXN_SAFE_DYN
      _GLIBCXX_USE_NOEXCEPT {
    return error_code_;
  }
  /**
   * @brief エラーコードに即したエラータイプを取得する.
   * @return エラータイプ文字列
   */
  virtual std::string GetErrorType() const _GLIBCXX_TXN_SAFE_DYN
      _GLIBCXX_USE_NOEXCEPT {
    static const std::map<CfdError, std::string> kErrorTypeMap(
        {{kCfdSuccess, "successful_completion"},
         {kCfdUnknownError, "unknown_error"},
         {kCfdInternalError, "internal_error"},
         {kCfdMemoryFullError, "memory_full"},
         {kCfdIllegalArgumentError, "illegal_argument"},
         {kCfdIllegalStateError, "illegal_state"},
         {kCfdOutOfRangeError, "out_of_range"},
         {kCfdInvalidSettingError, "invalid_setting"},
         {kCfdConnectionError, "connection_error"},
         {kCfdDiskAccessError, "disk_access_error"}});
    return kErrorTypeMap.at(error_code_);
  }

 protected:
  CfdError error_code_;  ///< エラーコード
  std::string message_;  ///< エラーメッセージ
};

// -----------------------------------------------------------------------------
// InvalidScriptException
// -----------------------------------------------------------------------------
/// @brief スクリプト例外メッセージ
const char kCfdInvalidScriptMessage[] = "invalid script error.";

/**
 * @brief スクリプト例外クラス.
 */
class InvalidScriptException : public CfdException {
 public:
  /**
   * @brief コンストラクタ.
   */
  InvalidScriptException()
      : CfdException(kCfdIllegalArgumentError, kCfdInvalidScriptMessage) {
    // do nothing
  }
  /**
   * @brief コンストラクタ.
   * @param[in] message   エラーメッセージ
   */
  explicit InvalidScriptException(const std::string& message)
      : CfdException(kCfdIllegalArgumentError, message) {
    // do nothing
  }
  /**
   * @brief デストラクタ.
   */
  virtual ~InvalidScriptException(void)
      _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_USE_NOEXCEPT {
    // do nothing
  }
};

}  // namespace core
}  // namespace cfd

#endif  // __cplusplus
#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_EXCEPTION_H_
