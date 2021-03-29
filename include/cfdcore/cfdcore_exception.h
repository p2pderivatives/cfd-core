// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_exception.h
 * @brief The cfd exception class definition file.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_EXCEPTION_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_EXCEPTION_H_
#ifdef __cplusplus

#include <exception>
#include <map>
#include <string>

#include "cfdcore/cfdcore_common.h"

#ifndef _GLIBCXX_TXN_SAFE_DYN
/// Include guard (_GLIBCXX_TXN_SAFE_DYN)
#define _GLIBCXX_TXN_SAFE_DYN
#endif
#ifndef _GLIBCXX_USE_NOEXCEPT
/// Include guard (_GLIBCXX_USE_NOEXCEPT)
#define _GLIBCXX_USE_NOEXCEPT noexcept
#endif

namespace cfd {
namespace core {

/**
 * @brief Error code definition.
 */
typedef enum {
  kCfdSuccess = 0,               //!< Successful completion
  kCfdUnknownError = -1,         //!< Unknown error
  kCfdInternalError = -2,        //!< Internal error
  kCfdMemoryFullError = -3,      //!< Memory allocation error
  kCfdIllegalArgumentError = 1,  //!< Invalid argument
  kCfdIllegalStateError = 2,     //!< Illegal state
  kCfdOutOfRangeError = 3,       //!< Out of range value
  kCfdInvalidSettingError = 4,   //!< Improper settings
  kCfdConnectionError = 5,       //!< Connection error
  kCfdDiskAccessError = 6        //!< Disk access error
} CfdError;

/// @brief Error message: Unknown error
const char kCfdUnknownErrorMessage[] = "Unknown error occurred.";

/**
 * @brief CFD exception class.
 */
class CfdException : public std::exception {
 public:
  /**
   * @brief Constructor.
   */
  CfdException()
      : error_code_(kCfdUnknownError), message_(kCfdUnknownErrorMessage) {}
  /**
   * @brief Constructor.
   * @param[in] message   Error message.
   */
  explicit CfdException(const std::string& message)
      : error_code_(kCfdUnknownError), message_(message) {}
  /**
   * @brief Constructor.
   * @param[in] error_code    Error code.
   */
  explicit CfdException(CfdError error_code)
      : error_code_(error_code), message_(kCfdUnknownErrorMessage) {}
  /**
   * @brief Constructor.
   * @param[in] error_code    Error code.
   * @param[in] message       Error message.
   */
  CfdException(CfdError error_code, const std::string& message)
      : error_code_(error_code), message_(message) {}
  /**
   * @brief Destructor.
   */
  virtual ~CfdException(void) _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_USE_NOEXCEPT {
    // do nothing
  }
  /**
   * @brief Get an error message.
   * @return Error message.
   */
  virtual const char* what() const _GLIBCXX_TXN_SAFE_DYN
      _GLIBCXX_USE_NOEXCEPT {
    return message_.c_str();
  }
  /**
   * @brief Get an error code.
   * @return Error code.
   */
  virtual CfdError GetErrorCode() const _GLIBCXX_TXN_SAFE_DYN
      _GLIBCXX_USE_NOEXCEPT {
    return error_code_;
  }
  /**
   * @brief Get the error type according to the error code.
   * @return Error type string.
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
  CfdError error_code_;  ///< error code
  std::string message_;  ///< error message
};

// -----------------------------------------------------------------------------
// InvalidScriptException
// -----------------------------------------------------------------------------
/// @brief Script exception message
const char kCfdInvalidScriptMessage[] = "invalid script error.";

/**
 * @brief Script exception class.
 */
class InvalidScriptException : public CfdException {
 public:
  /**
   * @brief Constructor.
   */
  InvalidScriptException()
      : CfdException(kCfdIllegalArgumentError, kCfdInvalidScriptMessage) {
    // do nothing
  }
  /**
   * @brief Constructor.
   * @param[in] message   error message
   */
  explicit InvalidScriptException(const std::string& message)
      : CfdException(kCfdIllegalArgumentError, message) {
    // do nothing
  }
  /**
   * @brief Destructor.
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
