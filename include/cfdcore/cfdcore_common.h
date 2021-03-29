// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_common.h
 * @brief Common definition file for cfdcore.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COMMON_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COMMON_H_
#include <cstddef>
#include <cstdint>

/**
 * @brief API DLL export definition
 */
#ifndef CFD_CORE_API
#if defined(_WIN32)
#ifdef CFD_CORE_BUILD
#define CFD_CORE_API __declspec(dllexport)
#elif defined(CFD_CORE_SHARED)
#define CFD_CORE_API __declspec(dllimport)
#else
#define CFD_CORE_API
#endif
#elif defined(__GNUC__) && defined(CFD_CORE_BUILD)
#define CFD_CORE_API __attribute__((visibility("default")))
#else
#define CFD_CORE_API
#endif
#endif

/**
 * @brief DLL export definition for class
 */
#ifndef CFD_CORE_EXPORT
#if defined(_WIN32)
#ifdef CFD_CORE_BUILD
#define CFD_CORE_EXPORT __declspec(dllexport)
#elif defined(CFD_CORE_SHARED)
#define CFD_CORE_EXPORT __declspec(dllimport)
#else
#define CFD_CORE_EXPORT
#endif
#elif defined(__GNUC__) && defined(CFD_CORE_BUILD)
#define CFD_CORE_EXPORT __attribute__((visibility("default")))
#else
#define CFD_CORE_EXPORT
#endif
#endif

/**
 * @brief cfd namespace
 */
namespace cfd {
/**
 * @brief cfd::core namespace
 */
namespace core {

/// Handle value of cfdcore.
using CfdCoreHandle = void*;

/**
 * @brief Definition value of the function supported by the library.
 */
enum LibraryFunction {
  kEnableBitcoin = 0x0001,   //!< enable bitcoin function
  kEnableElements = 0x0002,  //!< enable elements function
};

// API
/**
 * @brief Get the value of the function supported by the library.
 * @return Library Function bit flag
 */
CFD_CORE_API uint64_t GetSupportedFunction();
/**
 * @brief Initialize cfdcore.
 * @param[out] handle   Handle value.
 */
CFD_CORE_API void Initialize(CfdCoreHandle* handle);
/**
 * @brief Performs cfdcore termination processing.
 * @param[in] handle    Handle value.
 * @param[in] is_finish_process   Whether at the end of the process.
 */
CFD_CORE_API void Finalize(
    const CfdCoreHandle handle, bool is_finish_process = false);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COMMON_H_
