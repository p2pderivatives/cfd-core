// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_common.h
 * @brief cfdcoreの共通定義ファイル。
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COMMON_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COMMON_H_
#include <cstddef>
#include <cstdint>

/**
 * @brief APIのDLLエクスポート定義
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
 * @brief クラスのDLLエクスポート定義
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
 * @brief cfd名前空間
 */
namespace cfd {
/**
 * @brief cfd::core名前空間
 */
namespace core {

/// cfdcoreのハンドル値。
using CfdCoreHandle = void*;

/**
 * @brief ライブラリがサポートしている機能の定義値
 */
enum LibraryFunction {
  kEnableBitcoin = 0x0001,   //!< enable bitcoin function
  kEnableElements = 0x0002,  //!< enable elements function
};

// API
/**
 * @brief ライブラリがサポートしている機能の値を取得する。
 * @return LibraryFunctionのビットフラグ
 */
CFD_CORE_API uint64_t GetSupportedFunction();
/**
 * @brief cfdcoreの初期化を行う。
 * @param[out] handle   ハンドル値。
 */
CFD_CORE_API void Initialize(CfdCoreHandle* handle);
/**
 * @brief cfdcoreの終了処理を行う。
 * @param[in] handle    ハンドル値。
 * @param[in] is_finish_process   プロセス終了時かどうか
 */
CFD_CORE_API void Finalize(
    const CfdCoreHandle handle, bool is_finish_process = false);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_COMMON_H_
