// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_logger_interface.h
 *
 * @brief ログ処理のインタフェースを定義するファイル。
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_LOGGER_INTERFACE_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_LOGGER_INTERFACE_H_

#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

/**
 * @brief ログ出力用の関数ポインタを設定する。
 * @param[in] function_address   関数ポインタ
 */
CFD_CORE_API void SetLogger(void* function_address);

/**
 * @brief ログ機能の初期化を行う。
 */
CFD_CORE_API void InitializeLogger(void);

/**
 * @brief ログ機能の終了処理を行う。
 * @param[in] is_finish_process   プロセス終了時かどうか
 */
CFD_CORE_API void FinalizeLogger(bool is_finish_process = false);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_LOGGER_INTERFACE_H_
