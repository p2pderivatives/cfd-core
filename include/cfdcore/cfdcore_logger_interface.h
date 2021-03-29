// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_logger_interface.h
 *
 * @brief A file that defines the interface for log processing.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_LOGGER_INTERFACE_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_LOGGER_INTERFACE_H_

#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

/**
 * @brief Set a function pointer for log output.
 * @param[in] function_address   Function pointer
 */
CFD_CORE_API void SetLogger(void* function_address);

/**
 * @brief Initialize the log function.
 */
CFD_CORE_API void InitializeLogger(void);

/**
 * @brief Performs termination processing of the log function.
 * @param[in] is_finish_process   Whether at the end of the process
 */
CFD_CORE_API void FinalizeLogger(bool is_finish_process = false);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_LOGGER_INTERFACE_H_
