// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_manager.h
 *
 * @brief Definition of CfdCoreManager class
 *
 */
#ifndef CFD_CORE_SRC_CFDCORE_MANAGER_H_
#define CFD_CORE_SRC_CFDCORE_MANAGER_H_

#include <memory>
#include <mutex>  // NOLINT
#include <vector>

#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

/**
 * @brief cfdcore manaement class
 */
class CfdCoreManager {
 public:
  /**
   * @brief Construct.
   */
  CfdCoreManager();
  /**
   * @brief Destructor.
   */
  virtual ~CfdCoreManager();

  /**
   * @brief Initialization of cfd core
   * @param[out] handle_address   cfdcore handle value.
   */
  void Initialize(CfdCoreHandle* handle_address);
  /**
   * @brief Finalize cfdcore
   * @param[in] handle      cfdcire handle value
   * @param[in] is_finish_process   boolean check if process is finished
   */
  void Finalize(const CfdCoreHandle handle, bool is_finish_process);
  /**
   * @brief get values of supported LibraryFunction
   * @return LibraryFunction bitflag.
   */
  uint64_t GetSupportedFunction();

 protected:
  std::vector<int*> handle_list_;  ///< Handle list
  bool initialized_;               ///< Initalized flag
  bool finalized_;                 ///< Finalized flag
  std::mutex mutex_;               ///< Exclusive control object
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_SRC_CFDCORE_MANAGER_H_
