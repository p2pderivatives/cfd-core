// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_manager.h
 *
 * @brief \~japanese cfd-core管理クラス定義ファイル
 *   \~english Definition of CfdCoreManager class
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
 * @brief \~english cfdcore manaement class
 *   \~japanese cfdcore管理クラス
 */
class CfdCoreManager {
 public:
  /**
   * @brief \~english Construct.
   *   \~japanese コンストラクタ
   */
  CfdCoreManager();
  /**
   * @brief \~english Destruct.
   *   \~japanese デストラクタ
   */
  virtual ~CfdCoreManager();

  /**
   * \~english
   * @brief Initialization of cfd core
   * @param[out] handle_address   cfdcore handle value.
   * \~japanese
   * @brief cfdcoreを初期化する。
   * @param[out] handle_address   cfdcoreハンドル値
   */
  void Initialize(CfdCoreHandle* handle_address);
  /**
   * \~english
   * @brief Finalize cfdcore
   * @param[in] handle      cfdcire handle value
   * @param[in] is_finish_process   boolean check if process is finished
   * \~japanese
   * @brief cfdcoreを終了する。
   * @param[in] handle      cfdcoreハンドル値。
   * @param[in] is_finish_process   プロセス終了時かどうか
   */
  void Finalize(const CfdCoreHandle handle, bool is_finish_process);
  /**
   * \~english
   * @brief get values of supported LibraryFunction
   * @return LibraryFunction bitflag.
   * \~japanese
   * @brief ライブラリがサポートしている機能の値を取得する。
   * @return LibraryFunctionのビットフラグ
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
