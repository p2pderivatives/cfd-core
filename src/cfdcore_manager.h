// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_manager.h
 *
 * @brief cfd-core管理クラス定義ファイルです。
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
 * @brief cfdcore管理クラス。
 */
class CfdCoreManager {
 public:
  /**
   * @brief コンストラクタ。
   */
  CfdCoreManager();
  /**
   * @brief デストラクタ。
   */
  virtual ~CfdCoreManager();

  /**
   * @brief cfdcoreを初期化する。
   * @param[out] handle_address   cfdcoreハンドル値。
   */
  void Initialize(CfdCoreHandle* handle_address);
  /**
   * @brief cfdcoreを終了する。
   * @param[in] handle      cfdcoreハンドル値。
   * @param[in] is_finish_process   プロセス終了時かどうか
   */
  void Finalize(const CfdCoreHandle handle, bool is_finish_process);
  /**
   * @brief ライブラリがサポートしている機能の値を取得する。
   * @return LibraryFunctionのビットフラグ
   */
  uint64_t GetSupportedFunction();

 protected:
  std::vector<int*> handle_list_;  ///< ハンドル一覧
  bool initialized_;               ///< 初期化済みフラグ
  bool finalized_;                 ///< 終了済みフラグ
  std::mutex mutex_;               ///< 排他制御用オブジェクト
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_SRC_CFDCORE_MANAGER_H_
