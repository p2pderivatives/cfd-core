// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_manager.h
 *
 * @brief-eng definition for cfd-core manager class
 * @brief-jp cfd-core管理クラス定義ファイルです。
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
 * @brief cfdcore related class / cfdcore管理クラス。
 */
class CfdCoreManager {
 public:
  /**
   * @brief Construct / コンストラクタ。
   */
  CfdCoreManager();
  /**
   * @brief Destruct / デストラクタ。
   */
  virtual ~CfdCoreManager();

  /**
   * @brief Initialization of cfd cord / cfdcoreを初期化する。
   * @param[out] handle_address   cfdcore handle value.  cfdcoreハンドル値。
   */
  void Initialize(CfdCoreHandle* handle_address);
  /**
   * @brief Finalize cfdcore / cfdcoreを終了する。
   * @param[in] handle      cfdcire handle value / cfdcoreハンドル値。
   * @param[in] is_finish_process   boolean check if process is finished
                                    プロセス終了時かどうか
   */
  void Finalize(const CfdCoreHandle handle, bool is_finish_process);
  /**
   * @brief-eng get values of supported LibraryFunction
   * @brief-jp ライブラリがサポートしている機能の値を取得する。
   * @return LibraryFunction bitflag.  LibraryFunctionのビットフラグ
   */
  uint64_t GetSupportedFunction();

 protected:
  std::vector<int*> handle_list_;  ///< Handle list /  ハンドル一覧
  bool initialized_;               ///< Initalized flag /  初期化済みフラグ
  bool finalized_;                 ///< Finalized Flag /  終了済みフラグ
  std::mutex mutex_;               ///< Exclusive control object /
                                   ///< 排他制御用オブジェクト
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_SRC_CFDCORE_MANAGER_H_
