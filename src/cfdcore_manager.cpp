// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_manager.cpp
 *
 * @brief-eng implementation for cfdcore manager class
 * @brief-jp cfdcore管理クラスの実装ファイルです。
 */
#include "wally_core.h"  // NOLINT

#include "cfdcore_manager.h"  // NOLINT

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_logger_interface.h"

namespace cfd {
namespace core {

using logger::info;

/// instance for cfdcore / cfdcoreインスタンス
static CfdCoreManager core_instance;

// -----------------------------------------------------------------------------
// API
// -----------------------------------------------------------------------------
void Initialize(CfdCoreHandle* handle) { core_instance.Initialize(handle); }

void Finalize(const CfdCoreHandle handle, bool is_finish_process) {
  core_instance.Finalize(handle, is_finish_process);
}

uint64_t GetSupportedFunction() {
  return core_instance.GetSupportedFunction();
}

// -----------------------------------------------------------------------------
// Management
// -----------------------------------------------------------------------------
void CfdCoreManager::Initialize(CfdCoreHandle* handle_address) {
  if (handle_address == nullptr) {
    throw CfdException(
        kCfdIllegalArgumentError, "cfd::core::Initialize parameter NULL.");
  }
  if (finalized_) {
    throw CfdException(
        kCfdIllegalStateError, "cfd::core::Initialize already finalized.");
  }

  {
    // Start of exclusive control / 排他制御開始
    std::lock_guard<std::mutex> lock(mutex_);
    if ((!initialized_) && handle_list_.empty()) {
      // Perform initialization processing. 初期化処理実施
      InitializeLogger();

      // Since libwally does not produce errors other than its arguments,
      // will only call the function.
      // libwallyは引数以外でのエラーが発生しない構造のため、呼び出すだけとする。
      wally_init(0);
#if 0
      int wally_ret = wally_init(0);
      if (wally_ret != WALLY_OK) {
        throw CfdException(kCfdInternalError,
                           "cfd::core::Initialize parameter NULL.");
      }
#endif

#if 0
      int hidapi_ret = hid_init();
      if (hidapi_ret != 0) {
        error(CFD_LOG_SOURCE, "hid_init error.");
        // With the error of HIDAPI, should error be ignored?
        // →Pass thru core, check separately the wallet side.
        // throw CfdException(kCfdInternalError, "hid_init error.");

        // HIDAPIエラー時については、エラーを無視するべきか？
        // →coreはスルーして、wallet側で別途確認してもらうようにする。
        // throw CfdException(kCfdInternalError, "hid_init error.");
      }
#endif

      initialized_ = true;
    }

    // Generation and registration of handle / ハンドル生成＆登録
    int* handle = new int[1];
    handle_list_.push_back(handle);
    *handle_address = static_cast<void*>(handle);
    info(CFD_LOG_SOURCE, "core initialize. addr={:p}.", *handle_address);
  }
}

void CfdCoreManager::Finalize(
    const CfdCoreHandle handle, bool is_finish_process) {
  if (initialized_ && (!handle_list_.empty())) {
    // Start of exclusive control / 排他制御開始
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<int*>::iterator ite;
    for (ite = handle_list_.begin(); ite != handle_list_.end(); ++ite) {
      if (handle == *ite) {
        delete[] static_cast<int*>(handle);
        if (!is_finish_process) {
          info(CFD_LOG_SOURCE, "core finalize. addr={:p}.", handle);
        }
        handle_list_.erase(ite);
        break;
      }
    }

    if (handle_list_.empty()) {
      // Perform end processing / 終了処理実施
      FinalizeLogger(is_finish_process);
      wally_cleanup(0);
#if 0
      hid_exit();
#endif
      finalized_ = true;
    }
  }
}

uint64_t CfdCoreManager::GetSupportedFunction() {
  uint64_t support_function = 0;

#ifndef CFD_DISABLE_BITCOIN
  support_function |= LibraryFunction::kEnableBitcoin;
#endif  // CFD_DISABLE_BITCOIN

#ifndef CFD_DISABLE_ELEMENTS
  support_function |= LibraryFunction::kEnableElements;
#endif  // CFD_DISABLE_ELEMENTS

  return support_function;
}

CfdCoreManager::CfdCoreManager()
    : handle_list_(), initialized_(false), finalized_(false), mutex_() {
  // do nothing
}

CfdCoreManager::~CfdCoreManager() {
  if (!handle_list_.empty()) {
    for (CfdCoreHandle handle : handle_list_) {
      Finalize(handle, true);
    }
  }
}

}  // namespace core
}  // namespace cfd
