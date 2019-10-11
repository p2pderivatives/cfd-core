#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore_manager.h"   // NOLINT

using cfd::core::CfdException;
using cfd::core::CfdCoreHandle;
using cfd::core::Initialize;
using cfd::core::Finalize;
using cfd::core::GetSupportedFunction;
using cfd::core::CfdCoreManager;
using cfd::core::LibraryFunction;

class CfdCoreManagerFinalizedTest : public CfdCoreManager {
 public:
  CfdCoreManagerFinalizedTest() {
    finalized_ = true;
  }
  virtual ~CfdCoreManagerFinalizedTest() {
    // do nothing
  }
};

static uint64_t GetSupportedFunctionExpect() {
  uint64_t exp_function = 0;
#ifndef CFD_DISABLE_BITCOIN
  exp_function |= LibraryFunction::kEnableBitcoin;
#endif
#ifndef CFD_DISABLE_ELEMENTS
  exp_function |= LibraryFunction::kEnableElements;
#endif
  return exp_function;
}

TEST(cfdcore_manager, Initialize) {
  // 確保したハンドルはプロセス終了時に自動解放させる
  CfdCoreHandle  handle_ = nullptr;
  EXPECT_NO_THROW((Initialize(&handle_)));
  // error
  CfdCoreHandle* p_handle = nullptr;
  EXPECT_THROW((Initialize(p_handle)), CfdException);
}

TEST(cfdcore_manager, Finalize) {
  // error only
  CfdCoreHandle handle = nullptr;
  EXPECT_NO_THROW((Finalize(handle)));
}

TEST(cfdcore_manager, GetSupportedFunction) {
  EXPECT_EQ(GetSupportedFunction(), GetSupportedFunctionExpect());
}

TEST(CfdCoreManager, Initialize) {
  CfdCoreManagerFinalizedTest finalize_test;
  CfdCoreHandle handle = nullptr;
  EXPECT_THROW((finalize_test.Initialize(&handle)), CfdException);
}

TEST(CfdCoreManager, Destructor) {
  CfdCoreManager* object = new CfdCoreManager();
  EXPECT_EQ(object->GetSupportedFunction(), GetSupportedFunctionExpect());
  delete object;
}
