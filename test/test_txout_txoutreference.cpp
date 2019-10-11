#include "gtest/gtest.h"
#include <string>

#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"

#include "cfdcore/cfdcore_transaction.h"

using cfd::core::Amount;
using cfd::core::TxOut;
using cfd::core::Script;
using cfd::core::TxOutReference;

static const Script exp_script = Script(
    "76a914b0f196804dc7584977ff016b3022fac24cf125b688ac");

TEST(TxOut, Constractor) {
  {
    int64_t satoshi = 0;
    TxOut txout;
    EXPECT_EQ(txout.GetValue().GetSatoshiValue(), satoshi);
    EXPECT_EQ(txout.GetLockingScript().IsEmpty(), true);
  }

  {
    int64_t satoshi = 1000000;
    TxOut txout(Amount::CreateBySatoshiAmount(satoshi), exp_script);
    EXPECT_EQ(txout.GetValue().GetSatoshiValue(), satoshi);
    EXPECT_EQ(txout.GetLockingScript().IsEmpty(), false);
    EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(),
                 exp_script.GetHex().c_str());
  }
}

TEST(TxOutReference, Constractor) {
  {
    int64_t satoshi = 1000000;
    TxOut txout(Amount::CreateBySatoshiAmount(satoshi), exp_script);
    TxOutReference txout_ref(txout);

    EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), satoshi);
    EXPECT_EQ(txout_ref.GetLockingScript().IsEmpty(), false);
    EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
                 exp_script.GetHex().c_str());
  }
}
