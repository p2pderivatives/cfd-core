#include "gtest/gtest.h"
#include <string>

#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"

#include "cfdcore/cfdcore_transaction_common.h"

using cfd::core::Amount;
using cfd::core::AbstractTxOut;
using cfd::core::Script;

const Amount expect_value = Amount::CreateByCoinAmount(0.5);
const std::string expect_script_hex =
    "76a914b0f196804dc7584977ff016b3022fac24cf125b688ac";
const Script expect_locking_script = Script(expect_script_hex);

TEST(AbstractTxOut, ConstractorGetterSetter) {
  {
    AbstractTxOut actual = AbstractTxOut(expect_value, expect_locking_script);
    EXPECT_EQ(expect_value, actual.GetValue());
    EXPECT_STREQ(expect_script_hex.c_str(),
                 actual.GetLockingScript().GetScript().GetHex().c_str());
  }

  {
    AbstractTxOut actual = AbstractTxOut(expect_locking_script);
    EXPECT_EQ(0, actual.GetValue());
    EXPECT_STREQ(expect_script_hex.c_str(),
                 actual.GetLockingScript().GetScript().GetHex().c_str());
  }

  {
    AbstractTxOut actual = AbstractTxOut();
    EXPECT_EQ(Amount::CreateBySatoshiAmount(0), actual.GetValue());
    EXPECT_STREQ("", actual.GetLockingScript().GetScript().GetHex().c_str());
  }

  {
    AbstractTxOut actual = AbstractTxOut();
    Amount amt = Amount::CreateBySatoshiAmount(int64_t{10});
    actual.SetValue(amt);
    EXPECT_EQ(amt, actual.GetValue());
    EXPECT_STREQ("", actual.GetLockingScript().GetScript().GetHex().c_str());
  }
}
