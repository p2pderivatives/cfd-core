#include "gtest/gtest.h"
#include <string>

#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"

#include "cfdcore/cfdcore_transaction.h"

using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::Script;
using cfd::core::TxInReference;

static const Script exp_script = Script(
    "76a914b0f196804dc7584977ff016b3022fac24cf125b688ac");
static const Txid exp_txid(
    "52656be585f6697b16bdc436805e00560475ea6801ff78f3c0ed1c9a9ef4c74a");
static const uint32_t exp_index = 0;
static const uint32_t exp_sequence = 0xffffffff;

TEST(TxIn, Constractor) {
  {
    TxIn txin(exp_txid, exp_index, exp_sequence);
    EXPECT_EQ(txin.GetVout(), exp_index);
    EXPECT_EQ(txin.GetSequence(), exp_sequence);
    EXPECT_STREQ(txin.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  }

  {
    TxIn txin(exp_txid, exp_index, exp_sequence, exp_script);
    EXPECT_EQ(txin.GetVout(), exp_index);
    EXPECT_EQ(txin.GetSequence(), exp_sequence);
    EXPECT_STREQ(txin.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
    EXPECT_STREQ(txin.GetUnlockingScript().GetHex().c_str(),
                 exp_script.GetHex().c_str());
  }
}

TEST(TxInReference, Constractor) {
  {
    TxIn txin(exp_txid, exp_index, exp_sequence);
    TxInReference txin_ref(txin);

    EXPECT_EQ(txin_ref.GetVout(), exp_index);
    EXPECT_EQ(txin_ref.GetSequence(), exp_sequence);
    EXPECT_STREQ(txin_ref.GetTxid().GetHex().c_str(),
                 exp_txid.GetHex().c_str());
  }
}
