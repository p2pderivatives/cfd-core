#include "gtest/gtest.h"
#include <string>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"

#include "cfdcore/cfdcore_transaction.h"

using cfd::core::AddressType;
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

struct TestEstimateTxInSizeVector {
  AddressType addr_type;
  uint32_t size;
  uint32_t witness_size;
  Script redeem_script;
};

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

TEST(TxIn, EstimateTxInSize) {
  static const std::vector<TestEstimateTxInSizeVector> test_vector = {
    {AddressType::kP2pkhAddress, 149, 0, Script()},
    {AddressType::kP2shAddress, 207, 0, exp_script},
    {AddressType::kP2shP2wpkhAddress, 171, 108, Script()},
    {AddressType::kP2shP2wshAddress, 217, 142, Script("51")},
    {AddressType::kP2wpkhAddress, 149, 108, Script()},
    {AddressType::kP2wshAddress, 207, 166, exp_script},
  };

  for (const auto& test_data : test_vector) {
    uint32_t size = 0;
    uint32_t wit_size = 0;
    EXPECT_NO_THROW((size = TxIn::EstimateTxInSize(
        test_data.addr_type, test_data.redeem_script, &wit_size)));
    EXPECT_EQ(size, test_data.size);
    EXPECT_EQ(wit_size, test_data.witness_size);
  }
}

TEST(TxIn, EstimateTxInVsize) {
  static const std::vector<TestEstimateTxInSizeVector> test_vector = {
    {AddressType::kP2pkhAddress, 149, 0, Script()},
    {AddressType::kP2shAddress, 207, 0, exp_script},
    {AddressType::kP2shP2wpkhAddress, 90, 0, Script()},
    {AddressType::kP2shP2wshAddress, 111, 0, Script("51")},
    {AddressType::kP2wpkhAddress, 68, 0, Script()},
    {AddressType::kP2wshAddress, 83, 0, exp_script},
  };

  for (const auto& test_data : test_vector) {
    uint32_t vsize = 0;
    EXPECT_NO_THROW((vsize = TxIn::EstimateTxInVsize(
        test_data.addr_type, test_data.redeem_script)));
    EXPECT_EQ(vsize, test_data.size);
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
