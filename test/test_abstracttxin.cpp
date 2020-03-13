#include "gtest/gtest.h"
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_script.h"

#include "cfdcore/cfdcore_transaction_common.h"

using cfd::core::AbstractTxIn;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::Script;
using cfd::core::ScriptWitness;
using cfd::core::Txid;

const Txid expect_txid = Txid(
    "0d2a5386ec4fe2afb6fbf31b5d51781645ba8bd4a56daa1e7645bd4c4c4646d9");
const uint32_t expect_index = 1;
const uint32_t expect_sequence = 4294967295;
const std::string expect_script_hex =
    "463044022021e8dc7c7cfecfbcc8c1e2eeb52af09dae846e21372ca53b4134512e058da7ba02205cc676dab0aa0b2e91b5dc1ffcbf66bf44e98ff619cf92122e0bfc7502c3a7012102cb356017c8ce8e803946bbd5c978e959ac361e5b858215fa9ced7ac79236df77";  //NOLINT
const Script expect_unlocking_script = Script(expect_script_hex);

TEST(AbstractTxIn, ConstractorGetterSetter) {
  const auto check = [](AbstractTxIn actual) -> void {
    EXPECT_STREQ(expect_txid.GetHex().c_str(),
        actual.GetTxid().GetHex().c_str());
    EXPECT_EQ(expect_index, actual.GetVout());
    EXPECT_STREQ(expect_txid.GetHex().c_str(),
        actual.GetOutPoint().GetTxid().GetHex().c_str());
    EXPECT_EQ(expect_index, actual.GetOutPoint().GetVout());
    EXPECT_EQ(expect_sequence, actual.GetSequence());
    EXPECT_STREQ(expect_script_hex.c_str(),
        actual.GetUnlockingScript().GetScript().GetHex().c_str());
  };

  {
    AbstractTxIn actual = AbstractTxIn(expect_txid, expect_index,
                                       expect_sequence,
                                       expect_unlocking_script);
    check(actual);
  }

  {
    AbstractTxIn actual = AbstractTxIn(expect_txid, expect_index,
                                       expect_sequence);
    actual.SetUnlockingScript(expect_unlocking_script);
    check(actual);
  }
}

TEST(AbstractTxIn, WitnessStack) {
  std::vector<ByteData> expect_stack;
  AbstractTxIn actual = AbstractTxIn(expect_txid, expect_index, expect_sequence,
                                     expect_unlocking_script);

  const auto checkWitnessStack =
      [](AbstractTxIn actual, std::vector<ByteData> expect_stack) -> void {
        EXPECT_STREQ(expect_txid.GetHex().c_str(),
            actual.GetTxid().GetHex().c_str());
        EXPECT_EQ(expect_index, actual.GetVout());
        EXPECT_STREQ(expect_txid.GetHex().c_str(),
            actual.GetOutPoint().GetTxid().GetHex().c_str());
        EXPECT_EQ(expect_index, actual.GetOutPoint().GetVout());
        EXPECT_EQ(expect_sequence, actual.GetSequence());
        EXPECT_STREQ(expect_script_hex.c_str(),
            actual.GetUnlockingScript().GetScript().GetHex().c_str());

        EXPECT_EQ(expect_stack.size(), actual.GetScriptWitnessStackNum());
        std::vector<ByteData> actual_stack = actual.GetScriptWitness().GetWitness();
        for (size_t i = 0; i < actual.GetScriptWitnessStackNum(); ++i) {
          EXPECT_TRUE(expect_stack[i].Equals(actual_stack[i]));
        }
      };

  const auto addWitnessStack = [&actual, &expect_stack](ByteData data) -> void {
    actual.AddScriptWitnessStack(data);
    expect_stack.push_back(data);
  };

  const auto setWitnessStack =
      [&actual, &expect_stack](uint32_t index, ByteData data) -> void {
        ASSERT_NO_THROW(actual.SetScriptWitnessStack(index, data));
        expect_stack[index] = data;
      };

  const auto removeWitnessStack = [&actual, &expect_stack]() -> void {
    actual.RemoveScriptWitnessStackAll();
    expect_stack.clear();
  };

  checkWitnessStack(actual, expect_stack);
  addWitnessStack(ByteData("1111"));
  addWitnessStack(ByteData("aaaa"));
  addWitnessStack(ByteData("3333"));
  checkWitnessStack(actual, expect_stack);
  setWitnessStack(1, ByteData("2222"));
  checkWitnessStack(actual, expect_stack);
  removeWitnessStack();
  addWitnessStack(ByteData("aaaa"));
  checkWitnessStack(actual, expect_stack);
}

TEST(AbstractTxIn, WitnessStackError) {
  AbstractTxIn actual = AbstractTxIn(expect_txid, expect_index, expect_sequence,
                                     expect_unlocking_script);

  try {
    actual.SetScriptWitnessStack(0, ByteData("0123456789"));
  } catch (const CfdException &e) {
    EXPECT_STREQ(e.what(), "vin out_of_range error.");
    return;
  }
  ASSERT_TRUE(false);
}

TEST(AbstractTxIn, IsCoinBaseTest) {
  const Txid empty_txid = Txid(ByteData256());
  const uint32_t max_vout = std::numeric_limits<uint32_t>::max();
  const uint32_t sequence = 4294967295;
  AbstractTxIn coinbase_input = AbstractTxIn(
    empty_txid, max_vout, sequence);
  EXPECT_TRUE(coinbase_input.IsCoinBase());

  coinbase_input = AbstractTxIn(
    empty_txid, max_vout, 0);
  EXPECT_TRUE(coinbase_input.IsCoinBase());

  AbstractTxIn not_coinbase = AbstractTxIn(
    empty_txid, 0, sequence);
  EXPECT_FALSE(not_coinbase.IsCoinBase());

  not_coinbase = AbstractTxIn(
    Txid("0d2a5386ec4fe2afb6fbf31b5d51781645ba8bd4a56daa1e7645bd4c4c4646d9"),
    max_vout, sequence);
  EXPECT_FALSE(not_coinbase.IsCoinBase());
}
