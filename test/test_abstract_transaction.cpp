#include "gtest/gtest.h"
#include <vector>

#include "wally_core.h"
#include "wally_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_transaction.h"

using cfd::core::AbstractTransaction;
using cfd::core::Transaction;
using cfd::core::Script;
using cfd::core::Txid;
using cfd::core::TxInReference;
using cfd::core::TxOutReference;
using cfd::core::ByteData;
using cfd::core::Amount;
using cfd::core::CfdException;
using cfd::core::CfdError;
using cfd::core::ByteData256;
using cfd::core::StringUtil;

class TestTransaction : public AbstractTransaction {
 public:
  TestTransaction() {
    struct wally_tx *tx_pointer = NULL;
    int ret = wally_tx_init_alloc(2, 0, 0, 0, &tx_pointer);
    if (ret != WALLY_OK) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "transaction data generate error.");
    }
    wally_tx_pointer_ = tx_pointer;
  }
  virtual ~TestTransaction() {
    // do nothing
  }
  bool GetVariableIntTest(const std::string &test_data, uint64_t *value) {
    bool is_success = false;
    std::vector<uint8_t> test_array = StringUtil::StringToByte(test_data);
    size_t size = 0;
    is_success = GetVariableInt(test_array.data(), test_array.size(),
                                value, &size);
    return is_success;
  }

  bool CopyVariableBufferTest(const std::string &test_data,
      std::vector<uint8_t> *buffer) {
    bool is_success = false;
    buffer->resize(test_data.length() + 10);
    std::vector<uint8_t> test_array = StringUtil::StringToByte(test_data);
    uint8_t* ptr = CopyVariableBuffer(test_array.data(), test_array.size(),
                                      buffer->data());
    if (ptr != buffer->data()) {
      int diff_size = ptr - (uint8_t*)buffer->data();
      buffer->resize(diff_size);
      is_success = true;
    }
    return is_success;
  }
  virtual uint32_t GetTxInIndex(const Txid& , uint32_t ) const {
    return 0;
  }
  virtual uint32_t GetTxOutIndex(const Script& ) const {
    return 0;
  }
  virtual uint32_t GetWallyFlag() const {
    return 0;
  }

 protected:
  virtual void CheckTxInIndex(uint32_t , int ,
                              const char* ) const {
    // do nothing
  }
  virtual void CheckTxOutIndex(uint32_t , int ,
                               const char* ) const {
    // do nothing
  }
  virtual ByteData GetByteData(bool ) const {
    return ByteData();
  }
};

TEST(AbstractTransaction, GetVersion) {
  Transaction tx(2, 3);
  EXPECT_EQ(tx.GetVersion(), 2);
}

TEST(AbstractTransaction, GetLockTime) {
  Transaction tx(2, 3);
  EXPECT_EQ(tx.GetLockTime(), 3);
}

TEST(AbstractTransaction, AddTxIn_RemoveTxIn) {
  uint32_t txin_count = 2;
  int32_t version = 2;
  uint32_t locktime = 3;
  uint32_t vout = 0;
  uint32_t seq = 0xffffffff;

  Transaction tx(version, locktime);
  // script is not empty
  EXPECT_NO_THROW(
      tx.AddTxIn(
          Txid(
              "e9f71e1f6787f47af671b62f4e29bda856ec3d51a817c62e1cea7f9f0c0190b6"),
          vout, seq,
          Script("76a914100358d754597ca2f010f6d84f4a0fe74f71f7bb88ac")));

  // script is empty
  EXPECT_NO_THROW(
      tx.AddTxIn(
          Txid(
              "0d0afd7c8e65545f877fa58905d3b50aa114ed885becd6c12232b1d494a7d597"),
          vout, seq, Script()));

  std::vector<TxInReference> list = tx.GetTxInList();
  EXPECT_STREQ(
      list[0].GetTxid().GetHex().c_str(),
      "e9f71e1f6787f47af671b62f4e29bda856ec3d51a817c62e1cea7f9f0c0190b6");
  EXPECT_STREQ(list[0].GetUnlockingScript().GetHex().c_str(),
               "76a914100358d754597ca2f010f6d84f4a0fe74f71f7bb88ac");
  EXPECT_EQ(list[0].GetVout(), vout);
  EXPECT_EQ(list[0].GetSequence(), seq);
  EXPECT_EQ(tx.GetTxInCount(), txin_count);

  // index error
  EXPECT_THROW(tx.RemoveTxIn(3), CfdException);
  // remove success
  EXPECT_NO_THROW(tx.RemoveTxIn(0));
  txin_count--;
  EXPECT_EQ(tx.GetTxInCount(), txin_count);
}

TEST(AbstractTransaction, SetUnlockingScript) {
  int32_t version = 2;
  uint32_t locktime = 3;
  uint32_t vout = 0;
  uint32_t seq = 0xffffffff;

  Transaction tx(version, locktime);
  tx.AddTxIn(
      Txid("e9f71e1f6787f47af671b62f4e29bda856ec3d51a817c62e1cea7f9f0c0190b6"),
      vout, seq, Script("76a914100358d754597ca2f010f6d84f4a0fe74f71f7bb88ac"));

  // error
  EXPECT_THROW(tx.SetUnlockingScript(3, Script()), CfdException);
  EXPECT_THROW(tx.SetUnlockingScript(0, Script("61")), CfdException);

  EXPECT_NO_THROW(
      tx.SetUnlockingScript(
          0,
          Script(
              "47304402201934f30b8a2edc4554961b63ca7d540332d5d2f2769727113676b37e4e8ca7c5022076c5bd921d9c08e1c00d58d27bcef918bf025028a9a91f0f545d18a93dda5860012102158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d82780763")));

  EXPECT_STREQ(
      tx.GetTxIn(0).GetUnlockingScript().GetHex().c_str(),
      "47304402201934f30b8a2edc4554961b63ca7d540332d5d2f2769727113676b37e4e8ca7c5022076c5bd921d9c08e1c00d58d27bcef918bf025028a9a91f0f545d18a93dda5860012102158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d82780763");
}

TEST(AbstractTransaction, SetUnlockingScript_bytedata) {
  int32_t version = 2;
  uint32_t locktime = 3;
  uint32_t vout = 0;
  uint32_t seq = 0xffffffff;

  Transaction tx(version, locktime);
  tx.AddTxIn(
      Txid("e9f71e1f6787f47af671b62f4e29bda856ec3d51a817c62e1cea7f9f0c0190b6"),
      vout, seq, Script("76a914100358d754597ca2f010f6d84f4a0fe74f71f7bb88ac"));

  std::vector<ByteData> bytedatas;
  // error
  EXPECT_THROW(tx.SetUnlockingScript(3, bytedatas), CfdException);

  bytedatas.push_back(
      ByteData(
          "02158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d82780763"));

  EXPECT_NO_THROW(tx.SetUnlockingScript(0, bytedatas));
  EXPECT_STREQ(
      tx.GetTxIn(0).GetUnlockingScript().GetHex().c_str(),
      "2102158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d82780763");
}

TEST(AbstractTransaction, AddScriptWitnessStack_SetScriptWitnessStack_RemoveScriptWitnessStackAll) {
  int32_t version = 2;
  uint32_t locktime = 3;
  uint32_t vout = 0;
  uint32_t seq = 0xffffffff;

  Transaction tx(version, locktime);
  tx.AddTxIn(
      Txid("e9f71e1f6787f47af671b62f4e29bda856ec3d51a817c62e1cea7f9f0c0190b6"),
      vout, seq, Script("76a914100358d754597ca2f010f6d84f4a0fe74f71f7bb88ac"));

  ByteData bytedata;
  // AddScriptWitnessStack
  EXPECT_THROW(tx.AddScriptWitnessStack(3, bytedata), CfdException);

  ByteData bytedata2(
      "02158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d82780763");
  EXPECT_NO_THROW(tx.AddScriptWitnessStack(0, bytedata2));
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[0].GetHex().c_str(),
      "02158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d82780763");

  // SetScriptWitnessStack
  EXPECT_THROW(tx.SetScriptWitnessStack(3, 0, bytedata), CfdException);
  EXPECT_THROW(tx.SetScriptWitnessStack(3, 3, bytedata), CfdException);
  EXPECT_NO_THROW(tx.SetScriptWitnessStack(0, 0, ByteData("82780763")));
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[0].GetHex().c_str(),
      "82780763");
  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 1);

  // RemoveScriptWitnessStackAll
  EXPECT_THROW(tx.RemoveScriptWitnessStackAll(3), CfdException);
  EXPECT_NO_THROW(tx.RemoveScriptWitnessStackAll(0));
  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 0);
}

TEST(AbstractTransaction, AddTxOut_RemoveTxOut) {
  uint32_t txout_count = 1;
  int32_t version = 2;
  uint32_t locktime = 3;
  uint64_t satoshi = 0x12345678;

  Transaction tx(version, locktime);
  // script is not empty
  EXPECT_NO_THROW(
      tx.AddTxOut(Amount::CreateBySatoshiAmount(satoshi),
                  Script("0014913e0b9281dab16f502101ad4e655074396f34c5")));

  std::vector<TxOutReference> list = tx.GetTxOutList();
  EXPECT_EQ(list[0].GetValue(), satoshi);
  EXPECT_STREQ(list[0].GetLockingScript().GetHex().c_str(),
      "0014913e0b9281dab16f502101ad4e655074396f34c5");
  EXPECT_EQ(tx.GetTxOutCount(), txout_count);

  // index error
  EXPECT_THROW(tx.RemoveTxOut(3), CfdException);
  // remove success
  EXPECT_NO_THROW(tx.RemoveTxOut(0));
  txout_count--;
  EXPECT_EQ(tx.GetTxOutCount(), txout_count);
}

TEST(AbstractTransaction, GetValueOut) {
  int32_t version = 2;
  uint32_t locktime = 3;
  uint32_t vout = 0;
  uint32_t seq = 0xffffffff;

  Transaction tx(version, locktime);
  tx.AddTxIn(
      Txid("e9f71e1f6787f47af671b62f4e29bda856ec3d51a817c62e1cea7f9f0c0190b6"),
      vout, seq, Script("76a914100358d754597ca2f010f6d84f4a0fe74f71f7bb88ac"));
  tx.AddTxOut(Amount::CreateBySatoshiAmount(10000),
              Script("0014913e0b9281dab16f502101ad4e655074396f34c5"));
  Amount amount;
  // GetValueOut
  EXPECT_NO_THROW(amount = tx.GetValueOut());
  EXPECT_EQ(amount.GetSatoshiValue(), 10000);

  // GetHash(bool)
  ByteData256 bytedata;
  EXPECT_NO_THROW(bytedata = tx.GetHash());
  EXPECT_STREQ(
      bytedata.GetHex().c_str(),
      "94807f961466e1e236d8192f9a073fb9dea46cad8434c568b55dec0a0f197b0f");

  // GetWitnessHash
  ByteData bytedata2(
      "02158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d82780763");
  EXPECT_NO_THROW(tx.AddScriptWitnessStack(0, bytedata2));
  EXPECT_NO_THROW(bytedata = tx.GetWitnessHash());
  EXPECT_STREQ(
      bytedata.GetHex().c_str(),
      "0cc445f41d8b7af9d9f24b60516b1f4ce18d67595b1ca9143678a8df2a7b7416");

  // GetHex
  std::string hex;
  EXPECT_NO_THROW(hex = tx.GetHex());
  EXPECT_STREQ(
      hex.c_str(),
      "02000000000101b690010c9f7fea1c2ec617a8513dec56a8bd294e2fb671f67af487671f1ef7e9000000001976a914100358d754597ca2f010f6d84f4a0fe74f71f7bb88acffffffff011027000000000000160014913e0b9281dab16f502101ad4e655074396f34c5012102158a304e6dc2225de38fcd378d6252782085b1f316d6747414ae616d8278076303000000");

  // GetTxid
  Txid txid;
  EXPECT_NO_THROW(txid = tx.GetTxid());
  EXPECT_STREQ(
      txid.GetHex().c_str(),
      "0f7b190f0aec5db568c53484ad6ca4deb93f079a2f19d836e2e16614967f8094");
}

TEST(AbstractTransaction, GetVariableInt) {
  TestTransaction tx;
  std::string test_data = "fe11111111";
  uint64_t value = 0;
  EXPECT_TRUE(tx.GetVariableIntTest(test_data, &value));
  EXPECT_EQ(value, 286331153);
}

TEST(AbstractTransaction, CopyVariableBuffer) {
  TestTransaction tx;
  std::string test_data = "12345678";
  std::vector<uint8_t> buffer;
  EXPECT_TRUE(tx.CopyVariableBufferTest(test_data, &buffer));
  EXPECT_STREQ(StringUtil::ByteToString(buffer).c_str(), "0412345678");
}

TEST(AbstractTransaction, TxSizeByException) {
  TestTransaction tx;
  EXPECT_EQ(tx.GetTotalSize(), 10);
  EXPECT_EQ(tx.GetVsize(), 10);
  EXPECT_EQ(tx.GetWeight(), 40);
}

TEST(AbstractTransaction, TxArray) {
  std::vector<AbstractTransaction*> vector_info;
  TestTransaction tx;
  EXPECT_NO_THROW((vector_info.push_back(&tx)));
}

TEST(AbstractTransaction, IsCoinBase) {
  TestTransaction tx;
  bool is_coinbase = false;
  EXPECT_NO_THROW((is_coinbase = tx.IsCoinBase()));
  EXPECT_FALSE(is_coinbase);
}

TEST(AbstractTransaction, GetVsizeFromSize) {
  EXPECT_EQ(2, AbstractTransaction::GetVsizeFromSize(1, 4));
}
