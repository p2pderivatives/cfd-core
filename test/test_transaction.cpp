#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::AbstractTransaction;
using cfd::core::Amount;
using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::HashType;
using cfd::core::Script;
using cfd::core::SigHashAlgorithm;
using cfd::core::SigHashType;
using cfd::core::Transaction;
using cfd::core::Txid;
using cfd::core::TxInReference;
using cfd::core::TxOutReference;
using cfd::core::WitnessVersion;

static const int32_t exp_version = 2;
static const uint32_t exp_locktime = 0;
static const std::string exp_tx_witness =
    "02000000000101f1993fe8e7189542ee4506258e170201be292703cd275acb09ece16672fd848b0000000017160014703e50206e4d27ad1340a7b6a0d94563a3fb768afeffffff02080410240100000017a9141e60c63c6d099ee2b48eded11acfdf3a79a891f48700e1f5050000000017a9142699570770f32e0cf3e1d12d81064fbc45899e8a870247304402202b12edc9a75edd70a0e4261c5816efa2c5256e3f8bcffdd49182bd9f791c74e902201e3ae5c1062a83d787098322b3071fe68c4b181e0088b0e0087020495adaf6e3012102f466d403c0c4057257e7bcbed1d172880fe75f337c77df5490ad9bc8cc2d6a1600000000";
static const std::string exp_tx_legacy =
    "0200000001c6d2ea36e2e802b52ddac665dacbed2f831b5263459e1ca734f5c945d7515e40000000006a47304402205a2f94921f645669b2b4e073da43e6a5d32335b50207f9d27f0e8a8c0a24e75902205dea52d27ad747f2df786e0ad737595cf9c5a489143170668399764a5b4be44a01210229e026bab56c1c41d16e67f084362aef204b5b7ea08dafc2fb2e0db89d9c9551feffffff0178de052a0100000017a914d8de653e7763cc37305a00fc79a491ab70e2e5cb8700000000";

TEST(Transaction, ConstructorGetter) {
  {
    Transaction empty_tx;
    EXPECT_EQ(empty_tx.GetVersion(), exp_version);
    EXPECT_EQ(empty_tx.GetLockTime(), exp_locktime);
    EXPECT_STREQ(empty_tx.GetHex().c_str(), "02000000000000000000");

    // new transaction
    Transaction tx(exp_version, exp_locktime);
    EXPECT_EQ(tx.GetVersion(), exp_version);
    EXPECT_EQ(tx.GetLockTime(), exp_locktime);
    EXPECT_STREQ(
        Txid(tx.GetHash()).GetHex().c_str(),
        "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a");
    EXPECT_STREQ(
        tx.GetTxid().GetHex().c_str(),
        "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a");
    EXPECT_STREQ(tx.GetHex().c_str(), "02000000000000000000");
    EXPECT_EQ(tx.GetTotalSize(), 10);
    EXPECT_EQ(tx.GetVsize(), 10);
    EXPECT_EQ(tx.GetWeight(), 40);
    EXPECT_EQ(tx.GetTxInCount(), 0);
    EXPECT_EQ(tx.GetTxOutCount(), 0);
    EXPECT_THROW(tx.GetTxIn(0), CfdException);
    EXPECT_THROW(tx.GetTxOut(0), CfdException);
    EXPECT_EQ(tx.HasWitness(), false);
  }

  {
    // hex to transaction(empty)
    Transaction tx("02000000000000000000");
    EXPECT_EQ(tx.GetVersion(), exp_version);
    EXPECT_EQ(tx.GetLockTime(), exp_locktime);
    EXPECT_STREQ(
        Txid(tx.GetHash()).GetHex().c_str(),
        "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a");
    EXPECT_STREQ(
        tx.GetTxid().GetHex().c_str(),
        "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a");
    EXPECT_EQ(tx.GetTotalSize(), 10);
    EXPECT_EQ(tx.GetVsize(), 10);
    EXPECT_EQ(tx.GetWeight(), 40);
    EXPECT_EQ(tx.GetTxInCount(), 0);
    EXPECT_EQ(tx.GetTxOutCount(), 0);
    EXPECT_THROW(tx.GetTxIn(0), CfdException);
    EXPECT_THROW(tx.GetTxOut(0), CfdException);
    EXPECT_EQ(tx.HasWitness(), false);
  }

  {
    // hex to transaction(witness)
    Transaction tx(exp_tx_witness);

    EXPECT_EQ(tx.GetVersion(), exp_version);
    EXPECT_EQ(tx.GetLockTime(), exp_locktime);
    EXPECT_STREQ(
        Txid(tx.GetWitnessHash()).GetHex().c_str(),
        "7558bcad54a71317d1c9c7c4b60a05e9776723c5fe75011d3042840f9938a32d");
    EXPECT_STREQ(
        tx.GetTxid().GetHex().c_str(),
        "08e969a2d0a15e906caa60e7327ec725acfd40f6c5bdff108d6a49cd796e1ee7");
    EXPECT_EQ(tx.GetTotalSize(), 247);
    EXPECT_EQ(tx.GetVsize(), 166);
    EXPECT_EQ(tx.GetWeight(), 661);
    EXPECT_NO_THROW(tx.GetTxIn(0));
    EXPECT_THROW(tx.GetTxIn(1), CfdException);
    EXPECT_EQ(
        tx.GetTxInIndex(
            Txid(
                "8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1"),
            0),
        0);
    EXPECT_THROW(
        tx.GetTxInIndex(
            Txid(
                "8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1"),
            1),
        CfdException);
    EXPECT_EQ(tx.GetTxInCount(), 1);
    EXPECT_NO_THROW(std::vector<TxInReference> txins = tx.GetTxInList());
    EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 2);
    EXPECT_EQ(tx.GetTxOutCount(), 2);
    EXPECT_NO_THROW(std::vector<TxOutReference> txouts = tx.GetTxOutList());
    EXPECT_NO_THROW(tx.GetTxOut(0));
    EXPECT_EQ(
        tx.GetTxOutIndex(Script("a9142699570770f32e0cf3e1d12d81064fbc45899e8a87")),
        1);
    EXPECT_THROW(tx.GetTxOut(2), CfdException);
    EXPECT_EQ(tx.GetWallyFlag(), 1);
    EXPECT_EQ(tx.HasWitness(), true);
    EXPECT_THROW(
        tx.GetTxOutIndex(Script("a9142699570970f32e0cf3e1d12d81064fbc45899e8a87")),
        CfdException);
  }

  {
    ByteData exp_data = ByteData(exp_tx_witness);
    Transaction tx_b(exp_data);
    ByteData data = tx_b.GetData();
    EXPECT_STREQ(data.GetHex().c_str(), exp_tx_witness.c_str());
  }

  {
    // hex to transaction(legacy)
    Transaction tx(exp_tx_legacy);
    EXPECT_EQ(tx.GetVersion(), exp_version);
    EXPECT_EQ(tx.GetLockTime(), exp_locktime);
    EXPECT_STREQ(
        Txid(tx.GetHash()).GetHex().c_str(),
        "85a37a01f7924c7ee95e948274c306fee1b6a0731722da5039c900d43561a590");
    EXPECT_STREQ(
        tx.GetTxid().GetHex().c_str(),
        "85a37a01f7924c7ee95e948274c306fee1b6a0731722da5039c900d43561a590");
    EXPECT_EQ(tx.GetTotalSize(), 189);
    EXPECT_EQ(tx.GetVsize(), 189);
    EXPECT_EQ(tx.GetWeight(), 756);
    EXPECT_NO_THROW(tx.GetTxIn(0));
    EXPECT_THROW(tx.GetTxIn(1), CfdException);
    EXPECT_EQ(
        tx.GetTxInIndex(
            Txid(
                "405e51d745c9f534a71c9e4563521b832fedcbda65c6da2db502e8e236ead2c6"),
            0),
        0);
    EXPECT_THROW(
        tx.GetTxInIndex(
            Txid(
                "405e51d745c9f534a71c9e4563521b832fedcbda65c6da2db502e8e236ead2c6"),
            1),
        CfdException);
    EXPECT_EQ(tx.GetTxInCount(), 1);
    EXPECT_NO_THROW(std::vector<TxInReference> txins = tx.GetTxInList());
    EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 0);
    EXPECT_EQ(tx.GetTxOutCount(), 1);
    EXPECT_NO_THROW(std::vector<TxOutReference> txouts = tx.GetTxOutList());
    EXPECT_NO_THROW(tx.GetTxOut(0));
    EXPECT_THROW(tx.GetTxOut(1), CfdException);
    EXPECT_EQ(tx.GetWallyFlag(), 1);
    EXPECT_EQ(tx.HasWitness(), false);
  }

  {
    // copy constructor
    Transaction copy_tx(exp_tx_witness);
    Transaction tx(copy_tx);

    EXPECT_EQ(tx.GetVersion(), exp_version);
    EXPECT_EQ(tx.GetLockTime(), exp_locktime);
    EXPECT_STREQ(
        Txid(tx.GetWitnessHash()).GetHex().c_str(),
        "7558bcad54a71317d1c9c7c4b60a05e9776723c5fe75011d3042840f9938a32d");
    EXPECT_STREQ(
        tx.GetTxid().GetHex().c_str(),
        "08e969a2d0a15e906caa60e7327ec725acfd40f6c5bdff108d6a49cd796e1ee7");
    EXPECT_EQ(tx.GetTotalSize(), 247);
    EXPECT_EQ(tx.GetVsize(), 166);
    EXPECT_EQ(tx.GetWeight(), 661);
    EXPECT_NO_THROW(tx.GetTxIn(0));
    EXPECT_THROW(tx.GetTxIn(1), CfdException);
    EXPECT_EQ(
        tx.GetTxInIndex(
            Txid(
                "8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1"),
            0),
        0);
    EXPECT_THROW(
        tx.GetTxInIndex(
            Txid(
                "8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1"),
            1),
        CfdException);
    EXPECT_EQ(tx.GetTxInCount(), 1);
    EXPECT_NO_THROW(std::vector<TxInReference> txins = tx.GetTxInList());
    EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 2);
    EXPECT_EQ(tx.GetTxOutCount(), 2);
    EXPECT_NO_THROW(std::vector<TxOutReference> txouts = tx.GetTxOutList());
    EXPECT_NO_THROW(tx.GetTxOut(0));
    EXPECT_THROW(tx.GetTxOut(2), CfdException);
    EXPECT_EQ(tx.GetWallyFlag(), 1);
    EXPECT_EQ(tx.HasWitness(), true);
  }
}

TEST(Transaction, operator_equal) {
  Transaction copy_tx(exp_tx_legacy);
  Transaction tx(3, 3);
  EXPECT_NO_THROW(tx = copy_tx);

  EXPECT_EQ(tx.GetVersion(), exp_version);
  EXPECT_EQ(tx.GetLockTime(), exp_locktime);
  EXPECT_STREQ(
      Txid(tx.GetHash()).GetHex().c_str(),
      "85a37a01f7924c7ee95e948274c306fee1b6a0731722da5039c900d43561a590");
  EXPECT_STREQ(
      tx.GetTxid().GetHex().c_str(),
      "85a37a01f7924c7ee95e948274c306fee1b6a0731722da5039c900d43561a590");
  EXPECT_EQ(tx.GetTotalSize(), 189);
  EXPECT_EQ(tx.GetVsize(), 189);
  EXPECT_EQ(tx.GetWeight(), 756);
  EXPECT_NO_THROW(tx.GetTxIn(0));
  EXPECT_THROW(tx.GetTxIn(1), CfdException);
  EXPECT_EQ(tx.GetTxInCount(), 1);
  EXPECT_NO_THROW(std::vector<TxInReference> txins = tx.GetTxInList());
  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);
  EXPECT_NO_THROW(std::vector<TxOutReference> txouts = tx.GetTxOutList());
  EXPECT_NO_THROW(tx.GetTxOut(0));
  EXPECT_THROW(tx.GetTxOut(1), CfdException);
  EXPECT_EQ(tx.GetWallyFlag(), 1);
  EXPECT_EQ(tx.HasWitness(), false);
}

TEST(Transaction, AddTxIn_RemoveTxIn) {
  Transaction tx(exp_version, exp_locktime);

  Script script("1600141c673dd706e05b17e5c9ff033c8619d06098d7ac");
  EXPECT_NO_THROW(
      tx.AddTxIn(
          Txid(
              "306186bd70e56d820508ed3c9fd656ecb4b4ead0b1502fc3349145df5a15b7e9"),
          1, 4294967294, script));
  EXPECT_EQ(tx.GetTxInCount(), 1);
  EXPECT_NO_THROW(tx.GetTxIn(0));

  EXPECT_NO_THROW(tx.RemoveTxIn(0));
  EXPECT_EQ(tx.GetTxInCount(), 0);
  EXPECT_THROW(tx.GetTxIn(0), CfdException);
}

TEST(Transaction, SetUnlockingScript) {
  Transaction tx(exp_version, exp_locktime);
  EXPECT_NO_THROW(
      tx.AddTxIn(
          Txid(
              "d4470b3c4b616042e5004b1ab60cb1734d21b8e1c4854c379ec8c3f7ca1e450f"),
          0, 4294967294));
  EXPECT_NO_THROW(
      tx.AddTxIn(
          Txid(
              "26e04e16773d52088681d47cd6134e7de0cac124b01cf6cf76f6cfd4dc0c8758"),
          0, 4294967294));

  Script script("160014703e50206e4d27ad1340a7b6a0d94563a3fb768a");
  EXPECT_NO_THROW(tx.SetUnlockingScript(0, script));
  EXPECT_STREQ(tx.GetTxIn(0).GetUnlockingScript().GetHex().c_str(),
               "160014703e50206e4d27ad1340a7b6a0d94563a3fb768a");

  std::vector<ByteData> bytedatas;
  bytedatas.push_back(
      ByteData(
          "304402205a2f94921f645669b2b4e073da43e6a5d32335b50207f9d27f0e8a8c0a24e75902205dea52d27ad747f2df786e0ad737595cf9c5a489143170668399764a5b4be44a01"));
  bytedatas.push_back(
      ByteData(
          "0229e026bab56c1c41d16e67f084362aef204b5b7ea08dafc2fb2e0db89d9c9551"));
  EXPECT_NO_THROW(tx.SetUnlockingScript(1, bytedatas));
  EXPECT_STREQ(
      tx.GetTxIn(1).GetUnlockingScript().GetHex().c_str(),
      "47304402205a2f94921f645669b2b4e073da43e6a5d32335b50207f9d27f0e8a8c0a24e75902205dea52d27ad747f2df786e0ad737595cf9c5a489143170668399764a5b4be44a01210229e026bab56c1c41d16e67f084362aef204b5b7ea08dafc2fb2e0db89d9c9551");

  EXPECT_THROW(tx.SetUnlockingScript(3, bytedatas), CfdException);
}

TEST(Transaction, AddScriptWitnessStack_SetScriptWitnessStack_RemoveScriptWitnessStackAll) {
  Transaction tx(exp_version, exp_locktime);
  EXPECT_NO_THROW(
      tx.AddTxIn(
          Txid(
              "d4470b3c4b616042e5004b1ab60cb1734d21b8e1c4854c379ec8c3f7ca1e450f"),
          0, 4294967294));

  // AddScriptWitnessStack
  EXPECT_NO_THROW(tx.AddScriptWitnessStack(0, ByteData("1122334455667788")));
  EXPECT_NO_THROW(
      tx.AddScriptWitnessStack(
          0, ByteData160("1122334455667788990011223344556677889900")));
  EXPECT_NO_THROW(
      tx.AddScriptWitnessStack(
          0,
          ByteData256(
              "90a56135d400c93950da221773a0b6e1fe06c37482945ee97e4c92f7017aa385")));
  EXPECT_THROW(tx.AddScriptWitnessStack(3, ByteData("aaaa")), CfdException);

  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 3);
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[0].GetHex().c_str(),
      "1122334455667788");
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[1].GetHex().c_str(),
      "1122334455667788990011223344556677889900");
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[2].GetHex().c_str(),
      "90a56135d400c93950da221773a0b6e1fe06c37482945ee97e4c92f7017aa385");

  // SetScriptWitnessStack
  EXPECT_NO_THROW(tx.SetScriptWitnessStack(0, 0, ByteData("ffff")));
  EXPECT_NO_THROW(
      tx.SetScriptWitnessStack(
          0, 1, ByteData160("1111222233334444555566667777888899990000")));
  EXPECT_NO_THROW(
      tx.SetScriptWitnessStack(
          0,
          2,
          ByteData256(
              "1111222233334444555566667777888899990000111122223333444455556666")));
  EXPECT_THROW(tx.SetScriptWitnessStack(2, 0, ByteData("aaaa")), CfdException);
  EXPECT_THROW(tx.SetScriptWitnessStack(0, 4, ByteData("bbbb")), CfdException);

  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 3);
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[0].GetHex().c_str(),
      "ffff");
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[1].GetHex().c_str(),
      "1111222233334444555566667777888899990000");
  EXPECT_STREQ(
      tx.GetTxIn(0).GetScriptWitness().GetWitness()[2].GetHex().c_str(),
      "1111222233334444555566667777888899990000111122223333444455556666");

  // RemoveScriptWitnessStackAll
  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 3);
  EXPECT_THROW(tx.RemoveScriptWitnessStackAll(3), CfdException);
  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 3);

  EXPECT_NO_THROW(tx.RemoveScriptWitnessStackAll(0));
  EXPECT_EQ(tx.GetScriptWitnessStackNum(0), 0);
}

TEST(Transaction, AddTxOut_RemoveTxOut) {
  Transaction tx(exp_version, exp_locktime);
  Script script("76a9143f1f881ea0e079888a8a9d65025aacf6b98f853588ac");

  EXPECT_NO_THROW(tx.AddTxOut(Amount::CreateBySatoshiAmount(100000), script));
  EXPECT_EQ(tx.GetTxOutCount(), 1);
  EXPECT_NO_THROW(tx.GetTxOut(0));
  EXPECT_EQ(0, tx.GetTxOutIndex(script));

  EXPECT_NO_THROW(tx.AddTxOut(Amount::CreateBySatoshiAmount(100000), script));
  EXPECT_EQ(tx.GetTxOutCount(), 2);
  EXPECT_NO_THROW(tx.GetTxOut(1));
  EXPECT_EQ(0, tx.GetTxOutIndex(script));
  std::vector<uint32_t> index_list;
  EXPECT_NO_THROW((index_list = tx.GetTxOutIndexList(script)));
  EXPECT_EQ(2, index_list.size());
  if (index_list.size() == 2) {
    EXPECT_EQ(0, index_list[0]);
    EXPECT_EQ(1, index_list[1]);
  }

  EXPECT_NO_THROW(tx.RemoveTxOut(0));
  EXPECT_NO_THROW(tx.RemoveTxOut(0));
  EXPECT_EQ(tx.GetTxOutCount(), 0);
  EXPECT_THROW(tx.GetTxOut(0), CfdException);
}

TEST(Transaction, GetSignatureHash) {
  {
    // witness
    Transaction tx(
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000");
    ByteData script("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
    SigHashType sighashtype(SigHashAlgorithm::kSigHashAll, false);
    ByteData256 sighash;
    sighash = tx.GetSignatureHash(1, script, sighashtype,
                                  Amount::CreateByCoinAmount(6), WitnessVersion::kVersion0);
    EXPECT_STREQ(
        sighash.GetHex().c_str(),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
  }

  {
    // legacy
    Transaction tx(
        "01000000019c53cb2a6118530aaa345b799aeb7e4e5055de41ac5b2dd2ce47419624c57b580000000000ffffffff0130ea052a010000001976a9143cadb10040e9e7002bbd9d0620f5f79c05603ffd88ac00000000");
    ByteData script("76a9141462eca4b9b8d8df63550abd24d0cb64e8f2d74688ac");
    SigHashType sighashtype(SigHashAlgorithm::kSigHashAll, false);
    ByteData256 sighash;
    sighash = tx.GetSignatureHash(0, script, sighashtype);
    EXPECT_STREQ(
        sighash.GetHex().c_str(),
        "f66fdcfbe73820d26162111873d76062bb3e1b23bc9eaf6ab8a3b333f4bc5242");
  }

  {
    // error
    Transaction tx(
        "01000000019c53cb2a6118530aaa345b799aeb7e4e5055de41ac5b2dd2ce47419624c57b580000000000ffffffff0130ea052a010000001976a9143cadb10040e9e7002bbd9d0620f5f79c05603ffd88ac00000000");
    ByteData empty_script;
    SigHashType sighashtype(SigHashAlgorithm::kSigHashAll, false);
    ByteData256 sighash;
    EXPECT_THROW((sighash = tx.GetSignatureHash(0, empty_script, sighashtype)), CfdException);
  }
}

TEST(Transaction, CheckTxOutBuffer) {
  Transaction tx(
      "0200000000010000000000000000220020c5ae4ff17cec055e964b573601328f3f879fa441e53ef88acdfd4d8e8df429ef00000000");

  EXPECT_EQ(tx.GetVersion(), exp_version);
  EXPECT_EQ(tx.GetLockTime(), exp_locktime);
  EXPECT_STREQ(
      Txid(tx.GetHash()).GetHex().c_str(),
      "fe6845196483dc83b7de6150ffd050d17d21914c1ad2f14639ac04bbe78c3ac1");
  EXPECT_STREQ(
      tx.GetTxid().GetHex().c_str(),
      "fe6845196483dc83b7de6150ffd050d17d21914c1ad2f14639ac04bbe78c3ac1");
  EXPECT_EQ(tx.GetTotalSize(), 53);
  EXPECT_EQ(tx.GetVsize(), 53);
  EXPECT_EQ(tx.GetWeight(), 212);
  EXPECT_EQ(tx.GetTxInCount(), 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);
}
