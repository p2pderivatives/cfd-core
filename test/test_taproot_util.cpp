#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_taproot.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::TaprootScriptTree;
using cfd::core::TaprootUtil;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::Transaction;
using cfd::core::Amount;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::ScriptUtil;
using cfd::core::CryptoUtil;
using cfd::core::SigHashType;
using cfd::core::WitnessVersion;
using cfd::core::Address;
using cfd::core::TxOut;
using cfd::core::NetType;
using cfd::core::SchnorrUtil;
using cfd::core::SchnorrSignature;
using cfd::core::TapScriptData;

TEST(TaprootUtil, ValidLeafVersion) {
  EXPECT_FALSE(TaprootUtil::IsValidLeafVersion(0));
  EXPECT_TRUE(TaprootUtil::IsValidLeafVersion(0x66));
  EXPECT_TRUE(TaprootUtil::IsValidLeafVersion(0xc8));
  EXPECT_FALSE(TaprootUtil::IsValidLeafVersion(0xc9));
}

TEST(TaprootUtil, CreateTapScriptControl) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  Script redeem_script = (ScriptBuilder() << schnorr_pubkey.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54")
  };
  TaprootScriptTree tree(redeem_script);
  tree.AddBranch(nodes[0]);
  tree.AddBranch(SchnorrPubkey(nodes[1]));
  // auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  // Script locking_script = ScriptUtil::CreateTaprootLockingScript(
  //   pk.GetByteData256());
  Script locking_script;
  SchnorrPubkey pk0;
  auto taproot_control = TaprootUtil::CreateTapScriptControl(
      schnorr_pubkey, tree, &pk0, &locking_script);
  Address addr01(NetType::kRegtest, WitnessVersion::kVersion1, pk0);
  EXPECT_EQ("bcrt1p8hh955u8526hjqhn5m5a5pmhymgecmxgerrmqj70tgvhk25mq8fq50z666", addr01.GetAddress());
  EXPECT_EQ(locking_script.GetHex(), addr01.GetLockingScript().GetHex());
  EXPECT_EQ("51203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2", addr01.GetLockingScript().GetHex());

  Transaction tx1(2, 0);
  tx1.AddTxIn(
      Txid("cd6adc252632eb0768ac6407e586cc74bfed739d6c8b9efa55305eb37cbd76dd"),
      0, 0xffffffff);  // bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40
  Amount amt1(int64_t{2499999000});
  tx1.AddTxOut(amt1, locking_script);
  EXPECT_EQ("0200000001dd76bd7cb35e3055fa9e8b6c9d73edbf74cc86e50764ac6807eb322625dc6acd0000000000ffffffff0118f50295000000002251203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d200000000", tx1.GetHex());
  Privkey key1 = Privkey::FromWif("cNveTchXQTFjtsMmR7B7MZmebXnU69S7PmDfgrUX6KbT9kyDLH57");
  Pubkey pk1("023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c44");
  auto pkh_script1 = ScriptUtil::CreateP2pkhLockingScript(pk1);
  SigHashType sighash_type;
  auto sighash = tx1.GetSignatureHash(0, pkh_script1.GetData(),
        sighash_type, Amount(int64_t{2500000000}), WitnessVersion::kVersion0);
  auto sig = key1.CalculateEcSignature(sighash);
  auto der_sig = CryptoUtil::ConvertSignatureToDer(sig, sighash_type);
  tx1.AddScriptWitnessStack(0, der_sig);
  tx1.AddScriptWitnessStack(0, pk1.GetData());
  EXPECT_EQ("02000000000101dd76bd7cb35e3055fa9e8b6c9d73edbf74cc86e50764ac6807eb322625dc6acd0000000000ffffffff0118f50295000000002251203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d20247304402201db912bc61dab1c6117b0aec2965ea1b2d1caa42a1372adc16c8cf673f1187d7022062667d8a976b197f7ba33299365eeb68c1e45fa2a255411672d89f7afab12cb20121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c4400000000", tx1.GetHex());
  
  Transaction tx2(2, 0);
  tx2.AddTxIn(tx1.GetTxid(), 0, 0xffffffff);  // taproot
  Address addr2("bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40");
  tx2.AddTxOut(Amount(int64_t{2499998000}), addr2.GetLockingScript());
  std::vector<TxOut> utxo_list(1);
  utxo_list[0] = TxOut(amt1, locking_script);
  TapScriptData script_data;
  script_data.tap_leaf_hash = tree.GetTapLeafHash();
  auto sighash2 = tx2.GetSchnorrSignatureHash(0, sighash_type, utxo_list, &script_data);
  EXPECT_EQ("80e53eaee13048aee9c6c13fa5a8529aad7fe2c362bfc16f1e2affc71f591d36", sighash2.GetHex());
  auto sig2 = SchnorrUtil::Sign(sighash2, key);
  EXPECT_EQ("f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee9", sig2.GetHex());
  SchnorrSignature schnorr_sig(sig2);
  schnorr_sig.SetSigHashType(sighash_type);
  tx2.AddScriptWitnessStack(0, schnorr_sig.GetData(true));
  tx2.AddScriptWitnessStack(0, redeem_script.GetData());
  tx2.AddScriptWitnessStack(0, taproot_control);
  EXPECT_EQ("020000000001015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee90122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5400000000", tx2.GetHex());

  EXPECT_TRUE(schnorr_pubkey.Verify(schnorr_sig, sighash2));
}

TEST(TaprootUtil, CreateTapScriptControlParityBit) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  ScriptBuilder builder;
  builder.AppendData(schnorr_pubkey.GetData());
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script redeem_script = builder.Build();
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57")
  };
  TaprootScriptTree tree(redeem_script);
  tree.AddBranch(nodes[0]);
  tree.AddBranch(SchnorrPubkey(nodes[1]));
  // auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  // Script locking_script = ScriptUtil::CreateTaprootLockingScript(
  //   pk.GetByteData256());
  Script locking_script;
  auto taproot_control = TaprootUtil::CreateTapScriptControl(
      schnorr_pubkey, tree, nullptr, &locking_script);

  Transaction tx1(2, 0);
  tx1.AddTxIn(
      Txid("fee03a31ddbe8f8af75f9ccea23d2d49c27538b1c183aa90c4e35529161a78df"),
      0, 0xffffffff);  // bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40
  Amount amt1(int64_t{2499999000});
  tx1.AddTxOut(amt1, locking_script);
  EXPECT_EQ("0200000001df781a162955e3c490aa83c1b13875c2492d3da2ce9c5ff78a8fbedd313ae0fe0000000000ffffffff0118f5029500000000225120262d16c95b41f6a90a360837b5e9c3e213334deacffaec0413f8b6e98ad4016500000000", tx1.GetHex());
  Privkey key1 = Privkey::FromWif("cNveTchXQTFjtsMmR7B7MZmebXnU69S7PmDfgrUX6KbT9kyDLH57");
  Pubkey pk1("023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c44");
  auto pkh_script1 = ScriptUtil::CreateP2pkhLockingScript(pk1);
  SigHashType sighash_type;
  auto sighash = tx1.GetSignatureHash(0, pkh_script1.GetData(),
        sighash_type, Amount(int64_t{2500000000}), WitnessVersion::kVersion0);
  auto sig = key1.CalculateEcSignature(sighash);
  auto der_sig = CryptoUtil::ConvertSignatureToDer(sig, sighash_type);
  tx1.AddScriptWitnessStack(0, der_sig);
  tx1.AddScriptWitnessStack(0, pk1.GetData());
  EXPECT_EQ("02000000000101df781a162955e3c490aa83c1b13875c2492d3da2ce9c5ff78a8fbedd313ae0fe0000000000ffffffff0118f5029500000000225120262d16c95b41f6a90a360837b5e9c3e213334deacffaec0413f8b6e98ad4016502473044022068e673ac6db21d612864f432c5cfb64f3652e37be27de412c62dd6127ad63ce1022028507107481ad4fe97da3402eeff0540b0cc1677f9a53e87a7facf07c2696e500121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c4400000000", tx1.GetHex());
  
  Transaction tx2(2, 0);
  tx2.AddTxIn(tx1.GetTxid(), 0, 0xffffffff);  // taproot
  Address addr2("bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40");
  tx2.AddTxOut(Amount(int64_t{2499998000}), addr2.GetLockingScript());
  std::vector<TxOut> utxo_list(1);
  utxo_list[0] = TxOut(amt1, locking_script);
  TapScriptData script_data;
  script_data.tap_leaf_hash = tree.GetTapLeafHash();
  auto sighash2 = tx2.GetSchnorrSignatureHash(0, sighash_type, utxo_list, &script_data);
  EXPECT_EQ("194c654c0547d805c158711fcf96ed9bc4afbd48556a0632cd2b18ec94c3f773", sighash2.GetHex());
  auto sig2 = SchnorrUtil::Sign(sighash2, key);
  EXPECT_EQ("bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e0", sig2.GetHex());
  SchnorrSignature schnorr_sig(sig2);
  schnorr_sig.SetSigHashType(sighash_type);
  tx2.AddScriptWitnessStack(0, schnorr_sig.GetData(true));
  tx2.AddScriptWitnessStack(0, redeem_script.GetData());
  tx2.AddScriptWitnessStack(0, taproot_control);
  EXPECT_EQ("020000000001010513391eb3cb6529b86485dbee924a070a7e556c084ed6f0ff338d7a80335c450000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e00122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c11777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5700000000", tx2.GetHex());

  EXPECT_TRUE(schnorr_pubkey.Verify(schnorr_sig, sighash2));
}

TEST(TaprootUtil, ParseTaprootSignDataByPubkey) {
  Transaction tx2("0200000000010116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d5014161f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f208720100000000");
  auto stack = tx2.GetTxIn(0).GetScriptWitness().GetWitness();
  SchnorrSignature sig;
  bool parity = false;
  uint8_t tapleaf_flag = 0;
  SchnorrPubkey pk;
  std::vector<ByteData256> nodes;
  Script tapscript;
  std::vector<ByteData> script_stack;
  ByteData annex;
  TaprootUtil::ParseTaprootSignData(stack, &sig, &parity, &tapleaf_flag,
      &pk, &nodes, &tapscript, &script_stack, &annex);
  EXPECT_EQ("61f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f2087201", sig.GetHex(true));
  EXPECT_FALSE(parity);
  EXPECT_EQ(0, tapleaf_flag);
  EXPECT_FALSE(pk.IsValid());
  EXPECT_TRUE(nodes.empty());
  EXPECT_TRUE(tapscript.IsEmpty());
  EXPECT_TRUE(script_stack.empty());
  EXPECT_TRUE(annex.IsEmpty());
}

TEST(TaprootUtil, ParseAndVerifyTapScript) {
  Transaction tx2("020000000001015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee90122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5400000000");
  auto stack = tx2.GetTxIn(0).GetScriptWitness().GetWitness();
  SchnorrSignature sig;
  bool parity = false;
  uint8_t tapleaf_flag = 0;
  SchnorrPubkey pk;
  std::vector<ByteData256> nodes;
  Script tapscript;
  std::vector<ByteData> script_stack;
  ByteData annex;
  TaprootUtil::ParseTaprootSignData(stack, &sig, &parity, &tapleaf_flag,
      &pk, &nodes, &tapscript, &script_stack, &annex);
  EXPECT_EQ("", sig.GetHex());
  EXPECT_FALSE(parity);
  uint8_t ver = TaprootScriptTree::kTapScriptLeafVersion;
  EXPECT_EQ(ver, tapleaf_flag);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", pk.GetHex());
  EXPECT_EQ(2, nodes.size());
  if (nodes.size() == 2) {
    EXPECT_EQ("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d",
        nodes[0].GetHex());
    EXPECT_EQ("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54",
        nodes[1].GetHex());
  }
  EXPECT_EQ("201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
      tapscript.GetHex());
  EXPECT_EQ(1, script_stack.size());
  if (script_stack.size() == 1) {
    EXPECT_EQ(
        "f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee901",
        script_stack[0].GetHex());
  }
  EXPECT_TRUE(annex.IsEmpty());

  EXPECT_TRUE(TaprootUtil::VerifyTaprootCommitment(
      parity, tapleaf_flag,
      SchnorrPubkey("3dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2"),
      pk, nodes, tapscript));
}

TEST(TaprootUtil, ParseAndVerifyTapScriptParityBit) {
  Transaction tx2("020000000001010513391eb3cb6529b86485dbee924a070a7e556c084ed6f0ff338d7a80335c450000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e00122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c11777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5700000000");
  auto stack = tx2.GetTxIn(0).GetScriptWitness().GetWitness();
  SchnorrSignature sig;
  bool parity = false;
  uint8_t tapleaf_flag = 0;
  SchnorrPubkey pk;
  std::vector<ByteData256> nodes;
  Script tapscript;
  std::vector<ByteData> script_stack;
  ByteData annex;
  TaprootUtil::ParseTaprootSignData(stack, &sig, &parity, &tapleaf_flag,
      &pk, &nodes, &tapscript, &script_stack, &annex);
  EXPECT_EQ("", sig.GetHex());
  EXPECT_TRUE(parity);
  uint8_t ver = TaprootScriptTree::kTapScriptLeafVersion;
  EXPECT_EQ(ver, tapleaf_flag);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", pk.GetHex());
  EXPECT_EQ(2, nodes.size());
  if (nodes.size() == 2) {
    EXPECT_EQ("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d",
        nodes[0].GetHex());
    EXPECT_EQ("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57",
        nodes[1].GetHex());
  }
  EXPECT_EQ("201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac",
      tapscript.GetHex());
  EXPECT_EQ(1, script_stack.size());
  if (script_stack.size() == 1) {
    EXPECT_EQ(
        "bf55a5d15cc7dd2b583f571db0d59be9b1838a81191ad0e057caf9670d1b7de599864d6bd5e68bd56bb6da4d44e1dfd2deec3a03792c066613c4f6560d4876e001",
        script_stack[0].GetHex());
  }
  EXPECT_TRUE(annex.IsEmpty());

  EXPECT_TRUE(TaprootUtil::VerifyTaprootCommitment(
      parity, tapleaf_flag,
      SchnorrPubkey("262d16c95b41f6a90a360837b5e9c3e213334deacffaec0413f8b6e98ad40165"),
      pk, nodes, tapscript));
}
