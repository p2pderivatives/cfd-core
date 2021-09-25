#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_taproot.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::TaprootScriptTree;
using cfd::core::TapBranch;
using cfd::core::CfdException;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::ByteData256;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::SchnorrUtil;

TEST(TapBranch, Empty) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  TapBranch tree;
  EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000000",
      tree.GetBaseHash().GetHex());
  EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000000",
      tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("cc3b1538e0c8144375f71e848b12d609d743992fddfc60dd6ca9b33b8392f27a",
      tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  EXPECT_EQ("3a56ec9129732312a78db4b845138a3180c102621d7381ae6e6a5d530f14856a",
      tree.GetTweakedPrivkey(key).GetHex());
  EXPECT_FALSE(tree.HasTapLeaf());
  EXPECT_EQ("", tree.ToString());

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));
}

TEST(TaprootScriptTree, Empty) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  TaprootScriptTree tree;
  uint8_t ver = TaprootScriptTree::kTapScriptLeafVersion;
  EXPECT_EQ(ver, tree.GetLeafVersion());
  EXPECT_EQ("83d956a5b36109f8f667aa9b366e8479942e32396455b5f43b6df917768e4d45",
      tree.GetTapLeafHash().GetHex());
  EXPECT_EQ("83d956a5b36109f8f667aa9b366e8479942e32396455b5f43b6df917768e4d45",
      tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("350105043b07771830fe4e4bd1a694d6aba22eb6e7f953d530f49b581d816bec",
      tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  EXPECT_EQ("023534977a61f3167b576ee7e636a4041d6451a58f708da24fac8bbd2d9e6b25",
      tree.GetTweakedPrivkey(key).GetHex());
  EXPECT_FALSE(tree.IsValid());
  EXPECT_EQ("tl()", tree.ToString());

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));
}

TEST(TaprootScriptTree, Branch) {
  Privkey key("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  Script script = (ScriptBuilder() << ScriptOperator::OP_TRUE).Build();
  uint8_t leaf_version = 0xc4;
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54")
  };
  TaprootScriptTree tree(leaf_version, script);
  tree.AddBranch(TapBranch(nodes[0]));
  tree.AddBranch(SchnorrPubkey(nodes[1]));

  EXPECT_EQ(leaf_version, tree.GetLeafVersion());
  EXPECT_EQ(script.GetHex(), tree.GetScript().GetHex());
  EXPECT_EQ(nodes.size(), tree.GetNodeList().size());
  if (nodes.size() == tree.GetNodeList().size()) {
    for (size_t index=0; index<nodes.size(); ++index) {
      EXPECT_EQ(nodes[index].GetHex(), tree.GetNodeList()[index].GetHex());
    }
  }
  EXPECT_EQ("b893df7b9b277874f3427de6af5a8d9b1ba5ba6be139557d7a1db9cc4a4e5dae",
      tree.GetTapLeafHash().GetHex());
  EXPECT_EQ("daf066945913caa54e4ccfe32f0ca769b6c06679191cc01b9d96664226a1ffb4",
      tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("cbdec1ab4d09f48ada05aacd1507e89d60671e37c8b3f714b3f6f6fbd6c71a2a",
      tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  EXPECT_EQ("9d7a9466774edd50d61e404568ecd7690ec8b2a656bb30ae66858a28a8a776ab",
      tree.GetTweakedPrivkey(key).GetHex());

  TaprootScriptTree tree2(tree);
  EXPECT_EQ("9d7a9466774edd50d61e404568ecd7690ec8b2a656bb30ae66858a28a8a776ab",
      tree2.GetTweakedPrivkey(key).GetHex());

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));

  auto tree_str = tree.ToString();
  std::string exp_tree_str = "{{4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d,tl(51,c4)},dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54}";
  EXPECT_EQ(exp_tree_str, tree_str);

  try {
    auto br = TapBranch::FromString(exp_tree_str);
    EXPECT_EQ(exp_tree_str, br.ToString());
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }

  try {
    auto rebuild_tree = TaprootScriptTree::FromString(exp_tree_str, script);
    EXPECT_EQ(exp_tree_str, rebuild_tree.ToString());
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }
}

TEST(TaprootScriptTree, Branch2) {
  Privkey key("dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);

  Script script = (ScriptBuilder() << ScriptOperator::OP_TRUE).Build();
  uint8_t leaf_version = 0xc4;
  std::vector<ByteData256> nodes = {
    ByteData256("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
    ByteData256("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57")
  };
  TaprootScriptTree tree(leaf_version, script);
  for (const auto& node : nodes) {
    tree.AddBranch(node);
  }

  EXPECT_EQ(leaf_version, tree.GetLeafVersion());
  EXPECT_EQ(script.GetHex(), tree.GetScript().GetHex());
  EXPECT_EQ(nodes.size(), tree.GetNodeList().size());
  if (nodes.size() == tree.GetNodeList().size()) {
    for (size_t index=0; index<nodes.size(); ++index) {
      EXPECT_EQ(nodes[index].GetHex(), tree.GetNodeList()[index].GetHex());
    }
  }
  bool parity = false;
  EXPECT_EQ("b893df7b9b277874f3427de6af5a8d9b1ba5ba6be139557d7a1db9cc4a4e5dae",
      tree.GetTapLeafHash().GetHex());
  EXPECT_EQ("dc650bb6e95f7ee50dfbddf68651f77cd78c68f8f6c0c64014e5ef7c829c3635",
      tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ("300af27b4b5d270ec1ccc147210af5904724ef72d3ead21c569564a1536d33a3",
      tree.GetTweakedPubkey(schnorr_pubkey).GetHex());
  EXPECT_EQ("7801a8819654c6c31f5a7cbd152f881a138e2adfc64da9dc1f78fbf80640f53a",
      tree.GetTweakedPrivkey(key, &parity).GetHex());
  EXPECT_TRUE(parity);

  ByteData256 msg("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02");
  auto pk = tree.GetTweakedPubkey(schnorr_pubkey);
  auto sk = tree.GetTweakedPrivkey(key);
  auto sig = SchnorrUtil::Sign(msg, sk);
  EXPECT_TRUE(pk.Verify(sig, msg));
}

TEST(TaprootScriptTree, TreeTest1) {
  Privkey key("dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8");
  ByteData256 tweak1("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d");
  ByteData256 tweak2("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57");
  Pubkey pubkey = key.GeneratePubkey();
  bool is_parity = false;
  SchnorrPubkey schnorr_pubkey = SchnorrPubkey::FromPubkey(pubkey, &is_parity);
  EXPECT_EQ("ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440",
      schnorr_pubkey.GetHex());
  EXPECT_TRUE(is_parity);
  SchnorrPubkey schnorr_pubkey2 = schnorr_pubkey.CreateTweakAdd(tweak1);
  SchnorrPubkey schnorr_pubkey3 = schnorr_pubkey.CreateTweakAdd(tweak2);

  Script script = (ScriptBuilder() << schnorr_pubkey.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  TaprootScriptTree tree1(script);

  Script script_true = (ScriptBuilder() << ScriptOperator::OP_TRUE).Build();
  TaprootScriptTree tree2(script_true);

  // <pubkey_1> CHECKSIGVERIFY ... <pubkey_(n-1)> CHECKSIGVERIFY <pubkey_n> CHECKSIG
  Script tree_2_of_2_sig = (ScriptBuilder() << schnorr_pubkey2.GetData()
      << ScriptOperator::OP_CHECKSIGVERIFY << schnorr_pubkey3.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  TaprootScriptTree tree3(tree_2_of_2_sig);

  auto exp_hash = "a625d1251a1100263fa9a77b81e9e6f46c2eb8d44b9f27b629875cc102efb0ec";
  auto exp_str = "{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),tl(51)},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}";
  TaprootScriptTree root = tree1;
  root.AddBranch(tree2);
  root.AddBranch(tree3);
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, root.ToString());

  root = tree2;
  root.AddBranch(tree1);
  root.AddBranch(tree3);
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, root.ToString());

  auto branch = tree2;
  branch.AddBranch(tree1);
  root = tree3;
  root.AddBranch(branch);
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, root.ToString());

  // blind leaf
  root = tree3;
  root.AddBranch(branch.GetCurrentBranchHash());
  EXPECT_EQ(exp_hash, root.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(
      "{af151388d3bfbebcdc87e4a0b4a97bbfa378f2e5a909eb38a6978cb2a71f39c4,tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}",
      root.ToString());

  root = TaprootScriptTree::FromString(exp_str, script);
  EXPECT_EQ(script.GetHex(), root.GetScript().GetHex());
  EXPECT_EQ(2, root.GetBranchList().size());

  root = TaprootScriptTree::FromString(exp_str, script_true);
  EXPECT_EQ(script_true.GetHex(), root.GetScript().GetHex());
  EXPECT_EQ(2, root.GetBranchList().size());

  root = TaprootScriptTree::FromString(exp_str, tree_2_of_2_sig);
  EXPECT_EQ(tree_2_of_2_sig.GetHex(), root.GetScript().GetHex());
  EXPECT_EQ(1, root.GetBranchList().size());
}

TEST(TaprootScriptTree, TreeTest2) {
  //        /\        //
  //       /\ H       //
  //      /  \        //
  //     /\  /\       //
  //    /  D E \      //
  //   / \     /\     //
  //  A   /\  F  G    //
  //     B  C         //
  Privkey key("dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8");
  ByteData256 tweak1("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d");
  ByteData256 tweak2("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57");
  ByteData256 tweak3("a78120a2d338fce91a49230935e8f000672f9511ee6fa5fc35ef22f0dfc89475");
  ByteData256 tweak4("4b79048979258d39c31b10f2bda70a433daa6e42f987089053f00db1d0f94a8e");
  Pubkey pubkey1 = key.GeneratePubkey();
  Pubkey pubkey2 = pubkey1 + tweak3;
  Pubkey pubkey3 = pubkey1 + tweak4;
  SchnorrPubkey schnorr_pubkey1 = SchnorrPubkey::FromPubkey(pubkey1);
  SchnorrPubkey schnorr_pubkey11 = schnorr_pubkey1 + tweak1;
  SchnorrPubkey schnorr_pubkey12 = schnorr_pubkey1 + tweak2;
  SchnorrPubkey schnorr_pubkey2 = SchnorrPubkey::FromPubkey(pubkey2);
  SchnorrPubkey schnorr_pubkey21 = schnorr_pubkey2 + tweak1;
  SchnorrPubkey schnorr_pubkey22 = schnorr_pubkey2 + tweak2;
  SchnorrPubkey schnorr_pubkey3 = SchnorrPubkey::FromPubkey(pubkey3);
  SchnorrPubkey schnorr_pubkey31 = schnorr_pubkey3 + tweak1;
  SchnorrPubkey schnorr_pubkey32 = schnorr_pubkey3 + tweak2;

  Script script_a = (ScriptBuilder() << schnorr_pubkey1.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_b = (ScriptBuilder() << ScriptOperator::OP_TRUE).Build();
  Script script_c = (ScriptBuilder() << schnorr_pubkey11.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  // <pubkey_1> CHECKSIGVERIFY ... <pubkey_(n-1)> CHECKSIGVERIFY <pubkey_n> CHECKSIG
  Script script_d = (ScriptBuilder() << schnorr_pubkey11.GetData()
      << ScriptOperator::OP_CHECKSIGVERIFY << schnorr_pubkey12.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  // Script script_e = (ScriptBuilder() << ScriptOperator::OP_TRUE).Build();
  Script script_e = (ScriptBuilder() << schnorr_pubkey2.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_f = (ScriptBuilder() << schnorr_pubkey21.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_g = (ScriptBuilder() << schnorr_pubkey22.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  // <pubkey_1> CHECKSIGVERIFY ... <pubkey_(n-1)> CHECKSIGVERIFY <pubkey_n> CHECKSIG
  Script script_h = (ScriptBuilder() << schnorr_pubkey31.GetData()
      << ScriptOperator::OP_CHECKSIGVERIFY << schnorr_pubkey32.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_j = (ScriptBuilder() << schnorr_pubkey32.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  EXPECT_EQ("20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac", script_a.GetHex());
  EXPECT_EQ("51", script_b.GetHex());
  EXPECT_EQ("2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac", script_c.GetHex());
  EXPECT_EQ("2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac", script_d.GetHex());
  EXPECT_EQ("20a6573124a479ab188b063bc383aa599da8ccc3b8f90fc18d570a8b367276eaf5ac", script_e.GetHex());
  EXPECT_EQ("2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac", script_f.GetHex());
  EXPECT_EQ("204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac", script_g.GetHex());
  EXPECT_EQ("2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac", script_h.GetHex());
  EXPECT_EQ("20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac", script_j.GetHex());

  struct TestScriptTree2Data {
    std::string name;
    Script script;
    size_t depth;
    std::string nodes;
  };
  std::vector<TestScriptTree2Data> exp_list = {
    {
      "a", script_a, 4,
      "4b3bb79ea92e0b4f2bfa7e8c88d81133e347da393d72a37fe9cdcf1f5f56b5e0e47f58011f27e9046b8195d0ab6a2acbc68ce281437a8d5132dadf389b2a5ebb0db59f44e1394f15d0f0332e106865849b6dff25aa6a9bf7fe82362d7637be55d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75"
    },
    {
      "b", script_b, 5,
      "06b46c960d6824f0da5af71d9ecc55714de5b2d2da51be60bd12c77df20a20df4691fbb1196f4675241c8958a7ab6378a63aa0cc008ed03d216fd038357f52fde47f58011f27e9046b8195d0ab6a2acbc68ce281437a8d5132dadf389b2a5ebb0db59f44e1394f15d0f0332e106865849b6dff25aa6a9bf7fe82362d7637be55d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75"
    },
    {
      "c", script_c, 5,
      "a85b2107f791b26a84e7586c28cec7cb61202ed3d01944d832500f363782d6754691fbb1196f4675241c8958a7ab6378a63aa0cc008ed03d216fd038357f52fde47f58011f27e9046b8195d0ab6a2acbc68ce281437a8d5132dadf389b2a5ebb0db59f44e1394f15d0f0332e106865849b6dff25aa6a9bf7fe82362d7637be55d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75"
    },
    {
      "d", script_d, 3,
      "7da36533760cede4c164d5c00eb1500a27dd86ca76914a9874112c43e0c1b9450db59f44e1394f15d0f0332e106865849b6dff25aa6a9bf7fe82362d7637be55d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75"
    },
    {
      "e", script_e, 3,
      "aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086aeeaab89d953f80ff117b3a94142c859f885c2d942ec13536f72dac0c961f27ed7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75"
    },
    {
      "f", script_f, 4,
      "1aac269b1edaa45c69fb8d1a703a1bb69e90129cef7b7cfe9e676b28e6d1175d7f0ebfee6d06410937c4fd9284a322d1ca33bd1dc315a04e44c4b7df65cfccffaeeaab89d953f80ff117b3a94142c859f885c2d942ec13536f72dac0c961f27ed7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75"
    },
    {
      "g", script_g, 4,
      "e82da59bb829eb21f7cb8eb9eb128626da9a9a31f3dfdeb29766faf14468e9967f0ebfee6d06410937c4fd9284a322d1ca33bd1dc315a04e44c4b7df65cfccffaeeaab89d953f80ff117b3a94142c859f885c2d942ec13536f72dac0c961f27ed7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75"
    },
    {
      "h", script_h, 1, "8f43855f8d9916a2cece54e67b4ce08950a60cc3cce8907d34e03788ade5a977"
    },
  };

  auto exp_hash = "ca0e12942fdb00ad71e84e02c44c0b9136e60ff2c25bcb3cade4d7dc53d246df";
  auto exp_str = "{{{tl(20a6573124a479ab188b063bc383aa599da8ccc3b8f90fc18d570a8b367276eaf5ac),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}},{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)}},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}},tl(2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac)}";
  TaprootScriptTree tree_efg(script_f);
  tree_efg.AddBranch(TaprootScriptTree(script_g));
  tree_efg.AddBranch(TaprootScriptTree(script_e));

  TaprootScriptTree tree_b(script_b);
  tree_b.AddBranch(TaprootScriptTree(script_c));
  tree_b.AddBranch(TaprootScriptTree(script_a));
  tree_b.AddBranch(TaprootScriptTree(script_d));
  tree_b.AddBranch(tree_efg);
  tree_b.AddBranch(TaprootScriptTree(script_h));

  TaprootScriptTree tree = tree_b;
  EXPECT_EQ(exp_hash, tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, tree.ToString());

  for (const auto& test_data : exp_list) {
    SCOPED_TRACE("script_" + test_data.name);
    tree = TaprootScriptTree::FromString(exp_str, test_data.script);
    EXPECT_EQ(exp_hash, tree.GetCurrentBranchHash().GetHex());
    EXPECT_EQ(exp_str, tree.ToString());
    EXPECT_EQ(test_data.script.GetHex(), tree.GetScript().GetHex());
    EXPECT_EQ(test_data.depth, tree.GetBranchList().size());
    std::string nodes;
    for (const auto& node : tree.GetNodeList()) nodes += node.GetHex();
    EXPECT_EQ(test_data.nodes, nodes);
  }

  // invalid leaf
  try {
    tree = TaprootScriptTree::FromString(exp_str, script_j);
    EXPECT_EQ("xxx", tree.GetScript().GetHex());
    EXPECT_EQ("xxx", script_j.GetHex());
  } catch (const CfdException& except) {
    EXPECT_STREQ(
      "This tapscript not exist in this tree.",
      except.what());
  }
}

TEST(TaprootScriptTree, TreeTest3) {
  //        /\        //
  //       /\ H       //
  //      /  \        //
  //     /\  /\       //
  //    /  D E \      //
  //   / \     /\     //
  //  A   /\  F  G    //
  //     B  C         //
  Privkey key("dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8");
  ByteData256 tweak1("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d");
  ByteData256 tweak2("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d57");
  ByteData256 tweak3("a78120a2d338fce91a49230935e8f000672f9511ee6fa5fc35ef22f0dfc89475");
  ByteData256 tweak4("4b79048979258d39c31b10f2bda70a433daa6e42f987089053f00db1d0f94a8e");
  Pubkey pubkey1 = key.GeneratePubkey();
  Pubkey pubkey2 = pubkey1 + tweak3;
  Pubkey pubkey3 = pubkey1 + tweak4;
  SchnorrPubkey schnorr_pubkey1 = SchnorrPubkey::FromPubkey(pubkey1);
  SchnorrPubkey schnorr_pubkey11 = schnorr_pubkey1 + tweak1;
  SchnorrPubkey schnorr_pubkey12 = schnorr_pubkey1 + tweak2;
  SchnorrPubkey schnorr_pubkey2 = SchnorrPubkey::FromPubkey(pubkey2);
  SchnorrPubkey schnorr_pubkey21 = schnorr_pubkey2 + tweak1;
  SchnorrPubkey schnorr_pubkey22 = schnorr_pubkey2 + tweak2;
  SchnorrPubkey schnorr_pubkey3 = SchnorrPubkey::FromPubkey(pubkey3);
  SchnorrPubkey schnorr_pubkey31 = schnorr_pubkey3 + tweak1;
  SchnorrPubkey schnorr_pubkey32 = schnorr_pubkey3 + tweak2;

  Script script_a = (ScriptBuilder() << schnorr_pubkey1.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_b = (ScriptBuilder() << ScriptOperator::OP_TRUE).Build();
  Script script_c = (ScriptBuilder() << schnorr_pubkey11.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();
  // <pubkey_1> CHECKSIGVERIFY ... <pubkey_(n-1)> CHECKSIGVERIFY <pubkey_n> CHECKSIG
  Script script_d = (ScriptBuilder() << schnorr_pubkey11.GetData()
      << ScriptOperator::OP_CHECKSIGVERIFY << schnorr_pubkey12.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_e = (ScriptBuilder() << ScriptOperator::OP_TRUE).Build();
  // Script script_e = (ScriptBuilder() << schnorr_pubkey2.GetData()
  //     << ScriptOperator::OP_CHECKSIG).Build();

  Script script_f = (ScriptBuilder() << schnorr_pubkey21.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_g = (ScriptBuilder() << schnorr_pubkey22.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  // <pubkey_1> CHECKSIGVERIFY ... <pubkey_(n-1)> CHECKSIGVERIFY <pubkey_n> CHECKSIG
  Script script_h = (ScriptBuilder() << schnorr_pubkey31.GetData()
      << ScriptOperator::OP_CHECKSIGVERIFY << schnorr_pubkey32.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  Script script_j = (ScriptBuilder() << schnorr_pubkey32.GetData()
      << ScriptOperator::OP_CHECKSIG).Build();

  EXPECT_EQ("20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac", script_a.GetHex());
  EXPECT_EQ("51", script_b.GetHex());
  EXPECT_EQ("2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac", script_c.GetHex());
  EXPECT_EQ("2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac", script_d.GetHex());
  EXPECT_EQ("51", script_e.GetHex());
  EXPECT_EQ("2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac", script_f.GetHex());
  EXPECT_EQ("204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac", script_g.GetHex());
  EXPECT_EQ("2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac", script_h.GetHex());
  EXPECT_EQ("20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac", script_j.GetHex());

  struct TestScriptTree3Data {
    std::string name;
    Script script;
    size_t depth;
    std::vector<ByteData256> nodes;
  };
  std::vector<TestScriptTree3Data> exp_list = {
    {
      "b", script_b, 5,
      {
        ByteData256("06b46c960d6824f0da5af71d9ecc55714de5b2d2da51be60bd12c77df20a20df"),
        ByteData256("4691fbb1196f4675241c8958a7ab6378a63aa0cc008ed03d216fd038357f52fd"),
        ByteData256("e47f58011f27e9046b8195d0ab6a2acbc68ce281437a8d5132dadf389b2a5ebb"),
        ByteData256("32a0a039ec1412be2803fd7b5f5444c03d498e5e8e107ee431a9597c7b5b3a7c"),
        ByteData256("d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75")
      }
    },
    {
      "e", script_e, 3,
      {
        ByteData256("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086"),
        ByteData256("aeeaab89d953f80ff117b3a94142c859f885c2d942ec13536f72dac0c961f27e"),
        ByteData256("d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75")
      }
    },
  };

  auto exp_hash = "0c1bebfc9a508bf4d5835d401d96d71b72f1873fd338aebfff06d7adbe0c0cc3";
  auto exp_str = "{{{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}},{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)}},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}},tl(2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac)}";

  TaprootScriptTree tree_fg(script_f);
  tree_fg.AddBranch(TaprootScriptTree(script_g));
  TaprootScriptTree tree_efg(script_e);
  tree_efg.AddBranch(tree_fg);
  EXPECT_EQ("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086", tree_fg.GetCurrentBranchHash().GetHex());

  TaprootScriptTree tree_b(script_b);
  tree_b.AddBranch(TaprootScriptTree(script_c));
  tree_b.AddBranch(TaprootScriptTree(script_a));
  tree_b.AddBranch(TaprootScriptTree(script_d));
  auto hash_abcd = tree_b.GetCurrentBranchHash();
  tree_b.AddBranch(tree_efg);
  tree_b.AddBranch(TaprootScriptTree(script_h));

  TaprootScriptTree tree = tree_b;
  EXPECT_EQ(exp_hash, tree.GetCurrentBranchHash().GetHex());
  EXPECT_EQ(exp_str, tree.ToString());
  std::string nodes_str;
  for (const auto& node : tree.GetNodeList()) nodes_str += node.GetHex();
  EXPECT_EQ("06b46c960d6824f0da5af71d9ecc55714de5b2d2da51be60bd12c77df20a20df4691fbb1196f4675241c8958a7ab6378a63aa0cc008ed03d216fd038357f52fde47f58011f27e9046b8195d0ab6a2acbc68ce281437a8d5132dadf389b2a5ebb32a0a039ec1412be2803fd7b5f5444c03d498e5e8e107ee431a9597c7b5b3a7cd7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75", nodes_str);
  EXPECT_EQ("aeeaab89d953f80ff117b3a94142c859f885c2d942ec13536f72dac0c961f27e", hash_abcd.GetHex());

  for (const auto& test_data : exp_list) {
    SCOPED_TRACE("script_" + test_data.name);
    std::vector<ByteData256> nodes;
    tree = TaprootScriptTree::FromString(exp_str, test_data.script);
    EXPECT_EQ(exp_hash, tree.GetCurrentBranchHash().GetHex());
    EXPECT_EQ(exp_str, tree.ToString());
    if (test_data.name == "b") {
      // see: script_e (duplicated script)
      EXPECT_EQ(exp_list[1].script.GetHex(), tree.GetScript().GetHex());
      EXPECT_EQ(exp_list[1].depth, tree.GetBranchList().size());
      nodes = tree.GetNodeList();
      EXPECT_EQ(exp_list[1].nodes.size(), nodes.size());
      for (size_t index=0; index<nodes.size(); ++index) {
        EXPECT_EQ(exp_list[1].nodes[index], nodes[index]);
      }
    } else {
      EXPECT_EQ(test_data.script.GetHex(), tree.GetScript().GetHex());
      EXPECT_EQ(test_data.depth, tree.GetBranchList().size());
      nodes = tree.GetNodeList();
      EXPECT_EQ(test_data.nodes.size(), nodes.size());
      for (size_t index=0; index<nodes.size(); ++index) {
        EXPECT_EQ(test_data.nodes[index], nodes[index]);
      }
    }

    try {
      tree = TaprootScriptTree::FromString(
          exp_str, test_data.script, test_data.nodes);
      EXPECT_EQ(exp_hash, tree.GetCurrentBranchHash().GetHex());
      EXPECT_EQ(exp_str, tree.ToString());
      EXPECT_EQ(test_data.script.GetHex(), tree.GetScript().GetHex());
      EXPECT_EQ(test_data.depth, tree.GetBranchList().size());
      nodes = tree.GetNodeList();
      EXPECT_EQ(test_data.nodes.size(), nodes.size());
      for (size_t index=0; index<nodes.size(); ++index) {
        EXPECT_EQ(test_data.nodes[index], nodes[index]);
      }
    } catch (const CfdException& except) {
      EXPECT_STREQ("", except.what());
    }
  }
  // invalid leaf
  try {
    tree = TaprootScriptTree::FromString(exp_str, script_j);
    EXPECT_EQ("xxx", tree.GetScript().GetHex());
    EXPECT_EQ("xxx", script_j.GetHex());
  } catch (const CfdException& except) {
    EXPECT_STREQ(
      "This tapscript not exist in this tree.",
      except.what());
  }
}

TEST(TaprootScriptTree, TreeTestContainBranchHash) {
  std::string tree_str = "{af151388d3bfbebcdc87e4a0b4a97bbfa378f2e5a909eb38a6978cb2a71f39c4,tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}";
  std::string tapscript = "2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac";

  try {
    auto tree = TaprootScriptTree::FromString(tree_str, Script(tapscript));
    EXPECT_EQ(tree_str, tree.ToString());
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }
}