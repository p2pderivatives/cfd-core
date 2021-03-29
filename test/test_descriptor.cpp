#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_hdwallet.h"

using cfd::core::Txid;
using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::Descriptor;
using cfd::core::DescriptorNode;
using cfd::core::DescriptorNodeType;
using cfd::core::DescriptorScriptReference;
using cfd::core::DescriptorScriptType;
using cfd::core::DescriptorKeyInfo;
using cfd::core::DescriptorKeyReference;
using cfd::core::DescriptorKeyType;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::Script;
using cfd::core::NetType;
using cfd::core::HashType;
using cfd::core::Address;
using cfd::core::AddressFormatData;
using cfd::core::AddressType;
using cfd::core::Privkey;
using cfd::core::Pubkey;

TEST(Descriptor, Parse_pk) {
  // cfd::core::CfdCoreHandle handle = nullptr;
  // cfd::core::Initialize(&handle);
  std::string descriptor = "pk(02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397)#rk5v7uqw";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397 OP_CHECKSIG");

  // copy constructor
  Descriptor desc2(desc);
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397 OP_CHECKSIG");
}

TEST(Descriptor, Parse_pkh) {
  std::string descriptor = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_DUP OP_HASH160 06afd46bcdfd22ef94ac122aa11f241244a37ecc OP_EQUALVERIFY OP_CHECKSIG");
}

TEST(Descriptor, Parse_wpkh) {
  std::string descriptor = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 7dd65592d0ab2fe0d0257d571abf032cd9db93dc");
}

TEST(Descriptor, Parse_sh_wpkh) {
  std::string descriptor = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_FALSE(desc.IsComboScript());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 cc6ffbc0bf31af759451068f90ba7a0272b6b332 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
        "0 7fda9cf020c16cacf529c87d8de89bfc70b8c9cb");
  }
}

TEST(Descriptor, Parse_combo) {
  std::string descriptor = "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> combo_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(combo_list = desc.GetLockingScriptAll());
  EXPECT_TRUE(desc.IsComboScript());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 751e76e8199196d454941c45d1b3a323f1433bd6");
  EXPECT_EQ(combo_list.size(), 4);
  if (combo_list.size() == 4) {
    EXPECT_STREQ(combo_list[0].ToString().c_str(),
        "0 751e76e8199196d454941c45d1b3a323f1433bd6");
    EXPECT_STREQ(combo_list[1].ToString().c_str(),
        "OP_HASH160 bcfeb728b584253d5f3f70bcb780e9ef218a68f4 OP_EQUAL");
    EXPECT_STREQ(combo_list[2].ToString().c_str(),
        "OP_DUP OP_HASH160 751e76e8199196d454941c45d1b3a323f1433bd6 OP_EQUALVERIFY OP_CHECKSIG");
    EXPECT_STREQ(combo_list[3].ToString().c_str(),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 OP_CHECKSIG");
  }
}

TEST(Descriptor, Parse_combo_uncompress) {
  std::string descriptor = "combo(04ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a116bc35b3f8d748aea5dfad083a73961908797c97fc0ca4f8d874aba9778fc77)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<Script> combo_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(combo_list = desc.GetLockingScriptAll());
  EXPECT_TRUE(desc.IsComboScript());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_DUP OP_HASH160 06399b0a8229214e0614afa119531b46e1d1f29b OP_EQUALVERIFY OP_CHECKSIG");
  EXPECT_EQ(combo_list.size(), 2);
  if (combo_list.size() == 2) {
    EXPECT_STREQ(combo_list[0].ToString().c_str(),
        "OP_DUP OP_HASH160 06399b0a8229214e0614afa119531b46e1d1f29b OP_EQUALVERIFY OP_CHECKSIG");
    EXPECT_STREQ(combo_list[1].ToString().c_str(),
        "04ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a116bc35b3f8d748aea5dfad083a73961908797c97fc0ca4f8d874aba9778fc77 OP_CHECKSIG");
  }
}

TEST(Descriptor, Parse_sh_wsh) {
  std::string descriptor = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 55e8d5e8ee4f3604aba23c71c2684fa0a56a3a12 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "0 fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f");
    EXPECT_TRUE(script_list[0].GetChild().HasRedeemScript());
    EXPECT_STREQ(script_list[0].GetChild().GetRedeemScript().ToString().c_str(),
      "OP_DUP OP_HASH160 c42e7ef92fdb603af844d064faad95db9bcdfd3d OP_EQUALVERIFY OP_CHECKSIG");
    EXPECT_FALSE(script_list[0].HasReqNum());
    EXPECT_EQ(script_list[0].GetReqNum(), 0);
  }
}

TEST(Descriptor, Parse_multi) {
  std::string descriptor = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc 2 OP_CHECKMULTISIG");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_FALSE(script_list[0].HasRedeemScript());
    EXPECT_STREQ(script_list[0].GetLockingScript().ToString().c_str(),
        "1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc 2 OP_CHECKMULTISIG");
    EXPECT_TRUE(script_list[0].HasReqNum());
    EXPECT_EQ(script_list[0].GetReqNum(), 1);
  }
}

TEST(Descriptor, Parse_sh_multi) {
  std::string descriptor = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
        "2 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe 2 OP_CHECKMULTISIG");
    EXPECT_TRUE(script_list[0].GetChild().HasReqNum());
    EXPECT_EQ(script_list[0].GetChild().GetReqNum(), 2);
  }
}

TEST(Descriptor, Parse_sh_multi_maximum) {
  std::string descriptor = "sh(multi(15,02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0,0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c,024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82,03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38,020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1,0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147,0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c,020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9,0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37,0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e,03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b,02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd,0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d,0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2,025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 3b94abddb86c04958381b48c615a7766bcb3e98f OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
        "15 02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0 0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c 024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82 03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38 020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1 0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147 0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c 020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9 0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37 0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e 03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b 02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd 0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d 0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2 025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db 15 OP_CHECKMULTISIG");
    EXPECT_TRUE(script_list[0].GetChild().HasReqNum());
    EXPECT_EQ(script_list[0].GetChild().GetReqNum(), 15);
  }
  
  std::string descriptor_err = "sh(multi(15,02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0,0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c,024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82,03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38,020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1,0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147,0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c,020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9,0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37,0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e,03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b,02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd,0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d,0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2,025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db,030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55))";
  try {
    Descriptor::Parse(descriptor_err);
    EXPECT_TRUE(false);
  } catch (const CfdException& except) {
    EXPECT_STREQ("CreateMultisigScript pubkeys array size is over.",
        except.what());
  }
}

TEST(Descriptor, Parse_sortedmulti) {
  std::string descriptor = "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "2 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe 2 OP_CHECKMULTISIG");
    EXPECT_TRUE(script_list[0].GetChild().HasReqNum());
    EXPECT_EQ(script_list[0].GetChild().GetReqNum(), 2);
  }
}

TEST(Descriptor, Parse_wsh_multi) {
  std::string descriptor = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb 03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a 3 OP_CHECKMULTISIG");
    EXPECT_TRUE(script_list[0].GetChild().HasReqNum());
    EXPECT_EQ(script_list[0].GetChild().GetReqNum(), 2);
  }
}

TEST(Descriptor, Parse_wsh_multi_maximum) {
  std::string descriptor = "wsh(multi(15,02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0,0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c,024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82,03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38,020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1,0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147,0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c,020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9,0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37,0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e,03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b,02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd,0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d,0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2,025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db,030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55,0267a49281bd9d6d366c39c62f2e95a2aab37638f2a4718891c542d0961962644e,02f48e8e2bcaeb16a6d781bb7a72f6250607bf21e32f08c48e37a9e4706e6d48b8,03968ac57888ddaa3b57caa39efd5d5382c24f3deed602775cd4895f7c7adb5950,024b64115bff6cc3718867114f7594fad535344f27ebe17ffa0e66288eb7bd2561))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 5213817e55f6309979372ce754d259e0658ca56e68ce0bcee2b281c7af92fc5f");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
        "15 02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0 0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c 024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82 03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38 020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1 0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147 0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c 020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9 0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37 0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e 03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b 02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd 0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d 0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2 025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db 030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55 0267a49281bd9d6d366c39c62f2e95a2aab37638f2a4718891c542d0961962644e 02f48e8e2bcaeb16a6d781bb7a72f6250607bf21e32f08c48e37a9e4706e6d48b8 03968ac57888ddaa3b57caa39efd5d5382c24f3deed602775cd4895f7c7adb5950 024b64115bff6cc3718867114f7594fad535344f27ebe17ffa0e66288eb7bd2561 20 OP_CHECKMULTISIG");
    EXPECT_TRUE(script_list[0].GetChild().HasReqNum());
    EXPECT_EQ(script_list[0].GetChild().GetReqNum(), 15);
  }
  
  std::string descriptor_err = "wsh(multi(15,02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0,0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c,024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82,03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38,020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1,0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147,0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c,020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9,0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37,0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e,03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b,02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd,0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d,0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2,025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db,030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55,0267a49281bd9d6d366c39c62f2e95a2aab37638f2a4718891c542d0961962644e,02f48e8e2bcaeb16a6d781bb7a72f6250607bf21e32f08c48e37a9e4706e6d48b8,03968ac57888ddaa3b57caa39efd5d5382c24f3deed602775cd4895f7c7adb5950,024b64115bff6cc3718867114f7594fad535344f27ebe17ffa0e66288eb7bd2561,03f3aba2366b71f8473dd8dd4186005a9e3c6f9a32f76fc45493fd2a78b78c0d8d))";
  try {
    Descriptor::Parse(descriptor_err);
    EXPECT_TRUE(false);
  } catch (const CfdException& except) {
    EXPECT_STREQ("Failed to multisig pubkey num.",
        except.what());
  }
}

TEST(Descriptor, Parse_sh_wsh_multi) {
  std::string descriptor = "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  std::vector<DescriptorScriptReference> script_list;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_HASH160 aec509e284f909f769bb7dda299a717c87cc97ac OP_EQUAL");
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "0 ef8110fa7ddefb3e2d02b2c1b1480389b4bc93f606281570cfc20dba18066aee");
    EXPECT_TRUE(script_list[0].GetChild().HasRedeemScript());
    EXPECT_STREQ(script_list[0].GetChild().GetRedeemScript().ToString().c_str(),
      "1 03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8 03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e 3 OP_CHECKMULTISIG");
    EXPECT_TRUE(script_list[0].GetChild().GetChild().HasReqNum());
    EXPECT_EQ(script_list[0].GetChild().GetChild().GetReqNum(), 1);
  }
}

TEST(Descriptor, Parse_addr) {
  std::string descriptor = "addr(bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d");
}

TEST(Descriptor, Parse_raw) {
  std::string descriptor = "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "OP_RETURN 54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e");

  std::vector<DescriptorScriptReference> script_list;
  std::vector<std::string> arg_list1;
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll(&arg_list1));
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_FALSE(script_list[0].HasAddress());
  }
}

TEST(Descriptor, Parse_raw_wsh) {
  std::string descriptor = "raw(0020ef8110fa7ddefb3e2d02b2c1b1480389b4bc93f606281570cfc20dba18066aee)#2xu4jtw0";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "0 ef8110fa7ddefb3e2d02b2c1b1480389b4bc93f606281570cfc20dba18066aee");

  std::vector<DescriptorScriptReference> script_list;
  std::vector<std::string> arg_list1;
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll(&arg_list1));
  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_TRUE(script_list[0].HasAddress());
    EXPECT_STREQ(script_list[0].GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "bc1qa7q3p7nammanutgzktqmzjqr3x6teylkqc5p2ux0cgxm5xqxdthq02yr5g");
  }
}

TEST(Descriptor, Parse_pk_extkey) {
  std::string descriptor = "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2 OP_CHECKSIG");
}

TEST(Descriptor, Parse_pkh_extkey) {
  // m/1'/2 -> m/1/2 : hardened is privkey only.
  std::string descriptor = "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(), "OP_DUP OP_HASH160 f833c08f02389c451ae35ec797fccf7f396616bf OP_EQUALVERIFY OP_CHECKSIG");
}

TEST(Descriptor, Parse_pkh_extkey_derive) {
  std::string descriptor = "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script gen_script;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_THROW(locking_script = desc.GetLockingScript(), CfdException);
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript("0"));
  EXPECT_NO_THROW(gen_script = desc.GetLockingScript("0/44"));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "OP_DUP OP_HASH160 2a05c214617c9b0434c92d0583200a85ef61818f OP_EQUALVERIFY OP_CHECKSIG");
  EXPECT_STREQ(gen_script.ToString().c_str(),
    "OP_DUP OP_HASH160 c463e6dedb2b780434e60fcee3f2d0a0fbcbbc90 OP_EQUALVERIFY OP_CHECKSIG");
  try {
    auto key = desc.GetKeyData("0");
    EXPECT_TRUE(key.IsValid());
    EXPECT_STREQ(key.ToString().c_str(),
      "[d34db33f/44'/0'/0'/1/0]03095e95d8c50ae3f3fea93fa8e983f710489f60ff681a658c06eba64622c824b1");
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
}

TEST(Descriptor, Parse_wsh_extkey_derive) {
  std::string descriptor = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script gen_script;
  std::vector<DescriptorScriptReference> script_list;
  std::vector<DescriptorScriptReference> script_list2;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  std::vector<std::string> arg_list1;
  std::vector<std::string> arg_list2;
  arg_list1.push_back("0");
  arg_list1.push_back("0");
  arg_list2.push_back("0/44");
  arg_list2.push_back("0/44");
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_THROW(locking_script = desc.GetLockingScript(), CfdException);
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript("0"));
  EXPECT_NO_THROW(gen_script = desc.GetLockingScript(arg_list2));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll(&arg_list1));
  EXPECT_NO_THROW(script_list2 = desc.GetReferenceAll(&arg_list2));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "0 64969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b");
  EXPECT_STREQ(gen_script.ToString().c_str(),
    "0 2070830c75de894b00286a87cbbb201aaec3487b5891dbf657c0500e11efa27d");

  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_TRUE(script_list[0].HasAddress());
    EXPECT_STREQ(script_list[0].GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c");
    EXPECT_EQ(script_list[0].GetAddressType(), AddressType::kP2wshAddress);
    EXPECT_EQ(script_list[0].GetHashType(), HashType::kP2wsh);
    EXPECT_EQ(script_list[0].GetScriptType(), DescriptorScriptType::kDescriptorScriptWsh);

    EXPECT_TRUE(script_list[0].HasChild());
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "1 0205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed87106 02c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e75144774 2 OP_CHECKMULTISIG");
    EXPECT_FALSE(script_list[0].GetChild().HasChild());
    EXPECT_TRUE(script_list[0].GetChild().HasKey());
    EXPECT_EQ(script_list[0].GetChild().GetKeyNum(), 2);
    std::vector<DescriptorKeyReference> keys = script_list[0].GetChild().GetKeyList();
    if (keys.size() == 2) {
      EXPECT_STREQ(keys[0].GetPubkey().GetHex().c_str(),
        "0205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed87106");
      EXPECT_TRUE(keys[0].HasExtPubkey());
      EXPECT_STREQ(keys[0].GetExtPubkey().ToString().c_str(),
        "xpub6BgWskLoyHmAUeKWgUXCGfDdCMRXseEjRCMEMvjkedmHpnvWtpXMaCRm8qcADw9einPR8o2c49ZpeHRZP4uYwGeMU2T63G7uf2Y1qJavrWQ");
      EXPECT_FALSE(keys[0].HasExtPrivkey());
      EXPECT_THROW(keys[0].GetExtPrivkey(), CfdException);
      EXPECT_STREQ(keys[0].GetArgument().c_str(), "0");
      EXPECT_STREQ(keys[1].GetPubkey().GetHex().c_str(),
        "02c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e75144774");
      EXPECT_STREQ(keys[1].GetExtPubkey().ToString().c_str(),
        "xpub6EKMC2gSMfKgQJ3iNMZVNB4GLH1Dc4hNPah1iMbbztxdUPRo84MMcTgkPATWNRyzr7WifKrt5VvQi4GEqRwybCP1LHoXBKLN6cB15HuBKPE");
      EXPECT_EQ(keys[1].GetKeyType(), DescriptorKeyType::kDescriptorKeyBip32);
    }
  }

  EXPECT_EQ(script_list2.size(), 1);
  if (script_list2.size() == 1) {
    EXPECT_STREQ(script_list2[0].GetRedeemScript().ToString().c_str(),
      "1 026e636c42ce086d19aae89eca84e95d568bad8a166b9e99b0e27041caab905f38 02bbd047b8f3dac46297e337fb91043fb7c211be89e6068f156e065ebe7fcca01c 2 OP_CHECKMULTISIG");
    std::vector<DescriptorKeyReference> keys = script_list2[0].GetChild().GetKeyList();
    if (keys.size() == 2) {
      EXPECT_STREQ(keys[0].GetArgument().c_str(), "0/44");
    }
    std::vector<Address> addresses = script_list2[0].GetChild()
        .GenerateAddresses(NetType::kMainnet);
    EXPECT_EQ(addresses.size(), 2);
    if (addresses.size() == 2) {
      EXPECT_STREQ(addresses[0].GetAddress().c_str(),
          "13HW6r2TPu5MULn8Do8TpvZs2qeARv1ZBA");
      EXPECT_STREQ(addresses[1].GetAddress().c_str(),
          "17jeEcwRN7u1W9KoRwpHFbCyyij478uvXF");
    }
  }
}

TEST(Descriptor, Parse_Privkey_Testnet_Compress) {
  //   pubkey: '03563a11061eb1422738e6bd6d932ce75f3be6915a9db28242437cff274781e973',
  //   privkey: 'cTffYQiudjHLwLdyiq4Vhj87c8vmsfeU49qj24K2coyXoGQ1eo5L'
  std::string pubkey_hex = "03563a11061eb1422738e6bd6d932ce75f3be6915a9db28242437cff274781e973";
  std::string descriptor1 = "pkh(cTffYQiudjHLwLdyiq4Vhj87c8vmsfeU49qj24K2coyXoGQ1eo5L)";
  std::string descriptor2 = "wpkh(cTffYQiudjHLwLdyiq4Vhj87c8vmsfeU49qj24K2coyXoGQ1eo5L)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  DescriptorScriptReference script_ref;
  Pubkey pubkey;

  try {
    desc = Descriptor::Parse(descriptor1);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }

  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(script_ref = desc.GetReference());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(pubkey = script_ref.GetKeyList()[0].GetPubkey());
  EXPECT_STREQ(desc_str.c_str(), descriptor1.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_DUP OP_HASH160 87fccc805971853683673046575a707df4e94500 OP_EQUALVERIFY OP_CHECKSIG");
  EXPECT_STREQ(pubkey.GetHex().c_str(),
      pubkey_hex.c_str());
  EXPECT_TRUE(pubkey.IsCompress());

  try {
    desc = Descriptor::Parse(descriptor2);
    EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
    EXPECT_NO_THROW(script_ref = desc.GetReference());
    EXPECT_NO_THROW(desc_str = desc.ToString(false));
    EXPECT_NO_THROW(pubkey = script_ref.GetKeyList()[0].GetPubkey());
    EXPECT_STREQ(desc_str.c_str(), descriptor2.c_str());
    EXPECT_STREQ(locking_script.ToString().c_str(),
        "0 87fccc805971853683673046575a707df4e94500");
    EXPECT_STREQ(pubkey.GetHex().c_str(),
        pubkey_hex.c_str());
    EXPECT_TRUE(pubkey.IsCompress());
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  }
}

TEST(Descriptor, Parse_Privkey_Mainnet_Uncompress) {
  //   pubkey: '04ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a116bc35b3f8d748aea5dfad083a73961908797c97fc0ca4f8d874aba9778fc77',
  //   privkey: '5JB4Tt43VA4qbBVRtf88CVKTkJ82pC6mhm9aHywDG27htnFHgqC'
  std::string pubkey_hex = "04ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a116bc35b3f8d748aea5dfad083a73961908797c97fc0ca4f8d874aba9778fc77";
  std::string descriptor1 = "pkh(5JB4Tt43VA4qbBVRtf88CVKTkJ82pC6mhm9aHywDG27htnFHgqC)";
  std::string descriptor2 = "wpkh(5JB4Tt43VA4qbBVRtf88CVKTkJ82pC6mhm9aHywDG27htnFHgqC)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  DescriptorScriptReference script_ref;
  Pubkey pubkey;

  try {
    desc = Descriptor::Parse(descriptor1);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }

  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(script_ref = desc.GetReference());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(pubkey = script_ref.GetKeyList()[0].GetPubkey());
  EXPECT_STREQ(desc_str.c_str(), descriptor1.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_DUP OP_HASH160 06399b0a8229214e0614afa119531b46e1d1f29b OP_EQUALVERIFY OP_CHECKSIG");
  EXPECT_STREQ(pubkey.GetHex().c_str(),
      pubkey_hex.c_str());
  EXPECT_FALSE(pubkey.IsCompress());

  try {
    desc = Descriptor::Parse(descriptor2);
    EXPECT_TRUE(false);
  } catch (const CfdException& except) {
    EXPECT_STREQ("Failed to unsing uncompressed pubkey.", except.what());
  }
}

TEST(Descriptor, Parse_Pubkey_Uncompress) {
  std::string pubkey_hex = "04ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a116bc35b3f8d748aea5dfad083a73961908797c97fc0ca4f8d874aba9778fc77";
  std::string descriptor1 = "pkh(04ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a116bc35b3f8d748aea5dfad083a73961908797c97fc0ca4f8d874aba9778fc77)";
  std::string descriptor2 = "wpkh(04ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a116bc35b3f8d748aea5dfad083a73961908797c97fc0ca4f8d874aba9778fc77)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  DescriptorScriptReference script_ref;
  Pubkey pubkey;

  try {
    desc = Descriptor::Parse(descriptor1);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }

  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(script_ref = desc.GetReference());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(pubkey = script_ref.GetKeyList()[0].GetPubkey());
  EXPECT_STREQ(desc_str.c_str(), descriptor1.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "OP_DUP OP_HASH160 06399b0a8229214e0614afa119531b46e1d1f29b OP_EQUALVERIFY OP_CHECKSIG");
  EXPECT_STREQ(pubkey.GetHex().c_str(),
      pubkey_hex.c_str());
  EXPECT_FALSE(pubkey.IsCompress());

  try {
    desc = Descriptor::Parse(descriptor2);
    EXPECT_TRUE(false);
  } catch (const CfdException& except) {
    EXPECT_STREQ("Failed to unsing uncompressed pubkey.", except.what());
  }
}

TEST(Descriptor, Parse_sh_miniscript) {
  // cfd::core::CfdCoreHandle handle = nullptr;
  // cfd::core::Initialize(&handle);
  std::string descriptor = "sh(or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305))))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script gen_script;
  std::vector<DescriptorScriptReference> script_list;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  std::vector<std::string> arg_list1;
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll(nullptr));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "OP_HASH160 4abf8cfc94ae837bf59965e0c74d02a611ec1329 OP_EQUAL");

  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_TRUE(script_list[0].HasAddress());
    EXPECT_STREQ(script_list[0].GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "38WFPv9fne2UeFxVkGMhLkamMadH8j6s1c");
    EXPECT_EQ(script_list[0].GetAddressType(), AddressType::kP2shAddress);
    EXPECT_EQ(script_list[0].GetHashType(), HashType::kP2sh);
    EXPECT_EQ(script_list[0].GetScriptType(), DescriptorScriptType::kDescriptorScriptSh);

    EXPECT_TRUE(script_list[0].HasChild());
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6 OP_EQUAL OP_IFDUP OP_NOTIF OP_IF 499999999 OP_CHECKLOCKTIMEVERIFY OP_0NOTEQUAL OP_ELSE 0 OP_ENDIF OP_NOTIF 0 OP_ELSE 4194305 OP_CHECKSEQUENCEVERIFY OP_ENDIF OP_ENDIF");
    EXPECT_FALSE(script_list[0].GetChild().HasChild());
    EXPECT_FALSE(script_list[0].GetChild().HasKey());
    EXPECT_FALSE(script_list[0].GetChild().HasRedeemScript());
    EXPECT_EQ(script_list[0].GetChild().GetScriptType(), DescriptorScriptType::kDescriptorScriptMiniscript);
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      script_list[0].GetChild().GetLockingScript().ToString().c_str());
  }
}

TEST(Descriptor, Parse_wsh_miniscript) {
  std::string descriptor = "wsh(thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script gen_script;
  std::vector<DescriptorScriptReference> script_list;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  std::vector<std::string> arg_list1;
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(gen_script = desc.GetLockingScript(arg_list1));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll(nullptr));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "0 6a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1");
  EXPECT_STREQ(gen_script.ToString().c_str(),
    "0 6a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1");

  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_TRUE(script_list[0].HasAddress());
    EXPECT_STREQ(script_list[0].GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "bc1qdfky9a3dh8atpy0l47fsuz5ywergnrfztcddjnl5xgnwyqvqh8gschn2ch");
    EXPECT_EQ(script_list[0].GetAddressType(), AddressType::kP2wshAddress);
    EXPECT_EQ(script_list[0].GetHashType(), HashType::kP2wsh);
    EXPECT_EQ(script_list[0].GetScriptType(), DescriptorScriptType::kDescriptorScriptWsh);

    EXPECT_TRUE(script_list[0].HasChild());
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00 2 OP_CHECKMULTISIG OP_TOALTSTACK 1 036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00 1 OP_CHECKMULTISIG OP_FROMALTSTACK OP_ADD OP_TOALTSTACK 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 OP_CHECKSIG OP_FROMALTSTACK OP_ADD 2 OP_EQUAL");
    EXPECT_FALSE(script_list[0].GetChild().HasChild());
    EXPECT_FALSE(script_list[0].GetChild().HasKey());
    EXPECT_FALSE(script_list[0].GetChild().HasRedeemScript());
    EXPECT_EQ(script_list[0].GetChild().GetScriptType(), DescriptorScriptType::kDescriptorScriptMiniscript);
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      script_list[0].GetChild().GetLockingScript().ToString().c_str());
  }
}

TEST(Descriptor, Parse_sh_wsh_miniscript_derive) {
  std::string descriptor = "sh(wsh(c:or_i(andor(c:pk_h(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*),pk_h(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))))";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";
  Script gen_script;
  std::vector<DescriptorScriptReference> script_list;
  std::vector<DescriptorScriptReference> script_list2;

  try {
    desc = Descriptor::Parse(descriptor);
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
  std::vector<std::string> arg_list1;
  std::vector<std::string> arg_list2;
  arg_list1.push_back("0");
  arg_list2.push_back("44");
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_THROW(locking_script = desc.GetLockingScript(), CfdException);
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript(arg_list1[0]));
  EXPECT_NO_THROW(gen_script = desc.GetLockingScript(arg_list2));
  EXPECT_NO_THROW(script_list = desc.GetReferenceAll(&arg_list1));
  EXPECT_NO_THROW(script_list2 = desc.GetReferenceAll(&arg_list2));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
    "OP_HASH160 a5257435d9c28329c8b8ab810f8813d347eddd17 OP_EQUAL");
  EXPECT_STREQ(gen_script.ToString().c_str(),
    "OP_HASH160 a7a9f411001e3e3db96d7f02fc9ab1d0dc6aa691 OP_EQUAL");

  EXPECT_EQ(script_list.size(), 1);
  if (script_list.size() == 1) {
    EXPECT_STREQ(script_list[0].GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "3GkEHYNEauSenEsqmnhjb9HGgb5pt4oaDm");
    EXPECT_STREQ(script_list[0].GetRedeemScript().ToString().c_str(),
      "0 ac9239e9359aaed6ef6c208ae6893ee0fabb5bb0a4775c0883902367a56eec58");
    EXPECT_STREQ(script_list[0].GetChild().GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "bc1q4jfrn6f4n2hddmmvyz9wdzf7uratkkas53m4czyrjq3k0ftwa3vqvjzukn");
    EXPECT_STREQ(script_list[0].GetChild().GetRedeemScript().ToString().c_str(),
      "OP_IF OP_DUP OP_HASH160 7620e8418ab0d9835cbce5316bb9c8cbfbb82726 OP_EQUALVERIFY OP_CHECKSIG OP_NOTIF OP_DUP OP_HASH160 06afd46bcdfd22ef94ac122aa11f241244a37ecc OP_EQUALVERIFY OP_ELSE OP_DUP OP_HASH160 4de5a5faaee2ab254f2f042503acada802dd9714 OP_EQUALVERIFY OP_ENDIF OP_ELSE 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e OP_ENDIF OP_CHECKSIG");
  }

  EXPECT_EQ(script_list2.size(), 1);
  if (script_list2.size() == 1) {
    EXPECT_STREQ(script_list2[0].GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "3GyYN9WnJBoMn8M5tuqVcFJq1BvbAcdPAt");
    EXPECT_STREQ(script_list2[0].GetRedeemScript().ToString().c_str(),
      "0 e29b7f3e543d581c99c92b59d45218b008b82c2d406bba3c7384d52e568124aa");
    EXPECT_STREQ(script_list2[0].GetChild().GenerateAddress(NetType::kMainnet).GetAddress().c_str(),
      "bc1qu2dh70j584vpexwf9dvag5sckqytstpdgp4m50rnsn2ju45pyj4qudazmh");
    EXPECT_STREQ(script_list2[0].GetChild().GetRedeemScript().ToString().c_str(),
      "OP_IF OP_DUP OP_HASH160 520e6e72bcd5b616bc744092139bd759c31d6bbe OP_EQUALVERIFY OP_CHECKSIG OP_NOTIF OP_DUP OP_HASH160 06afd46bcdfd22ef94ac122aa11f241244a37ecc OP_EQUALVERIFY OP_ELSE OP_DUP OP_HASH160 5ab62f0be26fe9d6205a155403f33e2ad2d31efe OP_EQUALVERIFY OP_ENDIF OP_ELSE 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e OP_ENDIF OP_CHECKSIG");
  }
}

TEST(Descriptor, GetNode_sh_wsh) {
  std::string descriptor = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))";
  Descriptor desc;
  Script locking_script;
  DescriptorScriptReference script_ref;
  DescriptorNode node;

  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(node = desc.GetNode());
  EXPECT_NO_THROW(script_ref = desc.GetReference());
  EXPECT_STREQ(node.ToString(false).c_str(), descriptor.c_str());
  EXPECT_TRUE(script_ref.HasRedeemScript());
  EXPECT_STREQ(script_ref.GetRedeemScript().ToString().c_str(),
      "0 fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f");
  EXPECT_TRUE(script_ref.GetChild().HasRedeemScript());
  EXPECT_STREQ(script_ref.GetChild().GetRedeemScript().ToString().c_str(),
      "OP_DUP OP_HASH160 c42e7ef92fdb603af844d064faad95db9bcdfd3d OP_EQUALVERIFY OP_CHECKSIG");
}

#ifndef CFD_DISABLE_ELEMENTS
TEST(Descriptor, ParseElements_addr) {
  std::string descriptor = "addr(ert1qcc5c9wnzly8zj2dcsvxv83kupsu0uamx69u0y9lsmw7shuns2gqsflana4)";
  Descriptor desc;
  Script locking_script;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::ParseElements(descriptor));
  EXPECT_NO_THROW(locking_script = desc.GetLockingScript());
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), descriptor.c_str());
  EXPECT_STREQ(locking_script.ToString().c_str(),
      "0 c62982ba62f90e2929b8830cc3c6dc0c38fe7766d178f217f0dbbd0bf2705201");
}
#endif  // CFD_DISABLE_ELEMENTS

TEST(Descriptor, xpriv_derive_hardened) {
  std::string descriptor = "sh(wsh(pkh(xprvA5P4YtgFjzqM4QpXJZ8Zr7Wkhng7ugTybA3KWMAqDfAamqu5nqJ3zKRhB29cxuqCc8hPagZcN5BsuoXx4Xn7iYHnQvEdyMwZRFgoJXs8CDN/0'/44/*')))";
  Descriptor desc;
  Script locking_script;
  DescriptorScriptReference script_ref;
  DescriptorNode node;

  std::vector<std::string> arg_list{"0'/0'"};
  EXPECT_NO_THROW(desc = Descriptor::Parse(descriptor));
  EXPECT_NO_THROW(node = desc.GetNode());
  EXPECT_NO_THROW(script_ref = desc.GetReference(&arg_list));
  EXPECT_STREQ(node.ToString(false).c_str(), descriptor.c_str());
  EXPECT_TRUE(script_ref.HasRedeemScript());
  EXPECT_STREQ(script_ref.GetRedeemScript().ToString().c_str(),
      "0 7b2bb92ed714a0534e2a35442f5e4f2718a77143d74edefca3f9fa72bbca9723");
  EXPECT_TRUE(script_ref.GetChild().HasRedeemScript());
  EXPECT_STREQ(script_ref.GetChild().GetRedeemScript().ToString().c_str(),
      "OP_DUP OP_HASH160 1f030158408c421e09107cc81916f82f470a9df4 OP_EQUALVERIFY OP_CHECKSIG");
  DescriptorScriptReference pkh_ref = script_ref.GetChild().GetChild();
  EXPECT_FALSE(pkh_ref.HasRedeemScript());
  EXPECT_TRUE(pkh_ref.HasKey());
  std::vector<DescriptorKeyReference> keylist = pkh_ref.GetKeyList();
  EXPECT_EQ(keylist.size(), 1);
  if (!keylist.empty()) {
    EXPECT_STREQ(keylist[0].GetExtPrivkey().ToString().c_str(),
        "xprvABvmZt3VZFopkh2oWpe8ndMPU2nA3RahBPVutV6wQQN4rd353GNxoJg9KBsWi5sDompQVHUgJKb1eXYZmPrq7VykUyvxugUrMPWXes9jHSk");
    EXPECT_STREQ(keylist[0].GetExtPubkey().ToString().c_str(),
        "xpub6Qv7yPaPPdN7yB7GcrB99mJ824ceStJYYcRWgsWYxju3jRNDaohDM6zdATtizz9TnE8Ra83b4RQSRcoj95xDsH4eLyb2wappmRy2bPdr28u");
    EXPECT_STREQ(keylist[0].GetPubkey().GetHex().c_str(),
        "0321d3b2d7b0e6c3679dd0ff8f02ec7713e8e6ae502e34692ae1eb247c25dcb7a1");
  }
}

TEST(Descriptor, CheckChecksum) {
  std::string base_descriptor = "sh(wpkh([ef57314e/0'/0'/4']03d3f817091de0bbe51e19b53303b12e463f664894d49cb5bf5bb19c88fbc54d8d))";
  std::string success_descriptor = base_descriptor + "#euerft8t";
  std::string fail_descriptor = base_descriptor + "#euerfa8t";
  Descriptor desc;
  std::string desc_str = "";

  EXPECT_NO_THROW(desc = Descriptor::Parse(success_descriptor));
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), success_descriptor.c_str());

  EXPECT_THROW((desc = Descriptor::Parse(fail_descriptor)), CfdException);

  EXPECT_NO_THROW(desc = Descriptor::Parse(base_descriptor));
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), success_descriptor.c_str());
  try {
    auto key_list = desc.GetKeyDataAll();
    EXPECT_FALSE(key_list.empty());
    if (!key_list.empty()) {
      EXPECT_STREQ(key_list[0].ToString().c_str(),
        "[ef57314e/0'/0'/4']03d3f817091de0bbe51e19b53303b12e463f664894d49cb5bf5bb19c88fbc54d8d");
    }
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
}

TEST(Descriptor, CreateDescriptor_wpkh) {
  std::string ext_descriptor = "wpkh([1422fcb3/0'/0'/68']02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995)#r5cw72t3";
  std::string parent_info = "[1422fcb3/0'/0'/68']";
  std::string pubkey_str = "02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995";
  DescriptorKeyInfo key_info;
  Descriptor desc;
  std::string desc_str = "";

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(Pubkey(pubkey_str), parent_info));
  EXPECT_NO_THROW(desc = Descriptor::CreateDescriptor(DescriptorScriptType::kDescriptorScriptWpkh, key_info));
  EXPECT_NO_THROW(desc_str = desc.ToString());
  EXPECT_STREQ(desc_str.c_str(), ext_descriptor.c_str());
  try {
    auto key = desc.GetKeyData();
    EXPECT_TRUE(key.IsValid());
    EXPECT_STREQ(key.ToString().c_str(),
      "[1422fcb3/0'/0'/68']02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995");
  } catch (const CfdException& except) {
    EXPECT_STREQ(except.what(), "");
  }
}

TEST(Descriptor, CreateDescriptor_sh_wsh_sortedmulti) {
  std::string ext_descriptor = "sh(wsh(sortedmulti(2,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*,[1422fcb3/0'/0'/68']02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995)))";

  std::vector<DescriptorScriptType> type_list;
  type_list.push_back(DescriptorScriptType::kDescriptorScriptSh);
  type_list.push_back(DescriptorScriptType::kDescriptorScriptWsh);
  type_list.push_back(DescriptorScriptType::kDescriptorScriptSortedMulti);
  std::vector<DescriptorKeyInfo> key_list;
  key_list.emplace_back(DescriptorKeyInfo("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*"));
  key_list.emplace_back(DescriptorKeyInfo("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*"));
  key_list.emplace_back(DescriptorKeyInfo("02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995", "[1422fcb3/0'/0'/68']"));

  Descriptor desc;
  std::string desc_str = "";
  EXPECT_NO_THROW(desc = Descriptor::CreateDescriptor(type_list, key_list, 2));
  EXPECT_NO_THROW(desc_str = desc.ToString(false));
  EXPECT_STREQ(desc_str.c_str(), ext_descriptor.c_str());
}

TEST(DescriptorKeyInfo, Constructor_Pubkey) {
  Pubkey pubkey("03d3f817091de0bbe51e19b53303b12e463f664894d49cb5bf5bb19c88fbc54d8d");
  std::string parent_info = "[ef57314e/0'/0'/4']";
  DescriptorKeyInfo key_info;
  std::string key_str;

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(pubkey));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), pubkey.GetHex().c_str());
  EXPECT_EQ(key_info.GetKeyType(),  DescriptorKeyType::kDescriptorKeyPublic);

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(pubkey, parent_info));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), (parent_info + pubkey.GetHex()).c_str());
  EXPECT_FALSE(key_info.HasPrivkey());
  EXPECT_FALSE(key_info.HasExtPubkey());
  EXPECT_FALSE(key_info.HasExtPrivkey());
  EXPECT_STREQ(key_info.GetPubkey().GetHex().c_str(),  pubkey.GetHex().c_str());
}

TEST(DescriptorKeyInfo, Constructor_Privkey_Testnet_Compress) {
  Privkey privkey("0b64eb8f5ddfffed8ffd09339cbb9de1b9ceee2a76760173fe4b130a91e56383");
  std::string privkey_wif_str = "cPoefvB147bYpWCf9JqRBVMXENt4isSBAn91RYeiBh1jUp3ThhKN";
  Privkey privkey_wif = Privkey::FromWif(privkey_wif_str, NetType::kRegtest, true);
  std::string parent_info = "[ef57314e/0'/0'/4']";
  DescriptorKeyInfo key_info;
  std::string key_str;

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(privkey, false));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), privkey.GetHex().c_str());
  EXPECT_EQ(key_info.GetKeyType(),  DescriptorKeyType::kDescriptorKeyPublic);

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(privkey_wif, true, NetType::kRegtest, true, parent_info));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), (parent_info + privkey_wif_str).c_str());
  EXPECT_TRUE(key_info.HasPrivkey());
  EXPECT_FALSE(key_info.HasExtPubkey());
  EXPECT_FALSE(key_info.HasExtPrivkey());
  EXPECT_STREQ(key_info.GetPrivkey().GetHex().c_str(),  privkey_wif.GetHex().c_str());
}

TEST(DescriptorKeyInfo, Constructor_ExtPrivkey) {
  std::string extkey = "tprv8fFXTTUs3e5Q1CGAPnabXXFUJor2q2jXo3VCceUggUNGMgCQ4FsLgPemcq2FPym15qZ2kjNx414T3Ypha1gAL3GHUH3uN3xDB3ymD434uWh";
  ExtPrivkey privkey(extkey);
  std::string parent_info = "[ef57314e/0']";
  std::string path = "0'/1/*";
  DescriptorKeyInfo key_info;
  std::string key_str;

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(privkey));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), extkey.c_str());
  EXPECT_EQ(key_info.GetKeyType(),  DescriptorKeyType::kDescriptorKeyBip32Priv);

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(privkey, parent_info, path));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), (parent_info + extkey + "/" + path).c_str());
  EXPECT_FALSE(key_info.HasPrivkey());
  EXPECT_FALSE(key_info.HasExtPubkey());
  EXPECT_TRUE(key_info.HasExtPrivkey());
  EXPECT_STREQ(key_info.GetExtPrivkey().ToString().c_str(),  extkey.c_str());
  EXPECT_STREQ(key_info.GetBip32Path().c_str(),  ("/" + path).c_str());

}

TEST(DescriptorKeyInfo, Constructor_ExtPubkey) {
  std::string extkey = "tpubDDNapBCUaChXpE91grWNGp8xWg84GcS1iRSR7iynAFTv6JAGnKTEUB3vkHtsV4NbkZf6SfjYM6PvW3kZ77KLUZ2GTYNBN4PJRWCKN1ERjJe";
  ExtPubkey pubkey(extkey);
  std::string parent_info = "[ef57314e/0'/1]";
  std::string path = "0/1/*";
  DescriptorKeyInfo key_info;
  std::string key_str;

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(pubkey));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), extkey.c_str());
  EXPECT_EQ(key_info.GetKeyType(),  DescriptorKeyType::kDescriptorKeyBip32);

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(pubkey, parent_info, path));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), (parent_info + extkey + "/" + path).c_str());
  EXPECT_FALSE(key_info.HasPrivkey());
  EXPECT_TRUE(key_info.HasExtPubkey());
  EXPECT_FALSE(key_info.HasExtPrivkey());
  EXPECT_STREQ(key_info.GetExtPubkey().ToString().c_str(),  extkey.c_str());
  EXPECT_STREQ(key_info.GetBip32Path().c_str(),  ("/" + path).c_str());
}

TEST(DescriptorKeyInfo, Constructor_string) {
  std::string extkey = "tprv8fFXTTUs3e5Q1CGAPnabXXFUJor2q2jXo3VCceUggUNGMgCQ4FsLgPemcq2FPym15qZ2kjNx414T3Ypha1gAL3GHUH3uN3xDB3ymD434uWh";
  std::string parent_info = "[ef57314e/0'/1]";
  std::string path = "0'/1/*";
  DescriptorKeyInfo key_info;
  std::string key_str;

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(extkey));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), extkey.c_str());
  EXPECT_EQ(key_info.GetKeyType(),  DescriptorKeyType::kDescriptorKeyBip32Priv);

  EXPECT_NO_THROW(key_info = DescriptorKeyInfo(extkey + "/" + path, parent_info));
  EXPECT_NO_THROW(key_str = key_info.ToString());
  EXPECT_STREQ(key_str.c_str(), (parent_info + extkey + "/" + path).c_str());
  EXPECT_FALSE(key_info.HasPrivkey());
  EXPECT_FALSE(key_info.HasExtPubkey());
  EXPECT_TRUE(key_info.HasExtPrivkey());
  EXPECT_STREQ(key_info.GetExtPrivkey().ToString().c_str(),  extkey.c_str());
  EXPECT_STREQ(key_info.GetBip32Path().c_str(),  ("/" + path).c_str());
}

TEST(DescriptorKeyInfo, GetExtPrivkeyInformation) {
  std::string extkey = "tprv8fFXTTUs3e5Q1CGAPnabXXFUJor2q2jXo3VCceUggUNGMgCQ4FsLgPemcq2FPym15qZ2kjNx414T3Ypha1gAL3GHUH3uN3xDB3ymD434uWh";
  ExtPrivkey privkey(extkey);
  std::string path = "0'/1";
  std::string ext_str = "[f4a831a2]";
  std::string ext_path_str = "[f4a831a2/" + path + "]";
  std::string key_str;

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPrivkeyInformation(privkey, ""));
  EXPECT_STREQ(key_str.c_str(), ext_str.c_str());

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPrivkeyInformation(privkey, path));
  EXPECT_STREQ(key_str.c_str(), ext_path_str.c_str());
}

TEST(DescriptorKeyInfo, GetExtPrivkeyInformation_root) {
  std::string extkey = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF";
  ExtPrivkey privkey(extkey);
  std::string path = "m/0'/1";
  std::string ext_str = "[00000000]";
  std::string ext_path_str = "[00000000/0'/1]";
  std::string key_str;

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPrivkeyInformation(privkey, ""));
  EXPECT_STREQ(key_str.c_str(), ext_str.c_str());

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPrivkeyInformation(privkey, path));
  EXPECT_STREQ(key_str.c_str(), ext_path_str.c_str());
}

TEST(DescriptorKeyInfo, GetExtPubkeyInformation) {
  std::string extkey = "tpubDDNapBCUaChXpE91grWNGp8xWg84GcS1iRSR7iynAFTv6JAGnKTEUB3vkHtsV4NbkZf6SfjYM6PvW3kZ77KLUZ2GTYNBN4PJRWCKN1ERjJe";
  ExtPubkey pubkey(extkey);
  std::string path = "0/1";
  std::string ext_str = "[b7665978]";
  std::string ext_path_str = "[b7665978/" + path + "]";
  std::string key_str;

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPubkeyInformation(pubkey, ""));
  EXPECT_STREQ(key_str.c_str(), ext_str.c_str());

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPubkeyInformation(pubkey, path));
  EXPECT_STREQ(key_str.c_str(), ext_path_str.c_str());
}

TEST(DescriptorKeyInfo, GetExtPubkeyInformation_root) {
  std::string extkey = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  ExtPubkey pubkey(extkey);
  std::string path = "m/0/1";
  std::string ext_str = "[00000000]";
  std::string ext_path_str = "[00000000/0/1]";
  std::string key_str;

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPubkeyInformation(pubkey, ""));
  EXPECT_STREQ(key_str.c_str(), ext_str.c_str());

  EXPECT_NO_THROW(key_str = DescriptorKeyInfo::GetExtPubkeyInformation(pubkey, path));
  EXPECT_STREQ(key_str.c_str(), ext_path_str.c_str());
}
