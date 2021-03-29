#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_util.h"

using cfd::core::AddressType;
using cfd::core::Amount;
using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::BlindFactor;
using cfd::core::Txid;
using cfd::core::Script;
using cfd::core::ScriptWitness;
using cfd::core::ConfidentialValue;
using cfd::core::ConfidentialAssetId;
using cfd::core::ConfidentialNonce;
using cfd::core::ConfidentialTxIn;
using cfd::core::ConfidentialTxInReference;

static const Txid exp_txid(
    "56eb4a177459bae6d310cd117dde5ff86e0a6572d44dcf5e25e611435fff9b31");
static const uint32_t exp_index = 2;
static const uint32_t exp_sequence = 0xfffffffe;
static const Script exp_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");

static const ByteData256 exp_blinding_nonce(
    "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
static const ByteData256 exp_asset_entropy(
    "6f2a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
static const ConfidentialValue exp_issuance_amount("000000000000112233");
static const ConfidentialValue exp_inflation_keys("000000000000112244");
static const ByteData exp_issuance_amount_rangeproof("0011001100110011");
static const ByteData exp_inflation_keys_rangeproof("0011001100110022");

static ScriptWitness GetExpectWitnessStack() {
  ScriptWitness exp_witness_stack;
  exp_witness_stack.AddWitnessStack(ByteData("3044022075282f574650e20c3a87d0d1f67d0bcd8f9319b26d244eb254c0aa5bc0284e8002205bddfd4e2f5e278de5f473804a1d061ed6f9bdbcb65fec9b20402879c5a9980901"));
  exp_witness_stack.AddWitnessStack(ByteData("025c36c65910268ee06421053cb9bab1c849c4bdd467d6e77a89d33ff213adc3ca"));
  return exp_witness_stack;
}

static ScriptWitness GetExpectPeginWitnessStack() {
  ScriptWitness exp_pegin_witness;
  exp_pegin_witness.AddWitnessStack(ByteData("00e1f50500000000"));
  exp_pegin_witness.AddWitnessStack(ByteData("c23bd031406aa9f7ac994f7385cd8d2605adaadf5a473c82557b4586192681d3"));
  exp_pegin_witness.AddWitnessStack(ByteData("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
  exp_pegin_witness.AddWitnessStack(ByteData("0014e8d28b573816ddfcf98578d7b28543e273f5a72a"));
  exp_pegin_witness.AddWitnessStack(ByteData("02000000014578ddc14da3e19445b6e7b4c61d4af711d29e2703161aa9c11e4e6b0ea08843010000006b483045022100eea27e89c3cf2867393263bece040f34c03e0cddfa93a1a18c0d2e4322a37df7022074273c0ab3836affba53737c83673ca6c0d69bffdf722b4accfd7c0a9b2ea4e60121020bfcdbda850cd250c3995dfdb426dc40a9c8a5b378be2bf39f6b0642a783daf2feffffff02281d2418010000001976a914b56872c7b363bfb3f5af84d071ff282cf2abfe3988ac00e1f5050000000017a9141d4796c6e855ae00acecb0c20f65dd8bbeffb1ec87d1000000"));
  exp_pegin_witness.AddWitnessStack(ByteData("03000030ffba1d575800bf37a1ee1962dee7e153c18bcfc93cd013e7c297d5363b36cc2d63d5c4a9fdc746b9d3f4f62995d611c34ee9740ff2b5193ce458fdac6d173800ec402e5affff7f200500000002000000027ce06590120cf8c2bef7726200f0fa655940cadcf62708d7dc9f8f2a417c890b81af4d4299758e7e7a0daa6e7e3d3ec37f97df4ef2392ae5e6d286fc5e7e01d90105"));
  return exp_pegin_witness;
}

TEST(ConfidentialTxIn, ConstractorEmpty) {
  ConfidentialTxIn txin1;
  EXPECT_EQ(txin1.GetVout(), 0);
  EXPECT_EQ(txin1.GetSequence(), 0);
}

TEST(ConfidentialTxIn, Constractor1) {
  ConfidentialTxIn txin1(exp_txid, exp_index, exp_sequence);
  EXPECT_EQ(txin1.GetVout(), exp_index);
  EXPECT_EQ(txin1.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin1.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());

  ConfidentialTxIn txin2(exp_txid, exp_index, exp_sequence, exp_script);
  EXPECT_EQ(txin2.GetVout(), exp_index);
  EXPECT_EQ(txin2.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin2.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txin2.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
}

TEST(ConfidentialTxIn, Constractor2) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();

  ConfidentialTxIn txin3(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_EQ(txin3.GetVout(), exp_index);
  EXPECT_EQ(txin3.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin3.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txin3.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
  EXPECT_STREQ(txin3.GetBlindingNonce().GetHex().c_str(),
      exp_blinding_nonce.GetHex().c_str());
  EXPECT_STREQ(txin3.GetAssetEntropy().GetHex().c_str(),
      exp_asset_entropy.GetHex().c_str());
  EXPECT_STREQ(txin3.GetIssuanceAmount().GetHex().c_str(),
      exp_issuance_amount.GetHex().c_str());
  EXPECT_STREQ(txin3.GetInflationKeys().GetHex().c_str(),
      exp_inflation_keys.GetHex().c_str());
  EXPECT_STREQ(txin3.GetIssuanceAmountRangeproof().GetHex().c_str(),
      exp_issuance_amount_rangeproof.GetHex().c_str());
  EXPECT_STREQ(txin3.GetInflationKeysRangeproof().GetHex().c_str(),
      exp_inflation_keys_rangeproof.GetHex().c_str());
  EXPECT_EQ(txin3.GetScriptWitnessStackNum(),
      exp_witness_stack.GetWitnessNum());
  const std::vector<ByteData>& test_vector = txin3.GetScriptWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_vector = exp_witness_stack.GetWitness();
  for (size_t idx = 0; idx < test_vector.size(); ++idx) {
    EXPECT_STREQ(test_vector[idx].GetHex().c_str(),
        exp_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(txin3.GetPeginWitnessStackNum(),
      exp_pegin_witness.GetWitnessNum());
  const std::vector<ByteData>& test_peg_vector = txin3.GetPeginWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
        exp_peg_vector[idx].GetHex().c_str());
  }
  EXPECT_STREQ(txin3.GetWitnessHash().GetHex().c_str(),
    "c91991b67af0a40f5d200ba356b02afd3ae2c37174d0d79707a6bd6f9c69ce8c");
}

TEST(ConfidentialTxIn, Constractor3) {
  ConfidentialTxIn txin1(exp_txid, exp_index);
  EXPECT_EQ(txin1.GetVout(), exp_index);
  EXPECT_EQ(txin1.GetSequence(), 0);
  EXPECT_STREQ(txin1.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
}

TEST(ConfidentialTxIn, SetIssuance) {
  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script);
  EXPECT_NO_THROW((txin.SetIssuance(exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof)));

  EXPECT_EQ(txin.GetVout(), exp_index);
  EXPECT_EQ(txin.GetSequence(), exp_sequence);
  EXPECT_STREQ(txin.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txin.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
  EXPECT_STREQ(txin.GetBlindingNonce().GetHex().c_str(),
      exp_blinding_nonce.GetHex().c_str());
  EXPECT_STREQ(txin.GetAssetEntropy().GetHex().c_str(),
      exp_asset_entropy.GetHex().c_str());
  EXPECT_STREQ(txin.GetIssuanceAmount().GetHex().c_str(),
      exp_issuance_amount.GetHex().c_str());
  EXPECT_STREQ(txin.GetInflationKeys().GetHex().c_str(),
      exp_inflation_keys.GetHex().c_str());
  EXPECT_STREQ(txin.GetIssuanceAmountRangeproof().GetHex().c_str(),
      exp_issuance_amount_rangeproof.GetHex().c_str());
  EXPECT_STREQ(txin.GetInflationKeysRangeproof().GetHex().c_str(),
      exp_inflation_keys_rangeproof.GetHex().c_str());
  EXPECT_STREQ(txin.GetWitnessHash().GetHex().c_str(),
    "66c6bd6d38aa080d0c840687accfcec970fa81cadebf94b379eda6a436f2a300");
}

TEST(ConfidentialTxIn, AddPeginWitnessStack) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();
  const ByteData exp_data("1234567890");
  uint32_t target_index = 6;

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_NO_THROW((txin.AddPeginWitnessStack(exp_data)));
  EXPECT_EQ(txin.GetPeginWitnessStackNum(),
      exp_pegin_witness.GetWitnessNum() + 1);
  const std::vector<ByteData>& test_peg_vector = txin.GetPeginWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
        exp_peg_vector[idx].GetHex().c_str());
  }
  EXPECT_STREQ(test_peg_vector[target_index].GetHex().c_str(),
      exp_data.GetHex().c_str());
  EXPECT_STREQ(txin.GetWitnessHash().GetHex().c_str(), 
    "d4fa3782068f8f1cef563520691eafbc883d1caf1d928012462644c7148cf1d5");
}

TEST(ConfidentialTxIn, SetPeginWitnessStack) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();
  const ByteData exp_data("1234567890");
  uint32_t target_index = 1;

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_NO_THROW((txin.SetPeginWitnessStack(target_index, exp_data)));
  const std::vector<ByteData>& test_peg_vector = txin.GetPeginWitness()
      .GetWitness();
  EXPECT_STREQ(test_peg_vector[target_index].GetHex().c_str(),
      exp_data.GetHex().c_str());

  EXPECT_STREQ(txin.GetWitnessHash().GetHex().c_str(),
    "78edc6f5b6ee896fd2dca4ff75a7a23c734bf022528dad077c5570d02c2416fd");

  // fail case
  EXPECT_THROW((txin.SetPeginWitnessStack(9, exp_data)), CfdException);
}

TEST(ConfidentialTxIn, RemovePeginWitnessStackAll) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_NO_THROW((txin.RemovePeginWitnessStackAll()));
  EXPECT_EQ(txin.GetPeginWitnessStackNum(), 0);
  EXPECT_STREQ(txin.GetWitnessHash().GetHex().c_str(),
    "17f0c9b759a09c56116151cca94f18340acc3a782b2062cee3c41333b2dc63fe");
}

struct TestEstimateConfidentialTxInSizeVector {
  AddressType addr_type;
  uint32_t size;
  uint32_t witness_size;
  Script redeem_script;
  uint32_t pegin_btc_tx;
  Script fedpeg_script;
  bool is_issuance;
  bool is_blind;
  bool is_reissuance;
  std::string script_template;
  int exponent;
  int minimum_bits;
};

TEST(ConfidentialTxIn, EstimateTxInSize) {
  static const std::string multisig_script = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";
  static const std::string scriptsig_template = "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb014752210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae";
  static const std::vector<TestEstimateConfidentialTxInSizeVector> test_vector = {
    {AddressType::kP2pkhAddress, 150, 0, Script(), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2shAddress, 205, 0, exp_script, 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2shP2wpkhAddress, 176, 112, Script(), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2shP2wshAddress, 222, 146, Script("51"), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2wpkhAddress, 153, 112, Script(), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2wshAddress, 208, 167, exp_script, 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2wshAddress, 301, 260, Script(multisig_script), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2wshAddress, 191, 150, exp_script, 0, Script(), false, false, false, scriptsig_template, 0, 0},
    // pegin
    {AddressType::kP2wpkhAddress, 611, 570, Script(), 226, Script("51"), false, false, false, "", 0, 0},
    // issue
    {AddressType::kP2wpkhAddress, 235, 112, Script(), 0, Script(), true, false, false, "", 0, 0},
    {AddressType::kP2wpkhAddress, 8499, 8328, Script(), 0, Script(), true, true, false,
        "", 0, 36},
    {AddressType::kP2wpkhAddress, 8627, 8456, Script(), 0, Script(), true, true, false,
        "", 0, 52},
    // reissue
    {AddressType::kP2wpkhAddress, 4391, 4220, Script(), 0, Script(), true, true, true,
        "", 0, 36},
    {AddressType::kP2wpkhAddress, 4455, 4284, Script(), 0, Script(), true, true, true,
        "", 0, 52},
  };

  for (const auto& test_data : test_vector) {
    uint32_t size = 0;
    uint32_t wit_size = 0;
    Script script_template(test_data.script_template);
    Script* template_ptr = nullptr;
    if (!test_data.script_template.empty()) {
      template_ptr = &script_template;
    }
    uint32_t cache_size = 0;
    EXPECT_NO_THROW((size = ConfidentialTxIn::EstimateTxInSize(
        test_data.addr_type, test_data.redeem_script, test_data.pegin_btc_tx,
        test_data.fedpeg_script, test_data.is_issuance, test_data.is_blind,
        &wit_size, nullptr, test_data.is_reissuance, template_ptr,
        test_data.exponent, test_data.minimum_bits, &cache_size)));
    EXPECT_EQ(size, test_data.size);
    EXPECT_EQ(wit_size, test_data.witness_size);
    if (test_data.minimum_bits == 36) {
      // EXPECT_EQ(cache_size, 2892);
      EXPECT_EQ(cache_size, 4109);
    } else if (test_data.minimum_bits == 52) {
      EXPECT_EQ(cache_size, 4173);
    }
  }
}

TEST(ConfidentialTxIn, EstimateTxInVsize) {
  static const std::string multisig_script = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";
  static const std::vector<TestEstimateConfidentialTxInSizeVector> test_vector = {
    {AddressType::kP2pkhAddress, 150, 0, Script(), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2shAddress, 205, 0, exp_script, 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2shP2wpkhAddress, 92, 0, Script(), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2shP2wshAddress, 113, 0, Script("51"), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2wpkhAddress, 69, 0, Script(), 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2wshAddress, 83, 0, exp_script, 0, Script(), false, false, false, "", 0, 0},
    {AddressType::kP2wshAddress, 106, 0, Script(multisig_script), 0, Script(), false, false, false, "", 0, 0},
    // pegin
    {AddressType::kP2wpkhAddress, 184, 0, Script(), 226, Script("51"), false, false, false, "", 0, 0},
    // issue
    {AddressType::kP2wpkhAddress, 151, 0, Script(), 0, Script(), true, false, false, "", 0, 0},
    {AddressType::kP2wpkhAddress, /*1645*/ 2253, 0, Script(), 0, Script(), true, true, false, "", 0, 36},
    {AddressType::kP2wpkhAddress, 2285, 0, Script(), 0, Script(), true, true, false, "", 0, 52},
    // reissue
    {AddressType::kP2wpkhAddress, /*922*/ 1226, 0, Script(), 0, Script(), true, true, true, "", 0, 36},
    {AddressType::kP2wpkhAddress, 1242, 0, Script(), 0, Script(), true, true, true, "", 0, 52},
  };

  for (const auto& test_data : test_vector) {
    uint32_t vsize = 0;
    Script script_template(test_data.script_template);
    Script* template_ptr = nullptr;
    if (!test_data.script_template.empty()) {
      template_ptr = &script_template;
    }
    EXPECT_NO_THROW((vsize = ConfidentialTxIn::EstimateTxInVsize(
        test_data.addr_type, test_data.redeem_script, test_data.pegin_btc_tx,
        test_data.fedpeg_script, test_data.is_issuance, test_data.is_blind,
        test_data.is_reissuance, template_ptr,
        test_data.exponent, test_data.minimum_bits)));
    EXPECT_EQ(vsize, test_data.size);
  }
}

TEST(ConfidentialTxInReference, Constractor) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();

  ConfidentialTxIn txin(exp_txid, exp_index, exp_sequence, exp_script,
      exp_witness_stack, exp_blinding_nonce, exp_asset_entropy,
      exp_issuance_amount, exp_inflation_keys, exp_issuance_amount_rangeproof,
      exp_inflation_keys_rangeproof, exp_pegin_witness);
  EXPECT_STREQ(txin.GetWitnessHash().GetHex().c_str(),
    "c91991b67af0a40f5d200ba356b02afd3ae2c37174d0d79707a6bd6f9c69ce8c");
  
  ConfidentialTxInReference txinref(txin);
  EXPECT_EQ(txinref.GetVout(), exp_index);
  EXPECT_EQ(txinref.GetSequence(), exp_sequence);
  EXPECT_STREQ(txinref.GetTxid().GetHex().c_str(), exp_txid.GetHex().c_str());
  EXPECT_STREQ(txinref.GetUnlockingScript().GetHex().c_str(),
      exp_script.GetHex().c_str());
  EXPECT_STREQ(txinref.GetBlindingNonce().GetHex().c_str(),
      exp_blinding_nonce.GetHex().c_str());
  EXPECT_STREQ(txinref.GetAssetEntropy().GetHex().c_str(),
      exp_asset_entropy.GetHex().c_str());
  EXPECT_STREQ(txinref.GetIssuanceAmount().GetHex().c_str(),
      exp_issuance_amount.GetHex().c_str());
  EXPECT_STREQ(txinref.GetInflationKeys().GetHex().c_str(),
      exp_inflation_keys.GetHex().c_str());
  EXPECT_STREQ(txinref.GetIssuanceAmountRangeproof().GetHex().c_str(),
      exp_issuance_amount_rangeproof.GetHex().c_str());
  EXPECT_STREQ(txinref.GetInflationKeysRangeproof().GetHex().c_str(),
      exp_inflation_keys_rangeproof.GetHex().c_str());
  EXPECT_EQ(txinref.GetScriptWitnessStackNum(),
      exp_witness_stack.GetWitnessNum());
  const std::vector<ByteData>& test_vector = txinref.GetScriptWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_vector = exp_witness_stack.GetWitness();
  for (size_t idx = 0; idx < test_vector.size(); ++idx) {
    EXPECT_STREQ(test_vector[idx].GetHex().c_str(),
        exp_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(txinref.GetPeginWitnessStackNum(),
      exp_pegin_witness.GetWitnessNum());
  const std::vector<ByteData>& test_peg_vector = txinref.GetPeginWitness()
      .GetWitness();
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();
  for (size_t idx = 0; idx < test_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
        exp_peg_vector[idx].GetHex().c_str());
  }
}

struct TestEstimateConfidentialTxInRefVector {
  ConfidentialTxIn txin;
  AddressType addr_type;
  uint32_t size;
  uint32_t witness_size;
  Script redeem_script;
  Script fedpeg_script;
  bool is_blind;
  std::string script_template;
  int exponent;
  int minimum_bits;
};

TEST(ConfidentialTxInReference, EstimateTxInSize) {
  static const std::string multisig_script = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";
  static const std::string scriptsig_template = "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb014752210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae";

  Amount issue_amount(uint32_t{10000000});
  Amount token_amount(uint32_t{10000000});
  ConfidentialTxIn txin;
  ConfidentialTxIn pegin_txin;
  {
    pegin_txin.AddPeginWitnessStack(ByteData("00e1f50500000000"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "c23bd031406aa9f7ac994f7385cd8d2605adaadf5a473c82557b4586192681d3"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
    pegin_txin.AddPeginWitnessStack(
        ByteData("0014e8d28b573816ddfcf98578d7b28543e273f5a72a"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "02000000014578ddc14da3e19445b6e7b4c61d4af711d29e2703161aa9c11e4e6b0ea08843010000006b483045022100eea27e89c3cf2867393263bece040f34c03e0cddfa93a1a18c0d2e4322a37df7022074273c0ab3836affba53737c83673ca6c0d69bffdf722b4accfd7c0a9b2ea4e60121020bfcdbda850cd250c3995dfdb426dc40a9c8a5b378be2bf39f6b0642a783daf2feffffff02281d2418010000001976a914b56872c7b363bfb3f5af84d071ff282cf2abfe3988ac00e1f5050000000017a9141d4796c6e855ae00acecb0c20f65dd8bbeffb1ec87d1000000"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "03000030ffba1d575800bf37a1ee1962dee7e153c18bcfc93cd013e7c297d5363b36cc2d63d5c4a9fdc746b9d3f4f62995d611c34ee9740ff2b5193ce458fdac6d173800ec402e5affff7f200500000002000000027ce06590120cf8c2bef7726200f0fa655940cadcf62708d7dc9f8f2a417c890b81af4d4299758e7e7a0daa6e7e3d3ec37f97df4ef2392ae5e6d286fc5e7e01d90105"));
  }
  ConfidentialTxIn issue_txin;
  ConfidentialTxIn reissue_txin;
  ConfidentialValue issuance_amount(issue_amount);
  ConfidentialValue inflation_keys(token_amount);
  BlindFactor entropy("6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306");
  BlindFactor blind_factor("c8082e8f6980cb5c938cbeff8d72fd5109eddc337417c3b7a7e62deb9a1b9acf");
  {
    issue_txin.SetIssuance(
        ByteData256(), ByteData256(), issuance_amount,
        inflation_keys, ByteData(), ByteData());
    reissue_txin.SetIssuance(
        entropy.GetData(), blind_factor.GetData(), issuance_amount,
        ConfidentialValue(), ByteData(), ByteData());
  }

  const std::vector<TestEstimateConfidentialTxInRefVector> test_vector = {
    {txin, AddressType::kP2pkhAddress, 150, 0, Script(), Script(), false, "", 0, 0},
    {txin, AddressType::kP2shAddress, 205, 0, exp_script, Script(), false, "", 0, 0},
    {txin, AddressType::kP2shP2wpkhAddress, 176, 112, Script(), Script(), false, "", 0, 0},
    {txin, AddressType::kP2shP2wshAddress, 222, 146, Script("51"), Script(), false, "", 0, 0},
    {txin, AddressType::kP2wpkhAddress, 153, 112, Script(), Script(), false, "", 0, 0},
    {txin, AddressType::kP2wshAddress, 208, 167, exp_script,Script(), false, "", 0, 0},
    {txin, AddressType::kP2wshAddress, 301, 260, Script(multisig_script), Script(), false,
      "", 0, 0},
    {txin, AddressType::kP2wshAddress, 191, 150, exp_script, Script(), false,
      scriptsig_template, 0, 0},
    // pegin
    {pegin_txin, AddressType::kP2wpkhAddress, 609, 568, Script(), Script("51"), false, "", 0, 0},
    // issue
    {issue_txin, AddressType::kP2wpkhAddress, 4143, 3972, Script(), Script(), true, "", 0, 0},
    {issue_txin, AddressType::kP2wpkhAddress, 6065, 5894, Script(), Script(), true, "", 0, 36},
    {issue_txin, AddressType::kP2wpkhAddress, 8627, 8456, Script(), Script(), true, "", 0, 52},
    // reissue
    {reissue_txin, AddressType::kP2wpkhAddress, 3174, 3003, Script(), Script(), true, "", 0, 36},
    {reissue_txin, AddressType::kP2wpkhAddress, 4455, 4284, Script(),Script(), true, "", 0, 52},
  };

  for (const auto& test_data : test_vector) {
    uint32_t size = 0;
    uint32_t wit_size = 0;
    Script script_template(test_data.script_template);
    Script* template_ptr = nullptr;
    if (!test_data.script_template.empty()) {
      template_ptr = &script_template;
    }
    ConfidentialTxInReference txin_ref(test_data.txin);
    EXPECT_NO_THROW((size = txin_ref.EstimateTxInSize(
        test_data.addr_type, test_data.redeem_script, test_data.is_blind,
        test_data.exponent, test_data.minimum_bits, test_data.fedpeg_script,
        template_ptr, &wit_size, nullptr)));
    EXPECT_EQ(size, test_data.size);
    EXPECT_EQ(wit_size, test_data.witness_size);
  }
}

TEST(ConfidentialTxInReference, EstimateTxInVsize) {
  static const std::string multisig_script = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";

  Amount issue_amount(uint32_t{10000000});
  Amount token_amount(uint32_t{10000000});
  ConfidentialTxIn txin;
  ConfidentialTxIn pegin_txin;
  {
    pegin_txin.AddPeginWitnessStack(ByteData("00e1f50500000000"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "c23bd031406aa9f7ac994f7385cd8d2605adaadf5a473c82557b4586192681d3"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
    pegin_txin.AddPeginWitnessStack(
        ByteData("0014e8d28b573816ddfcf98578d7b28543e273f5a72a"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "02000000014578ddc14da3e19445b6e7b4c61d4af711d29e2703161aa9c11e4e6b0ea08843010000006b483045022100eea27e89c3cf2867393263bece040f34c03e0cddfa93a1a18c0d2e4322a37df7022074273c0ab3836affba53737c83673ca6c0d69bffdf722b4accfd7c0a9b2ea4e60121020bfcdbda850cd250c3995dfdb426dc40a9c8a5b378be2bf39f6b0642a783daf2feffffff02281d2418010000001976a914b56872c7b363bfb3f5af84d071ff282cf2abfe3988ac00e1f5050000000017a9141d4796c6e855ae00acecb0c20f65dd8bbeffb1ec87d1000000"));
    pegin_txin.AddPeginWitnessStack(
        ByteData(
            "03000030ffba1d575800bf37a1ee1962dee7e153c18bcfc93cd013e7c297d5363b36cc2d63d5c4a9fdc746b9d3f4f62995d611c34ee9740ff2b5193ce458fdac6d173800ec402e5affff7f200500000002000000027ce06590120cf8c2bef7726200f0fa655940cadcf62708d7dc9f8f2a417c890b81af4d4299758e7e7a0daa6e7e3d3ec37f97df4ef2392ae5e6d286fc5e7e01d90105"));
  }
  ConfidentialTxIn issue_txin;
  ConfidentialTxIn reissue_txin;
  ConfidentialValue issuance_amount(issue_amount);
  ConfidentialValue inflation_keys(token_amount);
  BlindFactor entropy("6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306");
  BlindFactor blind_factor("c8082e8f6980cb5c938cbeff8d72fd5109eddc337417c3b7a7e62deb9a1b9acf");
  {
    issue_txin.SetIssuance(
        ByteData256(), ByteData256(), issuance_amount,
        inflation_keys, ByteData(), ByteData());
    reissue_txin.SetIssuance(
        entropy.GetData(), blind_factor.GetData(), issuance_amount,
        ConfidentialValue(), ByteData(), ByteData());
  }

  const std::vector<TestEstimateConfidentialTxInRefVector> test_vector = {
    {txin, AddressType::kP2pkhAddress, 150, 0, Script(), Script(), false, "", 0, 0},
    {txin, AddressType::kP2shAddress, 205, 0, exp_script, Script(), false, "", 0, 0},
    {txin, AddressType::kP2shP2wpkhAddress, 92, 0, Script(), Script(), false, "", 0, 0},
    {txin, AddressType::kP2shP2wshAddress, 113, 0, Script("51"), Script(), false, "", 0, 0},
    {txin, AddressType::kP2wpkhAddress, 69, 0, Script(), Script(), false, "", 0, 0},
    {txin, AddressType::kP2wshAddress, 83, 0, exp_script, Script(), false, "", 0, 0},
    {txin, AddressType::kP2wshAddress, 106, 0, Script(multisig_script), Script(), false, "", 0, 0},
    // pegin
    {pegin_txin, AddressType::kP2wpkhAddress, 183, 0, Script(), Script("51"), false, "", 0, 0},
    // issue
    {issue_txin, AddressType::kP2wpkhAddress, 1164, 0, Script(), Script(), true, "", 0, 0},
    {issue_txin, AddressType::kP2wpkhAddress, 1645, 0, Script(), Script(), true, "", 0, 36},
    {issue_txin, AddressType::kP2wpkhAddress, 2285, 0, Script(), Script(), true, "", 0, 52},
    // reissue
    {reissue_txin, AddressType::kP2wpkhAddress, 922, 0, Script(),Script(), true, "", 0, 36},
    {reissue_txin, AddressType::kP2wpkhAddress, 1242, 0, Script(), Script(), true, "", 0, 52},
  };

  for (const auto& test_data : test_vector) {
    uint32_t vsize = 0;
    Script script_template(test_data.script_template);
    Script* template_ptr = nullptr;
    if (!test_data.script_template.empty()) {
      template_ptr = &script_template;
    }
    ConfidentialTxInReference txin_ref(test_data.txin);
    EXPECT_NO_THROW((vsize = txin_ref.EstimateTxInVsize(
        test_data.addr_type, test_data.redeem_script, test_data.is_blind,
        test_data.exponent, test_data.minimum_bits,
        test_data.fedpeg_script, template_ptr)));
    EXPECT_EQ(vsize, test_data.size);
  }
}

#endif  // CFD_DISABLE_ELEMENTS
