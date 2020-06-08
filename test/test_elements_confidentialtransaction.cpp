#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"

using cfd::core::Address;
using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::BlindFactor;
using cfd::core::Amount;
using cfd::core::Txid;
using cfd::core::Pubkey;
using cfd::core::Privkey;
using cfd::core::NetType;
using cfd::core::SigHashType;
using cfd::core::SigHashAlgorithm;
using cfd::core::HashUtil;
using cfd::core::Script;
using cfd::core::ScriptOperator;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptWitness;
using cfd::core::ConfidentialValue;
using cfd::core::ConfidentialAssetId;
using cfd::core::ConfidentialNonce;
using cfd::core::ConfidentialTxIn;
using cfd::core::ConfidentialTxInReference;
using cfd::core::ConfidentialTxOut;
using cfd::core::ConfidentialTxOutReference;
using cfd::core::ConfidentialTransaction;
using cfd::core::IssuanceParameter;
using cfd::core::IssuanceBlindingKeyPair;
using cfd::core::BlindParameter;
using cfd::core::UnblindParameter;
using cfd::core::PegoutKeyData;

static const std::string exp_tx_hex =
    "020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000";
static const std::string exp_tx_empty_hex = "0200000000000000000000";

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

static const Script exp_locking_script(
    "76a9146a98a3f2935718df72518c00768ec67c589e0b2888ac");
static const std::string exp_assetid =
    "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3";

static ScriptWitness GetExpectWitnessStack() {
  ScriptWitness exp_witness_stack;
  exp_witness_stack.AddWitnessStack(
      ByteData(
          "3044022075282f574650e20c3a87d0d1f67d0bcd8f9319b26d244eb254c0aa5bc0284e8002205bddfd4e2f5e278de5f473804a1d061ed6f9bdbcb65fec9b20402879c5a9980901"));
  exp_witness_stack.AddWitnessStack(
      ByteData(
          "025c36c65910268ee06421053cb9bab1c849c4bdd467d6e77a89d33ff213adc3ca"));
  return exp_witness_stack;
}

static ScriptWitness GetExpectPeginWitnessStack() {
  ScriptWitness exp_pegin_witness;
  exp_pegin_witness.AddWitnessStack(ByteData("00e1f50500000000"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "c23bd031406aa9f7ac994f7385cd8d2605adaadf5a473c82557b4586192681d3"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"));
  exp_pegin_witness.AddWitnessStack(
      ByteData("0014e8d28b573816ddfcf98578d7b28543e273f5a72a"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "02000000014578ddc14da3e19445b6e7b4c61d4af711d29e2703161aa9c11e4e6b0ea08843010000006b483045022100eea27e89c3cf2867393263bece040f34c03e0cddfa93a1a18c0d2e4322a37df7022074273c0ab3836affba53737c83673ca6c0d69bffdf722b4accfd7c0a9b2ea4e60121020bfcdbda850cd250c3995dfdb426dc40a9c8a5b378be2bf39f6b0642a783daf2feffffff02281d2418010000001976a914b56872c7b363bfb3f5af84d071ff282cf2abfe3988ac00e1f5050000000017a9141d4796c6e855ae00acecb0c20f65dd8bbeffb1ec87d1000000"));
  exp_pegin_witness.AddWitnessStack(
      ByteData(
          "03000030ffba1d575800bf37a1ee1962dee7e153c18bcfc93cd013e7c297d5363b36cc2d63d5c4a9fdc746b9d3f4f62995d611c34ee9740ff2b5193ce458fdac6d173800ec402e5affff7f200500000002000000027ce06590120cf8c2bef7726200f0fa655940cadcf62708d7dc9f8f2a417c890b81af4d4299758e7e7a0daa6e7e3d3ec37f97df4ef2392ae5e6d286fc5e7e01d90105"));
  return exp_pegin_witness;
}

TEST(ConfidentialTransaction, GetBitcoinTransactionTest) {
  // no witness
  ByteData no_witness_data(
      "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000");
  ByteData conv_nowit;
  EXPECT_NO_THROW(
      (conv_nowit = ConfidentialTransaction::GetBitcoinTransaction(
          no_witness_data)));
  EXPECT_STREQ(no_witness_data.GetHex().c_str(), conv_nowit.GetHex().c_str());

  // witness
  ByteData witness_data(
      "02000000000101d0b871d1a1c019d060e46878e6853c16a886fad7a7bdddcd199b1f4975952dcd0000000000ffffffff01b0069a3b0000000016001405dca32c20abe66ec786bc114fd67ad83e70868d024730440220533dda726705cbbae9cfb8e7a6ccbce581f3db9bb58ab923e71ae8de0e309280022004614f3bf2b7b11bbd02b382d206b9e0b7cba67c682dd88481f712cca2cc3f9d0121036b67e1bd3bd3efbc37fdc738ab159a4aa527057eae12a0c4b07d3132580dcdfd00000000");
  ByteData conv_wit;
  EXPECT_NO_THROW(
      (conv_wit = ConfidentialTransaction::GetBitcoinTransaction(witness_data,
                                                                 false)));
  EXPECT_STREQ(witness_data.GetHex().c_str(), conv_wit.GetHex().c_str());

  ByteData conv_rmwit;
  EXPECT_NO_THROW(
      (conv_rmwit = ConfidentialTransaction::GetBitcoinTransaction(witness_data,
                                                                   true)));
  EXPECT_STREQ(
      "0200000001d0b871d1a1c019d060e46878e6853c16a886fad7a7bdddcd199b1f4975952dcd0000000000ffffffff01b0069a3b0000000016001405dca32c20abe66ec786bc114fd67ad83e70868d00000000",
      conv_rmwit.GetHex().c_str());
}

TEST(ConfidentialTransaction, ConstructorTest) {
  uint32_t lock_time = 0;
  ConfidentialTransaction tx_null;
  EXPECT_STREQ(tx_null.GetHex().c_str(), "0200000000000000000000");

  const ConfidentialTransaction tx_empty(2, lock_time);
  EXPECT_STREQ(tx_empty.GetHex().c_str(), "0200000000000000000000");

  ConfidentialTransaction tx(exp_tx_hex);
  EXPECT_STREQ(tx.GetHex().c_str(), exp_tx_hex.c_str());

  ByteData exp_data = ByteData(exp_tx_hex);
  ConfidentialTransaction tx_b(exp_data);
  ByteData data = tx_b.GetData();
  EXPECT_STREQ(data.GetHex().c_str(), exp_tx_hex.c_str());

  EXPECT_NO_THROW((tx_null = tx));
  EXPECT_STREQ(
      tx_null.GetHex().c_str(),
      "020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000");
  EXPECT_NO_THROW((tx = ConfidentialTransaction(tx_empty)));
  EXPECT_STREQ(tx.GetHex().c_str(), "0200000000000000000000");

  // illegal transaction
  //const std::string txout_empty = "";
  //EXPECT_NO_THROW((tx = ConfidentialTransaction(txout_empty)));
  //EXPECT_STREQ(tx.GetHex().c_str(), txout_empty.c_str());

  const std::string txin_empty =
      "020000000100020b6c4dbd4a5ede07d381fc4f0f69c4166d59da5557c627d8361c13dc28103bbeeb084922fb4232da7c9d12c88dcbf329175771bf4333bbbea23343e86023490253b4025cf9778d533b213387a1e8b68d2acea450ac5ce68c9a550ffefb448a98cec1511976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b4000000000000043010001df8972dc12c7f680d8e1b95222c6e59a0e888d7b3eeea43f7ea41da798443f4034bd02edf6cc9d62cb17d119455f8448cc1e69b6000a6e981380311629ec2475fdcd0d602b000000000000000132af0c6c272999d7ea18001bcfd47a844970bd56b678f59302420fb180ccf25296953926cae9fd36f8ce6e169ab2e18e06175df111db4b55d6954cb8478dce9d847d6f1a57f8dd1c48194caab6d939a76843d154f7021b5b86230edf86366043c5d131a3a845c7470dfde074d7c453100975c0962af42d88da3d6364a7cf4a6123cb4f0e9f0d3d9a7eb96896e52d53bda4cabdd5225056855afcaa2464afc8c8d582d77dc1764b1b238b38e0550400282b33b3e3fbc15473a700aa7955f7f2f0a65ee384783dd173423c6637588a351df2ae60a7ed15e7740f4c77496f04a831e7b66755a354605c0c2eb1d5646483116e5155c384febacc2849b74c1c8d7163da96e5d510ff044ede7ec3a85f2dc32fd5991993ace8a0266726e6c2acca04667acd2b9cd8bf83e87927e06d608f6b22a90806d98e49fff37dfc018123b7b81a85dbfdc8cfb5ccbfa4cc987bf15bd1c927a0665d83cfd2ab9840066c638ace43a6818f7977d896e3612d491bad635c724bf453d5c397dc2b1dc3ed5d64fd9845f45f7af923cabdb32dc946f7c73f927644a141799838a759c918eccd7561144d825246fb84d4355a955c641fd339c0f79d3eb0a4754cff203897b124d1f27b3590acb97b934cfce48e9ce84d9d4078df9f1bd85ac138bc232026ec901e1e8873466d0cea38e1b4ea2c8e923bd301f59769cdc5c61a4b831bea0fb84ff9454a7e4f8f71d699d6927937c257a3c0ea29f9edf1e1fc2a1f22e6adacd711571fc55d548169a6440d83070c9c57b4954666d17fd1d914915e25fada803efb59f38748c77422fc979279f79d5d76a80421e7330989e873d1e5226273f0a4428595fd10f7e2449a216a32903e542fdf7313cc002c74caa676db4b4137d26b1e1a2789e45922556d0ddf0adc0ff15875900f7708a526ee7c4b226b1643d61f3d62de8a6921d4e4000a4c1f65e2507f97300bf18fbb4cef8ecb6add5b01b0c47fd52fd5f4811f1a04b5fcd2a0165cd4d9d9fafdfefca998f796f207d521ed338d2a0aae0c8c41eb51f385071ba2f8eced53f91673e7d756cee0cb9a4ac6335c389c2e138d696508fb9eaf90bbc4f50e9b091e87b1192b64ed0d61cdeaef8b7084c912388aa9c19f514a27597d88f966944298fc9006ae4236cb7d9f3eea7f48fa7b51826b74eaf67bd790a8c8cc3bf9a74db88341f634522b0ac035e016ba9a9e94d262a9899c41f20998f3523f8714e4ccf6b032122bfff0b0bd0a0829888a3d600ec6ba9b20d66ea0ed650e346bd74f590bc83ffc1c02f2091433cdb531c0ba9ac2f91dc0bd30988b11068dd976702544d6fa48235f974aca9b54b38cc8fd789d0f47b48bc9acae3ef585576c58eb846140aa4d703cd380b33ff06b34710871115634ff50c58807d2ed5461e7574775cd51667cd729d4d72f557db3e98d2816b02efb74ca52fb3cd9b15e792f8b33b14370723bbc454eeb70aa66b6d2f104d8519002eb335c9416bad7641dafffe4debec24ad435b9746d63dd2d76bbcaf415e90cfb51f3eddba9a649fb8462bd3627d261625fc95f83cb765f31ae8520129ca2c470b06ac7e5b41f023ad06f25ff0f7cbf9dad137010eb376e0cc3f99cbc716953e863364cd80d97b25988a9510dc617666d7a13da224364ebea7ca5ac03975752a979a21c73861b483165bd5bf4d2d3b402e43da34d58d9131e2207a8454666ac9d55eba79a2267ab5e731c1ce73f59782f5187a5e2f198598f0d86f18303177789830bc74d59167804f030a772753cf134932c880b7074ca7fa001a94f3c540e37e0e72d025106116b6df49fc24fe47200676025e0b45d594ac45c99ac3d481091ec7c4c218d1ad19e00a300be998f870f6252132d62820f0664afa88726b6f327da0c017bf6a9b34f152107524cee9140280acd704a0066cb5faa4e31ebbed5cea9497c573ac49ce32d99347b61f171d8bb431c7f25358e4da4213ea08886bf4691b060b2d2738ecabc2dc8459ebf64bc12d42105335d5e8bfe2bf7fd91db941c0921cd4bee04a3942b2dad6609a9c762e8ea9e28aeaa85758d0c8336da4c0f988e630e30522793e51a773bf509c761b347e98faf822e40aa62156364fb31153eb17d0a1b04792a9535169871378d301a525c8726d984c18bc9a83edf8a24997c20e1613d4144f07506e0f7fd97cee78b469eacfd0a6dcf5157b070a2d9ade2c3e3fd88413adc5e408bcdc75d8093a7aa12a08ea15dd57535073717ed3a1c2073703febca53c3fd048c992dfdeae58d7a91bd86cb30b4de40e4fccaca42db652d979225de33b17be881c95d65883a818f71118c4ae0f1d9d5044f729a2d71aacba8352b4b4ce4ec1b32f84b6eb899591ca0e15d8f6ba328fa0fb54a59445ddf934b55747d71795cc5f8ef9f2f020c9dbc5d3d668b0adb252d5dda38d93750a2d010fea412e32a8854ff464e945bc29ea8ec47f424928cebb920f7c159a5347fce9e034f4d50d680308f9ff6f93b88638f533a3728ddb715829e228c5269c8df3a381e1dc6605ed5a922d48532b6537fcfda1962a1eb4097321266826f10256178b98de34fda9327b379b38519d08a6a5dada265fa038772b706a0f65faf257c7d0d28fb7c2cc98203ad16b833a5dfb37601304c7752d959e2894584528860542b197d75ed7e7e2f412db8a3308f99e34a873e6f4ce21473ecd77d936faf07d1bd5e7c61c6bdc448ab7cb5a2811908ddfd39f9026dbaf67ad4ad12c59377fc0aedec2d6f21e2b3097753fec81ab749444b14c1e22b72fe89d92347e8be6ad9d966cacadff45f6ff517ea8c8be6df77acb4561ba87ee0eddd61f230ef177b84bc702fd0f882b19d5662517ce6f75432464eb9801f14b28a195ab1367282ed807665e8fa866751d32313e89bc30bb7bbeaba6edf78434b42eed146507bb594f2fac22bdfddb1b2dee48e4de07f56701f2f2821075b91ea3dfd5ac2a8e62db57d77d77afd1b55815f3d6978157f307e823f12991a222764997fd0e52f4788994b2649f9de558131d9145fcde4461f4a1d545cd8b385feebec31b43aebcaf40280b2de6101c350da43a97d72e9821e38e648a89363fe8ce4a7a5de1c226390943926e812d204ee22758bed6712d0a47f24ddbd1ee7080ea0e362252506852e3793ad00ec4dad89e210b240cff3132eb1e3834e1dadd56cef093786858c2ac8b55e2871e76e37c07ed23bbd3933c515a7a5b68a9c15e7acdf9deddeeadc98a0f5960e6ba76ccbf391884ceee470b3bbedc9e3fed2f277d9123bdd5435a5ba2522b984ea81eba2deb390d6e00f7acd7512d53c29014482976124593ecb13fd0630b08ae0005bb71eb56649ec8403f67942c17a024764f0dbb8dd4d463ce8ee6bb203fd8335f4940d0d46cd33e82ae87cc46921075a21ee17ad07e2e03c8fbd13b47e3b0018aa2bb77dacfee2ee66a807d10f1923ab673bcc92ecdf453910acecaaa471188d69ada006ae7de5cee5e48e1f64beb4763a945bd95aabeb3057b0a41ad544417d40fe8c915ac6f057fa5df28d056a1f4ca18a62c6d35eafbd766f0ad1d72c86b2305d6e3de0cffb40878a0cc1a1e4bf27d14197ff77516b56b657be3264559bca3654c95bfe7673a3c6dd831d088f0e758470ee69ca6f526938675fce01309f6377121c34429ca496bb89e4d091249dc7a2f5da35207ad7385c8f9d3a644ada38c3faabc0fbbc6a01021f612ef76f2e53ded390c36affa56d1365aeaaeb85469ce4d3619037196818e87e867532b1c417f19afe4795c5389803c30a064f42cfe68fbfb518f13bf84fc4f77c9d32df00818bcb831684a6149963c4851a3c7675a67f0111634abb3ed5d2995f4ff1cce9388e72e2be2e36efa28f29037a181ba09c2d30970024e9ca817d5c230a381d0402db6adaeb03375367eaad425b147b86211807b7ed68245ddc44bdbc32c818fad968e036fad46ca3d8c2a5b956c0228b61e1f66c0fbfd232e29fefbb51f2c68a7db0c3dd429db1a94277607c8323c288e596d53aec34c78c6db00370342c43354313ec4b012d3797d5ee23f38f91f2ac8c1e8043e4b84503e0c9e3fd0aa1c61d3f2c6e2202efd1f9a147ceaa456fffe841294e6ab1f055e5981217d8595bdf2254085656bf8686bf6972f3269de24e2afd82c159e38b97745c0cb6d5b584135c75ae86feff435d4d2071c5fb9b68e8a7ea4e2b987abe20811e1a99656ce5ff93260b6896812f6359ab5fa7fd6fb4066a158ac63abf39a8e1fa1d47e011ba33806c339078c6212e2c6fe794580bb27069fe70ff48c42e3bb2587bfa49650173d1991920ef8c3cd216f389ff2fb53fccaf88f9a8f1688aa4e2d577dc79ba41603721bdfe86073472d275d28896296c0e30842a85c06a6018b0a8d94bb72eeaba5fe09b0000ff7b29748e52ceb9088ab3224a2e6036932f484348cdf77dd326de421c0066d4b68102db6739347a19736cfe2dfaa90e488d4dc885d969f000f2e17bf9e52f7e870eb054d51ca9c435ed1378ecf8dd2541fc32ac662b588460b553e1820c6b1ca6d067442943a56806a6ea57c95bb013db6c474f049df048d322eaadb6a9fbfdd9f2c25511227787fe63fe4d0a80b1785d5d85c10398550cc2385e9bab225d58babe8268d3659fda6ccfdc23556ec27a924b9dee51b09ba03d1366704d63129f701c7e51cc80278faf69cdd7200f29f53f36094142677ce517e734b3b1bbf831548d2224b4dd0bd32370092f771e730f86dcc27fe80b663e95b51e33c0a303ca456e2ab688e84015ac29d8b782b3d79bdd69ce843af5e547616c4beba83c3b49e7041cbbda0545885864410353e581c657dd629646f43d4485d712cfaaf29ab15a023e6082e9b6ab21429fed74425d44eb7b00a0c9a5c6211a7041a31130ed92d1a2d385a540d827fe75cab210d8d508d55246a9143bcf24e8cddea3a5881d3814ada09e7685c9aee3caf7ea5855a79b0000";
  EXPECT_NO_THROW((tx = ConfidentialTransaction(txin_empty)));
  EXPECT_STREQ(tx.GetHex().c_str(), txin_empty.c_str());
}

TEST(ConfidentialTransaction, TxInTest) {
  ConfidentialTransaction tx(2, static_cast<uint32_t>(0));
  EXPECT_NO_THROW((tx = ConfidentialTransaction(exp_tx_hex)));
  EXPECT_EQ(tx.GetTxInCount(), 1);
  // GetTxIn
  ConfidentialTxInReference txin_ref;
  EXPECT_THROW((txin_ref = tx.GetTxIn(1)), CfdException);
  EXPECT_NO_THROW((txin_ref = tx.GetTxIn(0)));
  EXPECT_STREQ(
      txin_ref.GetTxid().GetHex().c_str(),
      "56eb4a177459bae6d310cd117dde5ff86e0a6572d44dcf5e25e611435fff9b31");
  EXPECT_EQ(txin_ref.GetVout(), 1);
  EXPECT_EQ(txin_ref.GetSequence(), 0xffffffff);
  EXPECT_STREQ(
      txin_ref.GetBlindingNonce().GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_STREQ(
      txin_ref.GetAssetEntropy().GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_STREQ(txin_ref.GetIssuanceAmount().GetHex().c_str(), "");
  EXPECT_STREQ(txin_ref.GetInflationKeys().GetHex().c_str(), "");
  EXPECT_STREQ(txin_ref.GetIssuanceAmountRangeproof().GetHex().c_str(), "");
  EXPECT_STREQ(txin_ref.GetInflationKeysRangeproof().GetHex().c_str(), "");

  // GetTxInIndex, AddTxIn
  uint32_t index = 0;
  uint32_t add_index;
  EXPECT_THROW((index = tx.GetTxInIndex(exp_txid, exp_index)), CfdException);

  EXPECT_NO_THROW(
      (add_index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));
  EXPECT_NO_THROW((index = tx.GetTxInIndex(exp_txid, exp_index)));
  EXPECT_EQ(add_index, 1);
  EXPECT_EQ(index, 1);
  EXPECT_EQ(tx.GetTxInCount(), 2);
  // mask check
  EXPECT_NO_THROW((index = tx.GetTxInIndex(exp_txid, exp_index | 0x80000000)));
  EXPECT_EQ(index, 1);

  // GetTxInList
  std::vector<ConfidentialTxInReference> ref_list;
  EXPECT_NO_THROW((ref_list = tx.GetTxInList()));
  EXPECT_EQ(ref_list.size(), 2);
  EXPECT_STREQ(
      ref_list[0].GetTxid().GetHex().c_str(),
      "56eb4a177459bae6d310cd117dde5ff86e0a6572d44dcf5e25e611435fff9b31");
  EXPECT_EQ(ref_list[0].GetVout(), 1);
  EXPECT_EQ(ref_list[0].GetSequence(), 0xffffffff);
  EXPECT_STREQ(ref_list[1].GetTxid().GetHex().c_str(),
               exp_txid.GetHex().c_str());
  EXPECT_EQ(ref_list[1].GetVout(), exp_index);
  EXPECT_EQ(ref_list[1].GetSequence(), exp_sequence);

  // RemoveTxIn
  EXPECT_THROW((tx.RemoveTxIn(5)), CfdException);
  EXPECT_NO_THROW((tx.RemoveTxIn(1)));
  EXPECT_EQ(tx.GetTxInCount(), 1);
}

// coinbase tx

TEST(ConfidentialTransaction, SetIssuance) {
  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW(
      (index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));

  EXPECT_NO_THROW(
      (tx.SetIssuance(index, exp_blinding_nonce, exp_asset_entropy,
                      exp_issuance_amount, exp_inflation_keys,
                      exp_issuance_amount_rangeproof,
                      exp_inflation_keys_rangeproof)));

  ConfidentialTxInReference txin;
  EXPECT_NO_THROW((txin = tx.GetTxIn(1)));

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
}

TEST(ConfidentialTransaction, PeginWitnessTest) {
  ScriptWitness exp_pegin_witness = GetExpectPeginWitnessStack();
  const ByteData exp_data("1234567890");
  const ByteData160 exp_data160("1234567890123456789012345678901234567890");
  const ByteData256 exp_data256(
      "1234567890123456789012345678901234567890123456789012345678901234");
  const std::vector<ByteData>& exp_peg_vector = exp_pegin_witness.GetWitness();
  ByteData256 witness_only_hash = ByteData256();

  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW(
      (index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));
  EXPECT_NO_THROW(
      (tx.SetIssuance(index, exp_blinding_nonce, exp_asset_entropy,
                      exp_issuance_amount, exp_inflation_keys,
                      exp_issuance_amount_rangeproof,
                      exp_inflation_keys_rangeproof)));
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), 0);

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "5e1940c383c21cc75720f61fcc7cf95a056239ce73d5bd1cee1ff0c578bbcf99");

  // AddPeginWitness
  ScriptWitness witness;
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_NO_THROW(
        (witness = tx.AddPeginWitnessStack(index, exp_peg_vector[idx])));
  }
  std::vector<ByteData> test_peg_vector = witness.GetWitness();
  for (size_t idx = 0; idx < exp_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
                 exp_peg_vector[idx].GetHex().c_str());
  }
  std::vector<ByteData> tx_peg_vector = tx.GetTxIn(index).GetPeginWitness()
      .GetWitness();
  for (size_t idx = 0; idx < tx_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
                 tx_peg_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), exp_peg_vector.size());

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "7d3c4a5dbe536fd91715b2560826eae62f014cdefa02a0291b5c7dd9f3ad6b3a");

  // AddPeginWitness(160,256)
  EXPECT_THROW((witness = tx.AddPeginWitnessStack(index + 5, exp_data160)),
               CfdException);
  EXPECT_NO_THROW((witness = tx.AddPeginWitnessStack(index, exp_data160)));
  EXPECT_NO_THROW((witness = tx.AddPeginWitnessStack(index, exp_data256)));
  test_peg_vector = witness.GetWitness();
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size()].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size() + 1].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), exp_peg_vector.size() + 2);

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "ab4c6b401c0a47da16ee3b9135960bbfe7175de798ba398bbd6810b4fbbbcecf");

  // SetPeginWitnessStack
  EXPECT_THROW(
      (witness = tx.SetPeginWitnessStack(index + 5, static_cast<size_t>(exp_peg_vector.size()),
                                         exp_data160)),
      CfdException);
  EXPECT_THROW(
      (witness = tx.SetPeginWitnessStack(index, static_cast<size_t>(exp_peg_vector.size()) + 5,
                                         exp_data160)),
      CfdException);
  EXPECT_NO_THROW((witness = tx.SetPeginWitnessStack(index, 0, exp_data)));
  EXPECT_NO_THROW(
      (witness = tx.SetPeginWitnessStack(index, static_cast<size_t>(exp_peg_vector.size()),
                                         exp_data256)));
  EXPECT_NO_THROW(
      (witness = tx.SetPeginWitnessStack(index, static_cast<size_t>(exp_peg_vector.size()) + 1,
                                         exp_data160)));
  test_peg_vector = witness.GetWitness();
  EXPECT_STREQ(test_peg_vector[0].GetHex().c_str(), exp_data.GetHex().c_str());
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size()].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_STREQ(test_peg_vector[exp_peg_vector.size() + 1].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  tx_peg_vector = tx.GetTxIn(index).GetPeginWitness().GetWitness();
  for (size_t idx = 0; idx < tx_peg_vector.size(); ++idx) {
    EXPECT_STREQ(test_peg_vector[idx].GetHex().c_str(),
                 tx_peg_vector[idx].GetHex().c_str());
  }

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "28fb92ba0f34d2073bbb6f41c262da513166a350b89da6103df13327ec8668fa");

  // RemovePeginWitnessStackAll
  EXPECT_THROW((tx.RemovePeginWitnessStackAll(index + 5)), CfdException);
  EXPECT_NO_THROW((tx.RemovePeginWitnessStackAll(index)));
  EXPECT_EQ(tx.GetPeginWitnessStackNum(index), 0);
}

TEST(ConfidentialTransaction, ScriptWitnessTest) {
  ScriptWitness exp_witness_stack = GetExpectWitnessStack();
  const ByteData exp_data("1234567890");
  const ByteData160 exp_data160("1234567890123456789012345678901234567890");
  const ByteData256 exp_data256(
      "1234567890123456789012345678901234567890123456789012345678901234");
  const std::vector<ByteData>& exp_wit_vector = exp_witness_stack.GetWitness();
  ByteData256 witness_only_hash;

  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW(
      (index = tx.AddTxIn(exp_txid, exp_index, exp_sequence, exp_script)));
  EXPECT_NO_THROW(
      (tx.SetIssuance(index, exp_blinding_nonce, exp_asset_entropy,
                      exp_issuance_amount, exp_inflation_keys,
                      exp_issuance_amount_rangeproof,
                      exp_inflation_keys_rangeproof)));
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), 0);

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "5e1940c383c21cc75720f61fcc7cf95a056239ce73d5bd1cee1ff0c578bbcf99");

  // AddScriptWitnessStack
  ScriptWitness witness;
  for (size_t idx = 0; idx < exp_wit_vector.size(); ++idx) {
    EXPECT_NO_THROW(
        (witness = tx.AddScriptWitnessStack(index, exp_wit_vector[idx])));
  }
  std::vector<ByteData> test_wit_vector = witness.GetWitness();
  for (size_t idx = 0; idx < exp_wit_vector.size(); ++idx) {
    EXPECT_STREQ(test_wit_vector[idx].GetHex().c_str(),
                 exp_wit_vector[idx].GetHex().c_str());
  }
  std::vector<ByteData> tx_wit_vector = tx.GetTxIn(index).GetScriptWitness()
      .GetWitness();
  for (size_t idx = 0; idx < tx_wit_vector.size(); ++idx) {
    EXPECT_STREQ(test_wit_vector[idx].GetHex().c_str(),
                 tx_wit_vector[idx].GetHex().c_str());
  }
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), exp_wit_vector.size());

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "17bd17d4d6122c1ffc8c5cbbaa3ac33051f50a85a09dbaa8c52f98ef21f3e5df");

  // AddScriptWitnessStack(160,256)
  EXPECT_THROW((witness = tx.AddScriptWitnessStack(index + 5, exp_data160)),
               CfdException);
  EXPECT_NO_THROW((witness = tx.AddScriptWitnessStack(index, exp_data160)));
  EXPECT_NO_THROW((witness = tx.AddScriptWitnessStack(index, exp_data256)));
  test_wit_vector = witness.GetWitness();
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size()].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size() + 1].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), exp_wit_vector.size() + 2);

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "8088774d9f59f484294dfd11cac751c33166becdcb8fb89856fab90b0c81e92f");

  // SetScriptWitnessStack
  EXPECT_THROW(
      (witness = tx.SetScriptWitnessStack(index + 5, static_cast<size_t>(exp_wit_vector.size()),
                                          exp_data160)),
      CfdException);
  EXPECT_THROW(
      (witness = tx.SetScriptWitnessStack(index, static_cast<size_t>(exp_wit_vector.size()) + 5,
                                          exp_data160)),
      CfdException);
  EXPECT_NO_THROW((witness = tx.SetScriptWitnessStack(index, 0, exp_data)));
  EXPECT_NO_THROW(
      (witness = tx.SetScriptWitnessStack(index, static_cast<size_t>(exp_wit_vector.size()),
                                          exp_data256)));
  EXPECT_NO_THROW(
      (witness = tx.SetScriptWitnessStack(index, static_cast<size_t>(exp_wit_vector.size()) + 1,
                                          exp_data160)));
  test_wit_vector = witness.GetWitness();
  EXPECT_STREQ(test_wit_vector[0].GetHex().c_str(), exp_data.GetHex().c_str());
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size()].GetHex().c_str(),
               exp_data256.GetHex().c_str());
  EXPECT_STREQ(test_wit_vector[exp_wit_vector.size() + 1].GetHex().c_str(),
               exp_data160.GetHex().c_str());
  tx_wit_vector = tx.GetTxIn(index).GetScriptWitness().GetWitness();
  for (size_t idx = 0; idx < tx_wit_vector.size(); ++idx) {
    EXPECT_STREQ(test_wit_vector[idx].GetHex().c_str(),
                 tx_wit_vector[idx].GetHex().c_str());
  }

  EXPECT_NO_THROW(
    (witness_only_hash = tx.GetWitnessOnlyHash()));
  EXPECT_STREQ(
    witness_only_hash.GetHex().c_str(),
    "939475f226f92b9b06810fe472e73cb02a1402be2f17f815c0ddf7e103373c0f");

  // RemoveScriptWitnessStackAll
  EXPECT_THROW((tx.RemoveScriptWitnessStackAll(index + 5)), CfdException);
  EXPECT_NO_THROW((tx.RemoveScriptWitnessStackAll(index)));
  EXPECT_EQ(tx.GetScriptWitnessStackNum(index), 0);
}

TEST(ConfidentialTransaction, SetUnlockingScriptTest) {
  ConfidentialTransaction tx(exp_tx_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));
  EXPECT_EQ(index, 1);

  // SetUnlockingScript
  EXPECT_THROW((tx.SetUnlockingScript(index + 5, exp_script)), CfdException);
  EXPECT_NO_THROW((tx.SetUnlockingScript(index, exp_script)));

  ConfidentialTxInReference txin_ref;
  EXPECT_NO_THROW((txin_ref = tx.GetTxIn(1)));
  EXPECT_STREQ(txin_ref.GetUnlockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());

  // SetUnlockingScript2
  const ByteData exp_data1("1234567890");
  const ByteData exp_data2("1234567890123456789012345678901234567890");
  std::vector<ByteData> exp_list;
  exp_list.push_back(exp_data1);
  exp_list.push_back(exp_data2);
  EXPECT_THROW((tx.SetUnlockingScript(index + 5, exp_list)), CfdException);
  EXPECT_NO_THROW((tx.SetUnlockingScript(index, exp_list)));

  EXPECT_NO_THROW((txin_ref = tx.GetTxIn(1)));
  EXPECT_STREQ(txin_ref.GetUnlockingScript().GetHex().c_str(),
               "051234567890141234567890123456789012345678901234567890");
}

TEST(ConfidentialTransaction, TxOutTest) {
  ConfidentialTransaction tx(exp_tx_empty_hex);
  uint32_t index = 0;
  uint32_t get_index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));

  // AddTxOut, GetTxOut, GetTxOutCount
  EXPECT_EQ(tx.GetTxOutCount(), 0);
  int64_t exp_satoshi = 12345678;
  EXPECT_THROW((get_index = tx.GetTxOutIndex(exp_locking_script)), CfdException);

  Amount amt = Amount::CreateBySatoshiAmount(exp_satoshi);
  ConfidentialAssetId asset(exp_assetid);
  ConfidentialTxOutReference txout_ref;
  EXPECT_NO_THROW((index = tx.AddTxOut(amt, asset, exp_locking_script)));
  EXPECT_EQ(index, 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);
  EXPECT_NO_THROW(get_index = tx.GetTxOutIndex(exp_locking_script));
  EXPECT_EQ(index, get_index);

  EXPECT_THROW((txout_ref = tx.GetTxOut(index + 5)), CfdException);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");

  // AddTxOut
  Script exp_locking_script2("00146a98a3f2935718df72518c00768ec67c589e0b28");
  ConfidentialNonce nonce(
      "991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  ByteData surjection_proof("1234567890");
  ByteData range_proof("1234567890123456789012345678901234567890");
  EXPECT_NO_THROW(
      (index = tx.AddTxOut(amt, asset, exp_locking_script2, nonce,
                           surjection_proof, range_proof)));
  EXPECT_EQ(index, 1);
  EXPECT_EQ(tx.GetTxOutCount(), 2);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script2.GetHex().c_str());
  EXPECT_STREQ(
      txout_ref.GetNonce().GetHex().c_str(),
      "01991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               surjection_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               range_proof.GetHex().c_str());
  EXPECT_NO_THROW(get_index = tx.GetTxOutIndex(exp_locking_script2));
  EXPECT_EQ(index, get_index);

  // GetTxOutList
  std::vector<ConfidentialTxOutReference> txout_list;
  EXPECT_NO_THROW((txout_list = tx.GetTxOutList()));
  EXPECT_EQ(txout_list.size(), 2);
  txout_ref = txout_list[0];
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");

  txout_ref = txout_list[1];
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script2.GetHex().c_str());
  EXPECT_STREQ(
      txout_ref.GetNonce().GetHex().c_str(),
      "01991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               surjection_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               range_proof.GetHex().c_str());

  // AddTxOut (address duplex)
  EXPECT_NO_THROW((index = tx.AddTxOut(amt, asset, exp_locking_script)));
  EXPECT_EQ(index, 2);
  EXPECT_EQ(tx.GetTxOutCount(), 3);
  EXPECT_NO_THROW(get_index = tx.GetTxOutIndex(exp_locking_script));
  EXPECT_EQ(0, get_index);
  std::vector<uint32_t> index_list;
  EXPECT_NO_THROW(index_list = tx.GetTxOutIndexList(exp_locking_script));
  EXPECT_EQ(2, index_list.size());
  if (index_list.size() == 2) {
    EXPECT_EQ(0, index_list[0]);
    EXPECT_EQ(2, index_list[1]);
  }

  // SetTxOutValue (address duplex)
  Amount amt2 = Amount::CreateBySatoshiAmount(7654321);
  EXPECT_NO_THROW(tx.SetTxOutValue(2, amt2));
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(2)));
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "01000000000074cbb1");

  // RemoveTxOut
  EXPECT_THROW((tx.RemoveTxOut(3)), CfdException);
  EXPECT_NO_THROW((tx.RemoveTxOut(0)));
  EXPECT_EQ(tx.GetTxOutCount(), 2);
}

TEST(ConfidentialTransaction, AddTxOutFeeTest) {
  ConfidentialTransaction tx(exp_tx_empty_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));

  // AddTxOut, GetTxOut, GetTxOutCount
  EXPECT_EQ(tx.GetTxOutCount(), 0);
  int64_t exp_satoshi_fee = 12345;

  Amount amt = Amount::CreateBySatoshiAmount(exp_satoshi_fee);
  ConfidentialAssetId asset(exp_assetid);
  ConfidentialTxOutReference txout_ref;
  EXPECT_NO_THROW((index = tx.AddTxOutFee(amt, asset)));
  EXPECT_EQ(index, 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);

  EXPECT_THROW((txout_ref = tx.GetTxOut(index + 5)), CfdException);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000003039");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
}

TEST(ConfidentialTransaction, SetTxOutCommitmentTest) {
  ConfidentialTransaction tx(exp_tx_empty_hex);
  uint32_t index = 0;
  EXPECT_NO_THROW((index = tx.AddTxIn(exp_txid, exp_index, exp_sequence)));

  // AddTxOut, GetTxOut, GetTxOutCount
  EXPECT_EQ(tx.GetTxOutCount(), 0);
  int64_t exp_satoshi = 12345678;

  Amount amt = Amount::CreateBySatoshiAmount(exp_satoshi);
  ConfidentialAssetId asset(exp_assetid);
  ConfidentialTxOutReference txout_ref;
  EXPECT_NO_THROW((index = tx.AddTxOut(amt, asset, exp_locking_script)));
  EXPECT_EQ(index, 0);
  EXPECT_EQ(tx.GetTxOutCount(), 1);
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));

  // SetTxOutCommitment
  ConfidentialNonce nonce(
      "991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  ByteData surjection_proof("1234567890");
  ByteData range_proof("1234567890123456789012345678901234567890");
  EXPECT_NO_THROW(
      (tx.SetTxOutCommitment(index, asset, txout_ref.GetConfidentialValue(),
                             nonce, surjection_proof, range_proof)));
  EXPECT_NO_THROW((txout_ref = tx.GetTxOut(index)));
  EXPECT_STREQ(
      txout_ref.GetAsset().GetHex().c_str(),
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               "010000000000bc614e");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_locking_script.GetHex().c_str());
  EXPECT_STREQ(
      txout_ref.GetNonce().GetHex().c_str(),
      "01991a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               surjection_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               range_proof.GetHex().c_str());
}

TEST(ConfidentialTransaction, BlindTxOutTest) {
  std::string tx_hex = "020000000001e6162f9bbac022e67327e717a3885b316a54e50c34ba266b58f1999854c596810100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000138800017a914a3949e9a8b0b813db67c8fc5ad14194a297979cd870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000027100017a9145227b0820cf08f489873888672a5d97face863b2870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000002710000000000000";
  ConfidentialTransaction tx(tx_hex);
  double inputamount = 0.001;
  std::string inputblinder =
      "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee";
  std::string inputasset =
      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
  std::string inputassetblinder =
      "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5";
  std::string pubkey1_hex =
      "0213c4451645063e1edd5fe76e5194864c2246d4c4e6c8df5a305224046e1ea2c4";
  std::string privkey1_hex =
      "66e4df5035a64acef16b4aa52ddc8bebd22b22c9eca150774e355abc72909d83";
  std::string pubkey2_hex =
      "0222722d38de0463756bdfc460de0547a89e17159150d07b6cf69029ba33adf967";
  std::string privkey2_hex =
      "715b3d80726388b7daff92388f82c8ddf5ee7248900552a0bcd16d7d46b439c0";
  Pubkey pubkey1(pubkey1_hex);
  Privkey privkey1(privkey1_hex);
  Pubkey pubkey2(pubkey2_hex);
  Privkey privkey2(privkey2_hex);

  std::vector<BlindParameter> blind_list;
  BlindParameter param;
  param.asset = ConfidentialAssetId(inputasset);
  param.abf = BlindFactor(inputassetblinder);
  param.vbf = BlindFactor(inputblinder);
  param.value = ConfidentialValue(Amount::CreateByCoinAmount(inputamount));
  blind_list.push_back(param);
  std::vector<Pubkey> pubkeys;
  pubkeys.push_back(pubkey1);
  pubkeys.push_back(pubkey2);
  pubkeys.push_back(Pubkey());

  EXPECT_NO_THROW((tx.BlindTxOut(blind_list, pubkeys)));
  // 乱数が混ざるため、サイズだけチェック
  EXPECT_EQ(tx.GetHex().length(), 17676);
  std::string blind_tx = tx.GetHex();

  std::vector<Privkey> blinding_keys;
  blinding_keys.push_back(privkey1);
  blinding_keys.push_back(privkey2);
  blinding_keys.push_back(Privkey());
  std::vector<UnblindParameter> unblindList;
  EXPECT_NO_THROW((unblindList = tx.UnblindTxOut(blinding_keys)));
  EXPECT_STREQ(tx.GetHex().c_str(), tx_hex.c_str());
  EXPECT_EQ(unblindList.size(), 2);
  EXPECT_EQ(unblindList[0].value.GetAmount().GetSatoshiValue(), 80000);
  EXPECT_EQ(unblindList[1].value.GetAmount().GetSatoshiValue(), 10000);
}

TEST(ConfidentialTransaction, BlindTxOutUncompressedPubkeyTest) {
  std::string tx_hex = "020000000001438cbb074e26715c25a11d12ef22f8e6080c466ff607936208473787138ba95a0000000000ffffffff0301f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000000895440001976a914dff13ae1f9b4ce176adbeef85db623a6ee5a907988ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000000f1b30001976a914de89a605e67cabd0391ecc8b01ba1ec9434394fe88ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000000002710000000000000";
  ConfidentialTransaction tx(tx_hex);
  double inputamount = 0.1;
  std::string inputblinder =
      "0000000000000000000000000000000000000000000000000000000000000000";
  std::string inputasset =
      "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3";
  std::string inputassetblinder =
      "0000000000000000000000000000000000000000000000000000000000000000";
  std::string pubkey1_hex =
      "04dada4cf7659309225a0a7cc34b7281fde98181a871ff9666ee7118895fe2a659d5f346c08488fb6a73a0d92ad1b547e58265b338fb2e73cea9ae6cd224225e22";
  std::string pubkey2_hex =
      "04964523753907b96be824651f55eac8aead20f97759333813b3c0d9edc213e6abbce207ea330383fdccc5c78e9cd89f3eae8ed6089ddb7dd0878c7836e82e38bd";
  Pubkey pubkey1(pubkey1_hex);
  Pubkey pubkey2(pubkey2_hex);

  std::vector<BlindParameter> blind_list;
  BlindParameter param;
  param.asset = ConfidentialAssetId(inputasset);
  param.abf = BlindFactor(inputassetblinder);
  param.vbf = BlindFactor(inputblinder);
  param.value = ConfidentialValue(Amount::CreateByCoinAmount(inputamount));
  blind_list.push_back(param);
  std::vector<Pubkey> pubkeys;
  pubkeys.push_back(pubkey1);
  pubkeys.push_back(pubkey2);
  pubkeys.push_back(Pubkey());

  EXPECT_NO_THROW((tx.BlindTxOut(blind_list, pubkeys)));
  // 乱数が混ざるため、サイズだけチェック
  EXPECT_EQ(tx.GetHex().length(), 17684);
}

TEST(ConfidentialTransaction, BlindTransactionTest1) {
  std::string tx_hex = "020000000001e6162f9bbac022e67327e717a3885b316a54e50c34ba266b58f1999854c596810000008000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000003b9aca00010000000005f5e10004017d63e62c547bcc63dcdd626493ca47219edb08de15e68dc12d773abcc6b4076e01000000003b9aca000017a914ba570779a432049e072b0f201e43f482c772a0808701e30071704b5fbe1cca1bdfb1760d46ec1d094b7057b4d45fad23f4bdd321debc010000000005f5e1000017a914bb1706309b3384d40a63619a353014018afd142b870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000298100017a914a3949e9a8b0b813db67c8fc5ad14194a297979cd870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000002710000000000000";
  ConfidentialTransaction tx(tx_hex);
  double inputamount = 0.0018;
  std::string inputblinder =
      "0fb8bb7ffe429a536c41e5f7328499fdf8ee44394fa5f4a532eedd76caeeccb7";
  std::string inputasset =
      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
  std::string inputassetblinder =
      "48b33c437a3eb3da46a14064c91bc431213fe03fe13d0774f5d84b4296617e48";
  std::string pubkey_issue1_hex =
      "029392a91eca1c4c31ef03f8297e8b1e339119f177d36e7fae547c8642791ab578";
  std::string privkey_issue1_hex =
      "5cf8bb2df2de6427475e6c1f1bea7a16dd6d6f6fab0ee20c8559aa90aa8e8a03";
  std::string pubkey_issue2_hex =
      "03c167b83234f6fb74ee40f9e3f22f723287fffc53aec9d71ab4e34c2070211061";
  std::string privkey_issue2_hex =
      "597c03264c9f0caf11119dc239825669a85c65ec926607a03e2140db78380c6b";
  std::string pubkey1_hex =
      "0213c4451645063e1edd5fe76e5194864c2246d4c4e6c8df5a305224046e1ea2c4";
  std::string privkey1_hex =
      "66e4df5035a64acef16b4aa52ddc8bebd22b22c9eca150774e355abc72909d83";
  Pubkey pubkey1(pubkey1_hex);
  Privkey privkey1(privkey1_hex);
  Pubkey pubkeyIssue1(pubkey_issue1_hex);
  Privkey privkeyIssue1(privkey_issue1_hex);
  Pubkey pubkeyIssue2(pubkey_issue2_hex);
  Privkey privkeyIssue2(privkey_issue2_hex);
  Privkey issue_blind_key(
      "89ef3af787f3263d50fe81b6e1e5514a2c489b30614f5b29b29a846662196092");

  std::vector<BlindParameter> blind_list;
  std::vector<IssuanceBlindingKeyPair> issue_keys;
  BlindParameter param;
  IssuanceBlindingKeyPair issue_key;
  param.asset = ConfidentialAssetId(inputasset);
  param.abf = BlindFactor(inputassetblinder);
  param.vbf = BlindFactor(inputblinder);
  param.value = ConfidentialValue(Amount::CreateByCoinAmount(inputamount));
  blind_list.push_back(param);
  issue_key.asset_key = issue_blind_key;
  issue_key.token_key = issue_blind_key;
  issue_keys.push_back(issue_key);
  std::vector<Pubkey> pubkeys;
  pubkeys.push_back(pubkeyIssue1);
  pubkeys.push_back(pubkeyIssue2);
  pubkeys.push_back(pubkey1);
  pubkeys.push_back(Pubkey());

  EXPECT_NO_THROW((tx.BlindTransaction(blind_list, issue_keys, pubkeys)));
  // 乱数が混ざるため、サイズだけチェック
  EXPECT_EQ(tx.GetHex().length(), 43728);
  std::string blind_tx = tx.GetHex();
  // if(tx.GetHex().length() != 30918) {
  //   EXPECT_STREQ("", blind_tx.c_str());
  // }

  std::vector<Privkey> blinding_keys;
  blinding_keys.push_back(privkeyIssue1);
  blinding_keys.push_back(privkeyIssue2);
  blinding_keys.push_back(privkey1);
  blinding_keys.push_back(Privkey());
  std::vector<UnblindParameter> unblindList;
  EXPECT_NO_THROW((unblindList = tx.UnblindTxOut(blinding_keys)));
  EXPECT_EQ(unblindList.size(), 3);
  if (unblindList.size() == 3) {
    EXPECT_EQ(unblindList[0].value.GetAmount().GetSatoshiValue(), 1000000000);
    EXPECT_EQ(unblindList[1].value.GetAmount().GetSatoshiValue(), 100000000);
    EXPECT_EQ(unblindList[2].value.GetAmount().GetSatoshiValue(), 170000);
  }

  std::vector<UnblindParameter> unblindIssueList;
  EXPECT_NO_THROW(
      (unblindIssueList = tx.UnblindTxIn(0, issue_blind_key, issue_blind_key)));
  EXPECT_EQ(unblindIssueList.size(), 2);
  if (unblindIssueList.size() == 2) {
    EXPECT_EQ(unblindIssueList[0].value.GetAmount().GetSatoshiValue(), 1000000000);
    EXPECT_EQ(unblindIssueList[1].value.GetAmount().GetSatoshiValue(), 100000000);
  }

  EXPECT_STREQ(tx.GetHex().c_str(), tx_hex.c_str());
}

TEST(ConfidentialTransaction, SignatureHashTest) {
  ConfidentialTransaction tx(
      "020000000001319bff5f4311e6255ecf4dd472650a6ef85fde7d11cd10d3e6ba5974174aeb560100000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000bd2cc1584c002deb65cc52301e1622f482a2f588b9800d2b8386ffabf74d6b2d73d17503a2f921976a9146a98a3f2935718df72518c00768ec67c589e0b2888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000004c4b40000000000000");
  // double inputamount = 130000.0;
  // Amount amount = Amount::CreateByCoinAmount(inputamount);
  ByteData256 byte_data;
  SigHashType sig_hash_type(SigHashAlgorithm::kSigHashAll);
  Pubkey utxo_pubkey(
      "020ff7000e2754f34aeb894f1e4dc985e3f9742b194fac2350f963dfa219f177c4");
  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_DUP);
  builder.AppendOperator(ScriptOperator::OP_HASH160);
  builder.AppendData(HashUtil::Hash160(utxo_pubkey));
  builder.AppendOperator(ScriptOperator::OP_EQUALVERIFY);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  ByteData script_byte = builder.Build().GetData();

  EXPECT_NO_THROW(
      (byte_data = tx.GetElementsSignatureHash(0, script_byte, sig_hash_type)));
  EXPECT_STREQ(
      byte_data.GetHex().c_str(),
      "d0b8a3b596813756ca042fd510c4acac522378e8e3ac610fdc0301f6921aac34");

  Script empty_script;
  EXPECT_THROW(
      (byte_data = tx.GetElementsSignatureHash(
          0, empty_script.GetData(), sig_hash_type)), CfdException);
}

TEST(ConfidentialTransaction, SetAssetIssuanceTest) {
  ConfidentialTransaction tx_base(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000000171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff020135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb5390770000000000");
  ConfidentialTransaction expect_tx(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000080171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000002540be40001000000003b9aca00040135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000107ec1ec7027d89071814d5ccd1f5ea4cee45e598287fc8f59acbb1d9129081dc0100000002540be400001976a914144f003aa8dd6408ba0e8ee91757cf1f1976315c88ac01aaf1579c847497d406605b4ef875a2b37164f4c5b9e5d2a23b2b2a16e132ec0501000000003b9aca00001976a914ae8cab151547d6f6e25b62b41200368dfdabe62b88ac0000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb539077000000000000000000");

  // not blind
  ConfidentialTransaction tx(tx_base);
  Amount asset_amount = Amount::CreateByCoinAmount(100.0);
  Amount token_amount = Amount::CreateByCoinAmount(10.0);
  Script asset_script("76a914144f003aa8dd6408ba0e8ee91757cf1f1976315c88ac");
  Script token_script("76a914ae8cab151547d6f6e25b62b41200368dfdabe62b88ac");
  ConfidentialNonce asset_nonce;
  ConfidentialNonce token_nonce;
  ByteData256 contract_hash;
  bool is_blind = false;
  IssuanceParameter param;
  EXPECT_NO_THROW(
      (param = tx.SetAssetIssuance(0, asset_amount, asset_script, asset_nonce,
                                   token_amount, token_script, token_nonce,
                                   is_blind, contract_hash)));
  EXPECT_STREQ(tx.GetHex().c_str(), expect_tx.GetHex().c_str());
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "0a002ed099bd2d52f4bb04d36ebc159c838f0557461d462127845b996e61cb70");
}

TEST(ConfidentialTransaction, SetAssetIssuanceTest_multi) {
  ConfidentialTransaction tx_base(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000000171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff020135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb5390770000000000");
  ConfidentialTransaction expect_tx1(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000080171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000002540be40001000000003b9aca00020135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb5390770000000000");
  ConfidentialTransaction expect_tx2(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000080171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000002540be40001000000003b9aca00060135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000107ec1ec7027d89071814d5ccd1f5ea4cee45e598287fc8f59acbb1d9129081dc0100000001bf08eb00001976a914144f003aa8dd6408ba0e8ee91757cf1f1976315c88ac0107ec1ec7027d89071814d5ccd1f5ea4cee45e598287fc8f59acbb1d9129081dc01000000009502f90002074a50df2248e62bbd18a4a4abf2c8923f0740da61a28dc9e9156092c90e20aa160014144f003aa8dd6408ba0e8ee91757cf1f1976315c01aaf1579c847497d406605b4ef875a2b37164f4c5b9e5d2a23b2b2a16e132ec05010000000017d78400001976a914ae8cab151547d6f6e25b62b41200368dfdabe62b88ac01aaf1579c847497d406605b4ef875a2b37164f4c5b9e5d2a23b2b2a16e132ec05010000000023c3460002d297469a08ddce74d2954809504da9af5c806ea91aac8f382857b575b006c590160014ae8cab151547d6f6e25b62b41200368dfdabe62b0000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb53907700000000000000000000000000");

  std::vector<Amount> asset_amount_list;
  std::vector<Script> asset_script_list;
  std::vector<ConfidentialNonce> asset_nonce_list;
  std::vector<Amount> token_amount_list;
  std::vector<Script> token_script_list;
  std::vector<ConfidentialNonce> token_nonce_list;

  // empty check
  ConfidentialTransaction tx(tx_base);
  Amount asset_amount = Amount::CreateByCoinAmount(100.0);
  Amount token_amount = Amount::CreateByCoinAmount(10.0);
  Script asset_script("76a914144f003aa8dd6408ba0e8ee91757cf1f1976315c88ac");
  Script token_script("76a914ae8cab151547d6f6e25b62b41200368dfdabe62b88ac");
  ConfidentialNonce asset_nonce;
  ConfidentialNonce token_nonce;
  ByteData256 contract_hash;
  bool is_blind = false;
  IssuanceParameter param;
  EXPECT_NO_THROW(
      (param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash)));
  EXPECT_STREQ(tx.GetHex().c_str(), expect_tx1.GetHex().c_str());
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "0a002ed099bd2d52f4bb04d36ebc159c838f0557461d462127845b996e61cb70");

  // 2-output check
  tx = ConfidentialTransaction(tx_base);
  Amount asset_amount1 = Amount::CreateByCoinAmount(75.0);
  Amount asset_amount2 = Amount::CreateByCoinAmount(25.0);
  Script asset_script1("76a914144f003aa8dd6408ba0e8ee91757cf1f1976315c88ac");
  Script asset_script2("0014144f003aa8dd6408ba0e8ee91757cf1f1976315c");
  ConfidentialNonce asset_nonce1;
  ConfidentialNonce asset_nonce2("02074a50df2248e62bbd18a4a4abf2c8923f0740da61a28dc9e9156092c90e20aa");
  Amount token_amount1 = Amount::CreateByCoinAmount(4.0);
  Amount token_amount2 = Amount::CreateByCoinAmount(6.0);
  Script token_script1("76a914ae8cab151547d6f6e25b62b41200368dfdabe62b88ac");
  Script token_script2("0014ae8cab151547d6f6e25b62b41200368dfdabe62b");
  ConfidentialNonce token_nonce1;
  ConfidentialNonce token_nonce2("02d297469a08ddce74d2954809504da9af5c806ea91aac8f382857b575b006c590");
  asset_amount_list.push_back(asset_amount1);
  asset_script_list.push_back(asset_script1);
  asset_nonce_list.push_back(asset_nonce1);
  asset_amount_list.push_back(asset_amount2);
  asset_script_list.push_back(asset_script2);
  asset_nonce_list.push_back(asset_nonce2);
  token_amount_list.push_back(token_amount1);
  token_script_list.push_back(token_script1);
  token_nonce_list.push_back(token_nonce1);
  token_amount_list.push_back(token_amount2);
  token_script_list.push_back(token_script2);
  token_nonce_list.push_back(token_nonce2);
  EXPECT_NO_THROW(
      (param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash)));
  EXPECT_STREQ(tx.GetHex().c_str(), expect_tx2.GetHex().c_str());
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "0a002ed099bd2d52f4bb04d36ebc159c838f0557461d462127845b996e61cb70");

  // error (count unmatch)
  {
    tx = ConfidentialTransaction(tx_base);
    asset_amount_list.clear();
    asset_script_list.clear();
    asset_nonce_list.clear();
    token_amount_list.clear();
    token_script_list.clear();
    token_nonce_list.clear();
    asset_amount_list.push_back(asset_amount);
    EXPECT_THROW(param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash), CfdException);
    asset_amount_list.clear();
    asset_script_list.push_back(asset_script1);
    EXPECT_THROW(param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash), CfdException);
    asset_script_list.clear();
    token_amount_list.push_back(token_amount);
    EXPECT_THROW(param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash), CfdException);
    token_amount_list.clear();
    token_script_list.push_back(token_script1);
    EXPECT_THROW(param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash), CfdException);
    token_script_list.clear();
  }
  // error (amount unmatch)
  {
    asset_amount_list.push_back(asset_amount1);
    asset_script_list.push_back(asset_script1);
    asset_nonce_list.push_back(asset_nonce1);
    EXPECT_THROW(param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash), CfdException);
    asset_amount_list.clear();
    asset_script_list.clear();
    asset_nonce_list.clear();

    asset_amount_list.push_back(asset_amount);
    asset_script_list.push_back(asset_script1);
    asset_nonce_list.push_back(asset_nonce1);
    token_amount_list.push_back(token_amount1);
    token_script_list.push_back(token_script1);
    token_nonce_list.push_back(token_nonce1);
    EXPECT_THROW(param = tx.SetAssetIssuance(0, asset_amount, asset_amount_list,
                                   asset_script_list, asset_nonce_list,
                                   token_amount, token_amount_list,
                                   token_script_list, token_nonce_list,
                                   is_blind, contract_hash), CfdException);
    asset_amount_list.clear();
    asset_script_list.clear();
    asset_nonce_list.clear();
    token_amount_list.clear();
    token_script_list.clear();
    token_nonce_list.clear();
  }
}

TEST(ConfidentialTransaction, SetAssetReissuanceTest) {
  ConfidentialTransaction tx_base(
      "0200000000025e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0000000000ffffffff5e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0200000000ffffffff03017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000029b9270003f4f10478f5fae2c77c44fdb2a304109a9ae8ba7cab1c125deba9e618ca737e851976a91484c2ef274919355bb532a5bbdbfa95490c5d749388ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b97049c03b69e5ef61aef08565404bc3c98d6e4dfd1e02eb94138617d9b3eb12ec790885317a91401e940d9dcd77a5043356941641aa2fd6ec6a68887017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000000002710000000000000");
  ConfidentialTransaction expect_tx(
      "0200000000025e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0000000000ffffffff5e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0200008000ffffffffcf9a1b9aeb2de6a7b7c3177433dced0951fd728dffbe8c935ccb80698f2e08c80683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000029b927000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000029b9270003f4f10478f5fae2c77c44fdb2a304109a9ae8ba7cab1c125deba9e618ca737e851976a91484c2ef274919355bb532a5bbdbfa95490c5d749388ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b97049c03b69e5ef61aef08565404bc3c98d6e4dfd1e02eb94138617d9b3eb12ec790885317a91401e940d9dcd77a5043356941641aa2fd6ec6a68887017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000000002710000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000029b9270003f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac00000000");

  // not blind
  ConfidentialTransaction tx(tx_base);
  Amount amount = Amount::CreateByCoinAmount(7.0);
  Script script("76a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac");
  ConfidentialNonce nonce("03f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef311687");
  BlindFactor blind_factor("c8082e8f6980cb5c938cbeff8d72fd5109eddc337417c3b7a7e62deb9a1b9acf");
  BlindFactor entropy("6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306");
  IssuanceParameter param;
  EXPECT_NO_THROW(
      (param = tx.SetAssetReissuance(1, amount, script, nonce, blind_factor, entropy)));
  EXPECT_STREQ(tx.GetHex().c_str(), expect_tx.GetHex().c_str());

  // error
  {
    EXPECT_THROW(param = expect_tx.SetAssetReissuance(1, amount, script, nonce, blind_factor, entropy), CfdException);
    EXPECT_THROW(param = tx_base.SetAssetReissuance(1, Amount::CreateByCoinAmount(0), script, nonce, blind_factor, entropy), CfdException);
  }
}

TEST(ConfidentialTransaction, SetAssetReissuanceListTest_multi) {
  ConfidentialTransaction tx_base(
      "0200000000025e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0000000000ffffffff5e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0200000000ffffffff03017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000029b9270003f4f10478f5fae2c77c44fdb2a304109a9ae8ba7cab1c125deba9e618ca737e851976a91484c2ef274919355bb532a5bbdbfa95490c5d749388ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b97049c03b69e5ef61aef08565404bc3c98d6e4dfd1e02eb94138617d9b3eb12ec790885317a91401e940d9dcd77a5043356941641aa2fd6ec6a68887017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000000002710000000000000");
  ConfidentialTransaction expect_tx1(
      "0200000000025e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0000000000ffffffff5e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0200008000ffffffffcf9a1b9aeb2de6a7b7c3177433dced0951fd728dffbe8c935ccb80698f2e08c80683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000029b927000003017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000029b9270003f4f10478f5fae2c77c44fdb2a304109a9ae8ba7cab1c125deba9e618ca737e851976a91484c2ef274919355bb532a5bbdbfa95490c5d749388ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b97049c03b69e5ef61aef08565404bc3c98d6e4dfd1e02eb94138617d9b3eb12ec790885317a91401e940d9dcd77a5043356941641aa2fd6ec6a68887017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000000002710000000000000");
  ConfidentialTransaction expect_tx2(
      "0200000000025e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0000000000ffffffff5e67a3542db02871642bdf0923d33ac5bd1105f3421520297f01617c6323918d0200008000ffffffffcf9a1b9aeb2de6a7b7c3177433dced0951fd728dffbe8c935ccb80698f2e08c80683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000029b927000005017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000029b9270003f4f10478f5fae2c77c44fdb2a304109a9ae8ba7cab1c125deba9e618ca737e851976a91484c2ef274919355bb532a5bbdbfa95490c5d749388ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b97049c03b69e5ef61aef08565404bc3c98d6e4dfd1e02eb94138617d9b3eb12ec790885317a91401e940d9dcd77a5043356941641aa2fd6ec6a68887017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18010000000000002710000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000011e1a30003f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac01cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000017d7840002074a50df2248e62bbd18a4a4abf2c8923f0740da61a28dc9e9156092c90e20aa16001435ef6d4b59f26089dfe2abca21408e15fee42a3300000000");

  std::vector<Amount> amount_list;
  std::vector<Script> script_list;
  std::vector<ConfidentialNonce> nonce_list;

  // empty check
  ConfidentialTransaction tx(tx_base);
  Amount amount = Amount::CreateByCoinAmount(7.0);
  BlindFactor blind_factor("c8082e8f6980cb5c938cbeff8d72fd5109eddc337417c3b7a7e62deb9a1b9acf");
  BlindFactor entropy("6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306");
  IssuanceParameter param;
  EXPECT_NO_THROW(
      (param = tx.SetAssetReissuance(1, amount, amount_list, script_list,
          nonce_list, blind_factor, entropy)));
  EXPECT_STREQ(tx.GetHex().c_str(), expect_tx1.GetHex().c_str());

  // 2-output check
  tx = ConfidentialTransaction(tx_base);
  Amount amount1 = Amount::CreateByCoinAmount(3.0);
  Amount amount2 = Amount::CreateByCoinAmount(4.0);
  Script script1("76a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac");
  Script script2("001435ef6d4b59f26089dfe2abca21408e15fee42a33");
  ConfidentialNonce nonce1("03f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef311687");
  ConfidentialNonce nonce2("02074a50df2248e62bbd18a4a4abf2c8923f0740da61a28dc9e9156092c90e20aa");
  amount_list.push_back(amount1);
  script_list.push_back(script1);
  nonce_list.push_back(nonce1);
  amount_list.push_back(amount2);
  script_list.push_back(script2);
  nonce_list.push_back(nonce2);
  EXPECT_NO_THROW(
      (param = tx.SetAssetReissuance(1, amount, amount_list, script_list,
          nonce_list, blind_factor, entropy)));
  EXPECT_STREQ(tx.GetHex().c_str(), expect_tx2.GetHex().c_str());

  // error (count unmatch)
  {
    tx = ConfidentialTransaction(tx_base);
    amount_list.clear();
    script_list.clear();
    nonce_list.clear();
    amount_list.push_back(amount);
    EXPECT_THROW(param = tx.SetAssetReissuance(1, amount, amount_list, script_list,
          nonce_list, blind_factor, entropy), CfdException);
    amount_list.clear();
    script_list.push_back(script1);
    EXPECT_THROW(param = tx_base.SetAssetReissuance(1, amount, amount_list, script_list,
          nonce_list, blind_factor, entropy), CfdException);
    script_list.clear();
  }
  // error (amount unmatch)
  {
    tx = ConfidentialTransaction(tx_base);
    amount_list.push_back(amount1);
    script_list.push_back(script1);
    nonce_list.push_back(nonce1);
    EXPECT_THROW(param = tx.SetAssetReissuance(1, amount, amount_list, script_list,
          nonce_list, blind_factor, entropy), CfdException);
    amount_list.clear();
  }
}

TEST(ConfidentialTransaction, RandomSortTxOutTest) {
  // out: value, fee
  ConfidentialTransaction tx(
      "0200000001017f3da365db9401a4d3facf68d2ccb6372bb714491987e5d035d2b474721078c601000000171600149a417c11cb67e1dc522997f07e1ff89e960d5ff1fdffffff020135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c84010000000002f9c1ec0017a914c9cbab5b0f3430e824b1961bf8e876be43d3fee0870135e7a177b434ee0799be6dcffc945a1d892f2e0fdfc5975ba0f80d3bdbab9c8401000000000000e07400000000000000000247304402207ab059e55e3e4337e88e1a6db00b7549110065eb5770880b1081dcdcdcf1c9a402207a3a0bc7d0d40661f54eff63c67838260a489984138d24eeee04b689f393bf2e012103753cff6c6123d25d99a3d02dc050a2c6b3ea40bcc04029c4330a4d30cb5390770000000000");

  EXPECT_NO_THROW((tx.RandomSortTxOut()));
}

TEST(ConfidentialTransaction, CalculateIssuanceValueTest) {
  Txid txid("d1efb621591f94f66a9c3161addd6d7db0ae82cc1674e3b098051793fb70028a");
  uint32_t vout = 1;
  ByteData256 contract_hash_empty;
  IssuanceParameter param;

  // not blind
  EXPECT_NO_THROW(
      (param = ConfidentialTransaction::CalculateIssuanceValue(
          txid, vout, false, contract_hash_empty, ByteData256())));
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "18dde72422dba6e922b41ae3c23243e64d361a6e18c49b75a0b02e627b1dae0c");
  EXPECT_STREQ(
      param.asset.GetHex().c_str(),
      "598ae0bb5298b89e257b64bcbb05e4f70a2def1c1c74d929ef753021e0559e07");
  EXPECT_STREQ(
      param.token.GetHex().c_str(),
      "4dda0f2bc939213feae25a16dcade5f235ab28564d56dc4f7f69d977d441f993");

  // contract hash
  ByteData256 contract_hash(
      "fdf4d615b2b78b61c85ccd5129584dc1b7cbd6c75a1c799cc0738bc783dafd68");
  EXPECT_NO_THROW(
      (param = ConfidentialTransaction::CalculateIssuanceValue(txid, vout,
                                                               false,
                                                               contract_hash,
                                                               ByteData256())));
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "9ed3d5d8f571d5b6ad03b5d17cee4fec1de36b65f4eb7d84aad264ddf260c09c");
  EXPECT_STREQ(
      param.asset.GetHex().c_str(),
      "76ab84689c4b03e254c89188962d262d159d21b4f1ccdfaf061d79dd53ddf303");
  EXPECT_STREQ(
      param.token.GetHex().c_str(),
      "e9aab5dcff7203b1dd77d42b727058835eb0034b3fad91e6d2bb69c21d7a5879");

  // blind
  EXPECT_NO_THROW(
      (param = ConfidentialTransaction::CalculateIssuanceValue(
          txid, vout, true, contract_hash_empty, ByteData256())));
  EXPECT_STREQ(
      param.entropy.GetHex().c_str(),
      "18dde72422dba6e922b41ae3c23243e64d361a6e18c49b75a0b02e627b1dae0c");
  EXPECT_STREQ(
      param.asset.GetHex().c_str(),
      "598ae0bb5298b89e257b64bcbb05e4f70a2def1c1c74d929ef753021e0559e07");
  EXPECT_STREQ(
      param.token.GetHex().c_str(),
      "3b4a21657d88d5004008ccf00441270a20984228eb06289660b63b475b539610");
}

TEST(ConfidentialTransaction, CalculateEachTest) {
  Txid txid("d1efb621591f94f66a9c3161addd6d7db0ae82cc1674e3b098051793fb70028a");
  uint32_t vout = 1;
  ByteData256 contract_hash_empty;
  BlindFactor entropy;
  ConfidentialAssetId asset;
  ConfidentialAssetId token;

  // not blind
  EXPECT_NO_THROW(
      (entropy = ConfidentialTransaction::CalculateAssetEntropy(
          txid, vout, contract_hash_empty)));
  EXPECT_STREQ(
      entropy.GetHex().c_str(),
      "18dde72422dba6e922b41ae3c23243e64d361a6e18c49b75a0b02e627b1dae0c");
  EXPECT_NO_THROW((asset = ConfidentialTransaction::CalculateAsset(entropy)));
  EXPECT_STREQ(
      asset.GetHex().c_str(),
      "598ae0bb5298b89e257b64bcbb05e4f70a2def1c1c74d929ef753021e0559e07");
  EXPECT_NO_THROW((token = 
      ConfidentialTransaction::CalculateReissuanceToken(entropy, false)));
  EXPECT_STREQ(
      token.GetHex().c_str(),
      "4dda0f2bc939213feae25a16dcade5f235ab28564d56dc4f7f69d977d441f993");

  // contract hash
  ByteData256 contract_hash(
      "fdf4d615b2b78b61c85ccd5129584dc1b7cbd6c75a1c799cc0738bc783dafd68");
  EXPECT_NO_THROW(
      (entropy = ConfidentialTransaction::CalculateAssetEntropy(
          txid, vout, contract_hash)));
  EXPECT_STREQ(
      entropy.GetHex().c_str(),
      "9ed3d5d8f571d5b6ad03b5d17cee4fec1de36b65f4eb7d84aad264ddf260c09c");
  EXPECT_NO_THROW((asset = ConfidentialTransaction::CalculateAsset(entropy)));
  EXPECT_STREQ(
      asset.GetHex().c_str(),
      "76ab84689c4b03e254c89188962d262d159d21b4f1ccdfaf061d79dd53ddf303");
  EXPECT_NO_THROW((token = 
      ConfidentialTransaction::CalculateReissuanceToken(entropy, false)));
  EXPECT_STREQ(
      token.GetHex().c_str(),
      "e9aab5dcff7203b1dd77d42b727058835eb0034b3fad91e6d2bb69c21d7a5879");

  // blind
  EXPECT_NO_THROW(
      (entropy = ConfidentialTransaction::CalculateAssetEntropy(
          txid, vout, contract_hash_empty)));
  EXPECT_STREQ(
      entropy.GetHex().c_str(),
      "18dde72422dba6e922b41ae3c23243e64d361a6e18c49b75a0b02e627b1dae0c");
  EXPECT_NO_THROW((asset = ConfidentialTransaction::CalculateAsset(entropy)));
  EXPECT_STREQ(
      asset.GetHex().c_str(),
      "598ae0bb5298b89e257b64bcbb05e4f70a2def1c1c74d929ef753021e0559e07");
  EXPECT_NO_THROW((token = 
      ConfidentialTransaction::CalculateReissuanceToken(entropy, true)));
  EXPECT_STREQ(
      token.GetHex().c_str(),
      "3b4a21657d88d5004008ccf00441270a20984228eb06289660b63b475b539610");
}

TEST(ConfidentialTransaction, UnblindTxOutTest) {
  /** asset function **/
  // assert UnblindParam struct func
  auto CheckUnblindParams =
      [](UnblindParameter actual, UnblindParameter expect) {
        // check confidential asset id
        EXPECT_STREQ(
            actual.asset.GetHex().c_str(),
            expect.asset.GetHex().c_str());
        // check asset blind factor
        EXPECT_STREQ(
            actual.abf.GetHex().c_str(),
            expect.abf.GetHex().c_str());
        // check value blind factor
        EXPECT_STREQ(
            actual.vbf.GetHex().c_str(),
            expect.vbf.GetHex().c_str());
        // check confidential value
        EXPECT_EQ(
            actual.value.GetAmount().GetSatoshiValue(),
            expect.value.GetAmount().GetSatoshiValue());
        EXPECT_STREQ(
            actual.value.GetHex().c_str(),
            expect.value.GetHex().c_str());
      };

  // assert ConfidentialTxIn data func
  auto CheckTxIns =
      [](ConfidentialTxInReference actual, UnblindParameter unblind_asset, UnblindParameter unblind_token, ConfidentialTxInReference prev_data) {
        // not change locking script
        EXPECT_STREQ(
            actual.GetUnlockingScript().GetHex().c_str(),
            prev_data.GetUnlockingScript().GetHex().c_str());
        // not change value
        EXPECT_STREQ(
            actual.GetTxid().GetHex().c_str(),
            prev_data.GetTxid().GetHex().c_str());
        // change asset
        EXPECT_EQ(
            actual.GetVout(),
            prev_data.GetVout());
        EXPECT_EQ(
            actual.GetSequence(),
            prev_data.GetSequence());
        EXPECT_STREQ(
            actual.GetBlindingNonce().GetHex().c_str(),
            prev_data.GetBlindingNonce().GetHex().c_str());
        EXPECT_STREQ(
            actual.GetAssetEntropy().GetHex().c_str(),
            prev_data.GetAssetEntropy().GetHex().c_str());
        // change confidential_value
        EXPECT_STRNE(
            actual.GetIssuanceAmount().GetHex().c_str(),
            prev_data.GetIssuanceAmount().GetHex().c_str());
        EXPECT_STRNE(
            actual.GetInflationKeys().GetHex().c_str(),
            prev_data.GetInflationKeys().GetHex().c_str());
        EXPECT_STRNE(
            actual.GetIssuanceAmountRangeproof().GetHex().c_str(),
            prev_data.GetIssuanceAmountRangeproof().GetHex().c_str());
        EXPECT_STRNE(
            actual.GetInflationKeysRangeproof().GetHex().c_str(),
            prev_data.GetInflationKeysRangeproof().GetHex().c_str());
        EXPECT_STREQ(
            actual.GetIssuanceAmount().GetHex().c_str(),
            unblind_asset.value.GetHex().c_str());
        EXPECT_STREQ(
            actual.GetInflationKeys().GetHex().c_str(),
            unblind_token.value.GetHex().c_str());
      };

  // assert ConfidentialTxOut data func
  auto CheckTxOuts =
      [](ConfidentialTxOutReference actual, UnblindParameter unblind_params, ConfidentialTxOutReference prev_data) {
        // not change locking script
        EXPECT_STREQ(
            actual.GetLockingScript().GetHex().c_str(),
            prev_data.GetLockingScript().GetHex().c_str());
        // not change value
        EXPECT_EQ(
            actual.GetValue().GetSatoshiValue(),
            prev_data.GetValue().GetSatoshiValue());
        // change asset
        EXPECT_STRNE(
            actual.GetAsset().GetHex().c_str(),
            prev_data.GetAsset().GetHex().c_str());
        EXPECT_STREQ(
            actual.GetAsset().GetHex().c_str(),
            unblind_params.asset.GetHex().c_str());
        // change confidential_value
        EXPECT_STRNE(
            actual.GetConfidentialValue().GetHex().c_str(),
            prev_data.GetConfidentialValue().GetHex().c_str());
        EXPECT_STREQ(
            actual.GetConfidentialValue().GetHex().c_str(),
            unblind_params.value.GetHex().c_str());
        // empty nonce
        EXPECT_EQ(
            actual.GetNonce().GetData().GetDataSize(),
            0);
        // empty surjection proof
        EXPECT_EQ(
            actual.GetSurjectionProof().GetDataSize(),
            0);
        // empty range proof
        EXPECT_EQ(
            actual.GetRangeProof().GetDataSize(),
            0);
      };
  /** Prepare source data **/
  // from rpc sendtoaddress command "address" 33
  ConfidentialTransaction org_ctx(
      "020000000104a76c51c1a0ad26df3eae8e8391a9da3cecea24edabcda10436cd3e550cd2f9e2010000006a473044022037a85467fb53a0b579678d4427686772c440a72b1ca414a277c89541fdeec17e02204b83132cce2ea41eeac04fb9f75b8feda74baa46f240b05f441319cadeb1a8fc0121035bcdbee25133f192f51e13af9e60d571fb97cf1a4952225d9bba4c184edc69c7fdffffff37ae0d4fdb2e319449897e6defb3826632a5eaaab84ac5b4539979c4b5e042ea0100000017160014077042bf149434cda92751a2ca017eb35b1ae29cfdffffff08c67897576709ee329620a9d63f0e6f662ddaecceac73e5a8807f9c9fcb88430100000017160014a65e7f101ff5f4f4106603b884d2c631717f61d8fdffffff8daed986c59703a36742a38b9c379afa2489532a876da63e9cd1fe61577c0a74000000006a473044022054beb6150beb677cc2eff5325ac169384a378aa82ac9474cdc43f1c8510f0d790220536fa1e8230548fae4928f6d7a4dd6a35e10bbc069b07788c9c53499fd300d2d01210231ac57012170dfdbd4adcb737b1a795896b57e2cc004c5e98ee5721b78ad3940fdffffff030a151e78448b0efec64069c8d11ac9d494635c81c68be60dd8dc5d00b61e66937009f2c7d4ec124a14c9b6e4a2311b4081944d7c493da119117fff8118f09b5c20c703bc52778cf3328c1bccc647e890df68294bcd38632d39a10e53d0757453a6c1b81976a914027aa64642c68f9e3d2d06c3141484ef1704fa8c88ac0b8a04b307c5bb5d383137600d5815347f6fb3f712672ff9c104af1eed3f7b2c9909e02b1ef9d285f8bd1b310f30facc9b9b267f18692ebe675fba02b2eda9febd67025eb7264392705673c88a2dea01a2325354ebb60a5cf045af41351077bb0a0e4917a914df01567680d27699b7d84dafa2bdabb5ada034d5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b3740000dd0700000000000000000247304402204efc7d568f382eccba5a33c74e51a70ee694f1d6509bbaf115e20fc898ed262602207f4408d44f79f451fac416958b00998e073a1eee8bd2997ab6fb6b3c02a651470121028e9137d413e21d84b86deb7f455ea5693d2e37f34105d6a48dfbdef212001a0a00000002473044022005083890177505328661bb51e2871cc60356c2ef4af7edd14c9a38435ef39bbd02207e6cb720bba6acbfb7a0ced98cff1eafcb32f96c0e24d5861677cbf7570ca35b012102360a8ed10131a6e99a0342c5c62163ec78430293d21a76a3571553bf99530a7000000000008304000b13f3245f12994306c0732649e27622e0460517da75dae7bf3c3976bb7ab9cbed4719e56eb21b7fb65c2b938b61a6a53f368195b128c3178feec7ddaff3a9cc64e59fe0bfad6cb9506211c945fbba0be14a5457dab662094539b82d80ff2f50a492abaa7fe406810879833f2452651e0f6b51faaa5a0e507293330bfa16ea6283fd4d0b60230000000000000001c2b101c36161ea32674a76fc474e5a45d8bf234dc0dadaf96837b9b3117a63c06128b58861827accd9e5f4f64e61b1efdbc4b7757f7baa8d7072757e4bb65c6045cd70ff8b1ab4b9f1e82283dae8c61651351f56695a752f9f5bcc0ea785fdfce0d49f38c541912bcd55df51dc09cc161b35a0b04e0df400b122d4d4a393dbde8933ea7cea3c5be1caff45f3a760cd51315101d27456da3fb01acbf1af4a53a668ea7e5ebfe456ceef332b3878a21acd717a82557d2d353f39789893403987dadec79a934fd4d62418bcf5af3c9fb4250f9ae1456de1b110f25e9c713fc26470bd0acf2095799e3a73d91e4e187b30731d062ac917f6261df0c58e579a075019a8cb1e88f95fe509456510009ef5e0f9502ac426c264806f5bf1374ba826677b8b1b06fd00c060cf130bf1943a0a85d7b9993d937a1321aed730c13cc9a22316e57a526b0f5ec2e4f1355ef1d4820afa35d9d2c441fe128da31ca8f18b27c4e6fc5d73bf68165aaa4ad066aefee3cd342b85ec8b806433e58b49f300340b140bb042c63959f52a0b68155318f38065521c1564bbc80306fdbabd70c0805cebdd50e3f78ff5d55b53be8443bac0013ea25c0d1e5b9cf4edeaee946a266424c5ce45099b5f14ec0ec9ae9d1fafbdbdfcb608e3b3d6bc26ceb1e32d9535817f0ef1e90dbbd6013e94686fd846d50fc9b9312bd3016d81c0513c4c09078b3199f799dc1791f4e02e635de7295ed0e8bcf9971fa0cdb7067f71fe6226e6c5d6c9911fc5865a74a05d9f596c29e9ca2be83663f0ff1e41a5ec8ddc01c667026eb778c6b1f0d4f3d2dc0c937841238d8ded60a3f4a012a859b66d40bcd260acc6068bad56c8c3834ba4d1b4f778213d2d8365fa068b86613e3da1105123efc4b5ba934f532f5b6cb4af2e4828a1a560d3cd720eeef41f0fda6c466a6993c65ab9223cd3f0a09d99a6d7bac4974a586ea0bad4bc646c456e7df4ef84dda95943784cef2710653a9bdeacedbb7a541db754ea6a15ee9d38eac49a1c9e1ad1f38f4ebaa782da4b1e6fde7b66cd81ab60c002080dea754dabb296d4408e926a45f7f1301d551432d8c8e1294fdd307d9ee2a77e395e3684bae5a9b5afe76a389d67ee0913ef8832967955c0434fef85270411f5c60379512231c428bc03cdec09f0334659ebae151e2f7449f538b37c8c758fed826ab10da63a136938f12e8ad9c3cb76489c0610b8c1908820cc8dda284dda57e1e4c1e4f16c904aae0fc491019a273037d036ee0aa88cb43b4682fa8026933200ead8e0ad1792b2a9f2e177a58321f97ca0db36b6e1ce2661608b8d0bb654d43f676678ab2994436cac1f4c593abf0f11bc5dd737e2d645a6e92ecf7597b139268e5c565e24e7e0987358ae46900df03bc971b7a856181d551c149d6750459c56f1905799ef0552e0148418898839f5ed3167ec2fc1e0184514cd243c830e9092c6cb66a51f45d6a12b363adbc669b7aadf4d0b5cc2bf9922d6c1364dfdaca171fb6c3fd001fd1b053f42a24e9776a75daba64701a7248da6c7d4719c069364f86cb2f364b3f4e8fab3452545a24764bad1db29bc271bb8869c4dbf031f3786a12339ee562451c2b66d1af7ddbd7d65f6d06fafa06422be1312d144c1bc649e98fe665d0e5842cca596ea3a14a85d230da00e1f2880dfcd482535a617b4eb9d762d6771a90420bea9fbeb211e8794bbc77d353287a40c0b17ad86964a96318831fc815d92c5e6dd89968931f7487c86415cc1d600aa27bd164e3c4d0a15c01a7377d5a85ca3262f4462b945414bb9e4714f28fa6c8b0e57db2cf29b012a1730e976edb2f27ac24386bae63cd6022425fd8c2453aa6cd98e401ed8cdd6e86836d917c2bdd3e66b7c71c8a1628587b46c710df92fe74e16711179bc8eb19bae77cde2dc680fb2d862b74bba838621de9573c0b9875578441eb65e266b82db937e092e5260a42ac07659f7100aae03ee02977743a6249c685232851768a022fe95b7f35fa080d81f7de31a456d1a01d252b4e8860b48cfda15080616ce9f628c9ca670225102315ce92da545ddabce9943f257ff61f6ffc220840f1b29a64a8eada361386cdebc03d146f7682149e7bfcb3338430da40226714ff35a31aff60bdac47a0816806a1de48eeaaffbab88e82cc643d4ceb527f5c94bce1659bb56301460bb718f3ead9323345a7ecec1b8f0fd6297ef7d3850430fa8b90e75d45db87a265d3457fbefd6951c7d628496f06e75373c96f2eb97809b10c0143809cc28174b0a949f4dc8df6e6eb22896f26e5331e6ab66d7e0bc0347da39f0e7a3bd2c3369538bdea29a7d76461832dee3fe593bd598cb51a8b1966b135e3a84b8f4ec9a174b2be7cd0f6315d4ca03a958d2e88c1be4e19fc517111cd2a90c4fffc76583e6c361f5fabac6f0aac54cccaa02015e5cdb7f99b84b8026f5667c5f9b57a4f57cad899b7be8ce66b817a0483091378a8db14579cf1e9568ce2c4af3ed872193f449fe05bac79a7ea92743ffa72cf212f8da9679f733c89fee4b78dfe66a982c79cdd16e97b3a316f3191542a022a517f49566edb5bdbafe8a63fd844d5f6763e42e46bdc2c7de22705b8644253397c17480dc0c9484909ae99f3c5038ace18bddce9be9cae3b86312af4ec937a5e05e1a119a2dcc57391d291b25ffe3dff7da88451e5b9270ce7bac6086197a8a2796bf953b3b0fe70b1a53035ee560d302a9ab55f2926e7f888086367c9cf469d4b0a276525e567f73a7b55b48f0ddb36e1a7c1b97d2ee008e61c2bc635e6db9585b01dca600d81b044bb1af230c9ed6e658eb8c3c4b35e1d9773295ec57eec12ebf7da3135beb7e7de0ca086f254770ee0df3341271c6df96b10b3569fc479fbfe1cce62504612d38e30fc7b70fb22aab65ab178fbb095e04767a0198e3dcb6dd6aa04e538453d9e933e8c56bb16078ed85490963fb99ec7279b5d46618d2e596c5c057367d6ef3dfde0f6e61d9d0c9ec076c6ee1fe588463cb596921b5f130b278c1ba13ebec24cda89b4d8b25ac475c34de025b4a04a319367a5745a9963095a9f560e57b61c442a3b02c46302d2f8464966b4fdb28caa592da61695f292f76f69c3120ddd9308f6cc13c2008eee3ea874914cb1a8357949829fd8afd68ca1f854393d6aeb26bfc130d1e6c62d45b0ef5eb6700b7c0f5aa066ab985a825b65212affcc901278fe79f3b6cb45015f0010e92fb190758a64729a8b46f299564eb59a2ddb03057d97843723318f6ddf0f7e9254235dc49318dac7c028df6f680491ea1ab28a820a95d35f1937a9f035bb6cfb56050989900ef809fd55961d10832c2abd79e565d80131908a84d53f8a51752ed00abbb9ae41e6ffecc93fabc19373effa546cdf715c26456238f06651bdf4ffda9c0d77ada10354030480301f09ec383db5bca36deb002c482202e574e63cb5156d09bf511fae0a72125bb61d3efd2197f84e029558a3dd1cde325df7f639d4b030373807ca64fb49100ae21c632fca67ce4821132bd5c488517b5ef45a76013dd41d4449fd585bb128ee9eef39ceef57854e52a9cd61fd5122d8a249454e4f6cae75f37f616b20b5b340c789e5599541af4778d85efaa849e25b5224029179026245d5ced747e6871fa5a200898fedbae2954c452e267ab2a001b3ebd5920390e79687af5c012f53479c37a57897e578cf0e1fc3b4f038a84d72b3ca5363257a48919d74c606b1ed4361c5a1f7610ad70b5ee40f248a6c6822880e8ed4901b6ec0bca46aff4623273d256078701af941f4925df504961632c7e427c0dfd8607c5d1acc55c2f30ead6ea485512965f2a1d6015e6c4cf71453df81f70ced854eb0b23839223c5e18d1b63bbef7d79bc49a720e4fc2fe06e459d81340dc36f186c353295eb548838bfdd22876e34e2ea3170bb09104b77640e89dbd1048e6685df2d46bbc8ef682157d91f518d6ea083c649dbfeb23956164407b325424850ee2c0a98e6d2c3f19a1aeb4a5e6c38cf6792022ea6d5116671a1dee15006f2bbcb45b2f335e803c04d04fe089aae6c2151d30cd8e7d58304000ec0e7f42f42e6df0b144f11c0d5a3f6ad7cf84936e9d5a38fa266c3f7a742d4011f95f54553243fb35972ec66b650d781dad6ff672cbd8a935bd477b838595380ffe1586bf1bcee43e0ff18d252263250e952d39b0f215ebb69cf0c23a6b1a1d2b686c01c5d79fc5b486a88afbe466b4d4bc8e559b0b1f6432c98d8e0844cafecfd4d0b6023000000000000000111cb01acd74ab4034d001feb7cd326bb4f078d678ff1f7d281d3b1262864f97e6dbd42fcc90e63b1bfeacb96f2ee0b5889a2c1550467af8f940791eb2af806628252ff52a77cb2a48cc7b8ecfb0cf6db934e90d812bb4d51c73f84b32a7e9c481f89d56f24a2e7d36b2f6932f2ffc8eea9f9798f25f6f03e51729f4164171ce6475a9d0b9da3fa04922745ceaae12327bd7e40ff22f17d01dc4a6148674c4fcff4a3974fc48b8fb924f0545392d1b329301fba3a5e71fb541e8be0a96ad79bd2cd586bc43fecbc705e61240b58a21dbe0d2e0f0dab734ac0be7655e08917fa62fec78cda4cc83c50e8ae5089f94e14bf70f6f1698c23e914003f3633ef257cfe997327cce8bdf7f2adff2070785e651334e5a0ca97d5e8528e0b47e88570e152a18026c99658cc3350174bc83d887192fdf6221c938f25d09d64bddf98f4313c4f67909e9aeef61a633e2c708a1dc5f995882a780eb93f9db0bd97470b77fb61b0263abdc6232b654da092bbfe22f486b90a7c5898f83ec595a003a3ea66c4288cc6e529262d6226675a7009dd1bd762491a509225651c356b60ffdd1f36a6cc7c24ee719b941f02f2a88406e93d0d0b81c75ba33ce4821f7009c21274af21a5f61fd105b25cfa857df61b2cdd29ce0eeeec86faa52ead261dd3b1326d52d96945e8b15974d2c4be711813f7130234dafbb7715cc4dd8ed69d3c4ca62f0bf448bbf8a32e52df9334a094bfa9f577eab017de57bbbe028fc08014a2f3ee55d9df9cadff760dcab6d06257c814c031bb11c836a8363f261982a7ce73392f82fcb6bdd5968835f657831e7dd1b0252a2112a45c403bf2975bebabfaccc365eb09bb25abfc3b80797cb2058268b9899ba642570d17ce05b8d9a304eaeb4a61b6fec6dc189f54f3d337df46918a76bc7f1ce9846ede724eaef34d4f02b6da0a293aa3a60b306b7c937bc2fd11f58d08440287b0c7793649ecb23b69181af9912f83afb283af17f48f05c79fad79b2aafadb64309a29ee3d08521f5b08d075eca726e2731c6cf85209c9341ee65878b7f86d85503b96c115f8cd603dfebfd24d9d6fb1df2cd92a32bfbb5eb926c280f902cb5bff0ca683a64a5b215fc2f377995363f42080bf96d953153a640762f91a4e68fff1c62c382eba70301dea1823345c9b5e52c5e2488881a76f5aa29f30a24fbc720ef24e1811640e44d0e92fafffde3bb7c3c8c8e813569d89604afbd7e09bd99418dbe31457a33d528924fa51291b62be9e8bb4fea91578296d1ffda0eaf0549347010e64181271b52036613153b61b8e83ea1aeff860ecf4af953639ff008a92a8c2e15d846ac75da55c1732277273ba070235f40d60554181f17b17b05158260e62b0f3cb7a11fb92e20dea7eda89ded7a69b16a359cfe9b3f334d369def50b1700d250bf003cfe23af5a2ee44b7ec2109650c1d88b33edc4f9404cdec8916f84366b36a79e05b4083f201ac59e688dd1ba03e2ea48fd6a42f8ae524a48b6ebb4b4326c667ec75f79e88af078ca667caacc06af34ca42eacabf441dff6fd80a8d6daa89e184d80e9516df2544a539723c9ed18cbaecbc94557e3a31b6ca5b0ecd15d1839c0f193405f2a461e7a520f414d056864f0ff6591d6f0bac63746f9887b5cad36b208160fe008d4eae56384019f92de1ecc2ca53be8055c900ad94521440bd99646f365ef944b6caf92e2614454ae032cb52e59bdc4aff6710a978a4bb6c3ff4eaa478f6a40c96fdb26268cbb422b6ee7d6fda354de6ca7cde33456762a04db65389ff0c10f2852158b543abd9c26e0f1bd0ae04f7e40452f9b4d5d5aab0947856ba73202a5ac577b5a9a329299849b4304436289f271b8bb8f7da91f9c9d4d4fb2d707c3b0ccbf1820c4723ad5a6a1e4d79dbd62ab086ef409c3fc8b5e11bc7e8aa187b7d576d50fbfb755f1dbb8fa7658d52da16a8a7575747a841b52ad6d89c53bfc8afaf0f4d3041c774e05b40bbbaa4fccffa93054efa769d1566313c7f840a0ef9b91c45ac79f1b5e12c866157e4203f8860af2fcb26d2ff665d8e4e2baec6d7c05d5ba45cbcdb0c270b7e0b992e54ceeed41397a11d8478ced4f98ed161e335c4133372d1e4bcbcfa87fdb3fb0930cd99e4af6ac732ea164a328ee5445c374b59e9dfcd665399ed8d795b53dfca7059eb1364eac50d4a8e85ea72803069979843ebdb49436a3db93144b0438f0b15cf1d30b171a3352a6d3b2007fd7a4b97c62a20dd801944cd1e1e924a887fdb41fadee7a571a2d824f3c3925a8f32faa7308190c77b7da7516c81d2ba0302c4eb0763442b7873d85530080ec023aebc7191336c420db7b9c066eb6067f66fa2f6b03a510a1ccf301585aba7ba442b7f9be6182bf60db46a3e2ff380b350b7cf1432f530ce7d3503fd34195f74ee3292a6db28943d0362ee7de7f3bfc7103f074ef0bdb5c5741ed54ff27a11f1159fc2ec4334bad8050464df238403fb0b5d814f65fed6a6ed76bb11868abcf36509fafa05b04fbb80185a58022d87badafe4c09cc475566b4b883558f459c97652eb82510b07a1ad530342573d36722c35e3a3fecdb616a72942e1e889f7fbbed4c7f2fa30c1a1bdfb92fa55e047d7d51f89633f21fdd74315731ccf0c1ca647135cbea7db9a62f4b3cb43a92b1b8b03e910d2e709c9c8a0fe25041f72120a51a2c9ab4155c01685132a9cfb62718a483fdcfb87bfb705dd5a85b10c8bba2c4df81a63d10480812f42a2a2d57ef71c6b685f0faa79d08d01ffab71037f0276b5b966756532470d115d63e6bcca2e420b04f628017b022c95cb991663b85be23fa70014bea539bc02c033711fa3ac026813f233941917507b1bd2dad073668f92e8697834ac12fcf6da847535afa019726fbe5acfbb3df32f231322b11069a46d0e883d62ca1766d1f91063be7e2e55d2a875ff5a24bef810bf068edd93863bb21a03d478d8bf78ac902614aeb19a8be6eb82fff7db2588d93cbe55628b1abcfce379b9cebadd718f0cb96b72f859bc7e944777f182c0ad160d912b5e43cf3b7ae27b894a4b4f0c704ee9fbfb87e63b9d812a8277634e8e0960d0c736230d78d91d7268129562a5fc7674321833fc1085e826dec7bb6c7d98172302ea2abe016f0e38d75e0fb895f364378a5d8479879dba16d6248c6decf84e0ed58dcdc13c0b2c96fadd15cbc5bf92a6268bf1672b339581e90259accd515f66eb207ee962bab98179ea5d0438b40bbac52b248ef293d13beb22cdc081a1c7bbbbb4c0060e6ad1240ff46c1d43450839626365e768c3b8510e31c76a6166e023dad31077e9f6afea1dc9686454f25a60eb6cf7b999c51a005171ed8435588451de5f6ab831ede004f7e6be1d807cb45e45b82298764657ea17692c6198b27f5f93ece31297443dbed66bbe878fc7b2cecf11cfdab409c764e77015fb5bf8dc5add2986569e225f1890ef28c519e90f028e453b51a48d7896c0804c3297241d415bccd7e7cee0a859fc648635652e033311e59c70f08d588cb1fd1cd8cf0ed261d47d9cca08b777fe6e4d02ea586369a9f1e3f5dcfece64066eb3ce15f7c1e1fba956ed4aa3f9e9bec7e27f1dac19f4af425030a56ee318f7199959f26ab641de25ba563a2d1159528d4329ce84ce3bdff56306f7437f552e15a90072cd4b5f785fcca79b6b57e5adb7dfb5a957c8c9c42a44770336c0e6f57a584af3ecc0c08526ef33a044f14610decde7aa82741a764290f6cb9940152663aa118bd0fff7341b1e336823ccb6815f9404e3f4874c99e0d335d814516b8cf75a7931c5b344ab27366c08482b17b4374fbd4a61385143fbbec73845157ea9894472b0613f0892087fc7eb2cc92b3e47100ef3b2b404ad9dae0c447c53d7fa1907f2dca4c106ee66a4bd6a5136b1e303e8a50827b8a9a65c551a84bee01de37c30cb3e00073c641da19a3f405e94f22ff7ab713d9f3d94dd7a2831291db9b886d53ba7430ff863df094262ef8fe8cfae9e6dfc1aef29d7ba0ce49060c829b7f85ddb9138ef76b51df1bf51e1eddfc057895d113bc4cc98d9a964b22a2ca0000");
  std::vector<Privkey> blinding_keys;
  // TxOut[0]
  //    destination confidential address : "CTEutTrasoQiGBYbMANmRwLdM6Jmh25rnQE8g2fT2Dc2MnSf4qJrLGRg8SD3jdtQJo1dqB5jUmvfCkvo"
  //    blinding key: "c5b99c20f6a19e865baccea19addaa9e4fe4cb71686d785885acd12e4c067ea5"
  blinding_keys.push_back(
      Privkey(
          "c5b99c20f6a19e865baccea19addaa9e4fe4cb71686d785885acd12e4c067ea5"));
  // TxOut[1]
  //    change confidential address : "Azpvmq7pZ43m6uHDJt2YRH9ubHcZuHEC6p9NTS3KrVuz8KVf1HPJiHwA8rAJtTsdJ3DxQBH9XszFCTRL"
  //    blinding key: "e8c134da3a2489a24a76c0d0aee71b10dfa4ab6a1bf19a13e24ee6c66939d87f"
  blinding_keys.push_back(
      Privkey(
          "e8c134da3a2489a24a76c0d0aee71b10dfa4ab6a1bf19a13e24ee6c66939d87f"));
  blinding_keys.push_back(Privkey());

  // unblind single TxOut test
  {
    /** Prepare Condition **/
    ConfidentialTransaction ctx(org_ctx);
    uint32_t target_idx = 0;
    Privkey blinding_key(blinding_keys[target_idx]);

    /** Prepare Expect Value **/
    ConfidentialTransaction expect_tx(
        "020000000104a76c51c1a0ad26df3eae8e8391a9da3cecea24edabcda10436cd3e550cd2f9e2010000006a473044022037a85467fb53a0b579678d4427686772c440a72b1ca414a277c89541fdeec17e02204b83132cce2ea41eeac04fb9f75b8feda74baa46f240b05f441319cadeb1a8fc0121035bcdbee25133f192f51e13af9e60d571fb97cf1a4952225d9bba4c184edc69c7fdffffff37ae0d4fdb2e319449897e6defb3826632a5eaaab84ac5b4539979c4b5e042ea0100000017160014077042bf149434cda92751a2ca017eb35b1ae29cfdffffff08c67897576709ee329620a9d63f0e6f662ddaecceac73e5a8807f9c9fcb88430100000017160014a65e7f101ff5f4f4106603b884d2c631717f61d8fdffffff8daed986c59703a36742a38b9c379afa2489532a876da63e9cd1fe61577c0a74000000006a473044022054beb6150beb677cc2eff5325ac169384a378aa82ac9474cdc43f1c8510f0d790220536fa1e8230548fae4928f6d7a4dd6a35e10bbc069b07788c9c53499fd300d2d01210231ac57012170dfdbd4adcb737b1a795896b57e2cc004c5e98ee5721b78ad3940fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000c4b20100001976a914027aa64642c68f9e3d2d06c3141484ef1704fa8c88ac0b8a04b307c5bb5d383137600d5815347f6fb3f712672ff9c104af1eed3f7b2c9909e02b1ef9d285f8bd1b310f30facc9b9b267f18692ebe675fba02b2eda9febd67025eb7264392705673c88a2dea01a2325354ebb60a5cf045af41351077bb0a0e4917a914df01567680d27699b7d84dafa2bdabb5ada034d5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b3740000dd0700000000000000000247304402204efc7d568f382eccba5a33c74e51a70ee694f1d6509bbaf115e20fc898ed262602207f4408d44f79f451fac416958b00998e073a1eee8bd2997ab6fb6b3c02a651470121028e9137d413e21d84b86deb7f455ea5693d2e37f34105d6a48dfbdef212001a0a00000002473044022005083890177505328661bb51e2871cc60356c2ef4af7edd14c9a38435ef39bbd02207e6cb720bba6acbfb7a0ced98cff1eafcb32f96c0e24d5861677cbf7570ca35b012102360a8ed10131a6e99a0342c5c62163ec78430293d21a76a3571553bf99530a70000000000000008304000ec0e7f42f42e6df0b144f11c0d5a3f6ad7cf84936e9d5a38fa266c3f7a742d4011f95f54553243fb35972ec66b650d781dad6ff672cbd8a935bd477b838595380ffe1586bf1bcee43e0ff18d252263250e952d39b0f215ebb69cf0c23a6b1a1d2b686c01c5d79fc5b486a88afbe466b4d4bc8e559b0b1f6432c98d8e0844cafecfd4d0b6023000000000000000111cb01acd74ab4034d001feb7cd326bb4f078d678ff1f7d281d3b1262864f97e6dbd42fcc90e63b1bfeacb96f2ee0b5889a2c1550467af8f940791eb2af806628252ff52a77cb2a48cc7b8ecfb0cf6db934e90d812bb4d51c73f84b32a7e9c481f89d56f24a2e7d36b2f6932f2ffc8eea9f9798f25f6f03e51729f4164171ce6475a9d0b9da3fa04922745ceaae12327bd7e40ff22f17d01dc4a6148674c4fcff4a3974fc48b8fb924f0545392d1b329301fba3a5e71fb541e8be0a96ad79bd2cd586bc43fecbc705e61240b58a21dbe0d2e0f0dab734ac0be7655e08917fa62fec78cda4cc83c50e8ae5089f94e14bf70f6f1698c23e914003f3633ef257cfe997327cce8bdf7f2adff2070785e651334e5a0ca97d5e8528e0b47e88570e152a18026c99658cc3350174bc83d887192fdf6221c938f25d09d64bddf98f4313c4f67909e9aeef61a633e2c708a1dc5f995882a780eb93f9db0bd97470b77fb61b0263abdc6232b654da092bbfe22f486b90a7c5898f83ec595a003a3ea66c4288cc6e529262d6226675a7009dd1bd762491a509225651c356b60ffdd1f36a6cc7c24ee719b941f02f2a88406e93d0d0b81c75ba33ce4821f7009c21274af21a5f61fd105b25cfa857df61b2cdd29ce0eeeec86faa52ead261dd3b1326d52d96945e8b15974d2c4be711813f7130234dafbb7715cc4dd8ed69d3c4ca62f0bf448bbf8a32e52df9334a094bfa9f577eab017de57bbbe028fc08014a2f3ee55d9df9cadff760dcab6d06257c814c031bb11c836a8363f261982a7ce73392f82fcb6bdd5968835f657831e7dd1b0252a2112a45c403bf2975bebabfaccc365eb09bb25abfc3b80797cb2058268b9899ba642570d17ce05b8d9a304eaeb4a61b6fec6dc189f54f3d337df46918a76bc7f1ce9846ede724eaef34d4f02b6da0a293aa3a60b306b7c937bc2fd11f58d08440287b0c7793649ecb23b69181af9912f83afb283af17f48f05c79fad79b2aafadb64309a29ee3d08521f5b08d075eca726e2731c6cf85209c9341ee65878b7f86d85503b96c115f8cd603dfebfd24d9d6fb1df2cd92a32bfbb5eb926c280f902cb5bff0ca683a64a5b215fc2f377995363f42080bf96d953153a640762f91a4e68fff1c62c382eba70301dea1823345c9b5e52c5e2488881a76f5aa29f30a24fbc720ef24e1811640e44d0e92fafffde3bb7c3c8c8e813569d89604afbd7e09bd99418dbe31457a33d528924fa51291b62be9e8bb4fea91578296d1ffda0eaf0549347010e64181271b52036613153b61b8e83ea1aeff860ecf4af953639ff008a92a8c2e15d846ac75da55c1732277273ba070235f40d60554181f17b17b05158260e62b0f3cb7a11fb92e20dea7eda89ded7a69b16a359cfe9b3f334d369def50b1700d250bf003cfe23af5a2ee44b7ec2109650c1d88b33edc4f9404cdec8916f84366b36a79e05b4083f201ac59e688dd1ba03e2ea48fd6a42f8ae524a48b6ebb4b4326c667ec75f79e88af078ca667caacc06af34ca42eacabf441dff6fd80a8d6daa89e184d80e9516df2544a539723c9ed18cbaecbc94557e3a31b6ca5b0ecd15d1839c0f193405f2a461e7a520f414d056864f0ff6591d6f0bac63746f9887b5cad36b208160fe008d4eae56384019f92de1ecc2ca53be8055c900ad94521440bd99646f365ef944b6caf92e2614454ae032cb52e59bdc4aff6710a978a4bb6c3ff4eaa478f6a40c96fdb26268cbb422b6ee7d6fda354de6ca7cde33456762a04db65389ff0c10f2852158b543abd9c26e0f1bd0ae04f7e40452f9b4d5d5aab0947856ba73202a5ac577b5a9a329299849b4304436289f271b8bb8f7da91f9c9d4d4fb2d707c3b0ccbf1820c4723ad5a6a1e4d79dbd62ab086ef409c3fc8b5e11bc7e8aa187b7d576d50fbfb755f1dbb8fa7658d52da16a8a7575747a841b52ad6d89c53bfc8afaf0f4d3041c774e05b40bbbaa4fccffa93054efa769d1566313c7f840a0ef9b91c45ac79f1b5e12c866157e4203f8860af2fcb26d2ff665d8e4e2baec6d7c05d5ba45cbcdb0c270b7e0b992e54ceeed41397a11d8478ced4f98ed161e335c4133372d1e4bcbcfa87fdb3fb0930cd99e4af6ac732ea164a328ee5445c374b59e9dfcd665399ed8d795b53dfca7059eb1364eac50d4a8e85ea72803069979843ebdb49436a3db93144b0438f0b15cf1d30b171a3352a6d3b2007fd7a4b97c62a20dd801944cd1e1e924a887fdb41fadee7a571a2d824f3c3925a8f32faa7308190c77b7da7516c81d2ba0302c4eb0763442b7873d85530080ec023aebc7191336c420db7b9c066eb6067f66fa2f6b03a510a1ccf301585aba7ba442b7f9be6182bf60db46a3e2ff380b350b7cf1432f530ce7d3503fd34195f74ee3292a6db28943d0362ee7de7f3bfc7103f074ef0bdb5c5741ed54ff27a11f1159fc2ec4334bad8050464df238403fb0b5d814f65fed6a6ed76bb11868abcf36509fafa05b04fbb80185a58022d87badafe4c09cc475566b4b883558f459c97652eb82510b07a1ad530342573d36722c35e3a3fecdb616a72942e1e889f7fbbed4c7f2fa30c1a1bdfb92fa55e047d7d51f89633f21fdd74315731ccf0c1ca647135cbea7db9a62f4b3cb43a92b1b8b03e910d2e709c9c8a0fe25041f72120a51a2c9ab4155c01685132a9cfb62718a483fdcfb87bfb705dd5a85b10c8bba2c4df81a63d10480812f42a2a2d57ef71c6b685f0faa79d08d01ffab71037f0276b5b966756532470d115d63e6bcca2e420b04f628017b022c95cb991663b85be23fa70014bea539bc02c033711fa3ac026813f233941917507b1bd2dad073668f92e8697834ac12fcf6da847535afa019726fbe5acfbb3df32f231322b11069a46d0e883d62ca1766d1f91063be7e2e55d2a875ff5a24bef810bf068edd93863bb21a03d478d8bf78ac902614aeb19a8be6eb82fff7db2588d93cbe55628b1abcfce379b9cebadd718f0cb96b72f859bc7e944777f182c0ad160d912b5e43cf3b7ae27b894a4b4f0c704ee9fbfb87e63b9d812a8277634e8e0960d0c736230d78d91d7268129562a5fc7674321833fc1085e826dec7bb6c7d98172302ea2abe016f0e38d75e0fb895f364378a5d8479879dba16d6248c6decf84e0ed58dcdc13c0b2c96fadd15cbc5bf92a6268bf1672b339581e90259accd515f66eb207ee962bab98179ea5d0438b40bbac52b248ef293d13beb22cdc081a1c7bbbbb4c0060e6ad1240ff46c1d43450839626365e768c3b8510e31c76a6166e023dad31077e9f6afea1dc9686454f25a60eb6cf7b999c51a005171ed8435588451de5f6ab831ede004f7e6be1d807cb45e45b82298764657ea17692c6198b27f5f93ece31297443dbed66bbe878fc7b2cecf11cfdab409c764e77015fb5bf8dc5add2986569e225f1890ef28c519e90f028e453b51a48d7896c0804c3297241d415bccd7e7cee0a859fc648635652e033311e59c70f08d588cb1fd1cd8cf0ed261d47d9cca08b777fe6e4d02ea586369a9f1e3f5dcfece64066eb3ce15f7c1e1fba956ed4aa3f9e9bec7e27f1dac19f4af425030a56ee318f7199959f26ab641de25ba563a2d1159528d4329ce84ce3bdff56306f7437f552e15a90072cd4b5f785fcca79b6b57e5adb7dfb5a957c8c9c42a44770336c0e6f57a584af3ecc0c08526ef33a044f14610decde7aa82741a764290f6cb9940152663aa118bd0fff7341b1e336823ccb6815f9404e3f4874c99e0d335d814516b8cf75a7931c5b344ab27366c08482b17b4374fbd4a61385143fbbec73845157ea9894472b0613f0892087fc7eb2cc92b3e47100ef3b2b404ad9dae0c447c53d7fa1907f2dca4c106ee66a4bd6a5136b1e303e8a50827b8a9a65c551a84bee01de37c30cb3e00073c641da19a3f405e94f22ff7ab713d9f3d94dd7a2831291db9b886d53ba7430ff863df094262ef8fe8cfae9e6dfc1aef29d7ba0ce49060c829b7f85ddb9138ef76b51df1bf51e1eddfc057895d113bc4cc98d9a964b22a2ca0000");
    UnblindParameter expect_unblind_param = { ConfidentialAssetId(
        "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"),
        BlindFactor(
            "c476cd1617367852d9b981f6cb0b3899d2c500cb95b978ebc89b89d8831e7606"),
        BlindFactor(
            "71507ff4c052c404d16d2c0f85e86a443fd58fa50d7b8fb87a202320f099b3d2"),
        ConfidentialValue(Amount::CreateByCoinAmount(33.00000000)) };

    /** Execute Test **/
    // store before unblind txouts
    std::vector<ConfidentialTxOutReference> befere_unblind_tx_outs = ctx
        .GetTxOutList();

    UnblindParameter actual_unblind_param;
    // unblind transaction
    EXPECT_NO_THROW(
        actual_unblind_param = ctx.UnblindTxOut(target_idx, blinding_key));
    // check hex data
    EXPECT_STREQ(ctx.GetHex().c_str(), expect_tx.GetHex().c_str());
    // check return value
    CheckUnblindParams(actual_unblind_param, expect_unblind_param);
    // check txout data
    std::vector<ConfidentialTxOutReference> actual_tx_outs = ctx.GetTxOutList();
    CheckTxOuts(actual_tx_outs[target_idx], actual_unblind_param,
                befere_unblind_tx_outs[target_idx]);
  }

  // unblind all TxOuts test
  {
    /** Prepare Condition **/
    ConfidentialTransaction ctx(org_ctx);

    /** Prepare Expect Value **/
    // from rpc blindrawtransaction "ctx" commnad
    ConfidentialTransaction expect_tx(
        "020000000104a76c51c1a0ad26df3eae8e8391a9da3cecea24edabcda10436cd3e550cd2f9e2010000006a473044022037a85467fb53a0b579678d4427686772c440a72b1ca414a277c89541fdeec17e02204b83132cce2ea41eeac04fb9f75b8feda74baa46f240b05f441319cadeb1a8fc0121035bcdbee25133f192f51e13af9e60d571fb97cf1a4952225d9bba4c184edc69c7fdffffff37ae0d4fdb2e319449897e6defb3826632a5eaaab84ac5b4539979c4b5e042ea0100000017160014077042bf149434cda92751a2ca017eb35b1ae29cfdffffff08c67897576709ee329620a9d63f0e6f662ddaecceac73e5a8807f9c9fcb88430100000017160014a65e7f101ff5f4f4106603b884d2c631717f61d8fdffffff8daed986c59703a36742a38b9c379afa2489532a876da63e9cd1fe61577c0a74000000006a473044022054beb6150beb677cc2eff5325ac169384a378aa82ac9474cdc43f1c8510f0d790220536fa1e8230548fae4928f6d7a4dd6a35e10bbc069b07788c9c53499fd300d2d01210231ac57012170dfdbd4adcb737b1a795896b57e2cc004c5e98ee5721b78ad3940fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000c4b20100001976a914027aa64642c68f9e3d2d06c3141484ef1704fa8c88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f3ba9c0017a914df01567680d27699b7d84dafa2bdabb5ada034d5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b3740000dd0700000000000000000247304402204efc7d568f382eccba5a33c74e51a70ee694f1d6509bbaf115e20fc898ed262602207f4408d44f79f451fac416958b00998e073a1eee8bd2997ab6fb6b3c02a651470121028e9137d413e21d84b86deb7f455ea5693d2e37f34105d6a48dfbdef212001a0a00000002473044022005083890177505328661bb51e2871cc60356c2ef4af7edd14c9a38435ef39bbd02207e6cb720bba6acbfb7a0ced98cff1eafcb32f96c0e24d5861677cbf7570ca35b012102360a8ed10131a6e99a0342c5c62163ec78430293d21a76a3571553bf99530a700000000000000000000000");
    std::vector<UnblindParameter> expect_unblind_params = { {
        ConfidentialAssetId(
            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"),
        BlindFactor(
            "c476cd1617367852d9b981f6cb0b3899d2c500cb95b978ebc89b89d8831e7606"),
        BlindFactor(
            "71507ff4c052c404d16d2c0f85e86a443fd58fa50d7b8fb87a202320f099b3d2"),
        ConfidentialValue(Amount::CreateByCoinAmount(33.00000000)) }, {
        ConfidentialAssetId(
            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"),
        BlindFactor(
            "44efd448c275d553455802567cfc6a77fd359d8ddd4849c01aba25248f81f275"),
        BlindFactor(
            "f1afebe5bede796aefa8042311b39651060213181b84d6fe5254d1af88ba9e02"),
        ConfidentialValue(Amount::CreateByCoinAmount(0.99859100)) } };

    /** Execute Test **/
    // store before unblind txouts
    std::vector<ConfidentialTxOutReference> befere_unblind_tx_outs = ctx
        .GetTxOutList();

    // unblind transaction
    std::vector<UnblindParameter> actual_unblind_params;
    EXPECT_NO_THROW(actual_unblind_params = ctx.UnblindTxOut(blinding_keys));
    // check hex data
    EXPECT_STREQ(ctx.GetHex().c_str(), expect_tx.GetHex().c_str());
    // check return values
    EXPECT_TRUE(actual_unblind_params.size() == expect_unblind_params.size());
    for (size_t i = 0; i < expect_unblind_params.size(); ++i) {
      CheckUnblindParams(actual_unblind_params[i], expect_unblind_params[i]);
    }
    // check txout data
    std::vector<ConfidentialTxOutReference> actual_tx_outs = ctx.GetTxOutList();
    size_t unblindparam_index = 0;
    for (size_t i = 0; i < actual_tx_outs.size(); ++i) {
      if (actual_tx_outs[i].GetLockingScript().IsEmpty()) {
        continue;
      }
      CheckTxOuts(actual_tx_outs[i],
                  actual_unblind_params[unblindparam_index++],
                  befere_unblind_tx_outs[i]);
    }
  }

  // unblind single TxIn test
  {
    /** Prepare Condition **/
    std::string tx = "020000000102564d82f62046ac81e09499c473bd8a7530efeaa697c280d7da49e57068f13b830000008017160014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82bfdffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009bafb38bec9eb143cc7f020ead5d5bc7bea727faa4b0f385f3f7cd5c75333e655089196d11634e11f81e7a62410286b43d5308d201986ea301a2c02c984b359bcdd30a4b26d6218012231f85a79b7f9a8fc874fd15855c843ffb570d18939b03fe70000000017160014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82bfdffffff040ae13799934b4ad8e54944bbc20c9d5edb16a936aca98466c8f98caa4cb615d10408f1b8117305d629f90446d49a448288ad046bf3f23a660b806125ae227558ef430321d65b32b6d3f652293df0ce990c23be2f011ecd2facec89a00db94dbd5ec5c617a91470befeb928008476293abbe8568e063ba1240cde870a89ae7189cfdd5f7c1a8446d4b5ababd175598b42e6bb5e3c5b033ab4f22cc48a0955b98c57768fb1ad41e51f71b7852b338aed0f0a36728d331053b0f5be7d2fa60369b2a38bcb8b1f1efaa3f0c937390c9fe3e0ad72bcc9c08a4198a85a8396a4bc1976a914505b3bdab052c517a76b0acaa1520e01ee2b78f288ac0b91b91fb661db9be40ce86088cd8af1c6b67a7f9b8fd4248a5fde07ac9b02104008ee8543e0341709bbfc79ff74c7330f9439bf0da1490ccda06f040dab0603abe00294f8768ce1ed0116b38035cfb57bbb631b16d8fad0455a275d5f00682e23f8ba1976a91469a631d0d00cdeaa0fd1cc00bb567f995f9aea6e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000015c20000000000000fd450b40230c0800d8752ae1ebb7399e91263a4b05b32826b48bf07f6690d7e9b932bef8ed2162083a67989dc33560cd1ad85aa3274635047c25515f9ef7012db1127d22aa79c485b0c8d650ea2b60675595d0f1d662873548b156890e014dd00d9af9091cdbc9c7de2cd825c7734deb5a6ce1e6611deeb582a9954135747bcb67828a88021e598b42e24e910fae2ea7cd4c4a5355168abb678f0a450711a28b359d4c89b02079bf7ac5d0bd701fd0c7ca3c7b1f48974905954af7d23a528e1e54b503e88c150945a3c37a2fd224360e7699b4961890c68bbdba306d2f081d9a578a56807f5d979f7bf2de839879cd5d940545d4cfc64f7eaf334d90065f17eafd9ca0b2978ed52b61a827634fc4b856f4c91449eb0430149f281ba86db733a881059498b514500da7433670d83e5f4adcdc53172b22d6cc4b6318611a2e0aa624d7cf61456af4e5c25a571f3c605bdef8cc546449071ab9bdd90ff60f7acc3e66ab1f63097d6a7e693acc72e8d322b172514faf92733cc4c12756ea4421aa9ed56ba5bd2228638e583fccc58d6fdb1f71535dc8bb15939127894ce98983f268c33b9944de0aaf7affabe9107dbc30299d2c77dc713cfed5054b3d95e5b96c015c8ff8283189cea636284af5714641db337167cb81ccb39217df9b593aef458bc96345abab069aadcc6ce80dbc20b843063169a02161d2c8de1696d9c749a57103c4628d52a250f5176cf06d1d6dd69048bfed1f755be607e97610a3d13d9a45d64383c31063e6662a8d5e2b9a1f9b296fe29706a8587fad51ec9f25ac5779e048afdfca002c91384c246aab030291572b836e75af2b3d223339bf492d946b73daea90fa4697ac327b482e9c2706dd802bae46f93e1a1808aa6df54c2e8bac6e20850750532e2a1c35c70d967bb197ccf2c7b33474cdea382d26dd8af9f6e3415a5d58a407f46d67d02916b2941c943179c0aaf95db1af6e58a3f79c541f5687df18289e760ff866df14a720ef773b2fe3c42fc7d18cb0f1434862695c9490fda2d72ab1ed273037242e691a76d10b9e1989c8521f2fa04885c43c819f410a01b9561af8d6a5cbb70515bcdd57850d3f85eca0c98aebac19490c919594e2e4937757877d8b99952e0a849d336dc1d21dcf0ce4961df03e51d98d7a8343cb0e3e1be6fd1e28f4e84a64f8e4edb91a8713face04a51e1d36c50caacc995b6e7ab0ea3b1286758f91300ec0ab110a16ca1c94b2dffbd6ac9311701745e28a08f0db87e29396d3626040de87f11ef9301631364a47fcfc7c84c27ec4603c60983f64908e25b67e82e4cc6109f63d2af5c32c1530bef0dac789caad8d8dcae264f09ddabb870befdedc003548ff09b7673241feb03cb7c0ff28f5bead5ef028e44f11af82313a199360b02ff4d0fb790854cd74b6deaf4eae61b02e0124339dc2ddcdaae5b2be2a3257aba246f1b01c9178f2148ae1473e6e24bd45dbad9e4f1804b565dd73ec0a0f8f98d99f3ca6719da77baf5b52e6c6c332e2165dbdaca1aea31690de1dc82a4faee37ec495369fc73b46bd35ef877cc9ae536515ac036a40650f715c1cc290473d7685155ba64f6dd9041ed6b9399eccb84452482a97db850c75d773970b0e383e09f81e90df8effb2c2e57d815bc2d7dd4c2e33b8f37fca3ff257472008d81564624482110dd91fb3d9bb8597f261cc6aa1efdd8404da311b425ab7ebccca9f7560f64eb7531bc0655e7c4619b023370441973240cfe077b17ab673c145387f9ccdb2817b3c8b585aee96d122b6c92b435c02f300cc999c3c17517021f632ee20b746bc573bd8f229d50bcf85ae6a06b023398c1c7014f18c209359bafc6655934546f207693cd04a61f63e4f8b039c9391a7bcbd6e1ae120cc3c9d6d810fd6e877879caeadb83bf49438514f88889fe5a743b649056747dd3bdc9ff0da2a8f037520bb93e962e94a9e9b3c9192175093fc6255a2e8514cb8694b9b2c7de7feef525c53d60d0b57e99789aabd3c87dccd8d66454ca6b194f0337799ace9b7983d4e698eaf46bc27260534e1d712e8aca87ad3a3b554c76db5ca98e0876040d10c795d675b1d938b6d3f55ad5e9e7a42773efac14261632b90596e813e04ec4e17b9a9244e838ea24da9dfa1ac51f5bb3d73534b2bed082f76a55321b11ce70420303b71f1d942291630cc4b18558cb51024b7a3d23bb37c2d0ba687a6ca614245dc6b73d222f04ec97d8e8fc12172a95700ff682ed657246a88b7823eee12545aeed20a7eead79b6e6bed50377224edde804c93ec31175687a83dbcc02ca2b3092f8236c465c2f497966f0e2a11e7f3aa0a84363735a2bd24e56b7ef874d8ae308ae65047e46620d846512d5991cc5fa1d3fe785eb020975a1e6b6b9ab6caad542a6b99d1c364e7cd4b334487927f5dbb9f0da26e38a6a0d76ed8bc0f522b357cfbcea080f086ebdc63680f29682e2af6c930438e623c45cf54eaa438922df4c97d2829758360fb4da47ea202b5766267c8a1616637a668edd50e30ab1d462402b43bcc8fa598489da55c8e29f999067fccaa2cb53dd03fb21fb57e94ee4ac584cbd515b0006cc9f0728d1c1debd5789fa02874d420a0b69dc4cc956b9506c6cb6b0f509ee0121bcec8b354a9242d4ea390d921dd5d19749d10487ebc34722fec201db3edc84fd4715ed7fd5b0983937eeca9a1e09be71d36c6f9e4cce466ccb4a2dd75f3755fe915125a8809e019c46bb14ed299f9216b40dc65ee2d0fb157b900521dd27b5446d844563712d6dcb330ae3da746869794b07a64a230314f97dbc50099e5a13b3768b66e4d31bd0edee54826c7cc86304e628f8f00f5f8e12c845be2d2be42b8dea2d56f7b2164fec6a3f38e1076e00326219646258bb679efcaed524a33d8a5c07b09719182d44d07b22e357c76b8c24f5961ac603e3ddb60e3eca410564c3a41ac07f8bfd6b273ad9584c63aff023b113bed35b046d796c8854044305eb0d2ea97385cd88d4f6ec718e44d919525da90addadacaee65d78f9043e340ef8ea48f5f38f23a8c6e75759b9a032416b3b793b2bc45e878559c82d8705cde8e29a0c124f892100a772866ab99b6b14d907f354fb8e83ae81e307a72ff8325c52117a38be031d3c5f4139c72edf100af6aeb461a89ca550b522f722e98ce768860c043a92a7422f0874156d839925b47cc84e57d0397182e72faa9defee4f5589ed0aec687e4b02201893edb8e4b4688902f8dae0558c4b736c169352ec7e1b9a5771538f705d906ef623fcc5b6b6999d9113ca7b0b4315dcf96081a8ccdec165898932309b89be83e649ecf489335aa1e22622a390ec8a6ae8cdc03d1bb856d3e58b3f0ed827324f893e1d0ed5f44a4969b3d81d5ee050fe2282274be0bd97ac8c3cedecac0db43f94889d0c980731bc7a2c2d3689480748732dd3fcf82264fba3af196c4a960ef22e91391cf079529b8905a70f63a4d5d6460b4ad8901fde860a83165f165455c9898a466e7046a2b0d13fa6f3024111c8fe23eb8333dd23b92e117ec08ac65fccf382e97d8b6e6a800bdfa2c911321308903389093696b9c523f8aa4f272505db8d588a6490a33ba6e7b4c3f09a573a06857f77fe31031708700e12a094bd80e9e17cec86235c8384ae8f2e07d6d90f0ae4d73fa4e1e97b2248ca465ade60d888853ceb05e9596279c4e81595ff8e8070e072b698355765240ff836c51b86d959f50288c1d68eac3da452c707318241fd9a64f6e4ebbaf8a538e12178f4e104d8d4903347b139520705d7208099ffe7431a7f4751dcc7026924e7774aa151fe5de4f3ec136705daf411afe32bdfdc2fff04ed9edc06cb798bd7930f2f38f275debed028322714338bce522bdad5437ff668ebec5e2ba50b22a7c671bb3d2af44298eda2a7c7478f6ebacf09f24317339bb05d64e5abfbeac5fcca0bca369f49ef8b8f234b7e38c74143bd01997a22cdd02ad16a1f61e4e29501f5c19a11438f6d01dc3b76488a7944f4d46bf21a99a6eb8621e8470287678b9a4a345d77af17c99f9ec77e5cd56f2c6b85db4f73d7f2893efb67cd5fd450b402361820166fa94e32835715d360a13103b4eac76f94ee2e4d3df7f1f8bacf238cb609079b08c7f752e4c89057016a6d272fb24b90bfb244559d66cb4aebcc90daba892d2e85fddcc3b3ecdbaf00ef5191a0914836f6a33f110776c02f993e59ea823f501bd15f483a5722128bc08460c8fe3177b3f725123af9dafc4084240ccfa74749456b919e03ba452b9f0e066a8b7d3908e31c7e760920d190ab3a806474544e2a3ff432e74b5458bb8daac5c43a4a38ce63824e69f18dd9b863f320130bb38698b0827fdb82fd82a8d755531ebe10097fd0af6c189d4c6ecd9090f2725ef31b895745a1b2f2f71fe13ca4d3009f8e6be18950fcb8f8d371f7f2feab77be6b41ce59365d0038a8cb8670b70739a48508c7f251ae212f6bc5d783db1511677e1198d9b5e8255e496023894bc82035fa12947240de3ac8db89c8cdc1e84d40ddc15c9aa950f578c488cf589d0d332ad6ca5ec9d71345e64a895278fa03346530373d3be8860c721795b98b920a362aeb097665995ee84c26c435e9e17c140505abf9f1eea1303848f3b5aaddb66f859e6628314b482e0f228e458cd94f663b330bfd66fb94e37455b70a5a5a901dc218caea46314daa15190b3fbfe9d53eabc3abddd1be62a6de52b34f3658178fec14a626fd117b3d9d600dbf8012fb4df3489fcc5310dba3f613e4904569c8d0f2bf826959256dca1bf7085c3b5d1501534bc93dd008c47f45117204b9ccabd692201461a5fdb2d734893434df1d6c326e950975784aae96437760851b78a4e292a51be398e81e92761da1b339b28c210f2b5e75ae2420d3442d26195e50a6b9e08fa733b9d12dae2ea69d07c8d02c6c6ef9f47ce4474a1f581aa9a06408fd3cfef28cc380c1b89f76adfc67c1ee5460853d43212906cf8e6238ea57be7856b590c8327852ea126a307053005bcf70254629502a85e9e8c936b518d64860dad2cf314c0fb2aa9ae1dda507943df996d567f4606a0f817c0ddee1914e1c22f9487cdb7bd5b3a345b999fdef80e379c87b116946cb341a230c7f4d84a9b34713547b742f323bae7c6963e6abd425af9c199e422c1376c4288a132df78a26bc18663a0609e6e4f63795170dc09f1dfe01ac177b43b9cb82691f4357c8c6b019a7b5fdb510c9a0fa8f52174a443725fc599f53d99239642e5e7f65c0650229d87501cfbf17fbf03c322af05f5c0449035e6c5dbdbecd90a470e69c8de81dcf42aea44c2ebc552a93b2f96da381e8f9c4953669c8d75742e6be77f74fd893e60a6da02727ba1e513b45978ac115b55584bfcabaf42d50bf199969fef1aba76ffda91487bf606775c3a4e542f8dd96dcdd5241cf2aaaf52c5773535fb89c206a8e399197948d8ed4e390c56be83b9f322d0681fa3e865f34fed56c97535bcba8dec05f3214932417d03f80c7837d192e68fd1b2d95627219cb8e136c64784d63e2ca65a678b3302afa67e66c2b42cf644308e019325fb674fc9c3eca5e5ddcdd6cace36a17f810261f3ec0d0bc4f9c520e625ba30dbdc48b6a4fd80623ad846517a4096d2bf17734fd08b0bdc200dde1c81e8cb9a509bcdd256437d06c4b44dd435149e54ac4543f2f8db047485e39c467951f318311f3a8e2cad9b5dcba3863ed5e171f94fe0d3a9ae7fd99ba1cb32de050aa1917984481ee1d991927783ac2d77006ff511f474c6fdf3c1d47f933698b67faca5eeb2baeaa84de790c8cb1d8d9e8531bfe566b82742052f7c0760f82b5d2e3f22325a98c6e048ee5c7fdab1794d5ae59cab52cec8b55eb526f87e9eb19d3872c51603a9ae3d4296a2b8766be63bc9f0ab00e39dc877420eaefd42c50c3137d500351774467cae7b6b88b6c76dd4f37159400cae90c12601178ebd5d8065840074d4bdf70a9853a95376e6850931135847065eafa22192925d9df7b34aaa15a663d931ed8292c85ba29973740e44f5720f5294e0fbe54abff5727735a55d512c9ab232b2a7d73f6398e188ad9d03781e81113d25f068c90ca2750219ce8e2ec5e49ac6da0b7cd6ab57a6ba383464fdedf8ec60a0edbdc5b9b5ee29c98d0849f13c8d9d74028bf433002ad02ec726802b423641058d5696722610ba37586afc97977a1192aab39d145eac2f11e5cdbb3edc3e852e01440c1b6bbffc383e686d4a8ce78671664cd38f137c6e172375ff882d0641d7bc20118d0785d1cf0f13ba8de830e69b3a825dc6c9e2f0a732e99cff519f7bce53534b001a3f1864856f90088b366dd559bf107a4fc62c78d1294712cff02fca609de127866bc5834a910ed004c80eccd9c41d4f031e3c0a6c60da78f323095580b36b4efb12fd2e95799d1bbde92d3b75719d6e1a61fda63c0539efccc98b94bab016d540c4239edf38bd096bf2464aacd04da0b8c1c8812718a3e81ab5287122874333aa35403f1ec614eb5bfa68ce9be47cd86c45e49d1134434edba4a603d6d8af1a21bc5b6d105d667d8a69b9aeed922b2e22e85a9fcbb9d30dc096e600926aa07d57b1c86029285680633ed81ce38c0a284d384339ef2e885eb49bb2c799d9cb01ba0b087613ba9b0035024a2cf7ee340e7606530c3d34db396baefd2a735a0d6c50d511fd2d52aafb9b919954febe1aa3a4e25f9564e5ef4291d1a134ee2aeb46529edafdd46829eca58c9294257bf7a43b1fb6834629ee3cd1e60baad70271f0cd1070730f5356177e07780c539edb8a79b9042248c4922f33df7d57a7af15954d9a6f781f38d07b28b6971efcf22cbd5ecde394ffb2a76d9db40eb531acf6f924181ba6c2388c6d2619cb1209d739f69a6ca20049dd5d6e48770426013245f25c94a12a9ac2c345395bd2d9d9ef6facf13dcf4c714c77e40256bda7a0b645b5b05b8c1fbc44209226e20b6ec3c3107dde7680ab9a55ec7522c7afa71f8821ed6412ca501a007a681fe975d60a403d6dd1546b6a92535ae8b28b76670c4503ae407a1a8b371dcfc0844d57c5d72d4e05cc03d593e89cce0aceebe13ec7eea5ef6d9a465a7f57cf30427365080880f33b9cf5539b1d0c43e6754a8077ab490b1f9bae3daec7d41f2dfeb650059bada1a183f1ea66cf23502bfcc8ec5c8d00c69f135e244eedccf4ccca533438d11f34ddd2c3d263c1a1ba4a903893f9963c6a1bf57ec9208b4f2af825811af13256d5fa637fdf28743e3b2c8f39e4c3f1c12426dc315cad8de9900734c4f8b93376182a17e50576b413acebb265ad3bb791943ce99abdf61c6524a2dd2786899aa0a584663df9c4d612ebec154b01f3b1020c11341d1cb14b455205d2c5a808674af35e5ac84befa3142b0e514d81defd7d231a2b65cbe9b40b65f6e58c15f77b9620be1776daa63c7ec2340d6f8d5c5b0d8c12d86746c7c9581deb8b7333ccf0e586f653c3419e64e92e56276cd439dcdf2812fa0409dc2009061ec186c985e914d49e6c16c444b7134afb1a27d132e3531dc27c2c411b14334849dbdf6637f7c9489a92650a0cfd24bcc27be4313faa7476097474bff7711ea30faac72f75b598f3d09fb8a52708029f4c42bff64fc779024e322dbd9735667e9899e3479c26896faea211a91ad526dbb0ad4c2cfb7ac12a3c25799e7dfe3a73e5eb190a065a30a2996bf1b72047a07d38899e35aefb4fbd2b36e537aa2004c84f84716d751fd8bf9c1b46d65fc6b9deeca38ea72a86f803ee85de852bc5a98d457ab39e63c3e26bb637405e6a76e1c845a7debb87ab0080439bd3bfec126631936e6761458b13327bdad8b4b859708d16264edd8afcbc247d511776df8aadcc97b41a48f016a6a4e358c05d3d64ecdca3d0279c4b2ffa31b60bb33158679f9b0b263ce056a156149049ab142733dcf04e444d89d9efa5e1d53346f603689a582e46e5a86a63d98955a9af16ee87b0164c0afeca3a6f393faf47237f0af4f8b957279d02935f7d3d519e11af0f411dd497c450ffe3af83e61fc69feb2d18930fdc8cb4eddc227ef11a15c47c6e48873c8a80f97f586fb6605ded21f9864d7506bbbdea5d10e94549351819b0b0ccb7558571efbcf6f4b940f4331e1376b332cf78496c30c00247304402200eae1c3c561cfbcd51b31cb8cf79540b02530be10d0ccdf7a5aefa36c3ddbf5302202aa8d09051f79af4d102eb0a7ffbca4ac39f6abed7fd0db08e39e3e2658ef876012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d60000000247304402202315bc2164ebfee486115cc519fb496f550b940936c52160fca25f7992e8cedd02205f24a4b391332cac94cfd31129af4d7598e4079038c43fefd2f2a4ac04204edb012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d600830400071225c64581447dcdd176a29247865b1575ef6864ee10dfc44b614e59f1bbfa7417d0b09b60bdde82525ea1f2197438675ba23d3cc49cab9963cc523531719a41bc7e9077767c4259d882119522f9ed9b0c36c86eb5bf7ee243009caa1257a1f1a4a401002af7e2d098aebc7784106e9a60b09412d0632ff671bfe1ec6d5a4cd8fd4d0b602300000000000000011886001737939dde1a5675be34626c582db949118b57e005a583e626bd8cefdac8d198c7d5167217882dd90e480f52639d45e24f7a2dd74188e9ef109812fb7dc23d60b157fe8c5572494cae5342235c666201bba0e66c628743cb09790fd55bfc1d78dde7f7ad75dec7eb65e4e55fc77ccfbdfbe3bcd7ec7da16391cfe59a5fc274cc411b1e6f42222ba4a0c370a3959995e72c96b0ada99b0658b604eda01beab2d88dd60730548129c75bbd6631bc77a56116bd55dc6a80d038eef6c3a1d7177e0d266485599abc0c302e4149233abbc0dc2c24191f603295a0b9f71569882ac15c1372b133c11884bf6b4aa3aac57b00e3c99aafe43c6029cbea44de77c3f769a763223021c96c9b69f71418552768ffe245eeea273bf768f3be450c8bfdb706c66e2a8c44f9f62b0e82bbd59002e4ba4a8cb6ee2e40ac11e80181942ec99d8a867e0c771024f7776e351684abdadf0bd7b167ca76a639569179ed1392cbebcc9288932585337454f3ed9744bca92a3c5e5913371cca8722e00d26ad9a4bfad4f5bde440158519fc8c18dd3bedb614d762a6f54a8a6c2754dfdc7a23afd5867d341511629d74815cba2312919fb2021288b916523c766f1713c7d9c35003951c77cfdfa71f49d006485c4c1962c2713b93b272bc20b148cd00555ef97b3edf6652d48cbc810ef4bdd856ced6de7f46627aab9d41fb41825adf0390f93ac1a6f27a6e970c6f6ae6295aa6f03520d5bfcf1b1cb2fddce578109a43b4329e68f1ebee1b75b936ebd8bfa8cc6cefc06745e325c4f8d10c33d8da8c54eef4ad92f510bd9871a11e8781cc549133c125dc283eeebfcb219876766ee7d0a4a084818ef201e6eab8ed2677607fb4fd5b100cc168c805513b61090393edb61b8dcd1c3f20f903facf066d86ed93f9f039073bb4eca215733a025aa5fe4a6e46a77bad4783a8654944f7d9c068fa3931eba3e369515a7957396c60fdfda28d5ef7e8ca7a451c3ecc9eb125d139676412d27e3a7f7cd13147d46d1c451be30b03a5a1b3a91165ebe77e7ddab98034ac6c945d0702fb4c8b3551c64578ecc273355fce7848a86f910d4c6d563a3616015ae79cb6ad8b74e7ecd7810e7dd16d10e54fcbb0c0b871c770198b5ea0d86908f6f6aa7c65b3aad884d71213b33460fd674cba0cbf43d55135fc80f0bd0e753f7f88df001fa8c50383ab679519b370a02968a91eab39284fc0abe74110b49c99830817ee3977abf2a5d88835ec275a6e10bffccb0c893fc36fbd3dac0dbd14a3e058ebd60a59983414884daa04afcffb932104f77dc54484a3fc23de50eb8edcdb14a4fb17808bd5f9fb28334d4375cabdc594cd3290358467f56c4f7a1a929ee23f08bb3504da1c19dcdfb5fd7f014920c6baeffb01825683115d68963d4953f4d0138da1dc8a23c54327ede457592c1b51a2e10312246882818c60e05de34188cd2083152675cdc623234450b97d5c24631287bc";
    tx += "110e5c5339739c7cf308cd77bc8b9b583d7993e37ba237674ce7b3be475b20dc82bd4219145ed83338d59cca79091e3226de5e79e8b47b6a5f958f45af04fb2919fb3a33a0d40656bbee9a7469aed32849f50aa4a56618acb7ddd5fa929fbd5b6514759c6497a2eace2cee2d0db42611127a9049e1682b1b045499ef5c8054940b8ac6130ef874b3a231046d5da7346b8a285dba802c4ab7333df7be0a2f89337570b639ca7aa590ae69d24c2a7f97a99d75827c1495b1e691abf81e4de4b004ed10848d34db1779ec7d3dd398e65717b7a3d39121ed95e6e753ff7ebca0515620929206b1af2873e5eade98f614a0f35eae62b5968a6f73f68890a26fca6a96eb96f6a51c714f1da7a0643995926b8dc742f434722d5bfbc15881e0e9b1ed0d9c9d749e25c83b591b8b40c68e4bb2a6bd9fadc2f2ca699aab65f10217c5b10dad420030156bb15eb3ee73c664a2fcdb7f79229218d43955db0fa7ef7db08b8c80db2fec254a7a8b6492d3d14da5bc231ee37b4fe3562043378e1a855e06d677659f9eb3f96b1f6d41d78784953c5f343edda2301a62bb25b25306175c1873961b2bfdc059f3cfcb3056b1025b1d406adb0e2b809519a34ef7ea8ca40326f6d069467d32a921c072b6ce6722fa868bcd3f48df6834395cbaac72ae1e471bb9b0056fa744263d0440fe8c0c506855b10dd53d2d94bad9cebeb33bb87c71e8865f865b65eedb892d8fb884fc31c656b7426a7803d44090d3d38845018cd05fb8f953a4d3712f8d033878a12a700c1774cb9c691c2808a95b028bee0555003a515d83497a8a30a5e2c661cd14b0f74850e03db6746828887103d8ec93fc48174b5bf2b676ed3240ca654901b380e543b2214c0e054dbc6982a456eeed0b002f90f07445ef8385636761e183998117565477fe6c35fc2bcfea5dbcfdcc7053ef96329c63f7a2fc971e69391ab3392db8001016800cf04f2362ff75a087dc8670a0d985ba4b83beadf5741fdfff2c25d77af11ecc0ba7a1bee53d4654f0db7027d95f86e3ed7bca445c62737a0780ae8867be669ad4650f5a1d1da81c7594f0305800eaadf5b765bd35ec201b74f67249deade4d3dffa3ef2d9f5e08f6098bea32c1862cc8cfc17f4702ba6f498af844d2bbc2cd2893d3809ac89b5b812cc61b5be88a450625650145ba4c53af411fb52ad35d415d0180f8d628614e63c68e9c21c907b48346087604ae644b4cfb7037556e9926b0cc987d4a25ebf5ccd115de414ace2a77d4c51814e783b7de598052bf8a1b37bce2a6d2758dfb8debf6c51b9762f102580c2f96edf517d02aac7ec76fe2c7dbd1f4d231476a40dd86020aabbbf29b602c4bba3b394965237c7370c0401174e406e0130ff1a7cf5dcbfc9ad7544f0ea9fa6d6fe86991d8e00d28cf15a318a35d9b329a226788edc2d736d7ae15f5aa669d54e5981553e50e6444605db4bbd1ebe692f6fd881a62698a78123e0a4d3064b89a6fe21a6f9622496b488e04b76f380d5b3fd15f8f8cad7e49e7bf8032e600229ba7aae88c3f08564be415a1d13ff448149085d1eab643521d4e44752a891cff17f5dde58bb4da2b98de5255c747e76a972ba9cc7252046309eaebcdedab9c69910509ea38a3a70f7174be18d2648e98be87f10a11b20dd857903e6355209ab0e58f8827000c47f276972f782ded374e333581fb06d0e399593793447093755990bccc6c4f856713349bbc7bbf6d60025d29207f65707b4cf3c3e89db8c48aa6f56701b14580c3f7ca7c9e94b85ca3d451bed4832deaa56638c15cb084c64bde64fd54dc6ce638087e9f3ed99b8ee8eeb6f1dd45e560c11f3dd6fd4ed301cf9e99d90754010626acec5770aea173dda3360a20e2adccf68fa6d63d76a7a7af5b03ecb0419ba7bce8fc53411934e5eb2beec295afebee2937bbda11079f3d742c0f07a4f9822c91787887b0659aeb46ce10d4d8391ba3428be9cda785a3dc07f589d6b8e4753e7b4390da2b9878647e6c634debb3cec549e704cb78a65dea2e0b2d66b9ec4b860c714f24741fcb1db2ae40d92586e44e0cfb30bc5d6c75669ada1dd3633aec54667401fff439e3113db020b73b4790fcfa8615ad9b7a1dba7d3788f3f588eb7d848bc3901b0d939ede25eb92778ce2b112c65ca6bca1575310e921d64996a26e9d4439e42bc5a16b23c7cbbb45f5ab3cfb0acc3ffb26250452c92981bf619733ef8f20c8304e629a1d98271a6d9ae96404d81bc9b4d3e13c436541525207eba5b088fe8ca70a98fbd91d18843f602602a6116388896e5810f7e10a67e284f7763ff75b2821f83815af1788bd7ee91721e0389cea923d4d1f634fb96133792c8a7be0ed3418c983f6d07eae8c351783a86c9a4f6553fbaf405a75f0ea100ee053d542eb0a295f8e3ca554fbe0585800c630e9a40938776bf6d0d9e2e83647621e20d07c0388725afa5e12b915ff5c7cb078e523860a9b8ebce3d0390d78d05d6e5cce95c17e0c91b9af003f880175b863183340faf6f6ed3f5a1c30bbea0c0cee26de3ac5d98516b2d47c5149fd65bb260baaec12676c30b52878304000b1f2762264b99ef5a7ffeaa7d804a564e918ce5041c3683e80cdc426d880cde45dd231ffc99f3f0d1ebd592e7c3ae172912ccbd24c6aad099da6e0d8bcc9eefd53ae3cb20dce6a2bff78dc39b11a22a74aeee48c5006270b9bd525b42eab705eea7d356d61eebc542ef52470f295bf798c16ac093d478cc5c856cf35b127d28affd4d0b60230000000000000001646c0127a45ada3b18e00b9cc5bdceae6b3ba7eef9d9af8143cc3ff5dc256ef3a793d722c090d300adc98117400dd8596c2c3d42fa00ec7a8f20e2c3482033aeb07a45e33ffe88bc362fd7b1d79993e2c7552dc1efb64246dd235fe9ce6055b8ea59f6d3233ba17d5852156c2cf661a1ea635658d13f8be119b8b0653e230491213b03083c7c370612fe330a2cbb619d0cb4c4017b4d2a9bb0ce3aba1a8be7eb8630222f4c0fdad7f3122b9eb4792b59ccc449385ce18c897469de7de320fab18c0d1935cbd72b90dce02e7ad1f315904019d29952d6ef0549df04059f58d5b33de64781de816a76471fd676d4955f865e2d479027fa7a21fec352f4f318968fb59cd8eb6dfc2a9243942ee01a98b06f231f3f9aac98ff35ac5ec90c850bd1e75e43fe3215cf6dfd500dbd33739aa7a272f3d363333cb37faa61a25131b34e31dd7f2ec52ea8df7a4bfc8f879c1bcdd1d167318a8ab62f9a6900755fba33a8eb85346a8e70296febe916ddb306c4cdb89f7efef3ffcba2582c1ab6ea4ed2975c32d850f13791cc1fd4ce879e63feb8e7376fd90f928bb2d619cf4812eaaea8e6ced51475ca62024a43520c1c38ae498fa01261dcd1e20e597ea027a52e13c08537c6cebcba6311afa46864b27d9dd90bcca976580e07c0e6a16281e398dd091e051ff071d5cad393aa99dd55c38f9f0143fa2a1209e6f6a2816b7cf9afcc5b78d15df163bdf71cf87f80963c52c46cfca1f2011f272bf54196c48e91c8b46be173462fed4191d776bf6031f3120438cc1258f404b235f10c42a1faeaae4a44ea4d02be96218eaa71ad6773f722a5818ebd5101266c8bb0ecf7ff2fbf0ccd5a7262c5d894aa3998a97974ba47fb5ada2b5f3c435d59ef49b704b8d111b186d5b6f99f8afcee174b45c2e464d8ceb8f3b7b1786ee1fdd100b9faac12f8f2e77c285d680d2d03f9bc8a6ffaaf495e26ccfc51ad510fc17aa6d6ef82647dea29e62e463486c8bace18374ae7b8c03e6805607319a6e4d9d21adb097ab8e66bd1157c52cddef2b2cc6b843d0803213b04654ecb9221de4fcebf99b2a02acecabbc199aad63e6f6ed02b3291455fd5e5dfab09155c74c1cb061dc890ea26b0a35fac5ea8af22c2ae432941274f66414543f9cf8e9d06426580fd9804e21ab5ebb68f5d7290e628aaac4b924d560a493abddea7ea2d5614d62c138228fbdb57319511380ce2b1b76588ce639b0b65caefcf610a5ccc48af63f3158a0b3301118da678c9524ec5c5eb789ad54f7295bea64ed128fc1661cc89801fb47446713ddba1daafb7de106bc89038535496d804ba3363c58b460de053201e9dfae13c8536e358a19982cd389de8c731d0585197bca82e6b45f1ca9806f105747d6344f37a01b63af3080959810e5212ceac885a9b3b236c3279dd729dcce62d46f7882e2581d141587b76cfc8a184363aaa06282ecf7f833c17721125711c876cb657517c68704723cec81a133777a5d07ef6ad2c8c2598cfdab84f456bedfb87a10ffd8c9ac27c69a223b0e03ff4dc4b7bb045b395dd5b60ff332c8df475981dae982fcd34215b836973649b7a19041c61652d32bc56ee6d6969e4bd1ce3ba3169528114ee615819cde849715a8b1b706597bbfedd7efcc1cee188a2baaac85b72f0ea9a6f30e7b80b1582b567f93c7b3f86577800631e5eb8733663a16ce0ce2d48d1398f5a072a1053a09ce22e24f8bc1cdff9ec1fc6a4ff68e83256186191c909c58873dca41566b0087b9868ae8301db4c8d1ba13ed3ed826bc94204d98f7fa09506484ca1364e5c0f44ba8583b55a7369dfda18524938baf6933632feae9962e7d39894d8ae4ffab008217ad0615da82644894969fb2c07cc8f8b843ac00f8c9eaaecc916dbc1ce79f5d0d766a0ce6d4963dd83b02d24efa88a72f0727f7273038656851ef470c6a502497d50fcbd0cbad9d30b6f3f8e8a158707ee225dccbae5a9637c94cf42936df63dae4b726431b08ab3cbd2ef27ba449947f1a5d257b604777d65e82f03315791b3f8753e131d5dee46414810425e5b6a08c4ad554f7a43231782534813f5528fb7e600c1a218470b9c34eac516bee4a1a107b3ce7e658a649d94c531525daf934a77198257ccb6d45e54a86cb94d185d263f5cff2d42b5d2fd9ca8e7c9f1a2b1f4475b3232dc2da35b6abac2885b3bde3bcef4d75cd4b6b94c8f4e35fda5611b67b0f0a019c3a148c4f7cd2edaa93274e5f3204652b79266856855365b2bd611d4c285491bb5ba7c6d5c6146c9895c37bf5e518211ec867c8c6e9569b151b641ef73f4fbaa093c1d8baf359015f8e7a5f94df9ef537592257d01d6033738b31c715b4dbeaeec005b8d784ccac12135cc26c90f92f89d4cb959db944593403895d8a6c7a3664c8352101f603bdf1d78df67e736b72c14b7e9e29fbf28cf67d692803e596c2df1b2cdc7588453f9ce5b7bf6d67faf2d27fa48d1d2b2e3ea1a0d3b38eae0f2bae020ba860c88dc29cea88209a53b25108338939e57d9ad5ef678adef2c2fb79c57eb41d2a3344502f5f3c6430760d4d912f0cb6550c1d2640cdd2d4616d28fd92f6e89687d3f69e567841d74a7e77cec4a87ba70e3c8802629d4c098301f30d6d10933a59ff0e43bae4d5a487e8fbaad74f76768d6d143d03eb568b42d4a1f628d774dce237447613fbcf43e81bc4403d5b4c1a1ff4cfb4e0c28f55c6a972e387c24f50a5fef64cf8a6a79e804caa5216d98e22e407cd31a1ce172373a6e5b587703b51b9afebb05787e99b17cd892b92c9ba64a10558e6b7a94f5a8693299a252bda34377898a0013b497f54394e498aa83ed899d6b139ad584990e24d2a677d846a3fac7b51aff781cab31cd1a5fef4c1871d452532f409624adef19f0c1e1088db5855b0556df5904f10ad5ccbca92e8471fb399e8f4d7b7a42b49dd2dbe2d75ba02f0028e98b3d8493a801d6c018344d2554510559502c84a28ce123b34010dd1b457a5088e8fe3977052151496fdb93a48d6407bf23667e226dc3ab0e8037d86978329f9269fda30cea0acda68b2d212f4e179057af9e3140c968db20227cce91ec839386f48e57af1a3f869d9d48c58c3d7c43dd986754a1490638f03c0c1eca2f7c1c71cf0cbefda41d9c4454c0623ef1196d1267ac6ba1911742babd4cfac03edd6447a4da18b8e6a762262e822f136468f28ab632ec3a3a8b2e39b284325080f4ac79fd80c84e1c7bb49f1d139887406e00cffaf264ab5e1c4518f8a1fda31fe9c81f7b59467b88f4991347e85b1679c76764fec990c36242e78e6f38ce43df2a7b856b7611cacaa1520ee7bdcfe4991a95a8cad1c13613c78a808c31a6eab7f0a077df5b537da36c4ee6c6bd3ace18245ed2aeaf240dcef2c870bfc1531805bc4c6d56127691ec3411b731621a9df4c6b24171ba42011ec58d843131c5feb28a1c1e94c1484c4306b7e18d8420bc0051b24b4becc7c4bf629c8f8afa4e1657785ff128dfd6ac3c0cc180492d73ff8dcaf5d53525de5a4070f294ef9b27651d28c58018a30a94946d0e8d59599474666c7752130a699b9096e7ae8634dcd46479c79013a62856ad86a8f0eaccea3c20ebf0098ced12762e28657b34620c18f49f6d8ededf98914c7302e0dddb6a80f6d4182654abd58b56e8a98debc5549f386c53552336aea2d166f5ea1156cf7605bde250f1d4fe74075b68a8de5a6927f701fa1ff22bac009884ebc13c980672b06251e60c44013144160d0a7a9f2b7aadc01f2a5eb79fd31fba642bc95376f2e04d024b5b3094b57146abb8a7f404647746eb9c92bda0e0129f65bb443c9d30244a6914b98ceaa764e64cee9c475c4b3937501b15115a351c96f7d2f8f28d982871646a4e6e3e35ae6461baeea623e81ee2f5750957f7929255c355c2758074bc341aa33f2af092d805230692d5dc367b0b3b8646bc57729719a7e94c1848f777331a67b2f96fa69f96d1b1af85ffaf75326e7de7986b126b924ede269a7c4db9466a138bf47a1cce4b8699fe70791f8626fd51d51ff031dce9c9d558f797c04404c50a447e8304000efd9a38fd281520563c174d1f9660c64c3ffa7bedde1f535a71b94abfe3233a3b698d156763b71a41f5879a61e519325445dde67341b790043aa7b8e150811598a933dfa156e7ed1d8b99649369043228a485bbc8722506a3ec2c378d1a75efc36ce6e8da6ade23a4958ae05ddeafa72b66b479f2c8789e5d40e1af632e8b6526fd4d0b60230000000000000001138d00b4d9e6e6da9688de75c96932605b49300e794fa4f082cd79b82f26558d9fc0cac35341729519c76d0c9cf80c6c0b0739150ce4f27d72030e0dc06806abd61ae84735fa45f3d54ba6f40f9d9c7c6d486f081baf10e121971344a6dc2779d99702ad5e7ff11983b6d0906f28ab50454d0b1a6e7b71365d362683169cbd4f8e24842b33c01bb06b3edb6583be8718bd13b2297837770624e1ff84baedc98b883adf25acb57f43b8820c4a4712356205d343d3456f8bcd421414ccaef6d631f3975c0ceddc84cafc98e682496b8bac4f213dc09312d0a72f92d662c3c30fc98a01f197f9a72d2ba4af085a710da8591dc8dd72618a8aa7e17034b266581c91b1797bc9ce2bca5fcfe1e5f24242cc1345bec8bc6e7ab7190ace1d78e38ff9be226192bd328d7be71baadc644ab61c83484fd7a9d6f8baf6a96a90d0b0f00d19ec6408dfde4b64bbae56ce1b2fc4ee48dd9d8ab422926d9d947ed10c5d195933b144c1e1304277f52889f905642e0e7dd31672acf0771dd18483bfdfeab21d0329732aa4e3f98dc09dbe36294147ffdadae58e266b0b0ebc76f6c0cb28fb7aeb03a558d339535df7bdfea70a6d61265cfdd314e30bd8e7ee5afb7563394cc0db3c0f5f507065a4e9198ad3676876204cec16eae53aadc5d7cc345069d981b5f31182bf7b531c0ef474713816980fefc7291f1d5eae79793e1ce6bec7fb3860f936cc60ddb69913dddd73c335ac77b546468eeafe4daf7ca7ffc89bbf974194f0272d6417c793f4da72208a4283811a0f3a41bda7968ec7725fa24a158a9a736c3ecaa91c01362befabfb0c789f1b56e947d4ca84939288f3e5414ad9f282b7b22723f0dced7b9467e375467fc284e5141219b1be84f2e03f39943a8ea478f607fea34f671f7cfc686824c7c9f05e52b8561f78aea39a7daa5f74d08b1bf17fa55de7d98c281025487c31fc0cc37f3fe99d774ff0a72e726dbc18cfd1a9ec5e6debfed54db129df13c84219938ea72d16ca2a9d81be6af98aa10501ddd745889bb9326e74567c4905e6d64c676329983f65ff240c9985909794d7702d047772e60d13f2d422b25f2fdbb3c2f6e86bcdf5aa03c1450a5140b6da24a71ac0a8176c40a55250afe03c25b76fb25c9d8a63379b2a28e41d380068cf39a57cfd7fc31df62c71764349704330f1960eaa2eef6dd1d2eb26ff132afe2c7dd1bff21b800994a24d967e74490c96ebc8930495e71c1b61ae8be0ce7d6f34d2d8486c492392693882f463461ffa7f739a5dfe9f79b7aaa16d7099be0c759c98cf717e9ed87737edebc90e15d94f28f1765c89c240e08e98fc3f361a6a8a9e22ab0cba50cc489a7dd0feafcde380514cc84f2f8dc904506c845259fd19f7ac89da0f0bb61a8044a90c0192fae79466e217fcb340b5e5e13e50e059ffffdf1672162d732f2eed96a367dc7df564e449ccbede065d7c16ecb4d05df00b4b92afc60ae722eec4a5511f2f4660ab97dd3ffc55dedb67945e9d08b490fd2df771aa8b4272cc148eff17ae157cdd023c2430677982c17e7d0c0abc1cebc8d4288472c4e81eb898575f221e1990aa318e704ab4a235ede2654b1e5a3aa0a7ca291020f51803305aca40661e33b0b68cea41de969ccb1954a2f89fa6b8328d0414297ab48dce663a3f28c00434292e7bf482d96da60bead6fa2b494304aa7718c554b5c5b6c26441c846f2804c9e70b49a3d812e757135c687c183ed4a5bd8c738a229396cdef6dbf6303705c9fbc7482a6bcc9a26fd04ec6b83d3c21e41ccaf68bcb9dbcecc9b950cde842e5ef0cf506b6144cd4558c1b1c3153b2f3fc1eb4bcc95e0ac0b9f570dd1b43a7e805f84594018c9b79b314b652d72ce702d7b8a0e1f3f5778659c1aae869bdf21847dc2219628e5546b28dc7daa7fb66da81eb6be8c3d582404f69d693d2db0a83b7cdaf8a449e656464445637d3f33c737714c4e763870c2bd8c202fd2f8b08a3af7414f4994f52678721544abddc63d2b07ca2000b1c7b805cc65db0aa31ae95b3824e063990c3732c954c16149835e3f40f87926881928095d69310ee374ba73aad85dee76027a109db15b749faa1a6c0a3ef4205a6b5f44bea1183b4ac24b841cff4ac5946afc654e34904fd432e9ded453a55b2455a7b6be8dcf0ba6d06f6088e714bc6d1dcdaa0c058ae064982c35ccbd10d75b280d92b6f66172ef585765325d7a91d5a0b9c582560d623d7104b623872b9310e6f4bd9cf55f2582495d7b5b8c0c7628441cb2dd86e9bcceeb15d927ae37423ccb761b3201e910d63b37cb9e4efe89f0cbc3aa1f1714df13e21a512a1ba39556fae615ce5e6ffa52da72cdd349f19e6c5278febdc3763b5b530f1c059fdc06ad28c2963bf786f16bafb5dd9e36dedf1b21385443afa8fb1c9003034b2a20a54bcbb9b1fb519f68b7b50d6a71eb04319e34a8feecf4501b50a792657096e257b3b403b2300534b130f5a423a38d7bc5f181f49e66081e16c49f7588686f3155bc3f37d9d074aa1fac57e57e1734ac00af4f31124213c5cb89d2cc8e273bc3f6c56d35f1a3c3f9701ae0d35b8c2554fc338618d6a6c478a2cffae7b6d737dfd13b9d5a3f612e498529f4d8e1acf2b49765caea9eacd33cb3678442fa02653f62cdecce96212040dab1a322c4b13f7bd731a69e9f1e5a23a0948daee405f15d0961fb14c57d154c5118a3691e9c42c233a38fe1662bdb788ed1298b02f24dcafdc73ab3fba67dafe259e8651b4fac6a1fed0c3fb4c914a2b72f02499737d37be1c0da2da96d4e165fd4f7098e9e7d30045933005d13674192673b479e3dd4fdebf44a73327d4e416e5f7fc76487a685e9706ab08c3f4e5096bcf12c73e57de2bfcc217343b650002076631d1487af0147f9b13b6386bd1b2525433f8dd7b6aa4bff765b9701311c3419a2a76a0718a12e5333ce4a139fed6e97edbfa3b913ecad02b597c42a971f38f699f2fb63fb6eef10b19b773cd0c6673f8b7973cdc8d54e17f752871b28c317c0a6166d88b14f054c631ca588d2f3945322878b564c15d5bc8c9cc75fe32647547df1ad2b20f4a1ddffe78e62227242d861249f4a02715a6c5b005c3f9457c0eb28cad0252935896c701c5f6f47e75a8fe0a60d81b6b61053e779116903dd3573d04e95f1c9d4ba9033cabe74b8e8dccc5c8a5b87a9d07747a69e9c28fc92591120a477eaca4ae111372092a1d7e986c68a647b5d52df34fbdd7f4fa31bc744de889f82514f46af7b4426e22cfd96753cd55ec53a24661af259801783b4fa055f8ee4777e92c74c939a4a234b7c10ba9b2fcbac505997868aab4074c0055038ea0d47a3f12340bde41085f12ff25dd2e56931412af70bcb1d88e382bf046adb3348a20831a0d938f7a98c5d4c2dc1ac7137a7ba00c4745d361bd5aeeadd47af05cea3599075a214dc7974094a3e6a16f11a7566e19e553324f077b05c6833d74da7c3fd9b14f255f812a48f8c6e4e149ae2b1dfad224357496b4dce4c1a626d068a2fbb56f979eec8d784a696a3fa97667f2cf640dd9c3d7a17fb0072a70721c2ff3eb6224eee2b133b3625eb1aece5316c99b982a7291c62e63c9128c11e9186eef89a5bb6410c6b9f6b04bd274e8b9d4f4bcbf7a94fa37efcdd3c43c784a0365960cdf3b7b506cc9b24778110260fb3503c0fdd4be45fde0815e10b0fbc621c97dd3769e456b17d526a67ea5a3e7a3fc89e61854c9d3970e1e5648878c70ed52fe41c579e8e10d8146def6940bb0dc4673b43a650d7458934bb1c8a37bfe3fdb924a91a292b077d0ce9164ce64d03ac159afcbcb26aa87ff45aa4a2a61950bebaa50a552a875593f5523669ec1365c166e2a1a9629124f04af04526290d2410c5e840d9a0fff54e8551678288acf444ced24688e7990b77d8bd42c4d55f7e102d020c811bdbf1311b78c157622a531ac4701d5fc5d5f4b7732676ab898dbb7aa139d5a538e04dfff7a9c191dd4b359e5ff91c82b416b15a38bbf85919b8c3a71c45a521ec7b4d45048c112ce4a67f2673b8193b2fba1ec67615027f7c201253bd49150000";
    ConfidentialTransaction ctx(tx);
    uint32_t target_idx = 0;
    Privkey blinding_key("e1e81c2d88ab1a0187dafe3670aa0de9d4c0cb5285f53ab40f527604ce888052");

    /** Prepare Expect Value **/
    std::string exp_tx = "020000000102564d82f62046ac81e09499c473bd8a7530efeaa697c280d7da49e57068f13b830000008017160014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82bfdffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000003b9aca00010000000005f5e10030a4b26d6218012231f85a79b7f9a8fc874fd15855c843ffb570d18939b03fe70000000017160014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82bfdffffff040ae13799934b4ad8e54944bbc20c9d5edb16a936aca98466c8f98caa4cb615d10408f1b8117305d629f90446d49a448288ad046bf3f23a660b806125ae227558ef430321d65b32b6d3f652293df0ce990c23be2f011ecd2facec89a00db94dbd5ec5c617a91470befeb928008476293abbe8568e063ba1240cde870a89ae7189cfdd5f7c1a8446d4b5ababd175598b42e6bb5e3c5b033ab4f22cc48a0955b98c57768fb1ad41e51f71b7852b338aed0f0a36728d331053b0f5be7d2fa60369b2a38bcb8b1f1efaa3f0c937390c9fe3e0ad72bcc9c08a4198a85a8396a4bc1976a914505b3bdab052c517a76b0acaa1520e01ee2b78f288ac0b91b91fb661db9be40ce86088cd8af1c6b67a7f9b8fd4248a5fde07ac9b02104008ee8543e0341709bbfc79ff74c7330f9439bf0da1490ccda06f040dab0603abe00294f8768ce1ed0116b38035cfb57bbb631b16d8fad0455a275d5f00682e23f8ba1976a91469a631d0d00cdeaa0fd1cc00bb567f995f9aea6e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000015c2000000000000000000247304402200eae1c3c561cfbcd51b31cb8cf79540b02530be10d0ccdf7a5aefa36c3ddbf5302202aa8d09051f79af4d102eb0a7ffbca4ac39f6abed7fd0db08e39e3e2658ef876012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d60000000247304402202315bc2164ebfee486115cc519fb496f550b940936c52160fca25f7992e8cedd02205f24a4b391332cac94cfd31129af4d7598e4079038c43fefd2f2a4ac04204edb012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d600830400071225c64581447dcdd176a29247865b1575ef6864ee10dfc44b614e59f1bbfa7417d0b09b60bdde82525ea1f2197438675ba23d3cc49cab9963cc523531719a41bc7e9077767c4259d882119522f9ed9b0c36c86eb5bf7ee243009caa1257a1f1a4a401002af7e2d098aebc7784106e9a60b09412d0632ff671bfe1ec6d5a4cd8fd4d0b602300000000000000011886001737939dde1a5675be34626c582db949118b57e005a583e626bd8cefdac8d198c7d5167217882dd90e480f52639d45e24f7a2dd74188e9ef109812fb7dc23d60b157fe8c5572494cae5342235c666201bba0e66c628743cb09790fd55bfc1d78dde7f7ad75dec7eb65e4e55fc77ccfbdfbe3bcd7ec7da16391cfe59a5fc274cc411b1e6f42222ba4a0c370a3959995e72c96b0ada99b0658b604eda01beab2d88dd60730548129c75bbd6631bc77a56116bd55dc6a80d038eef6c3a1d7177e0d266485599abc0c302e4149233abbc0dc2c24191f603295a0b9f71569882ac15c1372b133c11884bf6b4aa3aac57b00e3c99aafe43c6029cbea44de77c3f769a763223021c96c9b69f71418552768ffe245eeea273bf768f3be450c8bfdb706c66e2a8c44f9f62b0e82bbd59002e4ba4a8cb6ee2e40ac11e80181942ec99d8a867e0c771024f7776e351684abdadf0bd7b167ca76a639569179ed1392cbebcc9288932585337454f3ed9744bca92a3c5e5913371cca8722e00d26ad9a4bfad4f5bde440158519fc8c18dd3bedb614d762a6f54a8a6c2754dfdc7a23afd5867d341511629d74815cba2312919fb2021288b916523c766f1713c7d9c35003951c77cfdfa71f49d006485c4c1962c2713b93b272bc20b148cd00555ef97b3edf6652d48cbc810ef4bdd856ced6de7f46627aab9d41fb41825adf0390f93ac1a6f27a6e970c6f6ae6295aa6f03520d5bfcf1b1cb2fddce578109a43b4329e68f1ebee1b75b936ebd8bfa8cc6cefc06745e325c4f8d10c33d8da8c54eef4ad92f510bd9871a11e8781cc549133c125dc283eeebfcb219876766ee7d0a4a084818ef201e6eab8ed2677607fb4fd5b100cc168c805513b61090393edb61b8dcd1c3f20f903facf066d86ed93f9f039073bb4eca215733a025aa5fe4a6e46a77bad4783a8654944f7d9c068fa3931eba3e369515a7957396c60fdfda28d5ef7e8ca7a451c3ecc9eb125d139676412d27e3a7f7cd13147d46d1c451be30b03a5a1b3a91165ebe77e7ddab98034ac6c945d0702fb4c8b3551c64578ecc273355fce7848a86f910d4c6d563a3616015ae79cb6ad8b74e7ecd7810e7dd16d10e54fcbb0c0b871c770198b5ea0d86908f6f6aa7c65b3aad884d71213b33460fd674cba0cbf43d55135fc80f0bd0e753f7f88df001fa8c50383ab679519b370a02968a91eab39284fc0abe74110b49c99830817ee3977abf2a5d88835ec275a6e10bffccb0c893fc36fbd3dac0dbd14a3e058ebd60a59983414884daa04afcffb932104f77dc54484a3fc23de50eb8edcdb14a4fb17808bd5f9fb28334d4375cabdc594cd3290358467f56c4f7a1a929ee23f08bb3504da1c19dcdfb5fd7f014920c6baeffb01825683115d68963d4953f4d0138da1dc8a23c54327ede457592c1b51a2e10312246882818c60e05de34188cd2083152675cdc623234450b97d5c24631287bc110e5c5339739c7cf308cd77bc8b9b583d7993e37ba237674ce7b3be475b20dc82bd4219145ed83338d59cca79091e3226de5e79e8b47b6a5f958f45af04fb2919fb3a33a0d40656bbee9a7469aed32849f50aa4a56618acb7ddd5fa929fbd5b6514759c6497a2eace2cee2d0db42611127a9049e1682b1b045499ef5c8054940b8ac6130ef874b3a231046d5da7346b8a285dba802c4ab7333df7be0a2f89337570b639ca7aa590ae69d24c2a7f97a99d75827c1495b1e691abf81e4de4b004ed10848d34db1779ec7d3dd398e65717b7a3d39121ed95e6e753ff7ebca0515620929206b1af2873e5eade98f614a0f35eae62b5968a6f73f68890a26fca6a96eb96f6a51c714f1da7a0643995926b8dc742f434722d5bfbc15881e0e9b1ed0d9c9d749e25c83b591b8b40c68e4bb2a6bd9fadc2f2ca699aab65f10217c5b10dad420030156bb15eb3ee73c664a2fcdb7f79229218d43955db0fa7ef7db08b8c80db2fec254a7a8b6492d3d14da5bc231ee37b4fe3562043378e1a855e06d677659f9eb3f96b1f6d41d78784953c5f343edda2301a62bb25b25306175c1873961b2bfdc059f3cfcb3056b1025b1d406adb0e2b809519a34ef7ea8ca40326f6d069467d32a921c072b6ce6722fa868bcd3f48df6834395cbaac72ae1e471bb9b0056fa744263d0440fe8c0c506855b10dd53d2d94bad9cebeb33bb87c71e8865f865b65eedb892d8fb884fc31c656b7426a7803d44090d3d38845018cd05fb8f953a4d3712f8d033878a12a700c1774cb9c691c2808a95b028bee0555003a515d83497a8a30a5e2c661cd14b0f74850e03db6746828887103d8ec93fc48174b5bf2b676ed3240ca654901b380e543b2214c0e054dbc6982a456eeed0b002f90f07445ef8385636761e183998117565477fe6c35fc2bcfea5dbcfdcc7053ef96329c63f7a2fc971e69391ab3392db8001016800cf04f2362ff75a087dc8670a0d985ba4b83beadf5741fdfff2c25d77af11ecc0ba7a1bee53d4654f0db7027d95f86e3ed7bca445c62737a0780ae8867be669ad4650f5a1d1da81c7594f0305800eaadf5b765bd35ec201b74f67249deade4d3dffa3ef2d9f5e08f6098bea32c1862cc8cfc17f4702ba6f498af844d2bbc2cd2893d3809ac89b5b812cc61b5be88a450625650145ba4c53af411fb52ad35d415d0180f8d628614e63c68e9c21c907b48346087604ae644b4cfb7037556e9926b0cc987d4a25ebf5ccd115de414ace2a77d4c51814e783b7de598052bf8a1b37bce2a6d2758dfb8debf6c51b9762f102580c2f96edf517d02aac7ec76fe2c7dbd1f4d231476a40dd86020aabbbf29b602c4bba3b394965237c7370c0401174e406e0130ff1a7cf5dcbfc9ad7544f0ea9fa6d6fe86991d8e00d28cf15a318a35d9b329a226788edc2d736d7ae15f5aa669d54e5981553e50e6444605db4bbd1ebe692f6fd881a62698a78123e0a4d3064b89a6fe21a6f9622496b488e04b76f380d5b3fd15f8f8cad7e49e7bf8032e600229ba7aae88c3f08564be415a1d13ff448149085d1eab643521d4e44752a891cff17f5dde58bb4da2b98de5255c747e76a972ba9cc7252046309eaebcdedab9c69910509ea38a3a70f7174be18d2648e98be87f10a11b20dd857903e6355209ab0e58f8827000c47f276972f782ded374e333581fb06d0e399593793447093755990bccc6c4f856713349bbc7bbf6d60025d29207f65707b4cf3c3e89db8c48aa6f56701b14580c3f7ca7c9e94b85ca3d451bed4832deaa56638c15cb084c64bde64fd54dc6ce638087e9f3ed99b8ee8eeb6f1dd45e560c11f3dd6fd4ed301cf9e99d90754010626acec5770aea173dda3360a20e2adccf68fa6d63d76a7a7af5b03ecb0419ba7bce8fc53411934e5eb2beec295afebee2937bbda11079f3d742c0f07a4f9822c91787887b0659aeb46ce10d4d8391ba3428be9cda785a3dc07f589d6b8e4753e7b4390da2b9878647e6c634debb3cec549e704cb78a65dea2e0b2d66b9ec4b860c714f24741fcb1db2ae40d92586e44e0cfb30bc5d6c75669ada1dd3633aec54667401fff439e3113db020b73b4790fcfa8615ad9b7a1dba7d3788f3f588eb7d848bc3901b0d939ede25eb92778ce2b112c65ca6bca1575310e921d64996a26e9d4439e42bc5a16b23c7cbbb45f5ab3cfb0acc3ffb26250452c92981bf619733ef8f20c8304e629a1d98271a6d9ae96404d81bc9b4d3e13c436541525207eba5b088fe8ca70a98fbd91d18843f602602a6116388896e5810f7e10a67e284f7763ff75b2821f83815af1788bd7ee91721e0389cea923d4d1f634fb96133792c8a7be0ed3418c983f6d07eae8c351783a86c9a4f6553fbaf405a75f0ea100ee053d542eb0a295f8e3ca554fbe0585800c630e9a40938776bf6d0d9e2e83647621e20d07c0388725afa5e12b915ff5c7cb078e523860a9b8ebce3d0390d78d05d6e5cce95c17e0c91b9af003f880175b863183340faf6f6ed3f5a1c30bbea0c0cee26de3ac5d98516b2d47c5149fd65bb260baaec12676c30b52878304000b1f2762264b99ef5a7ffeaa7d804a564e918ce5041c3683e80cdc426d880cde45dd231ffc99f3f0d1ebd592e7c3ae172912ccbd24c6aad099da6e0d8bcc9eefd53ae3cb20dce6a2bff78dc39b11a22a74aeee48c5006270b9bd525b42eab705eea7d356d61eebc542ef52470f295bf798c16ac093d478cc5c856cf35b127d28affd4d0b60230000000000000001646c0127a45ada3b18e00b9cc5bdceae6b3ba7eef9d9af8143cc3ff5dc256ef3a793d722c090d300adc98117400dd8596c2c3d42fa00ec7a8f20e2c3482033aeb07a45e33ffe88bc362fd7b1d79993e2c7552dc1efb64246dd235fe9ce6055b8ea59f6d3233ba17d5852156c2cf661a1ea635658d13f8be119b8b0653e230491213b03083c7c370612fe330a2cbb619d0cb4c4017b4d2a9bb0ce3aba1a8be7eb8630222f4c0fdad7f3122b9eb4792b59ccc449385ce18c897469de7de320fab18c0d1935cbd72b90dce02e7ad1f315904019d29952d6ef0549df04059f58d5b33de64781de816a76471fd676d4955f865e2d479027fa7a21fec352f4f318968fb59cd8eb6dfc2a9243942ee01a98b06f231f3f9aac98ff35ac5ec90c850bd1e75e43fe3215cf6dfd500dbd33739aa7a272f3d363333cb37faa61a25131b34e31dd7f2ec52ea8df7a4bfc8f879c1bcdd1d167318a8ab62f9a6900755fba33a8eb85346a8e70296febe916ddb306c4cdb89f7efef3ffcba2582c1ab6ea4ed2975c32d850f13791cc1fd4ce879e63feb8e7376fd90f928bb2d619cf4812eaaea8e6ced51475ca62024a43520c1c38ae498fa01261dcd1e20e597ea027a52e13c08537c6cebcba6311afa46864b27d9dd90bcca976580e07c0e6a16281e398dd091e051ff071d5cad393aa99dd55c38f9f0143fa2a1209e6f6a2816b7cf9afcc5b78d15df163bdf71cf87f80963c52c46cfca1f2011f272bf54196c48e91c8b46be173462fed4191d776bf6031f3120438cc1258f404b235f10c42a1faeaae4a44ea4d02be96218eaa71ad6773f722a5818ebd5101266c8bb0ecf7ff2fbf0ccd5a7262c5d894aa3998a97974ba47fb5ada2b5f3c435d59ef49b704b8d111b186d5b6f99f8afcee174b45c2e464d8ceb8f3b7b1786ee1fdd100b9faac12f8f2e77c285d680d2d03f9bc8a6ffaaf495e26ccfc51ad510fc17aa6d6ef82647dea29e62e463486c8bace18374ae7b8c03e6805607319a6e4d9d21adb097ab8e66bd1157c52cddef2b2cc6b843d0803213b04654ecb9221de4fcebf99b2a02acecabbc199aad63e6f6ed02b3291455fd5e5dfab09155c74c1cb061dc890ea26b0a35fac5ea8af22c2ae432941274f66414543f9cf8e9d06426580fd9804e21ab5ebb68f5d7290e628aaac4b924d560a493abddea7ea2d5614d62c138228fbdb57319511380ce2b1b76588ce639b0b65caefcf610a5ccc48af63f3158a0b3301118da678c9524ec5c5eb789ad54f7295bea64ed128fc1661cc89801fb47446713ddba1daafb7de106bc89038535496d804ba3363c58b460de053201e9dfae13c8536e358a19982cd389de8c731d0585197bca82e6b45f1ca9806f105747d6344f37a01b63af3080959810e5212ceac885a9b3b236c3279dd729dcce62d46f7882e2581d141587b76cfc8a184363aaa06282ecf7f833c17721125711c876cb657517c68704723cec81a133777a5d07ef6ad2c8c2598cfdab84f456bedfb87a10ffd8c9ac27c69a223b0e03ff4dc4b7bb045b395dd5b60ff332c8df475981dae982fcd34215b836973649b7a19041c61652d32bc56ee6d6969e4bd1ce3ba3169528114ee615819cde849715a8b1b706597bbfedd7efcc1cee188a2baaac85b72f0ea9a6f30e7b80b1582b567f93c7b3f86577800631e5eb8733663a16ce0ce2d48d1398f5a072a1053a09ce22e24f8bc1cdff9ec1fc6a4ff68e83256186191c909c58873dca41566b0087b9868ae8301db4c8d1ba13ed3ed826bc94204d98f7fa09506484ca1364e5c0f44ba8583b55a7369dfda18524938baf6933632feae9962e7d39894d8ae4ffab008217ad0615da82644894969fb2c07cc8f8b843ac00f8c9eaaecc916dbc1ce79f5d0d766a0ce6d4963dd83b02d24efa88a72f0727f7273038656851ef470c6a502497d50fcbd0cbad9d30b6f3f8e8a158707ee225dccbae5a9637c94cf42936df63dae4b726431b08ab3cbd2ef27ba449947f1a5d257b604777d65e82f03315791b3f8753e131d5dee46414810425e5b6a08c4ad554f7a43231782534813f5528fb7e600c1a218470b9c34eac516bee4a1a107b3ce7e658a649d94c531525daf934a77198257ccb6d45e54a86cb94d185d263f5cff2d42b5d2fd9ca8e7c9f1a2b1f4475b3232dc2da35b6abac2885b3bde3bcef4d75cd4b6b94c8f4e35fda5611b67b0f0a019c3a148c4f7cd2edaa93274e5f3204652b79266856855365b2bd611d4c285491bb5ba7c6d5c6146c9895c37bf5e518211ec867c8c6e9569b151b641ef73f4fbaa093c1d8baf359015f8e7a5f94df9ef537592257d01d6033738b31c715b4dbeaeec005b8d784ccac12135cc26c90f92f89d4cb959db944593403895d8a6c7a3664c8352101f603bdf1d78df67e736b72c14b7e9e29fbf28cf67d692803e596c2df1b2cdc7588453f9ce5b7bf6d67faf2d27fa48d1d2b2e3ea1a0d3b38eae0f2bae020ba860c88dc29cea88209a53b25108338939e57d9ad5ef678adef2c2fb79c57eb41d2a3344502f5f3c6430760d4d912f0cb6550c1d2640cdd2d4616d28fd92f6e89687d3f69e567841d74a7e77cec4a87ba70e3c8802629d4c098301f30d6d10933a59ff0e43bae4d5a487e8fbaad74f76768d6d143d03eb568b42d4a1f628d774dce237447613fbcf43e81bc4403d5b4c1a1ff4cfb4e0c28f55c6a972e387c24f50a5fef64cf8a6a79e804caa5216d98e22e407cd31a1ce172373a6e5b587703b51b9afebb05787e99b17cd892b92c9ba64a10558e6b7a94f5a8693299a252bda34377898a0013b497f54394e498aa83ed899d6b139ad584990e24d2a677d846a3fac7b51aff781cab31cd1a5fef4c1871d452532f409624adef19f0c1e1088db5855b0556df5904f10ad5ccbca92e8471fb399e8f4d7b7a42b49dd2dbe2d75ba02f0028e98b3d8493a801d6c018344d2554510559502c84a28ce123b34010dd1b457a5088e8fe3977052151496fdb93a48d6407bf23667e226dc3ab0e8037d86978329f9269fda30cea0acda68b2d212f4e179057af9e3140c968db20227cce91ec839386f48e57af1a3f869d9d48c58c3d7c43dd986754a1490638f03c0c1eca2f7c1c71cf0cbefda41d9c4454c0623ef1196d1267ac6ba1911742babd4cfac03edd6447a4da18b8e6a762262e822f136468f28ab632ec3a3a8b2e39b284325080f4ac79fd80c84e1c7bb49f1d139887406e00cffaf264ab5e1c4518f8a1fda31fe9c81f7b59467b88f4991347e85b1679c76764fec990c36242e78e6f38ce43df2a7b856b7611cacaa1520ee7bdcfe4991a95a8cad1c13613c78a808c31a6eab7f0a077df5b537da36c4ee6c6bd3ace18245ed2aeaf240dcef2c870bfc1531805bc4c6d56127691ec3411b731621a9df4c6b24171ba42011ec58d843131c5feb28a1c1e94c1484c4306b7e18d8420bc0051b24b4becc7c4bf629c8f8afa4e1657785ff128dfd6ac3c0cc180492d73ff8dcaf5d53525de5a4070f294ef9b27651d28c58018a30a94946d0e8d59599474666c7752130a699b9096e7ae8634dcd46479c79013a62856ad86a8f0eaccea3c20ebf0098ced12762e28657b34620c18f49f6d8ededf98914c7302e0dddb6a80f6d4182654abd58b56e8a98debc5549f386c53552336aea2d166f5ea1156cf7605bde250f1d4fe74075b68a8de5a6927f701fa1ff22bac009884ebc13c980672b06251e60c44013144160d0a7a9f2b7aadc01f2a5eb79fd31fba642bc95376f2e04d024b5b3094b57146abb8a7f404647746eb9c92bda0e0129f65bb443c9d30244a6914b98ceaa764e64cee9c475c4b3937501b15115a351c96f7d2f8f28d982871646a4e6e3e35ae6461baeea623e81ee2f5750957f7929255c355c2758074bc341aa33f2af092d805230692d5dc367b0b3b8646bc57729719a7e94c1848f777331a67b2f96fa69f96d1b1af85ffaf75326e7de7986b126b924ede269a7c4db9466a138bf47a1cce4b8699fe70791f8626fd51d51ff031dce9c9d558f797c04404c50a447e8304000efd9a38fd281520563c174d1f9660c64c3ffa7bedde1f535a71b94abfe3233a3b698d156763b71a41f5879a61e519325445dde67341b790043aa7b8e150811598a933dfa156e7ed1d8b99649369043228a485bbc8722506a3ec2c378d1a75efc36ce6e8da6ade23a4958ae05ddeafa72b66b479f2c8789e5d40e1af632e8b6526fd4d0b60230000000000000001138d";
    exp_tx += "00b4d9e6e6da9688de75c96932605b49300e794fa4f082cd79b82f26558d9fc0cac35341729519c76d0c9cf80c6c0b0739150ce4f27d72030e0dc06806abd61ae84735fa45f3d54ba6f40f9d9c7c6d486f081baf10e121971344a6dc2779d99702ad5e7ff11983b6d0906f28ab50454d0b1a6e7b71365d362683169cbd4f8e24842b33c01bb06b3edb6583be8718bd13b2297837770624e1ff84baedc98b883adf25acb57f43b8820c4a4712356205d343d3456f8bcd421414ccaef6d631f3975c0ceddc84cafc98e682496b8bac4f213dc09312d0a72f92d662c3c30fc98a01f197f9a72d2ba4af085a710da8591dc8dd72618a8aa7e17034b266581c91b1797bc9ce2bca5fcfe1e5f24242cc1345bec8bc6e7ab7190ace1d78e38ff9be226192bd328d7be71baadc644ab61c83484fd7a9d6f8baf6a96a90d0b0f00d19ec6408dfde4b64bbae56ce1b2fc4ee48dd9d8ab422926d9d947ed10c5d195933b144c1e1304277f52889f905642e0e7dd31672acf0771dd18483bfdfeab21d0329732aa4e3f98dc09dbe36294147ffdadae58e266b0b0ebc76f6c0cb28fb7aeb03a558d339535df7bdfea70a6d61265cfdd314e30bd8e7ee5afb7563394cc0db3c0f5f507065a4e9198ad3676876204cec16eae53aadc5d7cc345069d981b5f31182bf7b531c0ef474713816980fefc7291f1d5eae79793e1ce6bec7fb3860f936cc60ddb69913dddd73c335ac77b546468eeafe4daf7ca7ffc89bbf974194f0272d6417c793f4da72208a4283811a0f3a41bda7968ec7725fa24a158a9a736c3ecaa91c01362befabfb0c789f1b56e947d4ca84939288f3e5414ad9f282b7b22723f0dced7b9467e375467fc284e5141219b1be84f2e03f39943a8ea478f607fea34f671f7cfc686824c7c9f05e52b8561f78aea39a7daa5f74d08b1bf17fa55de7d98c281025487c31fc0cc37f3fe99d774ff0a72e726dbc18cfd1a9ec5e6debfed54db129df13c84219938ea72d16ca2a9d81be6af98aa10501ddd745889bb9326e74567c4905e6d64c676329983f65ff240c9985909794d7702d047772e60d13f2d422b25f2fdbb3c2f6e86bcdf5aa03c1450a5140b6da24a71ac0a8176c40a55250afe03c25b76fb25c9d8a63379b2a28e41d380068cf39a57cfd7fc31df62c71764349704330f1960eaa2eef6dd1d2eb26ff132afe2c7dd1bff21b800994a24d967e74490c96ebc8930495e71c1b61ae8be0ce7d6f34d2d8486c492392693882f463461ffa7f739a5dfe9f79b7aaa16d7099be0c759c98cf717e9ed87737edebc90e15d94f28f1765c89c240e08e98fc3f361a6a8a9e22ab0cba50cc489a7dd0feafcde380514cc84f2f8dc904506c845259fd19f7ac89da0f0bb61a8044a90c0192fae79466e217fcb340b5e5e13e50e059ffffdf1672162d732f2eed96a367dc7df564e449ccbede065d7c16ecb4d05df00b4b92afc60ae722eec4a5511f2f4660ab97dd3ffc55dedb67945e9d08b490fd2df771aa8b4272cc148eff17ae157cdd023c2430677982c17e7d0c0abc1cebc8d4288472c4e81eb898575f221e1990aa318e704ab4a235ede2654b1e5a3aa0a7ca291020f51803305aca40661e33b0b68cea41de969ccb1954a2f89fa6b8328d0414297ab48dce663a3f28c00434292e7bf482d96da60bead6fa2b494304aa7718c554b5c5b6c26441c846f2804c9e70b49a3d812e757135c687c183ed4a5bd8c738a229396cdef6dbf6303705c9fbc7482a6bcc9a26fd04ec6b83d3c21e41ccaf68bcb9dbcecc9b950cde842e5ef0cf506b6144cd4558c1b1c3153b2f3fc1eb4bcc95e0ac0b9f570dd1b43a7e805f84594018c9b79b314b652d72ce702d7b8a0e1f3f5778659c1aae869bdf21847dc2219628e5546b28dc7daa7fb66da81eb6be8c3d582404f69d693d2db0a83b7cdaf8a449e656464445637d3f33c737714c4e763870c2bd8c202fd2f8b08a3af7414f4994f52678721544abddc63d2b07ca2000b1c7b805cc65db0aa31ae95b3824e063990c3732c954c16149835e3f40f87926881928095d69310ee374ba73aad85dee76027a109db15b749faa1a6c0a3ef4205a6b5f44bea1183b4ac24b841cff4ac5946afc654e34904fd432e9ded453a55b2455a7b6be8dcf0ba6d06f6088e714bc6d1dcdaa0c058ae064982c35ccbd10d75b280d92b6f66172ef585765325d7a91d5a0b9c582560d623d7104b623872b9310e6f4bd9cf55f2582495d7b5b8c0c7628441cb2dd86e9bcceeb15d927ae37423ccb761b3201e910d63b37cb9e4efe89f0cbc3aa1f1714df13e21a512a1ba39556fae615ce5e6ffa52da72cdd349f19e6c5278febdc3763b5b530f1c059fdc06ad28c2963bf786f16bafb5dd9e36dedf1b21385443afa8fb1c9003034b2a20a54bcbb9b1fb519f68b7b50d6a71eb04319e34a8feecf4501b50a792657096e257b3b403b2300534b130f5a423a38d7bc5f181f49e66081e16c49f7588686f3155bc3f37d9d074aa1fac57e57e1734ac00af4f31124213c5cb89d2cc8e273bc3f6c56d35f1a3c3f9701ae0d35b8c2554fc338618d6a6c478a2cffae7b6d737dfd13b9d5a3f612e498529f4d8e1acf2b49765caea9eacd33cb3678442fa02653f62cdecce96212040dab1a322c4b13f7bd731a69e9f1e5a23a0948daee405f15d0961fb14c57d154c5118a3691e9c42c233a38fe1662bdb788ed1298b02f24dcafdc73ab3fba67dafe259e8651b4fac6a1fed0c3fb4c914a2b72f02499737d37be1c0da2da96d4e165fd4f7098e9e7d30045933005d13674192673b479e3dd4fdebf44a73327d4e416e5f7fc76487a685e9706ab08c3f4e5096bcf12c73e57de2bfcc217343b650002076631d1487af0147f9b13b6386bd1b2525433f8dd7b6aa4bff765b9701311c3419a2a76a0718a12e5333ce4a139fed6e97edbfa3b913ecad02b597c42a971f38f699f2fb63fb6eef10b19b773cd0c6673f8b7973cdc8d54e17f752871b28c317c0a6166d88b14f054c631ca588d2f3945322878b564c15d5bc8c9cc75fe32647547df1ad2b20f4a1ddffe78e62227242d861249f4a02715a6c5b005c3f9457c0eb28cad0252935896c701c5f6f47e75a8fe0a60d81b6b61053e779116903dd3573d04e95f1c9d4ba9033cabe74b8e8dccc5c8a5b87a9d07747a69e9c28fc92591120a477eaca4ae111372092a1d7e986c68a647b5d52df34fbdd7f4fa31bc744de889f82514f46af7b4426e22cfd96753cd55ec53a24661af259801783b4fa055f8ee4777e92c74c939a4a234b7c10ba9b2fcbac505997868aab4074c0055038ea0d47a3f12340bde41085f12ff25dd2e56931412af70bcb1d88e382bf046adb3348a20831a0d938f7a98c5d4c2dc1ac7137a7ba00c4745d361bd5aeeadd47af05cea3599075a214dc7974094a3e6a16f11a7566e19e553324f077b05c6833d74da7c3fd9b14f255f812a48f8c6e4e149ae2b1dfad224357496b4dce4c1a626d068a2fbb56f979eec8d784a696a3fa97667f2cf640dd9c3d7a17fb0072a70721c2ff3eb6224eee2b133b3625eb1aece5316c99b982a7291c62e63c9128c11e9186eef89a5bb6410c6b9f6b04bd274e8b9d4f4bcbf7a94fa37efcdd3c43c784a0365960cdf3b7b506cc9b24778110260fb3503c0fdd4be45fde0815e10b0fbc621c97dd3769e456b17d526a67ea5a3e7a3fc89e61854c9d3970e1e5648878c70ed52fe41c579e8e10d8146def6940bb0dc4673b43a650d7458934bb1c8a37bfe3fdb924a91a292b077d0ce9164ce64d03ac159afcbcb26aa87ff45aa4a2a61950bebaa50a552a875593f5523669ec1365c166e2a1a9629124f04af04526290d2410c5e840d9a0fff54e8551678288acf444ced24688e7990b77d8bd42c4d55f7e102d020c811bdbf1311b78c157622a531ac4701d5fc5d5f4b7732676ab898dbb7aa139d5a538e04dfff7a9c191dd4b359e5ff91c82b416b15a38bbf85919b8c3a71c45a521ec7b4d45048c112ce4a67f2673b8193b2fba1ec67615027f7c201253bd49150000";
    ConfidentialTransaction expect_tx(exp_tx);
    UnblindParameter expect_unblind_param1 = { ConfidentialAssetId(
        "509852f71d6c1c6b28cb06549e65ffcbd3c82bff90d3e23d2f69e0120d4871ef"),
        BlindFactor(
            "0000000000000000000000000000000000000000000000000000000000000000"),
        BlindFactor(
            "bc4d94fb6dc9af3c8069d775dcbbdb22bb39d2813fa54bc76ef565344305b49b"),
        ConfidentialValue(Amount::CreateByCoinAmount(10.00000000)) };
    UnblindParameter expect_unblind_param2 = { ConfidentialAssetId(
        "1250362306c95044c539144285aea3f38e804bb1adcfcdadb3cea77cea287165"),
        BlindFactor(
            "0000000000000000000000000000000000000000000000000000000000000000"),
        BlindFactor(
            "3ac3f6b344ab5bfab0c2ddaf9cc1150660badb82dce37aeece50cdec50d1495f"),
        ConfidentialValue(Amount::CreateByCoinAmount(1.00000000)) };

    /** Execute Test **/
    // store before unblind txouts
    std::vector<ConfidentialTxInReference> befere_unblind_tx_ins = ctx
        .GetTxInList();

    std::vector<UnblindParameter> actual_unblind_params;
    // unblind transaction
    try {
      actual_unblind_params = ctx.UnblindTxIn(target_idx, blinding_key, blinding_key);
    } catch (const CfdException& except) {
      EXPECT_STREQ("", except.what());
    }
    //EXPECT_NO_THROW(
    //    actual_unblind_params = ctx.UnblindTxIn(target_idx, blinding_key));
    // check hex data
    EXPECT_STREQ(ctx.GetHex().c_str(), expect_tx.GetHex().c_str());
    // check return value
    CheckUnblindParams(actual_unblind_params[0], expect_unblind_param1);
    CheckUnblindParams(actual_unblind_params[1], expect_unblind_param2);
    // check txin data
    std::vector<ConfidentialTxInReference> actual_tx_ins = ctx.GetTxInList();
    CheckTxIns(actual_tx_ins[target_idx], actual_unblind_params[0],
                actual_unblind_params[1], befere_unblind_tx_ins[target_idx]);
  }
}

TEST(ConfidentialTransaction, GetIssuanceBlindingKeyTest) {
  Privkey masterkey(
      "a0cd219833629db30c5210716c7b2e22fb8dd10aa231692f1f53acd8e662de01");
  Txid txid(
      "21fe3fc8e38256ec747fa8d8ea96319fd00cbcf318c2586b9b8e9e27a5afe9aa");
  uint32_t vout = 0;
  Privkey key;
  EXPECT_NO_THROW(
    (key = ConfidentialTransaction::GetIssuanceBlindingKey(
        masterkey, txid, vout)));

  EXPECT_STREQ(
      key.GetHex().c_str(),
      "24c10c3b128f220e3b4253cec39ea3b75d2f6000033508c8deeadc1b6eefc4a1");
}

struct GetPegoutPubkeyDataTestVector {
  std::string btc_pubkey_bytes;
  std::string whitelist_proof;
  std::string address;
};

// bip32_counter: 0 - 5
static const std::vector<GetPegoutPubkeyDataTestVector> kGetPegoutPubkeyDataTestVector = {
  {
    "031edbc17e3c1e67bb7d4aaceede0b78e5b4bd69d1b38b1a7048f605d96f572ef1",
    "01cac9aebddceb0cc8e869f43d080ab00895ce89c3127c85ffd221152c52d912134d7d3da862e36b66c63f39bb4e1920bcd74013ec9a97e3374678113251f6a12d",
    "2MtzmJDwuaD7RTnf6qQtpcTcjnHpS2h2P4i"
  },
  {
    "03b7b84f99dd7cb06da46f6153e1941f833e21ca8996e6b60b617d5b64f49f4fda",
    "018c9474fce171fa9da1f850d45885a5693a29714dde563bb59324c34309f1d662bb2afcb05d6cc6e2f757c4992c254e4e7af6150fd09b2683cf002658edb5e9dc",
    "2MspyB1f1DTTFE26aFAz1eAdbRsgk8H3vNr"
  },
  {
    "02e291a761061b948de9c28025ad26bf2dc308a34230a3bd32fae2abc0afac2a64",
    "01d508e9231475f40b5d48c8c26f7ee29d67cfc796ca9add9d28af572638e70dd158ed852a227c088683a28c9157964864895fc1dc7889758f4868f92d09ed6a05",
    "2MsNAQ9UZjtrfJqcKn6fiKyidZsdx5zCsih"
  },
  {
    "0257fbcaa2078b6e99d4c66643224fd7418b148e17b64d6063353bc0b1201e7c0c",
    "0168dbb3902e6a43bf740d9ae92396e8975e5958b3c42b7d38960741388bf5bad2a3995df93712c488682253b44b39935758d800b5e2e1e4256540b3d457d14adb",
    "2MyMsCP6wcPYsnWwg4EJSSDPje3GyG9ZLgL"
  },
  {
    "03205749a6df5ef4ea4566fe1ebb001c3c59c69ba6f05f02e7dc985b7cc19d6c15",
    "01aa16442b00148e25bfe7dd4c84273be1879a23a5607f5b7f26e0fbc3374aaf464e1341935df03bc13a9485b709d3b6b8e1cc9f5fdfd3f7a2f8eb69eec6b5cab9",
    "2NB7GRdYwyQ5r15uC2Jh7Xb49CKfGP3mFJJ"
  },
  {
    "03604f35e4918430282431f7b98a564b639ed5ee02f04d1e09052722455b32b0ff",
    "01eedfbefb3f1d71f781cbdebba92ad97faa5b57977ec180771cbce6a3c9358c05f4e880a31fc33f97e72b164c05720de88d6ec9e96409980a11185fc8064e3e42",
    "2NBp8wTHaUZ7ttSdsn1GnphwjFFAtYniwKE"
  }
};

TEST(ConfidentialTransaction, GetPegoutPubkeyDataTest) {
  // liquid_pak
  Pubkey online_pubkey("02a71e193ce21075d0966be16724e41fff666366d7ac13e3616a329005da4024da");
  // liquid_pak_privkey
  Privkey master_online_key = Privkey::FromWif(
      "cPoefvB147bYpWCf9JqRBVMXENt4isSBAn91RYeiBh1jUp3ThhKN", NetType::kTestnet, true);
  std::string bitcoin_descriptor = "sh(wpkh(tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz/0/*))";
  ByteData whitelist("020061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c002a71e193ce21075d0966be16724e41fff666366d7ac13e3616a329005da4024da");
  NetType net_type = NetType::kTestnet;
  ByteData pubkey_prefix = ByteData("043587cf");
  uint32_t bip32_counter = 0;
  PegoutKeyData key_data;

  Address addr;
  for (const auto& testdata : kGetPegoutPubkeyDataTestVector) {
    EXPECT_NO_THROW(
      (key_data = ConfidentialTransaction::GetPegoutPubkeyData(
          online_pubkey, master_online_key, bitcoin_descriptor, bip32_counter,
          whitelist, net_type, pubkey_prefix, NetType::kElementsRegtest, &addr)));
    EXPECT_STREQ(
        key_data.btc_pubkey_bytes.GetHex().c_str(),
        testdata.btc_pubkey_bytes.c_str());
    EXPECT_STREQ(
        key_data.whitelist_proof.GetHex().c_str(),
        testdata.whitelist_proof.c_str());
    EXPECT_STREQ(
        addr.GetAddress().c_str(),
        testdata.address.c_str());
    ++bip32_counter;
  }
}

TEST(ConfidentialTransaction, GetPegoutPubkeyDataPkhNoCounterTest) {
  // liquid_pak
  Pubkey online_pubkey("02a71e193ce21075d0966be16724e41fff666366d7ac13e3616a329005da4024da");
  // liquid_pak_privkey
  Privkey master_online_key = Privkey::FromWif(
      "cPoefvB147bYpWCf9JqRBVMXENt4isSBAn91RYeiBh1jUp3ThhKN", NetType::kTestnet, true);
  std::string bitcoin_descriptor = "tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz";
  ByteData whitelist("020061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c002a71e193ce21075d0966be16724e41fff666366d7ac13e3616a329005da4024da");
  NetType net_type = NetType::kTestnet;
  ByteData pubkey_prefix = ByteData("043587cf");
  uint32_t bip32_counter = 0;
  PegoutKeyData key_data;

  Address addr;
  GetPegoutPubkeyDataTestVector testdata = {
    "02b5e6f1c3b0d16cf15e9496dc2de977207947339bf50bded0f52af2e62f8dc648",
    "013fea92fc45099da667c69b60a5a3bca592ce5d61e84ab452d0984336091ee55f361475055d2bde0fa0eb339996c107b552ea5877d6508abeb3883642bc738704",
    "mx7egZtzUWR8aVviQnpKJCoaT4ytSiQjxL"
  };
  EXPECT_NO_THROW(
    (key_data = ConfidentialTransaction::GetPegoutPubkeyData(
        online_pubkey, master_online_key, bitcoin_descriptor, bip32_counter,
        whitelist, net_type, pubkey_prefix, NetType::kElementsRegtest, &addr)));
  EXPECT_STREQ(
      key_data.btc_pubkey_bytes.GetHex().c_str(),
      testdata.btc_pubkey_bytes.c_str());
  EXPECT_STREQ(
      key_data.whitelist_proof.GetHex().c_str(),
      testdata.whitelist_proof.c_str());
  EXPECT_STREQ(
      addr.GetAddress().c_str(),
      testdata.address.c_str());
}

#endif  // CFD_DISABLE_ELEMENTS
