#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_util.h"

using cfd::core::Amount;
using cfd::core::BlindFactor;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::ElementsConfidentialAddress;
using cfd::core::ConfidentialAssetId;
using cfd::core::ConfidentialNonce;
using cfd::core::ConfidentialTxOut;
using cfd::core::ConfidentialTxOutReference;
using cfd::core::ConfidentialValue;
using cfd::core::RangeProofInfo;
using cfd::core::Script;
using cfd::core::ScriptWitness;
using cfd::core::Txid;

static const Script exp_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");
static const ConfidentialAssetId exp_asset(
    "0a7f0c8d0a4e6fb92c63893345facbd99dc603dc1cd18c73e5700bd9a0babb1f0b");
static const ConfidentialValue exp_value(
    "09b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226");
static const ConfidentialNonce exp_nonce(
    "02c384a78ae89b9600a8d2b4ddb3090ba5dad224ff4b85e6868f2916ca64314ad9");
static const ByteData exp_surjection_proof(
    "0100017bb5ec655fa87e4cca4ed7bf37ae35d4e80d741cf1f86f8d0694f2b4e3ec9e2e72bea4cab89abddd262d016105b25b2b57ea3f304967a7b8093fc3da2f633708");
static const ByteData exp_range_proof(
    "602300000000000000018b000057b997ddb73af528b42ae583656ddeeb1bfa72ffee8eb0aec74ddf54d70c7bf6f7d2d8916a986b4c2fced512897d07a9ac79a7f17847adcb2153898b1199415117d2c7286413c97e6774fc4cd4c8ab56da30bb728670768d71242c763b00436e6b004ff98b79de797922c35a250fe471940eac9f1b63b316b34eac7c960d089551d8ef6d393d16f4eb325d7c6d4904a8f09a1ed78dbadfb2af4e9cf71c3c89ca42d45d50f2baa86c8921d91ab8f051c6844b8303f94aa6f1918181d0e072db0126fac6993ac0512f29b2ff2757a9819fb44a4978f21eeb6d1b55c8e57bbdc3290b7eca9f0f3653e3b2edcb76c08557ca48d418c92c716772c7723263532feddb16e1855b4c487f5ae546f1c5e375c3aed47a9104b9588e0880f91ecf51c0ce37e32367f265b904d195edf8d42f87a44f5cfa50f4c03df9621edbfc0e7d7ce06644d6eaac70f83904d65f60e8ff50536036b3063e4a65356acfd3e78e76755532c3e32d5c515ba1f3c7f504c1669b32479b1023730e1d4eefda59a1793eb7970d91ee98e7902caaa77fd50c56a10d5718588b1e434ecdc2334c0fecf4f53d55829c3058f17c209c3fb554e3dcc646b76b9ee4416168b240fd3ac15da6f49fca2a35c317489ab555f2868b07de03c873c0dc3525da0552e10afc11bc68b357f059017fea4c84fd83c7a07ab333ae0e262f479f5f48d53c4e84b961da7aeb5add83149cfca6914a4f755046c94836b23dbb0678d00cb2c48d15e424c275efb53845b1ad7968e569440773758e7f981a5c9f6831d6a52c115553db12df754c02e34b4f16db5ef362b1be0b94905442179677848d3ae0eb7ad5de47c28c48870dc08e1a3e4221977f3599319d1207de033025b571176eabaa20eea38db4070c3f09715afa2079765e35d079953b1228f6b781a18a92568c1ff608d135170b6ade9dd5282f0c21c40bb8240841ef1e6c54c920d9a50746c8bc161ee2a1693e2733966ba0bad17b34b10494683636fddeda80d984ce860af49ce96c49fdb69c779938115531abf4d361732787ac61e026f18c060fcb819adb62f16d1567e06a41662d633d2cdbfe211d68c70b1e51e27376b6472fbc67969ece59c0a2f7c39224f954730a384cf8fc6f2749a9c326978d881e955d6e0ab56e560a55b1702f765dbec1c6856c26d3c3c08c022f38cf2d3d92f9020dbb37966ce86d27d41c8f156600e928b6edf9450d4cbaa5f9b3a3fa8f8f492c8a4d0660e37b80a2ae7d4ecca955a1bc217f74b2776a18007c6d88630d8cb0f7f3c111663617f6b92ca272fdccbc4d90fa6f9b02b238db93b76ad1ffcf2920863c79de762a06e6ab538d491f2cca8fb4556b533b0584dbee0490c4adad9c00e0c8eb58874c8049db4b93404e47e8eed9719a8e4ecd5bffe16e853fe0d1e6c35ae99a91fd9febb4a3ca5b55206aa4e9f62fed1de1c550ccc871ddbb43e5aa60bb43487081b4e4be62cad18943deebef9370a6fdb98c3963688c6a887d6ebfed2ed774575e794526a4c5cec42ff98fc8abfa27775253662613f0389c70900e31bfb812dd458a71b53dfffcef0efba36627003cf6722362e717113c620764a1a361a9421e5ded53a9c6873319cca3763723aef0b7322eddba25673b48b8c3c25223ef8c11b408c2c9614082c85b68f987af065eb8a5fab99897c1c3a303c3d6aae5dd37cd6777f44e760e978632f0784e0b8bf5401c787ce66499888db906aef9cde617214f780d2a2ce193583aec36941b05dea17702c3562c027a99ee3b29cf0f5c74981fcf370c0c56548f626a08712e999a77dcbbf4bc06fdc390172e36f58867ec614815fac2d70b8bf4c3b1f29d100525381564b953b671f7084679f9a1196b8413f75c00b9f71a58c1d7541c3e08a215d61637d69063316e67df1c7fb263828635d1fbdee2d2a223950ad955f6ae6c690362f444e0c44f21627b15244fc3630313abb0d275f0f0014a86d16160345cfbbd430956adbc65dcb25c597d0ed33e30c749c78e630edfb72008729ac1ab8e6f09bc65dd8134d4f7762548b78255b3c64801fe49a392661a7a44c2cd507e243ba21b50ae9c5047789fd77df801c3def4ba8539d7daff99063e599920afc99b686848e35fb2092c8e502b3fd0c97a5d8e6aa3ebb49b20b64084a9c2b2b87c51fc75fa374530347b8aa856d93e9db98917f78c7b44718b64a0d6c5ad2615ab852912a691289d102285b3ea360d66d9e381c279a785a722895c24a2efb456724e2ba39cecdee11f79dac20917b9ebcd5284445ecc9c6ca288f7cef117f83a55541a520fa6468dcd1c48d2b84d1de60e25b292985635509fbb99296eae6655e47392b304d68f0a949e216601f04f12d61e89e8026f2bf03dfef1b47dad6471d106aa114938e6bc82318962ff5e8c5ed8e510ac313135fac1ad948b3c1ed1b898ff666f9c9840a8d39a11725dbfdde99c953c6a1cc9d60273fceeb93a538a0cb70456852d79d768507889c7431691e50fe3deb78697024561e873041bdfeacf527573a3486af3811140ba4ade4278d388f1b9498214cc10f8861cabd4ad24c74f6a469c552b297a126b7429e18982619a3a226bb530d58c6ed97a06aa0574594021f87cea4bfcad2577bb0f206a9871a408717d8ba3edaa7c93b2c609d771c8d9fab8ad637b1779d8742b127d7acd1dcb8610b3f4aa834882213e92b02cf8259653e46824c637c0963c4a6bc0a258b96c16004336ac11c5086e9f68995d81cf53b718824936f43aa179d47815afa73f875e545e6affd2b06d93b9b2be2a1a90adc51c4eba4faaa1c1682e435009d58d6565a18df92ad45178b71a53a7af0cc872cf6fc923bf63ca4360f1dd7dd1c9e28bebc4d412eea924945449210489798907e48222a079607b1fcdf0be09bf25d9dbba09e4b677f2b67afe18fc38b125dee82d0c3e7289f5e3c437fa5ffe5f5edfddab956be976c3493442961da351145ed70f0e96bb4efff14e4fee83aefd2bc9aee4b592f29be12dcdfd127b5522465686f5c667982410216b89404429fd57e2f04419110efb30e67a6bfb19ecf2e58a0024a717d22baf360c9a64e0689c245a2c0309d5aac3f88c7aa38e0eb77c23854b29c53aec38b004fd20c50c91becb9e094a1b5ccb5bf678304d326b4a14e3f0ba7165e2ce3773c7feb0a0e6c06ef5d4e21b57cdde81ff77afb50125cf4e29c8b18783790a4695d23b439a8591b2eaaa0a664f11c1f2d3231e6fd0da8292f3d77888717c91c298b5f7219c1380148a6390003423554c2a23e17275b2ec254a4dd4f08ffbf6488839be5d76e30545280f520f1a56a464ffb3eed9e5f949a0356dc2983d591e6027945c234ceed8ac40f0e7ab2757e9bf5b46fdae07e9fcc34bc57ce60d1afc3bfbd6aa75cef3fe3f9f55940ffaac02fb4e7daaf4bae694aaecbff2f3944c5117d08948e8cdc130215cc43ad99b244b7e335feecfa6f5ad8cfcfa3a1fae008fbf66d1304c2c962418306b5fb63fb41bd6543cbde9831b07deae90ec7aac53b79e21289382b338def494e949cbb8522f35d577ebafd5585d046584a8f200680be6a8410bb92630b1ff9d6e770a6e09dec6ba59a1a7ed21ed0520b8a99c65a45391b44bac1efac2f004ad5c395e64ca0f2fc808fe6441d5bef2e583600aa15b4e802b3fb2e548ea3b7bb8cb3980739905b04ed25cc01999504b1291c9aff12987ab00b8636ae13a69fb47abfdecf18b6cc881caf74dad934397c2715d49fd11ac451385c14f348fa7430fa13e2f7c5e0af9cb4883bf2c653811b28906ae33fbb21b721d3ba0d22f69aa2c209c8b0b2d19bd61dbf7ebfcc6ca9bdac1bdb6c17d16b05f59f4c5112ce7f2631b12c6945d541d1979de328ee5576e770a0f24ef5a95c62f650ca84d8e0ce33e6b15aca29ef6c407000beb846ff033dca353c2cce3832cca61196856effc5f939b034ae6e7c9e099f84b67ca904f018b4c8bc685098cfc9cb4630ceea66b42d21a4e9770f532a015876c810fddfe58dfc7515e494d5e7e772937d18992ae9aea3670dacba342aae96b08a7693c5da1645023");

TEST(ConfidentialTxOut, DefaultConstractor) {
  // default constructor
  ConfidentialTxOut txout;
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor1) {
  // Script, ConfidentialAssetId, ConfidentialValue
  ConfidentialTxOut txout(exp_script, exp_asset, exp_value);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor2) {
  // Script, ConfidentialAssetId, ConfidentialValue, ConfidentialNonce, ByteData, ByteData
  ConfidentialTxOut txout(exp_script, exp_asset, exp_value, exp_nonce,
                          exp_surjection_proof, exp_range_proof);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);
  EXPECT_STREQ(txout.GetWitnessHash().GetHex().c_str(),
    "51e1922fa92165e1705155a1973d9c3b78cbc253ec185f58a4d53a59b3eee093");

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(),
               exp_script.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(),
               exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor3) {
  // ConfidentialAssetId, ConfidentialValue
  ConfidentialTxOut txout(exp_asset, exp_value);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);
  EXPECT_STREQ(txout.GetWitnessHash().GetHex().c_str(),
    "7d993a3ac51b76589a07c59078e2e4241f4c13c5190a763f22213e0c9ed8e7d5");

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor4) {
  // ConfidentialAssetId, ConfidentialValue
  Amount amount(Amount::CreateBySatoshiAmount(100000000));
  ConfidentialTxOut txout(exp_asset, amount);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_EQ(txout.GetConfidentialValue().GetAmount().GetSatoshiValue(),
               amount.GetSatoshiValue());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor5) {
  // ConfidentialAssetId, ConfidentialValue
  ElementsConfidentialAddress address("el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz");
  Amount amount(Amount::CreateBySatoshiAmount(100000000));
  ConfidentialTxOut txout(address.GetUnblindedAddress(), exp_asset, amount);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_EQ(txout.GetConfidentialValue().GetAmount().GetSatoshiValue(),
               amount.GetSatoshiValue());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(),
      "0020332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Constractor6) {
  // ConfidentialAssetId, ConfidentialValue
  ElementsConfidentialAddress address("el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqve2xzutyaf7vjcap67f28q90uxec2ve95g3rpu5crapcmfr2l9xl5jzazvcpysz");
  Amount amount(Amount::CreateBySatoshiAmount(100000000));
  ConfidentialTxOut txout(address, exp_asset, amount);
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_EQ(txout.GetConfidentialValue().GetAmount().GetSatoshiValue(),
               amount.GetSatoshiValue());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(),
      "0020332a30b8b2753e64b1d0ebc951c057f0d9c29992d11118794c0fa1c6d2357ca6");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(),
      "03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);
}

TEST(ConfidentialTxOut, Setter) {
  ConfidentialTxOut txout;

  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 0);
  EXPECT_STREQ(txout.GetWitnessHash().GetHex().c_str(),
    "7d993a3ac51b76589a07c59078e2e4241f4c13c5190a763f22213e0c9ed8e7d5");

  txout.SetValue(Amount::CreateBySatoshiAmount(100000000));

  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
      "010000000005f5e100");
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(), "");
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 100000000);

  txout.SetCommitment(exp_asset, exp_value, exp_nonce, exp_surjection_proof,
                      exp_range_proof);
  EXPECT_STREQ(txout.GetWitnessHash().GetHex().c_str(),
    "51e1922fa92165e1705155a1973d9c3b78cbc253ec185f58a4d53a59b3eee093");

  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout.GetNonce().GetHex().c_str(), exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout.GetValue().GetSatoshiValue(), 100000000);

  ConfidentialTxOutReference txout_ref(txout);
  EXPECT_STREQ(txout_ref.GetAsset().GetHex().c_str(),
               exp_asset.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetConfidentialValue().GetHex().c_str(),
               exp_value.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetLockingScript().GetHex().c_str(), "");
  EXPECT_STREQ(txout_ref.GetNonce().GetHex().c_str(),
               exp_nonce.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetRangeProof().GetHex().c_str(),
               exp_range_proof.GetHex().c_str());
  EXPECT_STREQ(txout_ref.GetSurjectionProof().GetHex().c_str(),
               exp_surjection_proof.GetHex().c_str());
  EXPECT_EQ(txout_ref.GetValue().GetSatoshiValue(), 100000000);
}

TEST(ConfidentialTxOut, DecodeRangeProofInfoTest) {
    ByteData range_proof("602300000000000000013883013a31aceb91aa584fa6c14c012797397725bf53c0d938457d41e31318fb844ea088615d1cfb76a86396a2ea0b2a1e356315876651e47c0e8911918f1d7e75eda6dfe4444208c9c3c24a98a8f8616283a4459f1e928d38ff8c5cce40aa50b58deae228af10a00e4c5f07998095bc2e61880d8b0b0ae3ebf63c51a5f0b9f885c88f8332a8f83c457872517c3581f3d8a0f0f3e2eee3e6909a9cda1903bf4bb4bd801e6077761f19fe115496c3e6661b68ae2b2a81b55145cb127b3c71fc715d28ceb35cea14fe7561878bee42c71dd0ba00d5553f59e1665e55a953c1a01025ed0edf01147dbd035e2b2e32c36c9400c2ab04942db231d5b9545f406b9fc290d389483bfcd519a9697a6498e816d8914d7df8123b20ed6641ae75cca7510015425c999d491f6ad899fe4890e5ff653aaeb55e37ec5d641ab12f68d129c5ae2c57c1addb984fdf53c42967eb1dcfac30757a2c110f2b39c5f160ff870724e25b0d9f73127e515398b3a5bb9797aad60d6017c4df6bf2f42633fadfc38021bdc801cbd2a2fe7647bf7874d18c6fc78fc616e6e031748106fff811fc431daeb99dd35a26367e7dff965493af24fb0fc0efa14cff00b776650ebba8d0fced41d559a9bedc8b356dc754866ea1b0cbbf551cf58f54d3a0053f4a7f720fa04a50c4d56f3e9f8cc253fe4cf30e3190530da38d1df259fc9dd5f54756eb766085f75ee885cc477e823180b6a9e9188f1d3f22d1328afafe4de03a5a7d10b293e0de7e001ccd1b61f1b8e15c7a9a35d1e8d9bd8fcdda402c96f7e3e7eb48488b010932d8d95168d81082757117ebf2af899d154ae6870cc4f7f00db4f96292b4fc1b384b8c91fb422adcdcc570d2ddf99e2645104ca216440cdcb94e33bfca56eb2c4a42c89efc1e1c0a16bbd63eb476afdd5fdc0461d1c95d619cfb557b1049e0a6a7afcb58ace021f54fcc4f51ea25d00f58b16d3d0ecd7a52261407ebc45017b5d70a2e986eeede4db51e988f44a95ae1b482d2ee6ed097e37c5742bc496af5ecc526d14493537a0ed94a6e1d100a5a9f8be484bb0da9de7344ea487428e84f5ea5589553701a9dafb3636b94d2aaae49ff8abbf1576725b9e8143ef77358fa1341294705f19d1e90492273aa4c9e19a006a0444b533b38716844a1f4199da5f99ac5188926a42f92c75e75ed87b466ef89dd42f449c9769e14559f92b2620ea7ae1bc425fc0be66d98321c998c2dea5a405c06f86b127538642e87c9f127bd7ed9abf86d650b7c9c548af030f5fd1a79bc3189af7a9676181e0a15175438c4bc03782719624a831413b24b93e0d852906f3b47bcf7e181b0feed31145068e5945abe8de69d6e10f1ffbef18432269b5fa5c1ac3b023c466b071b278eca87c1f4eb174be7de34c194504bac074278fd0a38509ea1ab8048ff17554a4a2bc5eb792a3a2b96cdd3fb3a346ed7d5113dd6d9c62778ac0e3288714352ba0d39c2041cf00e4dbb2d4504f37af0a379d7b5271778f9b54a942e1f3352bffd6bd1ca46b87eedda712d93375bf5d5fc68b2f5694b846f596d767890615f3a8c2f0bbbc2dbc8624370aa650f4a4c58650e7161df308e58ca014c4666bf25700d8914999d681f503d37c1a14206319f911a2db2a28c41b1c2e526de61b473696d2a9766df40d4268cef0b4733f0ddeb1b652d831e806885650ab60196e28c2c7193c56b88435d98e6dc9498bcc6c5c30927a554f28f0f7ce57ac61a3dfbe67c6144693f4b8d272808f59c41c6466d81b6f16f9444ffadc13f5cbee235a61d895d80cb0fd12141b5cf8ea7784dbbad306a7580084d719407c3bd5fafd2afddeea08a11212a0efc643132465efb4e3383ff263f1408b2f891ff2af8efb8416e87069e0673a831837a24e3f876a3208146ac73ebc23b80b677f819023384a058e1076f94266cf9395b2af044d04276d7c9bb245b0c901d6770b59fe9590ff923d5cac95d83228c6cb9c47a3fadcbca7bc3326c5e97db84a7c3002875fd8c2f4ea2c56bb867ad5e005727444b6d826f6e22aadb658ebd1fa0eee5eaad0e15e42c268aabcd82ea6a81dfbc5d2c4b54ffd0e18b8de750fda77f6ac733a5a2d975304b24bd3b4d39515103c488d44f4ac71d9e5ae9a1c593a633203e20b0ab20e5179b8ef2e78ac66ea2353be0cbc6ac921cc9a2bcf50565a9d7eedfcfebbbb085e449994a0cfdc8184d15bfee1c80347c1ae6915b7d4844882c182f95808c1109cf1b48809aa2d9501acae828f57b155270eda04e9178c075386b569135752e7b01fa80b7167d91b7ab67ad1af6dc8113cc9753f91ec1a180bf11d8057461d23c85b4eaf675a6a14b5ffae03dd0c752474f007548f68530739cdae8e5b924572a976214ed2b6b131fcffe579c426fa28abc586fb176bd9bdcf907c7afb6a9cef3b27453e852f50a150e4faca9cc5dad0ec0531492ba658ca0f10e4d958d31aae1c9ed22d22889d23a944297e4005caf1e3d341628d5dce35a502340a0f1f47616db15027dc0c452830c691cc1ceea8f4c84604283a4dd968f37e7629fb06f28d834e3523d4e0d3e3d5ce1456bf9bf4147225cf04d92d053e1ee6578a0a614017ef3ca5f54636550a6d461ffbc4d99bde6721febed92e23853276f8f5ae1e0c8358a79164ed5642c05eb184101ffeaef10e744f72210532411f83e765fbb743611a01ca17dbd19c20983fd840111266e2600df563b4149989948f5c255a692b9c9d694ff89bb12171d6579823268335b6eba7ccc5f6b2bb7d74f5b55a44ad6709f32f72a4c85bdd4aff9db98a5572026db7bdcfe4d3e1afb8c319e496844870e67054eacd251dca3debe06e980665795d2d6dc1575b9fdf67bce7d98f2d6198a2c7896905f3db07c4a6213f29486d09b75c19b3eb457e4ff074ff11f4aa5cadf6d064ed5b712e980af23351d057caea494e1d190ab0c0f562282b4f7408f7c6dd8ba973a8c2a3bb8b4637ca6c5c6d31d2832fdf6deb8a64465c00fff79068edffec309a609af77c27ce851784ff6bb0f59c61620bfa6387aec8550d1a0e2304530e5a5dd5b597aeb032fd96a6d602b6e42863517a6e0c47c86a654fedae233ec446344fb4febd13d671463251e1dfdc35042e3ead23ddd8736189f261ac22251e5a7faa24e227f5c3454b4a00b221ff2399b4ce1a93e1d9c95987216a170642d2cec5ab2de802f0e8af3e2bd010abe00ef34ac8acca9608329929b0394f5c84bc025372fbcb4c407d09e25ce1211233472d85fc92adfa3f0fca28aa271515a944a489780d13f5cd70eccf4e2977c603a1f8f06692d62a92aa0bcad5519b5140668ff2575c6c9c777fc00a61adc6204061031dd0b14ec4cd60bacd0cee58be5734354441a9ba0b0fe6eb2f2d5f1f00173b393e2a1f1cc41f8d06707d654ec3add8ec215e73a44544270d06ebdbfef4ad4832a5e16783151a3ae1cf8c1a3da721ada1af7b5b5dc08ebcec069e4dba5656ceda98a099544fa324a0f53094a55db585e793597867e35c88cc2438dd8bc39742abfe9de67fa1d9ab00681a3bc5fa165450d261d54423eca6cbf75e4535ba31d84852e5964deaf97b24220460cd3c8374fa97d537cee75f93ce37cc2918a34a9b94727102efff15e647714d04bdc6bb015dcd4a6e5a9ebcaab36b61b5c973f3f7225b73e2c7481b38779ba8cade1c2e6cec4098ef4c2eaaacb2e1969f610be6c31939528d0a7fce5c0dfcdc72a2cf52286b1e3ac7eb02f172400fd115bc0c1515429c0fefdb476b89daaf7e7ada5710fa7a1b6de0d1fcf9e29e0542ec076290e32315bc2f9af2ae5665fcf005578fad5ac8b9281cd96ad64cb7d07301017cb2824eff3535ca8b51276fc81bd498b5216dd4a5f394f02e115828f77f5617b908d96babbada133770c00cc943a024438a76532f01e146a9ed7c290538aaae2d229c796b2a11d222901cda433132fa89825f74b810008b1aa6732c915451c1224c5eb1d6cdf3ef67143e30622f5330e15baf9148ab5d992b19631043374840173ffe4bf844b5a5365c2beafd25898e89aa6b7dad9fa607ea01043770cdc71");
    RangeProofInfo expected = {0, 36, 1, 68719476736};

    RangeProofInfo actual;
    EXPECT_NO_THROW(actual = ConfidentialTxOut::DecodeRangeProofInfo(range_proof));
    EXPECT_EQ(expected.exponent, actual.exponent);
    EXPECT_EQ(expected.mantissa, actual.mantissa);
    EXPECT_EQ(expected.min_value, actual.min_value);
    EXPECT_EQ(expected.max_value, actual.max_value);
}

TEST(ConfidentialTxOut, DecodeRangeProofInfoErrorTest) {  
  // empty range_proof
  {
    ByteData range_proof("");
    try {
      EXPECT_THROW(ConfidentialTxOut::DecodeRangeProofInfo(range_proof), CfdException);
    } catch (const CfdException &cfd_exception) {
      EXPECT_EQ(cfd_exception.GetErrorCode(), CfdError::kCfdIllegalArgumentError);
      EXPECT_STREQ(cfd_exception.what(), "Secp256k1 empty range proof Error.");
    }
  }
  
  // invalid range_proof
  {
    ByteData range_proof("0000");
    try {
      EXPECT_THROW(ConfidentialTxOut::DecodeRangeProofInfo(range_proof), CfdException);
    } catch (const CfdException &cfd_exception) {
      EXPECT_EQ(cfd_exception.GetErrorCode(), CfdError::kCfdIllegalArgumentError);
      EXPECT_STREQ(cfd_exception.what(), "Secp256k1 empty range proof Error.");
    }
  }
}

TEST(ConfidentialTxOut, CreateDestroyAmountTxOutTest) {  
  ConfidentialTxOut txout;
  ConfidentialAssetId asset("1234567890123456789012345678901234567890123456789012345678901234");
  Amount amount = Amount::CreateBySatoshiAmount(980000000);
  EXPECT_NO_THROW((txout = ConfidentialTxOut::CreateDestroyAmountTxOut(asset, amount)));
  EXPECT_STREQ(txout.GetAsset().GetHex().c_str(), asset.GetHex().c_str());
  EXPECT_EQ(txout.GetConfidentialValue().GetAmount().GetSatoshiValue(),
            amount.GetSatoshiValue());
  EXPECT_STREQ(txout.GetLockingScript().ToString().c_str(), "OP_RETURN");
}

TEST(ConfidentialTxOutReference, GetSerializeSize) {
  {
    int64_t satoshi = 1000000;
    ConfidentialAssetId asset("1234567890123456789012345678901234567890123456789012345678901234");
    ConfidentialTxOut txout(exp_script, asset,
        ConfidentialValue(Amount::CreateBySatoshiAmount(satoshi)));
    ConfidentialTxOutReference txout_ref(txout);

    uint32_t wit_size = 0;
    uint32_t no_wit_size = 0;
    EXPECT_EQ(txout_ref.GetSerializeSize(false, &wit_size, &no_wit_size), 68);
    EXPECT_EQ(wit_size, 2);
    EXPECT_EQ(no_wit_size, 66);

    uint32_t cache_size = 0;
    wit_size = 0;
    no_wit_size = 0;
    int exponent = 0;
    int minimum_bits = 36;
    EXPECT_EQ(3177,
        txout_ref.GetSerializeSize(true, &wit_size, &no_wit_size, exponent, minimum_bits, &cache_size));
    EXPECT_EQ(3055, wit_size);
    EXPECT_EQ(122, no_wit_size);
    EXPECT_EQ(2892, cache_size);

    minimum_bits = 52;
    cache_size = 0;
    EXPECT_EQ(4458,
        txout_ref.GetSerializeSize(true, &wit_size, &no_wit_size, exponent, minimum_bits, &cache_size, 256));
    EXPECT_EQ(4336, wit_size);
    EXPECT_EQ(122, no_wit_size);
    EXPECT_EQ(4173, cache_size);

    minimum_bits = 52;
    cache_size = 0;
    EXPECT_EQ(4395,
        txout_ref.GetSerializeSize(true, &wit_size, &no_wit_size, exponent, minimum_bits, &cache_size, 2));
    EXPECT_EQ(4273, wit_size);
    EXPECT_EQ(122, no_wit_size);
    EXPECT_EQ(4173, cache_size);
  }
}

TEST(ConfidentialTxOutReference, GetSerializeVsize) {
  int64_t satoshi = 1000000;
  ConfidentialAssetId asset("1234567890123456789012345678901234567890123456789012345678901234");
  ConfidentialTxOut txout(exp_script, asset,
      ConfidentialValue(Amount::CreateBySatoshiAmount(satoshi)));
  ConfidentialTxOutReference txout_ref(txout);

  EXPECT_EQ(txout_ref.GetSerializeVsize(false), 67);

  EXPECT_EQ(886, txout_ref.GetSerializeVsize(true, 0, 36));

  EXPECT_EQ(1206, txout_ref.GetSerializeVsize(true, 0, 52));

  EXPECT_EQ(1191, txout_ref.GetSerializeVsize(true, 0, 52, nullptr, 2));
}

#endif  // CFD_DISABLE_ELEMENTS
