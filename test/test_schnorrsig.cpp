#include <vector>
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_util.h"
#include "gtest/gtest.h"

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CryptoUtil;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::SchnorrSignature;
using cfd::core::SchnorrUtil;
using cfd::core::SigHashType;

const ByteData256 msg(
    "e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614");
const Privkey sk(
    "688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef");
const SchnorrPubkey pubkey(
    "b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390");
const bool pubkey_parity = true;
const ByteData256 aux_rand(
    "02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab");

const Privkey nonce(
    "8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe");

const SchnorrSignature signature(
    "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b"
    "8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8");

TEST(SchnorrSig, Sign) {
  auto sig = SchnorrUtil::Sign(msg, sk, aux_rand);

  EXPECT_EQ(signature.GetData().GetHex(), sig.GetData().GetHex());
}

TEST(SchnorrSig, SignWithNonce) {
  std::string expected_sig =
      "5da618c1936ec728e5ccff29207f1680dcf4146370bdcfab0039951b91e3637a958e91d"
      "68537d1f6f19687cec1fd5db1d83da56ef3ade1f3c611babd7d08af42";

  auto sig = SchnorrUtil::SignWithNonce(msg, sk, nonce);

  EXPECT_EQ(expected_sig, sig.GetHex());
}

TEST(SchnorrSig, ComputeSigPoint) {
  std::string expected_sig_point =
      "03735acf82eef9da1540efb07a68251d5476dabb11ac77054924eccbb4121885e8";

  SchnorrPubkey schnorr_nonce(
      "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547");

  auto point = SchnorrUtil::ComputeSigPoint(msg, schnorr_nonce, pubkey);

  EXPECT_EQ(expected_sig_point, point.GetHex());
}

TEST(SchnorrSig, Verify) {
  EXPECT_TRUE(SchnorrUtil::Verify(signature, msg, pubkey));
  EXPECT_TRUE(pubkey.Verify(signature, msg));
}

TEST(SchnorrSig, GetNonce) {
  std::string expected_nonce =
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee";

  auto sig_nonce = signature.GetNonce();

  EXPECT_EQ(expected_nonce, sig_nonce.GetData().GetHex());
}

TEST(SchnorrSig, GetPrivkey) {
  std::string expected_privkey =
      "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8";

  auto privkey = signature.GetPrivkey();

  EXPECT_EQ(expected_privkey, privkey.GetData().GetHex());
}

TEST(SchnorrSig, Constructor) {
  SchnorrSignature empty_obj;
  EXPECT_EQ(0, empty_obj.GetData().GetDataSize());
}

TEST(SchnorrPubkey, FromPubkey) {
  bool is_parity = false;
  auto actual_pubkey = SchnorrPubkey::FromPubkey(sk.GetPubkey(), &is_parity);
  EXPECT_EQ(pubkey.GetHex(), actual_pubkey.GetHex());
  EXPECT_EQ(pubkey_parity, is_parity);

  Pubkey pk_a1("024d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d");
  Pubkey pk_a2("034d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d");
  Pubkey pk_b1("02dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54");
  Pubkey pk_b2("03dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54");
  std::string exp_pk_a = "4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d";
  std::string exp_pk_b = "dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54";
  std::string exp_pk_c2 = "03417885176062c3ae707af06059e7b5e65f733938f818da509eb3e5c4074b8124";
  std::string exp_pk_c2p = "02417885176062c3ae707af06059e7b5e65f733938f818da509eb3e5c4074b8124";

  bool parity[4];
  auto spk_a1 = SchnorrPubkey::FromPubkey(pk_a1, &parity[0]);
  auto spk_a2 = SchnorrPubkey::FromPubkey(pk_a2, &parity[1]);
  auto spk_b1 = SchnorrPubkey::FromPubkey(pk_b1, &parity[2]);
  auto spk_b2 = SchnorrPubkey::FromPubkey(pk_b2, &parity[3]);

  EXPECT_EQ(exp_pk_a, spk_a1.GetHex());
  EXPECT_FALSE(parity[0]);
  EXPECT_EQ(exp_pk_a, spk_a2.GetHex());
  EXPECT_TRUE(parity[1]);
  EXPECT_EQ(exp_pk_b, spk_b1.GetHex());
  EXPECT_FALSE(parity[2]);
  EXPECT_EQ(exp_pk_b, spk_b2.GetHex());
  EXPECT_TRUE(parity[3]);

  Pubkey pk_aa1 = spk_a1.CreatePubkey(parity[0]);
  EXPECT_EQ(pk_a1.GetHex(), pk_aa1.GetHex());

}

TEST(SchnorrPubkey, FromPrivkey) {
  bool parity = false;
  auto actual_pubkey = SchnorrPubkey::FromPrivkey(sk, &parity);

  EXPECT_EQ(pubkey.GetHex(), actual_pubkey.GetHex());
  EXPECT_EQ(pubkey_parity, parity);
}

TEST(SchnorrPubkey, TweakAddFromPrivkey) {
  ByteData256 tweak1("45cfe14923541d2908a64f32aaf09b703dbd2cfb256830b0eebc5573b15a4476");
  Privkey tweaked_sk;
  bool parity = false;
  auto actual_pubkey = SchnorrPubkey::CreateTweakAddFromPrivkey(
      sk, tweak1, &tweaked_sk, &parity);

  std::string exp_pubkey1 = "ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440";
  std::string exp_privkey1 = "dd43698cf5f96d33bf895c28d67b5ffbd736c2d4cef91e1f8ce0e38c31a709c8";

  EXPECT_EQ(exp_pubkey1, actual_pubkey.GetHex());
  EXPECT_EQ(exp_privkey1, tweaked_sk.GetHex());
  EXPECT_EQ(pubkey_parity, parity);

  Privkey key = sk;
  if (parity) key = key.CreateNegate();
  key = key.CreateTweakAdd(tweak1);
  EXPECT_EQ(exp_privkey1, key.GetHex());
}

TEST(SchnorrPubkey, Constructor) {
  auto sk_pubkey = SchnorrPubkey::FromPrivkey(sk);
  SchnorrPubkey empty_obj;

  EXPECT_FALSE(empty_obj.IsValid());

  auto sk_obj = SchnorrPubkey::FromPrivkey(sk);
  SchnorrPubkey b256_obj(ByteData256(sk_pubkey.GetData()));

  EXPECT_EQ(sk_pubkey.GetHex(), sk_obj.GetHex());
  EXPECT_EQ(sk_pubkey.GetHex(), b256_obj.GetHex());
  EXPECT_TRUE(sk_obj.IsValid());
  EXPECT_TRUE(b256_obj.IsValid());
  EXPECT_TRUE(sk_obj.Equals(b256_obj));
}

TEST(SchnorrPubkey, TweakAdd) {
  ByteData256 tweak1("45cfe14923541d2908a64f32aaf09b703dbd2cfb256830b0eebc5573b15a4476");
  ByteData256 tweak2("0daf700e00c25a75feb3b747a5f31ba58f4a7c3c7b36eaceef7cb882a06a9bf1");
  SchnorrPubkey tweak_pubkey1;
  SchnorrPubkey tweak_pubkey2;
  bool is_parity1 = false;
  bool is_parity2 = false;

  std::string exp_pubkey1 = "ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440";
  std::string exp_pubkey2 = "943203db3a9a8845a4aee1af81b76cb9ec60ab08d700df59a32426a4e6e1557b";

  EXPECT_NO_THROW(tweak_pubkey1 = pubkey.CreateTweakAdd(tweak1, &is_parity1));
  EXPECT_EQ(exp_pubkey1, tweak_pubkey1.GetHex());
  EXPECT_TRUE(is_parity1);

  EXPECT_NO_THROW(tweak_pubkey2 = pubkey.CreateTweakAdd(tweak2, &is_parity2));
  EXPECT_EQ(exp_pubkey2, tweak_pubkey2.GetHex());
  EXPECT_FALSE(is_parity2);

  EXPECT_TRUE(tweak_pubkey1.IsTweaked(pubkey, tweak1, is_parity1));
  EXPECT_TRUE(tweak_pubkey2.IsTweaked(pubkey, tweak2, is_parity2));
  EXPECT_FALSE(tweak_pubkey1.IsTweaked(pubkey, tweak2, !is_parity1));
  EXPECT_FALSE(tweak_pubkey2.IsTweaked(pubkey, tweak2, !is_parity2));

  Privkey tweak_sk1;
  Privkey tweak_sk2;
  Privkey key = sk;
  if (pubkey_parity) key = sk.CreateNegate();
  EXPECT_NO_THROW(tweak_sk1 = key.CreateTweakAdd(tweak1));
  EXPECT_NO_THROW(tweak_sk2 = key.CreateTweakAdd(tweak2));

  SchnorrPubkey tweak_pubkey21 = SchnorrPubkey::FromPrivkey(tweak_sk1);
  SchnorrPubkey tweak_pubkey22 = SchnorrPubkey::FromPrivkey(tweak_sk2);
  EXPECT_EQ(exp_pubkey1, tweak_pubkey21.GetHex());
  EXPECT_EQ(exp_pubkey2, tweak_pubkey22.GetHex());
}

TEST(SchnorrPubkey, TweakTest) {
  // https://planethouki.wordpress.com/2018/03/15/pubkey-add-ecdsa/
  Privkey sk_a("1d52f68124c59c3125d5c2e043cabf01cef46fafaf45be3132fc1f52ff0ec434");
  Privkey sk_b("353a88e3c404380d9970d9b2d8ee9f6051b3d817ab32aabc12f5c3c65086e659");
  std::string exp_sk_c = "528d7f64e8c9d43ebf469c931cb95e6220a847c75a7868ed45f1e3194f95aa8d";
  std::string exp_pk_c = "c6cf31d72599553158c6ffed6139946bbd3a1648a6b1ef56bea812878bb2df71";
  Pubkey pk("03c6cf31d72599553158c6ffed6139946bbd3a1648a6b1ef56bea812878bb2df71");

  auto pk_a = SchnorrPubkey::FromPrivkey(sk_a);
  auto pk_b = SchnorrPubkey::FromPrivkey(sk_b);
  ByteData256 tweak1 = ByteData256(pk_b.GetData());

  auto pk_c1 = pk_a + tweak1;
  auto pk_c2 = pk_b;
  pk_c2 += tweak1;

  auto pk_c3 = pk_a - tweak1;
  auto pk_c4 = pk_b;
  pk_c2 -= tweak1;

  auto pk_c5 = pk_a.CreateTweakAdd(pk_b);

  auto sk_c = sk_a + sk_b;
  auto pk_c11 = SchnorrPubkey::FromPrivkey(sk_c);
  auto pk_c12 = SchnorrPubkey::FromPubkey(pk);

  EXPECT_NE(exp_pk_c, pk_c1.GetHex());  // tweak
  EXPECT_NE(exp_pk_c, pk_c2.GetHex());  // tweak
  EXPECT_NE(exp_pk_c, pk_c3.GetHex());  // tweak
  EXPECT_NE(exp_pk_c, pk_c4.GetHex());  // tweak
  EXPECT_NE(exp_pk_c, pk_c5.GetHex());  // tweak
  EXPECT_EQ(exp_pk_c, pk_c11.GetHex());  // combine
  EXPECT_EQ(exp_pk_c, pk_c12.GetHex());
  EXPECT_EQ(exp_sk_c, sk_c.GetHex());
}

TEST(SchnorrUtil, ComputeSigPointBatch) {
  std::vector<ByteData256> data = {
      ByteData256(
          "e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614"),
      ByteData256(
          "80a1c2125d13d6b2d639f2da507772040719d36c6228ec141befd1aecb901b17"),
      ByteData256(
          "375a7aec74bba181ffca89ef03bd8a10d7ddae7813190d4616652d9e91bcff20"),
  };

  std::vector<SchnorrPubkey> nonces = {
      SchnorrPubkey(
          "4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"),
      SchnorrPubkey(
          "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547"),
      SchnorrPubkey(
          "dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54")};

  std::vector<Pubkey> sig_points;
  for (size_t i = 0; i < data.size(); i++) {
    sig_points.push_back(
        SchnorrUtil::ComputeSigPoint(data[i], nonces[i], pubkey));
  }
  auto expected_sig_point = Pubkey::CombinePubkey(sig_points);

  auto actual_sig_point =
      SchnorrUtil::ComputeSigPointBatch(data, nonces, pubkey);

  ASSERT_EQ(expected_sig_point.GetHex(), actual_sig_point.GetHex());
}
