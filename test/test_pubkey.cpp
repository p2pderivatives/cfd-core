#include "gtest/gtest.h"
#include <iostream>
#include <string>

#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_util.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SignatureUtil;
using cfd::core::HashUtil;

typedef struct {
  std::string hex;
  bool expect_invalid;
  bool expect_compress;
} PubkeyTestVector;

// @formatter:off
const std::vector<PubkeyTestVector> pubkey_test_vectors = {
  // compressed form
  {
    "021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647",
    false,
    true
  },
  {
    "03990e1b210a8b1331b5d6c2cdd4bb75ebc699371ac190dcbd7f429171006dd444",
    false,
    true
  },
  // uncompressed form
  {
    "041f45896f5828c86752260148328be7d6e8e9531cb5010737db6e258bfe6e190e820d30232d85cc3c5580cb92bf93ef4925f64ada02c0765391379db2b1999255",
    false,
    false
  },
  // hybrid form
  {
    "061362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b7946474bcfcf28d1972f5479d9631ef825c29afc4af6a08f8f7eaf427b449bd8790b56",
    false,
    false
  },
  {
    "072078e969c197c71d02df1185f34b717d63265e152a4a125e6a280b12bcfd7985d3c0d487a1e3e3d1409881d83b117f8337896f2db4ee480282d2723f06c91ac7",
    false,
    false
  }
};
// @formatter:on

TEST(Pubkey, DefaultConstructorTest) {
  Pubkey pubkey = Pubkey();

  EXPECT_STREQ("", pubkey.GetHex().c_str());
  EXPECT_FALSE(pubkey.IsCompress());
  EXPECT_FALSE(pubkey.IsValid());
  EXPECT_TRUE(pubkey.GetData().Equals(ByteData("")));
}

void pubkeyFieldTest(Pubkey pubkey, PubkeyTestVector test_vector) {
  EXPECT_STREQ(test_vector.hex.c_str(), pubkey.GetHex().c_str());
  ASSERT_EQ(test_vector.expect_invalid, !pubkey.IsValid());
  EXPECT_EQ(test_vector.expect_compress, pubkey.IsCompress())
      << " : " << test_vector.hex.c_str() << " : "
      << test_vector.expect_compress;
  EXPECT_TRUE(pubkey.GetData().Equals(ByteData(test_vector.hex)));
}

TEST(Pubkey, ConstructorTest) {
  for (PubkeyTestVector test_vector : pubkey_test_vectors) {
    // hex string constructor
    Pubkey pubkey = Pubkey(test_vector.hex);
    pubkeyFieldTest(pubkey, test_vector);
    // ByteData constructor
    pubkey = Pubkey(ByteData(test_vector.hex));
    pubkeyFieldTest(pubkey, test_vector);
  }
}

void pubkeyExceptionTest(std::string hex) {
  Pubkey pubkey;
  EXPECT_THROW((pubkey = Pubkey(hex)), CfdException);
  EXPECT_THROW((pubkey = Pubkey(ByteData(hex))), CfdException);
}

TEST(Pubkey, ConstructorExceptionTest) {
  pubkeyExceptionTest("");
  pubkeyExceptionTest("1234567890");
  pubkeyExceptionTest("ABCDEFGHIJKLMN");
  pubkeyExceptionTest(
      "011362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647");
  pubkeyExceptionTest(
      "021362zzz255z304zzz29zzzz6z5z63z68zz7zz60z2z1zz156716zzz077z794647");
}

typedef struct {
  std::string pubkey1;
  std::string pubkey2;
  std::string combined_pubkey;
} PubkeyCombineTestVector;

// @formatter:off
const std::vector<PubkeyCombineTestVector> combine_pubkey_test_vectors = {
  // same forms
  {
    "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9",
    "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe",
    "022a66efd1ea9b1ad3acfcc62a5ce8c756fa6fc3917fce3d4952a8701244ed1049"
  },
  {
    "04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80",
    "046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078",
    "035ea9a4c685365c1c4bd74e1762f2c6c530d424389fc3b748d265811c9ed7263f"
  },
  {
    "061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba",
    "076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73",
    "02022628a92f5f920dfc56242f5f6fc426c66541d02c212de583615843129d281f"
  },
  // compressed and uncompressed form
  {
    "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9",
    "04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80",
    "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3",
  },
  {
    "046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078",
    "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe",
    "0388ed12c2b6e97ce020b916872b3c7a6f1da1d21a5d21b567d167de0c1f3ff37f",
  },
  // compressed and hybrid form
  {
    "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe",
    "061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba",
    "0369ff8964bb335ec84fa132ab7cb7878b28741e24ea8dc39017dc048f97f8a9ff",
  },
  {
    "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9",
    "076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73",
    "03d8d6501f1619206d947281f818d42f9a387339dcf614bdb0bdb0b02367d67021",
  },
  // uncompressed and hybrid form
  {
    "046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078",
    "061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba",
    "02ed3801bf14c64a5822127a3686d35423abe4004fc069720fcbe5ddd1d09dde4a",
  },
  {
    "076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73",
    "04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80",
    "026356a05be3fcf52a57e133b7fb1cdb52a1bf14ef43f7d053e79b2ac98d5c2dd3",
  }
};
// @formatter:on

TEST(Pubkey, CombinePubkeysTest) {
  for (PubkeyCombineTestVector test_vector : combine_pubkey_test_vectors) {
    Pubkey pubkey1 = Pubkey(test_vector.pubkey1);
    Pubkey pubkey2 = Pubkey(test_vector.pubkey2);

    Pubkey combined = Pubkey::CombinePubkey(pubkey1, pubkey2);
    EXPECT_STREQ(test_vector.combined_pubkey.c_str(),
                 combined.GetHex().c_str());

    std::vector<Pubkey> pubkeys;
    pubkeys.push_back(pubkey1);
    pubkeys.push_back(pubkey2);
    combined = Pubkey::CombinePubkey(pubkeys);
    EXPECT_STREQ(test_vector.combined_pubkey.c_str(),
                 combined.GetHex().c_str());
  }
}

TEST(Pubkey, NegateTest) {
  Pubkey pubkey = Pubkey("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
  Pubkey negate = pubkey.CreateNegate();
  EXPECT_FALSE(pubkey.Equals(negate));
  EXPECT_TRUE(pubkey.Equals(negate.CreateNegate()));
}

TEST(Pubkey, CompressUncompressTest) {
  std::string key_uncompressed = "076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73";
  std::string ext_key_uncompressed = "046468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73";
  std::string ext_key_compressed = "036468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955";
  Pubkey pubkey = Pubkey(key_uncompressed);
  Pubkey comp_pubkey = pubkey.Compress();
  EXPECT_STREQ(comp_pubkey.GetHex().c_str(), ext_key_compressed.c_str());

  Pubkey uncomp_pubkey = comp_pubkey.Uncompress();
  EXPECT_STREQ(uncomp_pubkey.GetHex().c_str(), ext_key_uncompressed.c_str());
}

TEST(Pubkey, VerifyEcSignature) {
  Pubkey pubkey(
      "031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb");
  ByteData256 sighash(
      "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e");
  ByteData signature(
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb"
      "12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");
  ByteData bad_signature1(
      "0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb"
      "12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f");
  ByteData bad_signature2(
      "0e68b55347fe37338ceb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb"
      "12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c");

  EXPECT_TRUE(pubkey.VerifyEcSignature(sighash, signature));

  EXPECT_FALSE(pubkey.VerifyEcSignature(sighash, bad_signature1));

  EXPECT_FALSE(pubkey.VerifyEcSignature(sighash, bad_signature2));
}

TEST(Pubkey, Combine) {
  // Arrange
  Privkey oracle_privkey(
      "0000000000000000000000000000000000000000000000000000000000000001");
  Pubkey oracle_pubkey = oracle_privkey.GeneratePubkey();
  Privkey oracle_k_value(
      "0000000000000000000000000000000000000000000000000000000000000002");
  std::string message = "WIN";
  Privkey local_fund_privkey(
      "0000000000000000000000000000000000000000000000000000000000000003");
  Pubkey local_fund_pubkey = local_fund_privkey.GeneratePubkey();
  Privkey local_sweep_privkey(
      "0000000000000000000000000000000000000000000000000000000000000004");
  Pubkey local_sweep_pubkey = local_sweep_privkey.GeneratePubkey();
  std::vector<Pubkey> oracle_r_points = {};

  // Act
  auto signature = SignatureUtil::CalculateSchnorrSignatureWithNonce(
      oracle_privkey, oracle_k_value, HashUtil::Sha256(message));

  // auto committed_key =
  //     DlcUtil::GetCommittedKey(oracle_pubkey, oracle_r_points, {});
  auto pubkey = Pubkey::GetSchnorrPubkey(oracle_pubkey,
      oracle_k_value.GeneratePubkey(), HashUtil::Sha256(message));
  // auto committed_key = Pubkey::CombinePubkey({pubkey});
  auto committed_key = pubkey;

  Pubkey combine_pubkey =
      Pubkey::CombinePubkey(local_fund_pubkey, committed_key);
  auto hashPub = Privkey(HashUtil::Sha256(local_sweep_pubkey.GetData()))
      .GeneratePubkey();
  auto combined_pubkey = Pubkey::CombinePubkey(combine_pubkey, hashPub);

  Privkey tweaked_key = local_fund_privkey.CreateTweakAdd(signature);
  auto hash = HashUtil::Sha256(local_sweep_pubkey);
  auto tweak_priv = tweaked_key.CreateTweakAdd(hash);

  // Assert
  EXPECT_EQ(tweak_priv.GeneratePubkey().GetHex(), combined_pubkey.GetHex());
  EXPECT_TRUE(SignatureUtil::VerifySchnorrSignatureWithNonce(
      oracle_pubkey, oracle_k_value.GeneratePubkey(), signature,
      HashUtil::Sha256(message)));
}
