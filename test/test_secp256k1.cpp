#include "gtest/gtest.h"

#include "wally_core.h"
#include "cfdcore_secp256k1.h"
#include "cfdcore/cfdcore_exception.h"

using cfd::core::ByteData;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::Secp256k1;

typedef struct {
  std::vector<ByteData> pubkeys;
  std::string expect;
} CombinePubkeyTestVector;

// @formatter:off
const std::vector<CombinePubkeyTestVector> combine_test_vectors = {
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        },
        "022a66efd1ea9b1ad3acfcc62a5ce8c756fa6fc3917fce3d4952a8701244ed1049"
    },
    {
        {
            ByteData("04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80"),
            ByteData("046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078"),
        },
        "035ea9a4c685365c1c4bd74e1762f2c6c530d424389fc3b748d265811c9ed7263f"
    },
    {
        {
            ByteData("061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba"),
            ByteData("076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73"),
        },
        "02022628a92f5f920dfc56242f5f6fc426c66541d02c212de583615843129d281f"
    },
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80"),
        },
        "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3"
    },
    {
        {
            ByteData("046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078"),
            ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        },
        "0388ed12c2b6e97ce020b916872b3c7a6f1da1d21a5d21b567d167de0c1f3ff37f"
    },
    {
        {
            ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
            ByteData("061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba"),
        },
        "0369ff8964bb335ec84fa132ab7cb7878b28741e24ea8dc39017dc048f97f8a9ff"
    },
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73"),
        },
        "03d8d6501f1619206d947281f818d42f9a387339dcf614bdb0bdb0b02367d67021"
    },
    {
        {
            ByteData("046a4f0992f7005360d32cfa9bcd3a1d46090e2420b1848844756f33d3ade4cb6f8f12dc43e8ccae87bd352156f727cde9c3f03e348928c1b20de8ee92e31f0078"),
            ByteData("061282d671e177781d5eaa18526b12066a7cb24708372e4d1092c493b7bd3fa9c28d771e462289ae968b17e2a075ff8fa143371f04c77991c599bc8d8bafdf07ba"),
        },
        "02ed3801bf14c64a5822127a3686d35423abe4004fc069720fcbe5ddd1d09dde4a"
    },
    {
        {
            ByteData("076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73"),
            ByteData("04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80"),
        },
        "026356a05be3fcf52a57e133b7fb1cdb52a1bf14ef43f7d053e79b2ac98d5c2dd3"
    },
    {
        {
            ByteData("0325bc01103946d17de22549fbc6e9b6a61d0e6a1043a219583a7b371163d139d4"),
            ByteData("03d9e6667b5e1bd4e9308fa4499aec7e9dcd0f35f1aa60e5adc66bd663abfdb98a"),
            ByteData("02a132258eb22f0bb943adf317aceeedb11eeab8a24bf205d1a5e1c8ba8149d347"),
        },
        "0245bd1dbb9ff255c42a421d38e99f9558bd19bfb28246dc73aca5bfdcfe699dc9"
    }
};
// @formatter:on

TEST(Secp256k1, CombinePubkeySecp256k1EcTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (CombinePubkeyTestVector test_vector : combine_test_vectors) {
    ByteData actual;
    EXPECT_NO_THROW(
        actual = secp.CombinePubkeySecp256k1Ec(test_vector.pubkeys));
    EXPECT_EQ(test_vector.expect, actual.GetHex());
  }
}

// @formatter:off
const std::vector<CombinePubkeyTestVector> combine_error_vectors = {
    // pass less than two pubkeys
    {
        {
        },
        ""
    },
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
        },
        ""
    },
    // invalid Data size
    {
        {
            ByteData("03662a01c232918c9deb3b330272483c3e4e"),
            ByteData("0261e37f277f02a977b4f11eb5055abab499"),
        },
        ""
    },
    // invalid ec pubkey data
    {
        {
            ByteData("01662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
            ByteData("0061e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        },
        ""
    },
};
// @formatter:on

TEST(Secp256k1, EmptyContextErrorTest) {
  struct secp256k1_context_struct *cxt = nullptr;
  Secp256k1 secp = Secp256k1(cxt);

  std::vector<ByteData> test_vector =
      { ByteData(
          "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
          ByteData(
              "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe") };
  EXPECT_THROW(ByteData actual = secp.CombinePubkeySecp256k1Ec(test_vector),
               CfdException);
}

TEST(Secp256k1, CombinePubkeySecp256k1EcErrorCaseTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (CombinePubkeyTestVector test_vector : combine_error_vectors) {
    EXPECT_THROW(
        ByteData actual = secp.CombinePubkeySecp256k1Ec(test_vector.pubkeys),
        CfdException);
  }
}

typedef struct {
  ByteData pubkey;
  ByteData tweak;
  bool is_check;
  std::string expect_add;
  std::string expect_mul;
} TweakPubkeyTestVector;

// @formatter:off
const std::vector<TweakPubkeyTestVector> tweak_pubkey_test_vectors = {
    // pass less than two pubkeys
    {
        ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
        ByteData("0000000000000000000000000000000000000000000000000000000000000001"),
        true,
        "02ca4ac065c33e2ec9777c711c8962f750a0d16ad648ff7714d18265f6cf5e5e4a",
        "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"
    },
    {
        ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
        ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5"),
        true,
        "02f7eb7db42b05503b0ab66523044044b0a1a96b73d41016da956b3483a1bbdd2f",
        "03f057567dfc74686aaa30750d2c13d2e25f5938735a3bfd29af56be565742efc9"
    },
    {
        ByteData("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe"),
        ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5"),
        false,
        "03b34e7d886ba9cccbe1f7ee2b021e99cd5a3c858c8f7af485409f3d6b839ce372",
        "026649c5a3374afc7e4c43f8856702fc8ec8f47c49fdd5908682524419586fcb59"
    },
};

const std::vector<TweakPubkeyTestVector> tweak_pubkey_error_vectors = {
  // tweak must non-zero bytes
  {
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    ByteData("0000000000000000000000000000000000000000000000000000000000000000"),
    false,
    "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9",
    ""
  },
  // invalid pubkey size(len isn't 33)
  {
    ByteData(""),
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5"),
    true,
    "",
    ""
  },
  // empty pubkey
  {
    ByteData(""),
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    true,
    "",
    ""
  },
  // invalid tweak size(len isn't 32)
  {
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    true,
    "",
    ""
  },
  // empty tweak
  {
    ByteData("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"),
    ByteData(""),
    true,
    "",
    ""
  },
};
// @formatter:on

TEST(Secp256k1, AddTweakPubkeySecp256k1EcTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (TweakPubkeyTestVector test_vector : tweak_pubkey_test_vectors) {
    ByteData actual_add;
    EXPECT_NO_THROW(
        actual_add = secp.AddTweakPubkeySecp256k1Ec(test_vector.pubkey,
            test_vector.tweak, test_vector.is_check));
    EXPECT_EQ(test_vector.expect_add, actual_add.GetHex());

    ByteData actual_mul;
    EXPECT_NO_THROW(
        actual_mul = secp.MulTweakPubkeySecp256k1Ec(test_vector.pubkey,
            test_vector.tweak));
    EXPECT_EQ(test_vector.expect_mul, actual_mul.GetHex());
  }
}

TEST(Secp256k1, AddTweakPubkeySecp256k1EcErrorTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (TweakPubkeyTestVector test_vector : tweak_pubkey_error_vectors) {
    if (test_vector.expect_add.empty()) {
      EXPECT_THROW(
        ByteData actual = secp.AddTweakPubkeySecp256k1Ec(test_vector.pubkey,
          test_vector.tweak, test_vector.is_check),
        CfdException);
    }
    if (test_vector.expect_mul.empty()) {
      EXPECT_THROW(
        ByteData actual = secp.MulTweakPubkeySecp256k1Ec(test_vector.pubkey,
          test_vector.tweak),
        CfdException);
    }
  }
}

typedef struct {
  ByteData privkey;
  ByteData tweak;
  std::string expect_add;
  std::string expect_mul;
} TweakPrivkeyTestVector;

// @formatter:off
const std::vector<TweakPrivkeyTestVector> tweak_privkey_test_vectors = {
    {
        ByteData("0000000000000000000000000000000000000000000000000000000000000001"),
        ByteData("0000000000000000000000000000000000000000000000000000000000000001"),
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000001"
    },
    {
        ByteData("0000000000000000000000000000000000000000000000000000000000000001"),
        ByteData("0000000000000000000000000000000000000000000000000000000000000002"),
        "0000000000000000000000000000000000000000000000000000000000000003",
        "0000000000000000000000000000000000000000000000000000000000000002"
    },
    {
        ByteData("036b13c5a0dd9935fe175b2b9ff86585c231e734b2148149d788a941f1f4f566"),
        ByteData("98430d10471cf697e2661e31ceb8720750b59a85374290e175799ba5dd06508e"),
        "9bae20d5e7fa8fcde07d795d6eb0d78d12e781b9e957122b4d0244e7cefb45f4",
        "aa71b12accba23b49761a7521e661f07a7e5742ac48cf708b8f9497b3a72a957"
    },
};

const std::vector<TweakPrivkeyTestVector> tweak_privkey_error_vectors = {
    // tweak must non-zero bytes
    {
        ByteData("0000000000000000000000000000000000000000000000000000000000000001"),
        ByteData("0000000000000000000000000000000000000000000000000000000000000000"),
        "0000000000000000000000000000000000000000000000000000000000000001",
        ""
    },
    // empty privkey
    {
        ByteData(""),
        ByteData("0000000000000000000000000000000000000000000000000000000000000000"),
        "",
        ""
    },
    // empty tweak
    {
        ByteData("0000000000000000000000000000000000000000000000000000000000000000"),
        ByteData(""),
        "",
        ""
    },
    // invalid privkey length
    {
        ByteData("00000000000000000000000000000000000000000000000000000000000000"),
        ByteData("0000000000000000000000000000000000000000000000000000000000000001"),
        "",
        ""
    },
    // invalid tweak length
    {
        ByteData("0000000000000000000000000000000000000000000000000000000000000001"),
        ByteData("00000000000000000000000000000000000000000000000000000000000000"),
        "",
        ""
    },
};
// @formatter:on

TEST(Secp256k1, TweakPrivkeySecp256k1EcTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (TweakPrivkeyTestVector test_vector : tweak_privkey_test_vectors) {
    ByteData actual_add;
    EXPECT_NO_THROW(
        actual_add = secp.AddTweakPrivkeySecp256k1Ec(test_vector.privkey,
            test_vector.tweak));
    EXPECT_EQ(test_vector.expect_add, actual_add.GetHex());

    ByteData actual_mul;
    EXPECT_NO_THROW(
        actual_mul = secp.MulTweakPrivkeySecp256k1Ec(test_vector.privkey,
            test_vector.tweak));
    EXPECT_EQ(test_vector.expect_mul, actual_mul.GetHex());
  }
}

TEST(Secp256k1, TweakPrivkeySecp256k1EcErrorTest) {
  struct secp256k1_context_struct *cxt = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(cxt);
  for (TweakPrivkeyTestVector test_vector : tweak_privkey_error_vectors) {
    if (test_vector.expect_add.empty()) {
      EXPECT_THROW(
        ByteData actual = secp.AddTweakPrivkeySecp256k1Ec(test_vector.privkey,
          test_vector.tweak),
        CfdException);
    }
    if (test_vector.expect_add.empty()) {
      EXPECT_THROW(
        ByteData actual = secp.MulTweakPrivkeySecp256k1Ec(test_vector.privkey,
          test_vector.tweak),
        CfdException);
    }
  }
}

typedef struct {
  ByteData range_proof;
  int expect_exp;
  int expect_mantissa;
  uint64_t expect_minv;
  uint64_t expect_maxv;
} RangeProofInfoTestVector;

// @formatter:off
const std::vector<RangeProofInfoTestVector> range_proof_info_test_vectors = {
    // range proof by elements transaction
    {
        ByteData("602300000000000000013883013a31aceb91aa584fa6c14c012797397725bf53c0d938457d41e31318fb844ea088615d1cfb76a86396a2ea0b2a1e356315876651e47c0e8911918f1d7e75eda6dfe4444208c9c3c24a98a8f8616283a4459f1e928d38ff8c5cce40aa50b58deae228af10a00e4c5f07998095bc2e61880d8b0b0ae3ebf63c51a5f0b9f885c88f8332a8f83c457872517c3581f3d8a0f0f3e2eee3e6909a9cda1903bf4bb4bd801e6077761f19fe115496c3e6661b68ae2b2a81b55145cb127b3c71fc715d28ceb35cea14fe7561878bee42c71dd0ba00d5553f59e1665e55a953c1a01025ed0edf01147dbd035e2b2e32c36c9400c2ab04942db231d5b9545f406b9fc290d389483bfcd519a9697a6498e816d8914d7df8123b20ed6641ae75cca7510015425c999d491f6ad899fe4890e5ff653aaeb55e37ec5d641ab12f68d129c5ae2c57c1addb984fdf53c42967eb1dcfac30757a2c110f2b39c5f160ff870724e25b0d9f73127e515398b3a5bb9797aad60d6017c4df6bf2f42633fadfc38021bdc801cbd2a2fe7647bf7874d18c6fc78fc616e6e031748106fff811fc431daeb99dd35a26367e7dff965493af24fb0fc0efa14cff00b776650ebba8d0fced41d559a9bedc8b356dc754866ea1b0cbbf551cf58f54d3a0053f4a7f720fa04a50c4d56f3e9f8cc253fe4cf30e3190530da38d1df259fc9dd5f54756eb766085f75ee885cc477e823180b6a9e9188f1d3f22d1328afafe4de03a5a7d10b293e0de7e001ccd1b61f1b8e15c7a9a35d1e8d9bd8fcdda402c96f7e3e7eb48488b010932d8d95168d81082757117ebf2af899d154ae6870cc4f7f00db4f96292b4fc1b384b8c91fb422adcdcc570d2ddf99e2645104ca216440cdcb94e33bfca56eb2c4a42c89efc1e1c0a16bbd63eb476afdd5fdc0461d1c95d619cfb557b1049e0a6a7afcb58ace021f54fcc4f51ea25d00f58b16d3d0ecd7a52261407ebc45017b5d70a2e986eeede4db51e988f44a95ae1b482d2ee6ed097e37c5742bc496af5ecc526d14493537a0ed94a6e1d100a5a9f8be484bb0da9de7344ea487428e84f5ea5589553701a9dafb3636b94d2aaae49ff8abbf1576725b9e8143ef77358fa1341294705f19d1e90492273aa4c9e19a006a0444b533b38716844a1f4199da5f99ac5188926a42f92c75e75ed87b466ef89dd42f449c9769e14559f92b2620ea7ae1bc425fc0be66d98321c998c2dea5a405c06f86b127538642e87c9f127bd7ed9abf86d650b7c9c548af030f5fd1a79bc3189af7a9676181e0a15175438c4bc03782719624a831413b24b93e0d852906f3b47bcf7e181b0feed31145068e5945abe8de69d6e10f1ffbef18432269b5fa5c1ac3b023c466b071b278eca87c1f4eb174be7de34c194504bac074278fd0a38509ea1ab8048ff17554a4a2bc5eb792a3a2b96cdd3fb3a346ed7d5113dd6d9c62778ac0e3288714352ba0d39c2041cf00e4dbb2d4504f37af0a379d7b5271778f9b54a942e1f3352bffd6bd1ca46b87eedda712d93375bf5d5fc68b2f5694b846f596d767890615f3a8c2f0bbbc2dbc8624370aa650f4a4c58650e7161df308e58ca014c4666bf25700d8914999d681f503d37c1a14206319f911a2db2a28c41b1c2e526de61b473696d2a9766df40d4268cef0b4733f0ddeb1b652d831e806885650ab60196e28c2c7193c56b88435d98e6dc9498bcc6c5c30927a554f28f0f7ce57ac61a3dfbe67c6144693f4b8d272808f59c41c6466d81b6f16f9444ffadc13f5cbee235a61d895d80cb0fd12141b5cf8ea7784dbbad306a7580084d719407c3bd5fafd2afddeea08a11212a0efc643132465efb4e3383ff263f1408b2f891ff2af8efb8416e87069e0673a831837a24e3f876a3208146ac73ebc23b80b677f819023384a058e1076f94266cf9395b2af044d04276d7c9bb245b0c901d6770b59fe9590ff923d5cac95d83228c6cb9c47a3fadcbca7bc3326c5e97db84a7c3002875fd8c2f4ea2c56bb867ad5e005727444b6d826f6e22aadb658ebd1fa0eee5eaad0e15e42c268aabcd82ea6a81dfbc5d2c4b54ffd0e18b8de750fda77f6ac733a5a2d975304b24bd3b4d39515103c488d44f4ac71d9e5ae9a1c593a633203e20b0ab20e5179b8ef2e78ac66ea2353be0cbc6ac921cc9a2bcf50565a9d7eedfcfebbbb085e449994a0cfdc8184d15bfee1c80347c1ae6915b7d4844882c182f95808c1109cf1b48809aa2d9501acae828f57b155270eda04e9178c075386b569135752e7b01fa80b7167d91b7ab67ad1af6dc8113cc9753f91ec1a180bf11d8057461d23c85b4eaf675a6a14b5ffae03dd0c752474f007548f68530739cdae8e5b924572a976214ed2b6b131fcffe579c426fa28abc586fb176bd9bdcf907c7afb6a9cef3b27453e852f50a150e4faca9cc5dad0ec0531492ba658ca0f10e4d958d31aae1c9ed22d22889d23a944297e4005caf1e3d341628d5dce35a502340a0f1f47616db15027dc0c452830c691cc1ceea8f4c84604283a4dd968f37e7629fb06f28d834e3523d4e0d3e3d5ce1456bf9bf4147225cf04d92d053e1ee6578a0a614017ef3ca5f54636550a6d461ffbc4d99bde6721febed92e23853276f8f5ae1e0c8358a79164ed5642c05eb184101ffeaef10e744f72210532411f83e765fbb743611a01ca17dbd19c20983fd840111266e2600df563b4149989948f5c255a692b9c9d694ff89bb12171d6579823268335b6eba7ccc5f6b2bb7d74f5b55a44ad6709f32f72a4c85bdd4aff9db98a5572026db7bdcfe4d3e1afb8c319e496844870e67054eacd251dca3debe06e980665795d2d6dc1575b9fdf67bce7d98f2d6198a2c7896905f3db07c4a6213f29486d09b75c19b3eb457e4ff074ff11f4aa5cadf6d064ed5b712e980af23351d057caea494e1d190ab0c0f562282b4f7408f7c6dd8ba973a8c2a3bb8b4637ca6c5c6d31d2832fdf6deb8a64465c00fff79068edffec309a609af77c27ce851784ff6bb0f59c61620bfa6387aec8550d1a0e2304530e5a5dd5b597aeb032fd96a6d602b6e42863517a6e0c47c86a654fedae233ec446344fb4febd13d671463251e1dfdc35042e3ead23ddd8736189f261ac22251e5a7faa24e227f5c3454b4a00b221ff2399b4ce1a93e1d9c95987216a170642d2cec5ab2de802f0e8af3e2bd010abe00ef34ac8acca9608329929b0394f5c84bc025372fbcb4c407d09e25ce1211233472d85fc92adfa3f0fca28aa271515a944a489780d13f5cd70eccf4e2977c603a1f8f06692d62a92aa0bcad5519b5140668ff2575c6c9c777fc00a61adc6204061031dd0b14ec4cd60bacd0cee58be5734354441a9ba0b0fe6eb2f2d5f1f00173b393e2a1f1cc41f8d06707d654ec3add8ec215e73a44544270d06ebdbfef4ad4832a5e16783151a3ae1cf8c1a3da721ada1af7b5b5dc08ebcec069e4dba5656ceda98a099544fa324a0f53094a55db585e793597867e35c88cc2438dd8bc39742abfe9de67fa1d9ab00681a3bc5fa165450d261d54423eca6cbf75e4535ba31d84852e5964deaf97b24220460cd3c8374fa97d537cee75f93ce37cc2918a34a9b94727102efff15e647714d04bdc6bb015dcd4a6e5a9ebcaab36b61b5c973f3f7225b73e2c7481b38779ba8cade1c2e6cec4098ef4c2eaaacb2e1969f610be6c31939528d0a7fce5c0dfcdc72a2cf52286b1e3ac7eb02f172400fd115bc0c1515429c0fefdb476b89daaf7e7ada5710fa7a1b6de0d1fcf9e29e0542ec076290e32315bc2f9af2ae5665fcf005578fad5ac8b9281cd96ad64cb7d07301017cb2824eff3535ca8b51276fc81bd498b5216dd4a5f394f02e115828f77f5617b908d96babbada133770c00cc943a024438a76532f01e146a9ed7c290538aaae2d229c796b2a11d222901cda433132fa89825f74b810008b1aa6732c915451c1224c5eb1d6cdf3ef67143e30622f5330e15baf9148ab5d992b19631043374840173ffe4bf844b5a5365c2beafd25898e89aa6b7dad9fa607ea01043770cdc71"),
        0,
        36,
        1,
        68719476736,
    },
    {
        ByteData("6028000000000000000134810a9e1ccd7a6ac7ae98cc045e654df08e9abeb89fdf6cb084cda8b4ce66a98620722fa551046d56c379383a84536f4625481d6217424056f8766c28842bde8ea8e4c6bba073188f4f0c6af38d897ba82fbff0382b0d02108254cd7e48d9769cc97ebe1fb3d3b6010cd14fb7f6864999b1bc52eb3d1b21545ee0eba4b0d9259904b26fb300ba4edbb4dd98a734efe77151c8ff0e7841509fd881356963907c974aaade33893c9773942facfdc51401b9e54224b2e1617da2f6231e21694788631046c0f51f2940d3ce47c8e553b526239d332597e3b2373908cfd707821bfd6b56751d439b83a60d1b577afeff365c202d62de4cae6ddb11aa3a87eea6d8a0428d575244d4b29640c62ab7a4b6e18bbb57f0bc5fa42a294db9e8f38c74dd05da6121d7d33dd64afc6493fe2b59b48fe8ae07c807b7a26c928ea2e25bac5f6f6921c8d3954158f19c2bd296a4add0828363eedf91b18576f45458163e06a8af0b0423cb79427324a221d5dde0a3ff2d52ae8e6106c103974940b5011e975384ebed60ee14c7ceaf32d60698be69680adb939557184aabf28851f557385874d47bc306389f03965da2acf3b3a0997b2be0a54de5c489eaa63a5c29c6eedee24b609af44d1b6634148db726e0133bc54ebd2361c97e3d64fde7830382eb9ecb1cd2b72f6676fc01ae295b270f0f55330d3a411f5abf6f941deba852626eb8cdfab8fe3fe39dd860423b17758f05e9fd98e1a0555dd789a925478d0a9f0a749aaefa3b58eed29e985dea4e54a1797764549fbe9d436043a691dd2bfbda966bbd7e7bef4e10dfb83b288d47a0c103074e84871dc49c382e5627552fd48050c0f379a7151c24a137038985affd1ec4614e1331dac8a79382f28ff6d31ece29cc56e24e307f79f605fa4cce99a2a774cb45c9ffcdb5fa1e5cecd5a50a7ac21e52a5b18efad59c1f9927cd0feae234bd06aa4cc402efa6ca4d56fb9f77f29660d05481db66d95f399f111933cde1f79c9a9ab2bb7108a974dc3654e72e67a8319d8cfb4ec5241befb6d6810f8e0cf3005bfc8201331fe4e9f1737ed9b799a9252a9c9895f12ba8b39dda57410a48e3c96ba379ebef64931f666a257524c9ec3e7528cb3fdf3395b882d223846255af163caea994ae2d22d2b3291028ae5667ceb838c5c0ace246c9f33491ff0e43a019f391bfd5b82f77a4b422f7b3d3aa74e85f5a9f56c4a0765d94ad96316acf54aa1528dfa0de1fd0e05083e6fd0ba62e0bbf0edaeefa634f9399ff119463b7cfa8bf0b9096a63b04b9ced1949ef71c256e5c93ae651f0df3c41ea22674667f222a64316644571b36d553cddec5c6686e801da95f965765c4210008b683c11bf792732dcc60387a71b955645e9d631a93f7c22896cd9da72f79fce7cab6700a9f88ddbe0f0f0e819268356ed107d80852ed385ba7050f7d0040e8a5eafe2518d51946d6c61f7dcddab7f66a55b54b3c8eadf809e3c07903c059958920d6a266dd272b276b2b72c53fe9130f6bcab3762ed51577a6667ce6dc40adf635ebe77e9383e67a80caa9509855df1fd97dd06fccb108e92170816121ec82865745aab95abc010bbffdeb702dd3e6125faea24cc33d16a152d222b14a95b0fc08510b408f7ec1a106ece29dd22a2d6239afff16233398527f2bf5a50192099105259a9fcca2870fa606c92896b6b1f481b606bb268d0eff7e632350aeb43d2e2354fef25bd201a19ba1b96e922f3deefadb1d199d52ed61b8046b2cfe7ffc95a6aff732e53c4aacfe9ccf76334ab8907e3cd7e92da9cf7940663733637551db0864dc8c5f40b2b1a4ad714a34f777d093f311c4a9fafe856e2adec829ca55fe03cb0f62a517f476e3f28bef5a9f3c2a9195c8d6a67fb1b104640041b2348088dade4b6c77d15a228408ee5eb524754e35deef91f7a7a554286a093d5ddb1be8288955563b766f976bfed848cc6377e0643fa44825779ef25b114207a1e5c01c9700921aace844e36b735d8ef089e2c9e09ab6a28d52700e5896b106dfe8b30b25ca24e1a164a29317b5944ba3136439d4acbb07013c12bc1c2a623496539c8a0528a00fc88610045332041d9ea1e06b3407685f3bfa963c4018ae6eb2b4363bc8265db04aa8cbd0aa8a5f8446e7766ddb23619e06876ced0e47a0d45319c146ec07762d2eac680bd9a751fcff6eee3c6a7a828bdce0340aadcb592ea05c490e49725b36f398699ad233a5eb19713ecc379d83724dd45ccb27bdddad154f2d41a5ffef1579a442ddee2b8a4049b549e11bb6588c449e590a79c5a9960911b61c043aefe4f1eb309a7b2314bbd968537fde6cf326b811907c9a408e38d227d9c1a74fe659df58bcd5273be9b6c7f4072c1f866c11aacd831a5575e73d6b290c2c3dfab6972f77afb9238dbe7b6b72a7c418c220975e19f63396d4cd132388ac52eb988834028313e1f8dd5aac60ec40a0905caf190dc3e61a9c5589fa92ed610266f03ad2172ea6ef2858f19a906f4db1dd1afaab79a3e54855ae03cfa990f435351ed69a2f32c5e28bb4d901b6250b6a1bda356d52e3cb84788b80c7c331b46b42ac747889664c2496ab79708640a5be1d7f25d8edf5664577eac1cfe58efa9c58c5b2eb78a0199df32ce7b00ba95867be9dc2fd0137a9ea0f82fc63353219d3580e692524810251aa781ca2d6ec2768e8c0562d5690353877e8819431a6dea2b62572d05a4b209a7d89c4a73424a81a63a4c20420afa0e3546b880429762615bd5b6368525b3ff84a2069de23a93abaa04f2ee00e8c43d6e7764373689552407132b1e09acb22526436a527dae39aa87309e7f977fb4b590bf5094e534d4f3bb2f223107a09185d66459f7ea1dbe2513d6dc0e7e7823bb8325c8c63a599790e63e2b814ba122ef66df1f3518eae9d1a6643c535ec4790675b157446407fac487b368f34ed6476e6810b105a6da818979c0b8c42be3c2ce908a9fc2812fd32b41bcfad38fb51a9bccd4b1373071d470e2c943689fbb60296a9987b2b10480a629e049314dcd88f7d7b320202dc42308876e1433f35cd81f001106b4f501d580ca3556cc4d3ad4f3f8c582ced7404966f1904211bda1456b27198d65b356c2cb6ee2551ba615d77e48574c3fd3d3adc555999ecab5e65131f6ed9e3707433b9bf391b4579b74da4ec3bf6d2ee57d7cc1025359f104af67605b48875af338f2f77a119924f276b215048f469003bcc72a3b8daac26d2f852bab1681646ff761b9f1e0d92826b68a321feaa590b3d4f93b1b863eb132481f22e562ae179f2f70ce597bba8d83d2cea5ab8288d4076f5a52df44a63fc60b5609d85e8b39399e39fae608700f0b01373f6200d5e9e32b314e714daed9b683023148b963b790ec56ec0c8b4e5761b62f670d012019dbac3b0b99eb4f80384039e3bd642a96df7b4b20cef8d4ad6a2bf096ac2fbf878f554b95e6474c17e02e1a1f3188a9b8ac114651ada7f8e13ca631e560dffe6943885c79f82b5ca96c3c3768dad8c1d7cf16d8459b284e6a495317e40c5c51e6cd27c6cd0c5f824ca74053c3670a8dc378033a329daf42524e794b2f5c61471083822df5359fd42f1248b4c561ff2f02837876aafdad956fe6cc0ae70580fb6216f9e6c6f8f99fce17fea515b4f864662ed9b9ee1fa8e62fb95428a9285b62882973299b7c83b98ef8d38332f84c8fd1975d42881fe7e1c3ad0d9d2109c0f5f7287e72417c01614b5879920a8d4ffb4bcccb86bac6b9b6df8cd1351059f46fa3ab98b4dba7be737a83e4d4a0841c759e5e290003ae627616cd8b417723c90f83f6181c3936f9757babcc7be1e466f6ee041349264c108106db1cfee872b4dd38dc993b9514bf66271b2cc2ba2bc146194a9383f4adc4551675ad95c9b044efc7e90b3442d256b60c2b4424505d1c59ee5bdea92faa61a487e29be08218560b295e2d579788f0d09be3360978700c02b7b80531f8907ca493346fc38857d526feeef083b71daeb556dccea93bf0e1c579456b0181f3eeeabe6950f6f0a2ca515537526e0249d06af23f803f75c27d445439abede56ac32eabcd9179b90fa869cdf1ebbb1f037d9056171fe8359989fbd705b7eca2165f7306fc52a48ef4bb80e95ab78f4be5eb9237b4cafd0c31f110f442ce2334997f3c79cccfd907a069dc371c0376000b209deb8fb812170b21b88210c814c54160e91e8fa759515810d0a69c00910ebcd58de8a70591cc3fd365b6bbc347212ca01b02646834affd4cf0a64cb55320cd3c4d42d28dc4c5b802aab3cbb1dddcd4978a68670747c62bdfe20ce4ae9e2a1ccdb59b8ca2eb9e078018263309f43b662543d0a34b22e71d0cd294a45c3d92da5b46e8c20b0d56f44cc0e267e622eec55e948541ae8413beae0bc577fea0a1c6783a68a5f289daeb0607bdccb59f3ea9f63d928e0c05ca97f1167e7aa042f99fa558ff25e9b8789255c3d4853ddccb232970811b313892b2249ee9df166543944ee197daacca770527153d860c367d710d4501071c4ead8d1c397208c2611d840cd503c2b1767603e292dc6d225f9628a4193995025cf9cd7cf2269bafa48640822b1924770fdaa0cd5a3bb956939ec7bc340e5ab3bf1aa2e337d90abf4bda8dd452fcdcacb49b4324561b9"),
        0,
        41,
        1,
        2199023255552,
    },
    // issuance
    {
        ByteData("602300000000000000017c770059b95754d13388aaef68806e6e74901facbd9178041b7d5ece040834494e17c1286e9885181120809a46f42e6ac31581261cb09b1da8a13148c94f3e59ae489b31dab96bc273ec3e80f760c0e6d54104225d68e9c693c895ea6140d5adc2945deac80784c95fd195079c2f6d551d8708e9ed7fa1c40779562f65b9f7a9c68a43825d5fdd02d3e807004e8527bb1a35a41c6c776940444304c50b12764bf4c72a86899454c527b48c942bebfdaac0f1fa095b0bfa3c17058631c9f96ae44de8d96172f0f1701cdcfff7ba5650e68d33895a0ed3c1611236d02ff27058812b10e5eef9c5d1ac2ac3b6c860e3accd0e8bb2bede0aa17995a7028ebaf55bf124774379a701349fde828b271c80b45b96010be95a82de5a6c2176db6e938ee1cc9fa4f2ab319821d4501b21ed1cd45d746f2ec08511efb38fcb0ee6c3e6273ba1448e6b2caa138caba78022a87f750b5f81036113db5b1c4c471615a5e4bdf01bc9078526ae8c780377fc0802ab1f0437255b6fbf9f6262c6e4211ccff69ff73c258d77ed46ed7b1c8ac478f8e737666ea3ef3c135193c66795992b0abfde0fc0db197050f301e1b0567b3eca5e76d19d8090c870429c75acdf26d0acc007b122eb47c1f8402d34dcdd75189f84e0f91299a126d8b27616cba8dd0ed0a84643fa69d61a81be5a760b3038dc0af7f1ea5cbffd58d441a73c4ff50be48e03d30c0cd2b2f0513c4babbce601bbe52c5b1008d0c4aef9180e8b099a7988434ad6bf4fdb42fab7357bc4982d99c000934222df4f2eb745f61d6d722ada564b31775fd8544384600c98ef5b904f020113af54fb11f0accd964b28e722bf75258f9dcce4d1b5f339baea5d03e28c2fd4057566bcafb59cabd79b5dca130a9f17290bf63df913fe34147a4eb2decdd2a3bb410453ea0a8844232d11f53a2e465a391628f3fb2380b98a5e1082be689652d98104140868884fcb3dd577a1ff66061fc91451ea145d88749a6448b25abfa2758b501ffb547b27230e46418b4a5461d98535f42b5e2b88c64f93a54b82b8d61ccd3f4c9b580546d401b13f653918a0a70b6577af9afbdfc7e498841faae99737af0cbeb110470ca61882ab79584bedadb5790c07e387d2a47028fbf7fec0e7497d8f9c699c91eb1a2d6beb2bd04d60149245a5951366a9cf614fa23a3386c5e22e85fbf88f726ae2bacf6b3c33399fdb08053f4480c4608b237d49386351f3f6741e61fcb497d7c469f5769af2bfbaf679f5f316857e20e8c1ddeffdb179231882f300f9313a173ed4985b098afc3e138192cc1382cf3d410cf4e0df1d71558be31ca8eacb90fefe3d2c67d943ce7ed21eaa988dbd0b643bb9af9b35adce13ea509ec7ff7830ead30e4adb2910eb4d496fd1331a117859627092a4ea93018851ce621b06a627e007f647dcfec8b1891cef2042bc519d9ad8870c8c4c0345fc0b9c24ba8f8b3071ea1c8a66694b0f042501cfd7d7691a640f74af20ba0f7ea46241648ea93d199b3ecb6fbf685475f1b983c3051ddd36f03d0172fa5c2fdf14dbf138cd52bb8bd0af35a214388bf71ad52ab9debb445515b3b48a0f9c408b82c924a106ba3295b222b8b1c650e510f49d451c7ef1d3eddb0d3051a55a6185ba687bbba4071982b08b5b2bc6464ab15605cec069d171de288f46a0567bf12932d4a8886be3d7091213104a46293ea5882b5198638408d3c0bd19484042e9b3b1dbd29fc5d1352a5b7b58bbe63e029c03e2d22dbb3900b1b5b243ad36f8b23a7992159b89cf63f669740087d021daf85469150bbf92a3fa906837b9b5eca443ea18c3f6971d713accfa5df983606fea8eef9773e6e160df3e975d17288c643f59efd4bf1472ba28e68110199314b556f1a3183f297fbb762437ea311177cc0ddebebcb936bac02922cf0310ae94e7f663151d3cf5c33a9e49a40ba253e29bc85cd219a29cf6a61fb973b24b73a80deb09872af5d7f81acbc5370b05e4611aec2612da1190c2b83fa2964abd05cbe506ef3caf218f36d81052d8b5289aac54f0dba03a1dece27ce4bf4118eba536b9d5635df1862fb0d618e8d78fa4fe17f8a443fb16b58f03956cf45f2d634379a7facafa10b6615b888121f91588a3aecd16da002cfcb2bf187f2898b1c0900b3645230d89676f3e61410b0b40443c44241593b5d41fbb6f19ea82ba65d9e7ce418866e9590a1aa4bf5634ae718e1dfe7ae06201b4d43f3f997f13f65d278e5cd209504c469925524bf1d7c6691dd9dcb00f3d1bb947a845c2861c1901b9b942adb8c167363dfcabf3c835dca19a4f7f40b09ad326af48629b5d9e7325f80f5ceb4be310a7daa34d0c9a4180dc3fdc2072a882e7dd50d2fcd28ca240033b59d9e5914291a60a0bd1fd027dce8a057915348849575724bf59c764b725afa691ad2173065243eb8dbd89607f614bbfc9a837b2127330c7fa55acf8516a0ffc6b7a69d48983b2847872e2431eca401641ae059ac311027311583c46e61493b98289b2f4475dcf5ba19113ac7eb210d394a830defbef3ed1f86fc6b8673e35f2aea03ae1b606b1c37f9c038ffbca0ccc5e2d2baf67792a1fc80cef0c68eaa174328bb215b9a406fc36373d764257510c2ee9abb6b7397e1bbf3fff7be5c17e7483721a3ae9619e74a565d041e3baeeaf92f9ba038d2920ce430c58ff38a0f10a1256d1bcd40a6ed37be232efc397c0be605f6f636e77ef7f20503b139069f6ffc9db53ecf840a895f6e1a852a2c64018c1e228b4bddd964c3a114f9635d2b9b87aae77d3aae82899a308367924ae9294890c80057cfb90b55a022126a47612a341953190eb852e201d913df37cece8f8ed4d998962ee4805cac1225d66b6c0e9bc581d283b8136b66255745d90b267bbe0a9d086bd5267c7dd20f260c58b13889a625c4f5cf07bf3f66128947192a5d86adfe6f4b888416ffcade888902f19cf9e06c98ef269b8e4f0558d5dbff59ef5c0b2db6e3c621e832f33ba697bf284be26e6a0596ae8561136581401dedb51c99dc2996128204e6b071812e7d43b0477553eaf01e32adee22d25d34f7279f68097c447d3a120532380b3a329291e908c947372c01c49e53c43d6108aa353b115530d2b7e0ef3e2bbb0196dbef804dc119831700663cbc62c72e3b7f5d51adbba33110849e5086fd371d4406d88135983da50f9c9baf98f87dab26c2902cef49166651066b0599c13c280d5877de7d96f75af5ee050085e36db66482921fdc44adf4886ca65779f2ae08ea95a1ff1b757808007903abd72496f61502ba526057e10e327263d2da4423cc2280ba8e1fdaf195904de03055be17bb39f0053b39f20a732a6a442ff3a5ecf8e667f314fb40baacb86340a1e132941b943f07085d0482578f38d10fa0e8ee78ab752ee0d94ca379973e089567452a341f390629a1395145dd9a808094c9381822ad5e123e5238d15982ddd893021a22a7ac80ece003a6786f44a59c8b6f9b1ff16463030729d824afb8ac004f5150e905f8ab0edec5f7b6a356cb44d41138bbadccb095e8c281483b4beb20fe79b33f3eebf09681f461db515681c8be5e3f90d1028ca6b303a1ab781d0614579166bc7cdf5972e1459d26ba589dbb74961f7ac627249f9e49e904923f3e14668584ea63683e02c329bdce46a2af27e70ee605543fec74fb74018645a6f5d5fff7f1933ded8318deff9ab982f25d900f3d07ff40434ac69267a5d9ba1e66a22e9215ea8bf448e2d24b28ad9fbd5e05fa4792cf548cc1ad5e0234caa21fd783c6e2a2916cfdd364a68127cd8e75f586a9345b10e85cac2c16765f93795124577878e4248070df8eda652202159f81c4f8565e7a2ed4a20b425c07ec75e0280184c90f4590661ffda3ba94521a5f8728090bdb959ccc5410b8ff4326a10012d73e3ea9f5328f91c77b17e8711b878a0df2afa4703b4523624c43bf2502275b84ab7e99bc354dfa61d7d53c927fe5e649427a7ad75f9741ea111b34a6fa6a84411c2f9e908431027c3830bfb60bfd01e4728d8384bd5de3ee698fdbbfa8bec48674fc8c4b97a"),
        0,
        36,
        1,
        68719476736,
    },
};
// @formatter:on

TEST(Secp256k1, RangeProofInfoSecp256k1Test) {
  struct secp256k1_context_struct *ctx = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(ctx);

  for (const RangeProofInfoTestVector& test_vector : range_proof_info_test_vectors) {
    int exponent;
    int mantissa;
    uint64_t min_value;
    uint64_t max_value;
    EXPECT_NO_THROW(secp.RangeProofInfoSecp256k1(test_vector.range_proof, &exponent, &mantissa, &min_value, &max_value));
    EXPECT_EQ(test_vector.expect_exp, exponent);
    EXPECT_EQ(test_vector.expect_mantissa, mantissa);
    EXPECT_EQ(test_vector.expect_minv, min_value);
    EXPECT_EQ(test_vector.expect_maxv, max_value);
  }
}

TEST(Secp256k1, RangeProofInfoSecp256k1ErrorTest) {
  struct secp256k1_context_struct *ctx = wally_get_secp_context();
  Secp256k1 secp = Secp256k1(ctx);

  int exponent;
  int mantissa;
  uint64_t min_value;
  uint64_t max_value;
  // empty range_proof
  {
    ByteData range_proof("");
    try {
      EXPECT_THROW(secp.RangeProofInfoSecp256k1(range_proof, &exponent, &mantissa, &min_value, &max_value), CfdException);
    } catch (const CfdException &cfd_exception) {
      EXPECT_EQ(cfd_exception.GetErrorCode(), CfdError::kCfdIllegalArgumentError);
      EXPECT_STREQ(cfd_exception.what(), "Secp256k1 empty range proof Error.");
    }
  }

  // invalid range_proof
  {
    ByteData range_proof("0000");
    try {
      EXPECT_THROW(secp.RangeProofInfoSecp256k1(range_proof, &exponent, &mantissa, &min_value, &max_value), CfdException);
    } catch (const CfdException &cfd_exception) {
      EXPECT_EQ(cfd_exception.GetErrorCode(), CfdError::kCfdIllegalArgumentError);
      EXPECT_STREQ(cfd_exception.what(), "Secp256k1 empty range proof Error.");
    }
  }
}
