#include "gtest/gtest.h"
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_util.h"

using cfd::core::BlockHash;
using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::HashUtil;
using cfd::core::Pubkey;
using cfd::core::Script;
using cfd::core::ScriptUtil;

// ファイルごとに構造体の名前を変えること
struct ScriptUtil_PubkeyTestVector {
  Pubkey input_pubkey;
  Script expect_locking_script;
};

TEST(ScriptUtil, GetP2pkLockingScriptTest) {
  const std::vector<ScriptUtil_PubkeyTestVector> test_vectors = {
    {
      Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
      Script("2102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0ac")
    },
    {
      Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
      Script("210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590cac")
    },
    {
      Pubkey("04fe53c78e36b86aae8082484a4007b706d5678cabb92d178fc95020d4d8dc41ef44cfbb8dfa7a593c7910a5b6f94d079061a7766cbeed73e24ee4f654f1e51904"),
      Script("4104fe53c78e36b86aae8082484a4007b706d5678cabb92d178fc95020d4d8dc41ef44cfbb8dfa7a593c7910a5b6f94d079061a7766cbeed73e24ee4f654f1e51904ac")
    },
  };

  Script actual;
  for (const ScriptUtil_PubkeyTestVector& test_vector : test_vectors) {
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2pkLockingScript(test_vector.input_pubkey)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
  }
}

TEST(ScriptUtil, GetP2pkhLockingScriptTest) {
  const std::vector<ScriptUtil_PubkeyTestVector> test_vectors = {
    {
      Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
      Script("76a914edaf2414751239b72b653ea004adc310a3522e3788ac")
    },
    {
      Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
      Script("76a91449a011f97ba520dab063f309bad59daeb30de10188ac")
    },
    {
      Pubkey("04fe53c78e36b86aae8082484a4007b706d5678cabb92d178fc95020d4d8dc41ef44cfbb8dfa7a593c7910a5b6f94d079061a7766cbeed73e24ee4f654f1e51904"),
      Script("76a9148c1c7f335f5db8ae4e01615edb14844213ead72588ac")
    },
  };

  Script actual;
  for (const ScriptUtil_PubkeyTestVector& test_vector : test_vectors) {
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2pkhLockingScript(test_vector.input_pubkey)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
    ByteData160 pubkey_hash = HashUtil::Hash160(test_vector.input_pubkey);
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2pkhLockingScript(pubkey_hash)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
  }
}

TEST(ScriptUtil, GetP2wpkhLockingScriptTest) {
  const std::vector<ScriptUtil_PubkeyTestVector> test_vectors = {
    {
      Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
      Script("0014edaf2414751239b72b653ea004adc310a3522e37")
    },
    {
      Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
      Script("001449a011f97ba520dab063f309bad59daeb30de101")
    },
    {
      Pubkey("04fe53c78e36b86aae8082484a4007b706d5678cabb92d178fc95020d4d8dc41ef44cfbb8dfa7a593c7910a5b6f94d079061a7766cbeed73e24ee4f654f1e51904"),
      Script("00148c1c7f335f5db8ae4e01615edb14844213ead725")
    },
  };

  Script actual;
  for (const ScriptUtil_PubkeyTestVector& test_vector : test_vectors) {
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2wpkhLockingScript(test_vector.input_pubkey)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
    ByteData160 pubkey_hash = HashUtil::Hash160(test_vector.input_pubkey);
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2wpkhLockingScript(pubkey_hash)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
  }
}

// ファイルごとに構造体の名前を変えること
struct ScriptUtil_ScriptTestVector {
  Script input_redeem_script;
  Script expect_locking_script;
};

TEST(ScriptUtil, GetP2shLockingScriptTest) {
  const std::vector<ScriptUtil_ScriptTestVector> test_vectors = {
    {
      // 00 11 2222 333333 4444 55 6666 777777 8888 99
      Script("01000111022222033333330244440155026666037777770288880199"),
      Script("a914f1b3a2cc24eba8a741f963b309a7686f3bb6bfb487")
    },
    {
      // p2pkh locking script
      Script("76a914edaf2414751239b72b653ea004adc310a3522e3788ac"),
      Script("a914fc3ddf7d4677ad022910dabd15c1fd14f5e7a15b87")
    },
    {
      // p2wpkh locking script
      Script("0014edaf2414751239b72b653ea004adc310a3522e37"),
      Script("a91430cf0c44f55fe85b110d6bcdc771f1866c1f506f87")
    },
  };

  Script actual;
  for (const ScriptUtil_ScriptTestVector& test_vector : test_vectors) {
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2shLockingScript(test_vector.input_redeem_script)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
    ByteData160 script_hash = HashUtil::Hash160(test_vector.input_redeem_script);
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2shLockingScript(script_hash)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
  }
}

TEST(ScriptUtil, GetP2wshLockingScriptTest) {
  const std::vector<ScriptUtil_ScriptTestVector> test_vectors = {
    {
      // 00 11 2222 333333 4444 55 6666 777777 8888 99
      Script("01000111022222033333330244440155026666037777770288880199"),
      Script("002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437")
    },
    {
      // p2pkh locking script
      Script("76a914edaf2414751239b72b653ea004adc310a3522e3788ac"),
      Script("002049672615b13c511f9cef005d2290211c5924e28da4d68f5a8c6dfd1f108bf388")
    },
    {
      // p2wpkh locking script
      Script("0014edaf2414751239b72b653ea004adc310a3522e37"),
      Script("0020c1a9921421f2ac0e76533e25ca211e6a1f9465bdf9931f5e9039dbdfdace0fa4")
    },
  };

  Script actual;
  for (const ScriptUtil_ScriptTestVector& test_vector : test_vectors) {
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2wshLockingScript(test_vector.input_redeem_script)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
    ByteData256 script_hash = HashUtil::Sha256(test_vector.input_redeem_script);
    EXPECT_NO_THROW((actual = ScriptUtil::CreateP2wshLockingScript(script_hash)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_locking_script.GetHex().c_str());
  }
}

struct MultisigTestVector {
  uint32_t req_sig;
  std::vector<Pubkey> input_pubkeys;
  Script expect_multisig_script;
  std::string expect_message;
  bool is_witness;
};

TEST(ScriptUtil, CreateMultisigRedeemScriptTest) {
  const std::vector<MultisigTestVector> test_vectors = {
    // 1-of-1 Multisig
    {
      1,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
      },
      Script("512102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a051ae"),
      "",
      false
    },
    // 1-of-2 Multisig
    {
      1,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
      },
      Script("512102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c52ae"),
      "",
      false
    },
    // 2-of-3 Multisig
    {
      2,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
        Pubkey("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82"),
      },
      Script("522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae"),
      "",
      false
    },
    // 12-of-15 Multisig
    {
      12,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
        Pubkey("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82"),
        Pubkey("03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38"),
        Pubkey("020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1"),
        Pubkey("0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147"),
        Pubkey("0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c"),
        Pubkey("020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9"),
        Pubkey("0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37"),
        Pubkey("0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e"),
        Pubkey("03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b"),
        Pubkey("02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd"),
        Pubkey("0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d"),
        Pubkey("0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2"),
        Pubkey("025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db"),
      },
      Script("5c2102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b822103ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb3821020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1210289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147210210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c21020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9210289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37210254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e2103a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b2102ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd210289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d210396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd221025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db5fae"),
      "",
      false
    },
    // 15-of-15 Multisig
    {
      15,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
        Pubkey("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82"),
        Pubkey("03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38"),
        Pubkey("020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1"),
        Pubkey("0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147"),
        Pubkey("0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c"),
        Pubkey("020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9"),
        Pubkey("0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37"),
        Pubkey("0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e"),
        Pubkey("03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b"),
        Pubkey("02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd"),
        Pubkey("0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d"),
        Pubkey("0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2"),
        Pubkey("025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db"),
      },
      Script("5f2102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b822103ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb3821020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1210289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147210210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c21020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9210289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37210254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e2103a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b2102ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd210289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d210396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd221025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db5fae"),
      "",
      false
    },
    // 20-of-20 Multisig on witness
    {
      20,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
        Pubkey("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82"),
        Pubkey("03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38"),
        Pubkey("020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1"),
        Pubkey("0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147"),
        Pubkey("0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c"),
        Pubkey("020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9"),
        Pubkey("0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37"),
        Pubkey("0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e"),
        Pubkey("03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b"),
        Pubkey("02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd"),
        Pubkey("0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d"),
        Pubkey("0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2"),
        Pubkey("025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db"),
        Pubkey("030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55"),
        Pubkey("0267a49281bd9d6d366c39c62f2e95a2aab37638f2a4718891c542d0961962644e"),
        Pubkey("02f48e8e2bcaeb16a6d781bb7a72f6250607bf21e32f08c48e37a9e4706e6d48b8"),
        Pubkey("03968ac57888ddaa3b57caa39efd5d5382c24f3deed602775cd4895f7c7adb5950"),
        Pubkey("024b64115bff6cc3718867114f7594fad535344f27ebe17ffa0e66288eb7bd2561"),
      },
      Script("01142102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b822103ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb3821020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1210289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147210210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c21020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9210289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37210254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e2103a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b2102ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd210289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d210396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd221025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db21030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55210267a49281bd9d6d366c39c62f2e95a2aab37638f2a4718891c542d0961962644e2102f48e8e2bcaeb16a6d781bb7a72f6250607bf21e32f08c48e37a9e4706e6d48b82103968ac57888ddaa3b57caa39efd5d5382c24f3deed602775cd4895f7c7adb595021024b64115bff6cc3718867114f7594fad535344f27ebe17ffa0e66288eb7bd25610114ae"),
      "",
      true
    },
  };

  Script actual;
  for (MultisigTestVector test_vector : test_vectors) {
    try {
      actual = ScriptUtil::CreateMultisigRedeemScript(
          test_vector.req_sig, test_vector.input_pubkeys,
          test_vector.is_witness);
      EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_multisig_script.GetHex().c_str());
    } catch (const CfdException& except) {
      EXPECT_STREQ(except.what(), "");
      EXPECT_EQ(test_vector.req_sig, 0);
    }
  }
}

TEST(ScriptUtil, CreateMultisigRedeemScriptErrorTest) {
  const std::vector<MultisigTestVector> test_vectors = {
    // 0-of-1 Multisig
    {
      0,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
      },
      Script(),
      "CreateMultisigScript require_num is 0.",
      false
    },
    // 1-of-0 Multisig
    {
      1,
      {
      },
      Script(),
      "CreateMultisigScript empty pubkey array.",
      false
    },
    // 3-of-2 Multisig
    {
      3,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
      },
      Script(),
      "CreateMultisigScript require_num is over.",
      false
    },
    // 1-of-16 Multisig
    {
      1,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
        Pubkey("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82"),
        Pubkey("03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38"),
        Pubkey("020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1"),
        Pubkey("0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147"),
        Pubkey("0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c"),
        Pubkey("020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9"),
        Pubkey("0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37"),
        Pubkey("0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e"),
        Pubkey("03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b"),
        Pubkey("02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd"),
        Pubkey("0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d"),
        Pubkey("0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2"),
        Pubkey("025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db"),
        Pubkey("030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55"),
      },
      Script(),
      "CreateMultisigScript pubkeys array size is over.",
      false
    },
    // 1-of-21 Multisig on witness
    {
      1,
      {
        Pubkey("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0"),
        Pubkey("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c"),
        Pubkey("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82"),
        Pubkey("03ce982e13798960b7c23fd2c1676f64ff6df80f75324d0e566432e2a884dafb38"),
        Pubkey("020bac40bcc23dd9b33a32b8183d2e9e79eb976bcfb2247141da1e58b2970bfde1"),
        Pubkey("0289d8f0fb8cbd369a9aad28070edf2e99544384c122b8af825e50ea219193f147"),
        Pubkey("0210fcaf81018c3f304ca792c9c1809ec00b159e23ebde669486c62787818f315c"),
        Pubkey("020847e443a4d6b9ea577b776ca232c5dc9a3cbbd6c82dde0ef5100ac6c5a36cf9"),
        Pubkey("0289e210d82121823dc5af09a0ab8c23d4a52273358295f4e4596b0f98e4973e37"),
        Pubkey("0254de5471d6c8b36c26a62e0b54385fe0e88563e34127c18e97e705f83172326e"),
        Pubkey("03a9c473d65af0420e600e085be058f98ac0634d13390e5d8d4962cbcfeb75422b"),
        Pubkey("02ebcde0a7ece63e607287af1542efddeb008b0d1693da2ca06b622ebaf92051dd"),
        Pubkey("0289b2b5852ffd7b89266338d746e05e7afe33e6005dab198b6a4b13065b93a89d"),
        Pubkey("0396436fd20f3c5d3638c8ed4195cf63b4467701c5d4de660bd9bced68f4588cd2"),
        Pubkey("025dffce0b5e131808a630d0d8769d22ead71fddf336836916c5906676e13394db"),
        Pubkey("030023121bed4585fdfea023aee4c7f9731e3cfa6b2a8ec21a159615d2bad57e55"),
        Pubkey("0267a49281bd9d6d366c39c62f2e95a2aab37638f2a4718891c542d0961962644e"),
        Pubkey("02f48e8e2bcaeb16a6d781bb7a72f6250607bf21e32f08c48e37a9e4706e6d48b8"),
        Pubkey("03968ac57888ddaa3b57caa39efd5d5382c24f3deed602775cd4895f7c7adb5950"),
        Pubkey("024b64115bff6cc3718867114f7594fad535344f27ebe17ffa0e66288eb7bd2561"),
        Pubkey("03f3aba2366b71f8473dd8dd4186005a9e3c6f9a32f76fc45493fd2a78b78c0d8d"),
      },
      Script(),
      "CreateMultisigScript pubkeys array size is over.",
      true
    },
  };

  Script actual;
  for (MultisigTestVector test_vector : test_vectors) {
    try{
      EXPECT_THROW((actual = ScriptUtil::CreateMultisigRedeemScript(
          test_vector.req_sig, test_vector.input_pubkeys,
          test_vector.is_witness)), CfdException);
    } catch (CfdException &e) {
      EXPECT_STREQ(e.what(), test_vector.expect_message.c_str());
    }
  }
}

TEST(ScriptUtil, IsValidRedeemScriptTest) {
  // valid script data
  Script empty_script("");
  EXPECT_TRUE(ScriptUtil::IsValidRedeemScript(empty_script));

  // valid script data
  Script valid_script_1("01000111022222033333330244440155026666037777770288880199");
  EXPECT_TRUE(ScriptUtil::IsValidRedeemScript(valid_script_1));

  // valid limit script data size ((1 + 51) * 10 byte data)
  Script valid_script_2("33000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_TRUE(ScriptUtil::IsValidRedeemScript(valid_script_2));

  // invalid script data ((1 + 51) * 10 + 1 byte data)
  Script invalid_script("3300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_FALSE(ScriptUtil::IsValidRedeemScript(invalid_script));
}

#ifndef CFD_DISABLE_ELEMENTS

struct PegoutTestVector {
  BlockHash genesisblock_hash;
  Script parent_locking_script;
  Pubkey btc_pubkey_bytes;
  ByteData whitelist_proof;
  Script expect_script;
};

TEST(ScriptUtil, CreatePegoutLogkingScriptTest) {
  std::vector<PegoutTestVector> test_vectors = {
    {
      BlockHash(),
      Script(),
      Pubkey(),
      ByteData(),
      Script("6a0000"),
    },
    {
      BlockHash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
      Script("a914f1b3a2cc24eba8a741f963b309a7686f3bb6bfb487"),
      Pubkey("03d12ccde87bdbed99cdad58f4eeab0db9c8d52810133d3ed9aaf6cd802a33a57c"),
      ByteData("01044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d0066"),
      Script("6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f17a914f1b3a2cc24eba8a741f963b309a7686f3bb6bfb4872103d12ccde87bdbed99cdad58f4eeab0db9c8d52810133d3ed9aaf6cd802a33a57c4101044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d0066"),
    },
    {
      BlockHash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
      Script("002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"),
      Pubkey("03d12ccde87bdbed99cdad58f4eeab0db9c8d52810133d3ed9aaf6cd802a33a57c"),
      ByteData("01044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d0066"),
      Script("6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f22002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a4372103d12ccde87bdbed99cdad58f4eeab0db9c8d52810133d3ed9aaf6cd802a33a57c4101044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d0066"),
    },
    // invalid Pubkey
    {
      BlockHash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
      Script("002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"),
      Pubkey(),
      ByteData("01044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d0066"),
      Script("6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f22002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"),
    },
    // empty whitelist proof
    {
      BlockHash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
      Script("002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"),
      Pubkey("03d12ccde87bdbed99cdad58f4eeab0db9c8d52810133d3ed9aaf6cd802a33a57c"),
      ByteData(),
      Script("6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f22002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"),
    },
    // invalid Pubkey and empty whitelist proof
    {
      BlockHash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
      Script("002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"),
      Pubkey(),
      ByteData(),
      Script("6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f22002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"),
    },
  };

  Script actual;
  for (PegoutTestVector test_vector : test_vectors) {
    EXPECT_NO_THROW((actual = ScriptUtil::CreatePegoutLogkingScript(test_vector.genesisblock_hash, test_vector.parent_locking_script, test_vector.btc_pubkey_bytes, test_vector.whitelist_proof)));
    EXPECT_STREQ(actual.GetHex().c_str(), test_vector.expect_script.GetHex().c_str());
  }
}

#endif  // CFD_DISABLE_ELEMENTS


TEST(ScriptUtil, ExtractPubkeysFromMultisigScript) {
  // valid script data
  Script script("5e2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec521032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db21030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a1432102927b60e6bdbd728009e7e19feb4700a04f25328929730a609471b8e236ff050a2102ff43fd9fdb705d223951806f349dd2090edc4d971eb1c2a60c48cfb2af2862e72102ce1316489880a77407f9637af4e806c5a7e731b45504d6f3fca506b207f8e3c12102b12d700c4d851f773c55d17d9f59bf689a7cbdc01450c8679de9702fc77ac4f22103f6d4cfd7688da7a130ea0f6bd7ecaa6e7ae868ae8614cd746c26b1cb9e808e6021022ac6940d159cd39b36cb4a2ec34fb2696e085be634ce1e7b5fcc118a6ac5e2cc2102e9662b666479ed7117aa76fb96f322a84408d0882707b301c7450098d439680d2103c0230a322f70675bef21097242ac70647798826588e47eca14e5715cef77008c2102063566b61b4754dc2956b3571bdce889decc23c789d6b58df0057808b20e66d821033acbe038580c25da0c0c6e94c4dcbfa9c09f2f3bff59ae16aebfbd35a238a5572103a1423fc026f41f3f786db98a793802f77819e33692301ed24426e6dbad05aeaa2102818c3deec9c1f717cd6d97d2d9cf6cedfc9d97114fc6894ef71d4e1f69d859c45fae");
  uint32_t reqnum = 0;
  std::vector<Pubkey> pubkeys;
  EXPECT_NO_THROW(pubkeys = ScriptUtil::ExtractPubkeysFromMultisigScript(script, &reqnum));
  EXPECT_EQ(pubkeys.size(), 15);
  EXPECT_EQ(reqnum, 14);
  if (pubkeys.size() == 15) {
    EXPECT_STREQ(pubkeys[0].GetHex().c_str(),
        "02be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec5");
    EXPECT_STREQ(pubkeys[1].GetHex().c_str(),
        "032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db");
    EXPECT_STREQ(pubkeys[2].GetHex().c_str(),
        "030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a143");
    EXPECT_STREQ(pubkeys[3].GetHex().c_str(),
        "02927b60e6bdbd728009e7e19feb4700a04f25328929730a609471b8e236ff050a");
    EXPECT_STREQ(pubkeys[4].GetHex().c_str(),
        "02ff43fd9fdb705d223951806f349dd2090edc4d971eb1c2a60c48cfb2af2862e7");
    EXPECT_STREQ(pubkeys[5].GetHex().c_str(),
        "02ce1316489880a77407f9637af4e806c5a7e731b45504d6f3fca506b207f8e3c1");
    EXPECT_STREQ(pubkeys[6].GetHex().c_str(),
        "02b12d700c4d851f773c55d17d9f59bf689a7cbdc01450c8679de9702fc77ac4f2");
    EXPECT_STREQ(pubkeys[7].GetHex().c_str(),
        "03f6d4cfd7688da7a130ea0f6bd7ecaa6e7ae868ae8614cd746c26b1cb9e808e60");
    EXPECT_STREQ(pubkeys[8].GetHex().c_str(),
        "022ac6940d159cd39b36cb4a2ec34fb2696e085be634ce1e7b5fcc118a6ac5e2cc");
    EXPECT_STREQ(pubkeys[9].GetHex().c_str(),
        "02e9662b666479ed7117aa76fb96f322a84408d0882707b301c7450098d439680d");
    EXPECT_STREQ(pubkeys[10].GetHex().c_str(),
        "03c0230a322f70675bef21097242ac70647798826588e47eca14e5715cef77008c");
    EXPECT_STREQ(pubkeys[11].GetHex().c_str(),
        "02063566b61b4754dc2956b3571bdce889decc23c789d6b58df0057808b20e66d8");
    EXPECT_STREQ(pubkeys[12].GetHex().c_str(),
        "033acbe038580c25da0c0c6e94c4dcbfa9c09f2f3bff59ae16aebfbd35a238a557");
    EXPECT_STREQ(pubkeys[13].GetHex().c_str(),
        "03a1423fc026f41f3f786db98a793802f77819e33692301ed24426e6dbad05aeaa");
    EXPECT_STREQ(pubkeys[14].GetHex().c_str(),
        "02818c3deec9c1f717cd6d97d2d9cf6cedfc9d97114fc6894ef71d4e1f69d859c4");
  }

  Script illegal_script("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");
  EXPECT_THROW(ScriptUtil::ExtractPubkeysFromMultisigScript(illegal_script, &reqnum),
      CfdException);
}
