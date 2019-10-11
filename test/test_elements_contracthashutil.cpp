#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_elements_script.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"

using cfd::core::Script;
using cfd::core::ContractHashUtil;
using cfd::core::CfdException;

TEST(ContractHashUtil, GetContractScriptMultisig1of1) {
  Script claim_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");
  Script fedpeg_script("512103198de2cfbd1cc09a15ce0eb8e23150243887e13c205a72ddbcf0ab1be529e79751ae");
  Script script;
  EXPECT_NO_THROW(
      (script = ContractHashUtil::GetContractScript(claim_script,
          fedpeg_script)));
  EXPECT_STREQ(
      script.GetHex().c_str(),
      "512102e822fbeefbfdc55f3577a5e78ad297a4bcbc1066c42c48561a4e2bd40b18248751ae");
}

TEST(ContractHashUtil, GetContractScript2of2) {
  Script claim_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");
  // 2-of-2 multisig
  Script fedpeg_script("5221032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db21030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a14352ae");
  Script script;
  EXPECT_NO_THROW(
      (script = ContractHashUtil::GetContractScript(claim_script,
          fedpeg_script)));
  EXPECT_STREQ(
      script.GetHex().c_str(),
      "522102aaf888b7e9fe586491887f65afd4d9c08f2791a74e6d60d3ebdac3d359cc26392102710f06a4fcdb7341b6410524dd920759d7d467ee76f525e586892f9ab63deff652ae");
}

TEST(ContractHashUtil, GetContractScriptLiquidV1) {
  Script claim_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");
  // LiquidV1 watchman script
  Script fedpeg_script("745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae");
  Script script;
  EXPECT_NO_THROW(
      (script = ContractHashUtil::GetContractScript(claim_script,
          fedpeg_script)));
  EXPECT_STREQ(
      script.GetHex().c_str(),
      "745c87635b210280b315645c20dc168f1798d0d5c1b67a2731dd1908a32a58781ec270e2c8a3762102642263762e43bd6300426a93bcfcfd2d246b04e68fcaeed9dce36feb82807a722103fdc313e1818b41672813e048245e2bd221fb7000fe25a6b35a282788d76c2b822102cb7d61eeab561306952c0310ffb51fa7da4655c9fed289ff169bb30cd9014f96210221d07d2cbf277a289f6e37bdc91b51ffe1cbb1e04b6c5639d7d1b91fd1c0c8cb21030cd1bf6e958c7927fb5cbb9f2dcb2e4ead183f8bba5f449a080d37890821e369210325183b219bb9e0912a72c0c5527e9ee4004efd29efcb44a2f665ec59fd1a21e8210344688ef7809c4097f7b54818b62e2d0f86658099d570a5aeea8a54a6bb7456ef2103e6a2c6f43d39b4bda721a1561e1147b0ef6a1318b0ebbff8390b08e8dbc457622102e6c5e0fc81c34c6f8689dafc83f5d2b0a6af3d889bf3ea616a0e51255c2d57e62103601f493cefa4803c095be1a0f0574ad0839a933970be407e3c93d2930b11328721030f6ae3b20a145cf6b546686ef68f190c7ab53ed0e89b54a47367bda62e9e6b042103c85c688115fa0bef8014954d68b5d34b00b1f64de5c900687c7e2f863f00818e2102d589c694cf5eda0f26222cc7248d0fe3b03a4ebc2e490866b76f121200d8b45e2102d2d74c40fe4fa9d08dd99e3ef61bab38fa6389ca9fdbe0c10e6030c3243b8d875f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae");
}

TEST(ContractHashUtil, GetContractScriptOpTrue) {
  Script claim_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");
  Script fedpeg_script("51");  // OP_TRUE
  Script script;
  EXPECT_NO_THROW(
      (script = ContractHashUtil::GetContractScript(claim_script,
          fedpeg_script)));
  EXPECT_STREQ(script.GetHex().c_str(), "51");
}

// @formatter:off
const std::vector<std::string> fedpeg_fail_test_vectors = {
  "512003c96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a14351ae",
  "5321030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a14351ae",
  "5121030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a14352ae",
  "5221030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a14352ae",
  "21032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db21030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a14352ae",
  "5221032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db21030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a143ae",
  "5221032f061438c62aa9a1685d7451a4bf1af8d0b8c132b0db4614147df19b687c01db21030dc96ba9b0dcce41a4b683164af15c045f0b169da1d1e234611a8cfc3195a14352",
};
// @formatter:on

TEST(ContractHashUtil, GetContractScriptFailFedpegScript) {
  Script claim_script("0014fd1cd5452a43ca210ba7153d64227dc32acf6dbb");
  Script script;
  for (std::string fedpeg_script : fedpeg_fail_test_vectors) {
    EXPECT_THROW(
        (script = ContractHashUtil::GetContractScript(claim_script,
            Script(fedpeg_script))), CfdException);
  }
}

#endif  // CFD_DISABLE_ELEMENTS
