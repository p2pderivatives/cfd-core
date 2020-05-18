#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::BlindFactor;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdException;

TEST(BlindFactor, Constractor) {
  BlindFactor blind_factor;

  EXPECT_STREQ(
      blind_factor.GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_STREQ(
      blind_factor.GetData().GetHex().c_str(),
      "0000000000000000000000000000000000000000000000000000000000000000");
  EXPECT_TRUE(blind_factor.IsEmpty());
}

TEST(BlindFactor, Constractor_hex_empty) {
  EXPECT_THROW(BlindFactor blind_factor(""), CfdException);
}

TEST(BlindFactor, Constractor_hex) {
  BlindFactor blind_factor(
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_STREQ(
      blind_factor.GetHex().c_str(),
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_STREQ(
      blind_factor.GetData().GetHex().c_str(),
      "7981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18");
  EXPECT_FALSE(blind_factor.IsEmpty());
}

TEST(BlindFactor, Constractor_hex_err) {
  EXPECT_THROW(BlindFactor blind_factor("112233"), CfdException);
}

TEST(BlindFactor, Constractor_bytedata256) {
  ByteData256 bytedata(
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  BlindFactor blind_factor(bytedata);
  EXPECT_STREQ(
      blind_factor.GetHex().c_str(),
      "7981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18");
  EXPECT_STREQ(
      blind_factor.GetData().GetHex().c_str(),
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_FALSE(blind_factor.IsEmpty());
}

TEST(BlindFactor, Constractor_bytedata) {
  ByteData bytedata(
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  BlindFactor blind_factor(bytedata);
  EXPECT_STREQ(
      blind_factor.GetHex().c_str(),
      "7981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c18");
  EXPECT_STREQ(
      blind_factor.GetData().GetHex().c_str(),
      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_FALSE(blind_factor.IsEmpty());
  ByteData bytedata_err(
      "7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179");
  EXPECT_THROW((blind_factor = BlindFactor(bytedata_err)), CfdException);
}

#endif  // CFD_DISABLE_ELEMENTS
