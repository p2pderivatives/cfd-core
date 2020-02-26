#ifndef CFD_DISABLE_ELEMENTS
#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_bytedata.h"

using cfd::core::ScriptWitness;
using cfd::core::CfdException;
using cfd::core::ByteData;

TEST(ScriptWitness, GetterSetter) {
  // default constructor
  ScriptWitness witness;
  ByteData serialize_data;
  EXPECT_EQ(witness.GetWitnessNum(), 0);
  // check serialize data
  EXPECT_NO_THROW((serialize_data = witness.Serialize()));
  EXPECT_STREQ(serialize_data.GetHex().c_str(), "00");
  EXPECT_TRUE(witness.IsEmpty());

  EXPECT_NO_THROW(witness.AddWitnessStack(ByteData("00")));
  EXPECT_EQ(witness.GetWitnessNum(), 1);
  EXPECT_STREQ(witness.GetWitness()[0].GetHex().c_str(), "00");
  // check serialize data
  EXPECT_NO_THROW((serialize_data = witness.Serialize()));
  EXPECT_STREQ(serialize_data.GetHex().c_str(), "010100");
  EXPECT_FALSE(witness.IsEmpty());

  EXPECT_NO_THROW(witness.AddWitnessStack(ByteData("1111")));
  EXPECT_EQ(witness.GetWitnessNum(), 2);
  EXPECT_STREQ(witness.GetWitness()[0].GetHex().c_str(), "00");
  EXPECT_STREQ(witness.GetWitness()[1].GetHex().c_str(), "1111");
  // check serialize data
  EXPECT_NO_THROW((serialize_data = witness.Serialize()));
  EXPECT_STREQ(serialize_data.GetHex().c_str(), "020100021111");
  EXPECT_FALSE(witness.IsEmpty());

  EXPECT_NO_THROW(witness.AddWitnessStack(ByteData("222222")));
  EXPECT_EQ(witness.GetWitnessNum(), 3);
  EXPECT_STREQ(witness.GetWitness()[0].GetHex().c_str(), "00");
  EXPECT_STREQ(witness.GetWitness()[1].GetHex().c_str(), "1111");
  EXPECT_STREQ(witness.GetWitness()[2].GetHex().c_str(), "222222");
  // check serialize data
  EXPECT_NO_THROW((serialize_data = witness.Serialize()));
  EXPECT_STREQ(serialize_data.GetHex().c_str(), "03010002111103222222");
  EXPECT_FALSE(witness.IsEmpty());

  EXPECT_NO_THROW(witness.SetWitnessStack(1, ByteData("33333333")));
  EXPECT_EQ(witness.GetWitnessNum(), 3);
  EXPECT_STREQ(witness.GetWitness()[0].GetHex().c_str(), "00");
  EXPECT_STREQ(witness.GetWitness()[1].GetHex().c_str(), "33333333");
  EXPECT_STREQ(witness.GetWitness()[2].GetHex().c_str(), "222222");
  // check serialize data
  EXPECT_NO_THROW((serialize_data = witness.Serialize()));
  EXPECT_STREQ(serialize_data.GetHex().c_str(), "030100043333333303222222");
  EXPECT_FALSE(witness.IsEmpty());

  EXPECT_THROW(witness.SetWitnessStack(3, ByteData("4444444444")),
               CfdException);
  EXPECT_EQ(witness.GetWitnessNum(), 3);
  EXPECT_STREQ(witness.GetWitness()[0].GetHex().c_str(), "00");
  EXPECT_STREQ(witness.GetWitness()[1].GetHex().c_str(), "33333333");
  EXPECT_STREQ(witness.GetWitness()[2].GetHex().c_str(), "222222");
  // check serialize data
  EXPECT_NO_THROW((serialize_data = witness.Serialize()));
  EXPECT_STREQ(serialize_data.GetHex().c_str(), "030100043333333303222222");
  EXPECT_FALSE(witness.IsEmpty());
}

#endif  // CFD_DISABLE_ELEMENTS
