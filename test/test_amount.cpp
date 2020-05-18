#include "gtest/gtest.h"
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"

// https://qiita.com/yohm/items/477bac065f4b772127c7

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::Amount;
using cfd::core::ByteData;
using cfd::core::CfdException;

//! bitcoinとsatoshi単位の変換に用いる因数(10^8)
static const int64_t kCoinBase = 100000000;
/**
 * @brief satoshi単位の最大値
 * @details 厳密には流通通貨の最大値とは異なるが、bitcoin coreに合わせて限度額を設定
 * @see https://github.com/bitcoin/bitcoin/blob/e756eca9e8bf39f0a891f1760df0a317ecb7fee8/src/amount.h#L25
 */
static const int64_t kMaxAmount = 21000000 * kCoinBase;

TEST(Amount, EmptyInstanceTest) {
  const double expect_coin_val = 0;
  Amount amt;
  EXPECT_DOUBLE_EQ(expect_coin_val, amt.GetCoinValue());
  EXPECT_EQ((expect_coin_val * kCoinBase), amt.GetSatoshiValue());
}

TEST(Amount, CreateInstanceTest) {
  const double expect_coin_val = 1.2;
  Amount amt = Amount::CreateByCoinAmount(expect_coin_val);
  EXPECT_DOUBLE_EQ(expect_coin_val, amt.GetCoinValue());
  EXPECT_EQ((expect_coin_val * kCoinBase), amt.GetSatoshiValue());

  const int64_t expect_satoshi_val = 240000000;
  amt = Amount::CreateBySatoshiAmount(expect_satoshi_val);
  EXPECT_DOUBLE_EQ((static_cast<double>(expect_satoshi_val) / kCoinBase),
                   amt.GetCoinValue());
  EXPECT_EQ(expect_satoshi_val, amt.GetSatoshiValue());

  const int expect_satoshi_ival = 240000000;
  amt = Amount(expect_satoshi_ival);
  EXPECT_EQ(expect_satoshi_val, amt.GetSatoshiValue());

  const uint32_t expect_satoshi_uval = 240000000;
  amt = Amount(expect_satoshi_uval);
  EXPECT_EQ(expect_satoshi_val, amt.GetSatoshiValue());
}

TEST(Amount, LimitTest) {
  const int64_t lower_limit_satoshi_val = 0;
  Amount amt = Amount::CreateBySatoshiAmount(0);
  ASSERT_THROW(
      (amt = Amount::CreateBySatoshiAmount(lower_limit_satoshi_val - 1)),
      CfdException);
  ASSERT_NO_THROW(
      (amt = Amount::CreateBySatoshiAmount(lower_limit_satoshi_val)));
  EXPECT_EQ(lower_limit_satoshi_val, amt.GetSatoshiValue());
  ASSERT_NO_THROW(
      (amt = Amount::CreateBySatoshiAmount(lower_limit_satoshi_val + 1)));
  EXPECT_EQ((lower_limit_satoshi_val + 1), amt.GetSatoshiValue());

  const int64_t uppper_limit_satoshi_val = kMaxAmount;
  ASSERT_NO_THROW(
      (amt = Amount::CreateBySatoshiAmount(uppper_limit_satoshi_val - 1)));
  EXPECT_EQ((uppper_limit_satoshi_val - 1), amt.GetSatoshiValue());
  ASSERT_NO_THROW(
      (amt = Amount::CreateBySatoshiAmount(uppper_limit_satoshi_val)));
  EXPECT_EQ(uppper_limit_satoshi_val, amt.GetSatoshiValue());
  ASSERT_THROW(
      (amt = Amount::CreateBySatoshiAmount(uppper_limit_satoshi_val + 1)),
      CfdException);

  // unlimit test
  const int64_t uppper_limitover_satoshi = int64_t{90000000000000000};
  ASSERT_NO_THROW((amt = Amount(uppper_limitover_satoshi, true)));
  EXPECT_EQ(uppper_limitover_satoshi, amt.GetSatoshiValue());

  // exception check CreateCoinAmount
  // lower
  ASSERT_THROW(
      (amt = Amount::CreateByCoinAmount(
          static_cast<double>(lower_limit_satoshi_val - 1)) / kCoinBase),
      CfdException);
  // upper
  ASSERT_THROW(
      (amt = Amount::CreateByCoinAmount(
          static_cast<double>(uppper_limit_satoshi_val + 1) / kCoinBase)),
      CfdException);
}

TEST(Amount, ComparisonOperatorsTest) {
  const int64_t base_satoshi_val = 1234567890;
  Amount base_amt = Amount::CreateBySatoshiAmount(base_satoshi_val);
  // compare
  const int64_t nq_satoshi_val = 1234567891;
  // equal
  EXPECT_TRUE(base_satoshi_val == base_amt);
  EXPECT_FALSE(nq_satoshi_val == base_amt);
  EXPECT_TRUE(base_amt == base_satoshi_val);
  EXPECT_FALSE(base_amt == nq_satoshi_val);
  EXPECT_TRUE(base_amt == Amount::CreateBySatoshiAmount(base_satoshi_val));
  EXPECT_FALSE(base_amt == Amount::CreateBySatoshiAmount(nq_satoshi_val));
  // not equal
  EXPECT_TRUE(nq_satoshi_val != base_amt);
  EXPECT_FALSE(base_satoshi_val != base_amt);
  EXPECT_TRUE(base_amt != nq_satoshi_val);
  EXPECT_FALSE(base_amt != base_satoshi_val);
  EXPECT_TRUE(base_amt != Amount::CreateBySatoshiAmount(nq_satoshi_val));
  EXPECT_FALSE(base_amt != Amount::CreateBySatoshiAmount(base_satoshi_val));
  // less
  EXPECT_FALSE(nq_satoshi_val < base_amt);
  EXPECT_FALSE(base_satoshi_val < base_amt);
  EXPECT_TRUE(base_amt < nq_satoshi_val);
  EXPECT_FALSE(base_amt < base_satoshi_val);
  EXPECT_FALSE(Amount::CreateBySatoshiAmount(nq_satoshi_val) < base_amt);
  EXPECT_FALSE(Amount::CreateBySatoshiAmount(base_satoshi_val) < base_amt);
  EXPECT_TRUE(base_amt < Amount::CreateBySatoshiAmount(nq_satoshi_val));
  EXPECT_FALSE(base_amt < Amount::CreateBySatoshiAmount(base_satoshi_val));
  // greater
  EXPECT_TRUE(nq_satoshi_val > base_amt);
  EXPECT_FALSE(base_satoshi_val > base_amt);
  EXPECT_FALSE(base_amt > nq_satoshi_val);
  EXPECT_FALSE(base_amt > base_satoshi_val);
  EXPECT_TRUE(Amount::CreateBySatoshiAmount(nq_satoshi_val) > base_amt);
  EXPECT_FALSE(Amount::CreateBySatoshiAmount(base_satoshi_val) > base_amt);
  EXPECT_FALSE(base_amt > Amount::CreateBySatoshiAmount(nq_satoshi_val));
  EXPECT_FALSE(base_amt > Amount::CreateBySatoshiAmount(base_satoshi_val));
  // less or equal
  EXPECT_FALSE(nq_satoshi_val <= base_amt);
  EXPECT_TRUE(base_satoshi_val <= base_amt);
  EXPECT_TRUE(base_amt <= nq_satoshi_val);
  EXPECT_TRUE(base_amt <= base_satoshi_val);
  EXPECT_FALSE(Amount::CreateBySatoshiAmount(nq_satoshi_val) <= base_amt);
  EXPECT_TRUE(Amount::CreateBySatoshiAmount(base_satoshi_val) <= base_amt);
  EXPECT_TRUE(base_amt <= Amount::CreateBySatoshiAmount(nq_satoshi_val));
  EXPECT_TRUE(base_amt <= Amount::CreateBySatoshiAmount(base_satoshi_val));
  // greater or equal
  EXPECT_TRUE(nq_satoshi_val >= base_amt);
  EXPECT_TRUE(base_satoshi_val >= base_amt);
  EXPECT_FALSE(base_amt >= nq_satoshi_val);
  EXPECT_TRUE(base_amt >= base_satoshi_val);
  EXPECT_TRUE(Amount::CreateBySatoshiAmount(nq_satoshi_val) >= base_amt);
  EXPECT_TRUE(Amount::CreateBySatoshiAmount(base_satoshi_val) >= base_amt);
  EXPECT_FALSE(base_amt >= Amount::CreateBySatoshiAmount(nq_satoshi_val));
  EXPECT_TRUE(base_amt >= Amount::CreateBySatoshiAmount(base_satoshi_val));
}

TEST(Amount, ArithmeticOperatorsTest) {
  int64_t base_satoshi_val = 12345;
  Amount base_amt = Amount::CreateBySatoshiAmount(base_satoshi_val);
  // arithmetic operators
  Amount rh_amt = Amount::CreateBySatoshiAmount(1);
  // addition
  EXPECT_EQ((base_satoshi_val + 1), (base_amt + 1));
  EXPECT_EQ((base_satoshi_val + 1), (base_amt + rh_amt));
  EXPECT_EQ((1 + base_satoshi_val), (1 + base_amt));
  // subtraction
  EXPECT_EQ((base_satoshi_val - 1), (base_amt - 1));
  EXPECT_EQ((base_satoshi_val - 1), (base_amt - rh_amt));
  EXPECT_EQ((123456 - base_satoshi_val), (123456 - base_amt));
  // multiplication
  EXPECT_EQ((base_satoshi_val * 2), (base_amt * 2));
  EXPECT_EQ((2 * base_satoshi_val), (2 * base_amt));
  // division
  EXPECT_EQ((base_satoshi_val / 5), (base_amt / 5));

  // assignment operators
  // addition assignment
  EXPECT_EQ((base_satoshi_val += 1), (base_amt += 1));
  EXPECT_EQ((base_satoshi_val += 1), (base_amt += rh_amt));
  // subtraction assignment
  EXPECT_EQ((base_satoshi_val -= 1), (base_amt -= 1));
  EXPECT_EQ((base_satoshi_val -= 1), (base_amt -= rh_amt));
  // multiplication assignment
  EXPECT_EQ((base_satoshi_val *= 2), (base_amt *= 2));
  // division assignment
  EXPECT_EQ((base_satoshi_val /= 2), (base_amt /= 2));
}

TEST(Amount, GetByteDataTest) {
  int64_t base_satoshi_val = 12345;
  Amount base_amt = Amount::CreateBySatoshiAmount(base_satoshi_val);
  ByteData byte_data;
  EXPECT_NO_THROW((byte_data = base_amt.GetByteData()));
  EXPECT_STREQ("3930000000000000", byte_data.GetHex().c_str());

  int64_t bit64_satoshi_val = 2090000000000000;
  Amount bit64_amt = Amount::CreateBySatoshiAmount(bit64_satoshi_val);
  EXPECT_NO_THROW((byte_data = bit64_amt.GetByteData()));
  EXPECT_STREQ("00a0940bd86c0700", byte_data.GetHex().c_str());
}
