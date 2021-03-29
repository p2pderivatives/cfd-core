// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_amount.h
 *
 * @brief The amount related class definition.
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_AMOUNT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_AMOUNT_H_

#include <cstdint>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"

/**
 * @brief cfd namespace
 */
namespace cfd {
/**
 * @brief cfd::core namespace
 */
namespace core {

//! Factors used to convert bitcoin and satoshi units(10^8)
static constexpr int64_t kCoinBase = 100000000;
/**
 * @brief Maximum value in satoshi unit.
 * @details Strictly speaking, it is different from the maximum \
 *   value of the currency in circulation, but the limit is \
 *   set according to the bitcoin core.
 * @see https://github.com/bitcoin/bitcoin/blob/e756eca9e8bf39f0a891f1760df0a317ecb7fee8/src/amount.h#L25
 */
static constexpr int64_t kMaxAmount = 21000000 * kCoinBase;

/**
 * @brief A class that represents Bitcoin's Amount.
 */
class CFD_CORE_EXPORT Amount {
 public:
  /**
   * @brief Create Amount instance by amount satoshi units
   * @param[in] amount amount in satoshi units
   * @return instance of Amount class
   * @exception CfdException if invalid value passed
   */
  static Amount CreateBySatoshiAmount(int64_t amount);

  /**
   * @brief Create Amount instance by amount bitcoin units
   * @param[in] coin_amount amount in bitcoin units
   * @return instance of Amount class
   * @exception CfdException if invalid value passed
   */
  static Amount CreateByCoinAmount(double coin_amount);

  /**
   * @brief Create Amount instance by amount satoshi units
   * @param[in] amount amount in satoshi units
   * @exception CfdException if invalid value passed
   */
  explicit Amount(int64_t amount);
  /**
   * @brief Create Amount instance by amount satoshi units
   * @param[in] amount amount in satoshi units
   * @exception CfdException if invalid value passed
   */
  explicit Amount(int amount);
  /**
   * @brief Create Amount instance by amount satoshi units
   * @param[in] amount amount in satoshi units
   * @exception CfdException if invalid value passed
   */
  explicit Amount(uint32_t amount);
  /**
   * @brief Create Amount instance by amount bitcoin units
   * @param[in] coin_amount amount in bitcoin units
   * @exception CfdException if invalid value passed
   */
  explicit Amount(double coin_amount);
  /**
   * @brief Create Amount instance by amount satoshi units
   * @param[in] amount amount in satoshi units
   * @param[in] ignore_check ignore valid check
   * @exception CfdException if invalid value passed
   */
  explicit Amount(int64_t amount, bool ignore_check);

  /**
   * @brief Get the Amount amount in satoshi units from object.
   * @return Amount value in satoshi units.
   */
  int64_t GetSatoshiValue() const;

  /**
   * @brief Get the Amount amount in bitcoin units from object.
   * @details Note that double precision errors may occur.
   * @return Amount value in bitcoin units.
   */
  double GetCoinValue() const;
  /**
   * @brief Get ByteData by BigEndian.
   * @return satoshi's ByteData
   */
  ByteData GetByteData() const;

  // operator overloading
  /**
   * @brief Equals operator.
   * @param[in] amount  Amount instance
   * @retval true equals
   * @retval false not equals
   */
  bool operator==(const Amount &amount) const;
  /**
   * @brief Equals operator.
   * @param[in] satoshi_amount  amount in satoshi units
   * @retval true equals
   * @retval false not equals
   */
  bool operator==(const int64_t satoshi_amount) const;
  /**
   * @brief not equals operator.
   * @param[in] amount  Amount instance
   * @retval true not equals
   * @retval false equals
   */
  bool operator!=(const Amount &amount) const;
  /**
   * @brief not equals operator.
   * @param[in] satoshi_amount  amount in satoshi units
   * @retval true not equals
   * @retval false equals
   */
  bool operator!=(const int64_t satoshi_amount) const;
  /**
   * @brief Addition operator (Amount += Amount)
   * @param[in] amount  Amount instance
   * @return Amount instance
   */
  Amount operator+=(const Amount &amount);
  /**
   * @brief Addition operator(Amount += int64_t)
   * @param[in] satoshi_amount  加数 amount in satoshi units
   * @return Amount instance
   */
  Amount operator+=(const int64_t satoshi_amount);
  /**
   * @brief Subtraction operator(Amount -= Amount)
   * @param[in] amount  Amount instance
   * @return Amount instance
   */
  Amount operator-=(const Amount &amount);
  /**
   * @brief Subtraction operator(Amount -= int64_t)
   * @param[in] satoshi_amount  amount in satoshi units
   * @return Amount instance
   */
  Amount operator-=(const int64_t satoshi_amount);
  /**
   * @brief Multiplication operator(Amount *= int64_t)
   * @param[in] value     multiplier
   * @return Amount instance
   */
  Amount operator*=(const int64_t value);
  /**
   * @brief Division operator(Amount /= int64_t)
   * @param[in] value     divisor
   * @return Amount instance
   */
  Amount operator/=(const int64_t value);

  /**
   * @brief default constructor.
   */
  Amount();

 private:
  //! amount in satoshi units
  int64_t amount_;
  //! ignore valid check flag.
  bool ignore_check_;

  /**
   * @brief Verify that the amount is not invalid.
   * @param[in] amount  amount in satoshi units
   * @retval true   valid
   * @retval false  invalid
   */
  static bool IsValidAmount(int64_t amount) {
    return (amount >= 0 && amount <= kMaxAmount);
  }

  /**
   * @brief 引数で与えられたsatoshi単位のAmountが不正な値でないかを検証する.
   * @param[in] satoshi_amount  amount in satoshi units
   * @exception CfdException  If an invalid value is passed
   */
  static void CheckValidAmount(int64_t satoshi_amount);
};

/**
 * @brief Equals operator.
 * @param[in] satoshi_amount  amount in satoshi units
 * @param[in] amount          Amount instance
 * @retval true equals
 * @retval false not equals
 */
CFD_CORE_EXPORT bool operator==(
    const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief not equals operator.
 * @param[in] satoshi_amount  amount in satoshi units
 * @param[in] amount          Amount instance
 * @retval true not equals
 * @retval false equals
 */
CFD_CORE_EXPORT bool operator!=(
    const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is less than rhs
 * @retval false lhs is greater than or equal rhs
 */
CFD_CORE_EXPORT bool operator<(const Amount &lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(int64_t)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is less than rhs
 * @retval false lhs is greater than or equal rhs
 */
CFD_CORE_EXPORT bool operator<(const int64_t lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(int64_t)
 * @retval true lhs is less than rhs
 * @retval false lhs is greater than or equal rhs
 */
CFD_CORE_EXPORT bool operator<(const Amount &lhs, const int64_t rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is greater than rhs
 * @retval false lhs is less than or equal rhs
 */
CFD_CORE_EXPORT bool operator>(const Amount &lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(int64_t)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is greater than rhs
 * @retval false lhs is less than or equal rhs
 */
CFD_CORE_EXPORT bool operator>(const int64_t lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(int64_t)
 * @retval true lhs is greater than rhs
 * @retval false lhs is less than or equal rhs
 */
CFD_CORE_EXPORT bool operator>(const Amount &lhs, const int64_t rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is less than or equal rhs
 * @retval false lhs is greater than rhs
 */
CFD_CORE_EXPORT bool operator<=(const Amount &lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(int64_t)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is less than or equal rhs
 * @retval false lhs is greater than rhs
 */
CFD_CORE_EXPORT bool operator<=(const int64_t lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(int64_t)
 * @retval true lhs is less than or equal rhs
 * @retval false lhs is greater than rhs
 */
CFD_CORE_EXPORT bool operator<=(const Amount &lhs, const int64_t rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is greater than or equal rhs
 * @retval false lhs is less than rhs
 */
CFD_CORE_EXPORT bool operator>=(const Amount &lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(int64_t)
 * @param[in] rhs   Value to compare(Amount)
 * @retval true lhs is greater than or equal rhs
 * @retval false lhs is less than rhs
 */
CFD_CORE_EXPORT bool operator>=(const int64_t lhs, const Amount &rhs);
/**
 * @brief comparison operator
 * @param[in] lhs   Value to be compared(Amount)
 * @param[in] rhs   Value to compare(int64_t)
 * @retval true lhs is greater than or equal rhs
 * @retval false lhs is less than rhs
 */
CFD_CORE_EXPORT bool operator>=(const Amount &lhs, const int64_t rhs);
/**
 * @brief Addition operator(Amount + Amount)
 * @param[in] left_amount     Amount instance
 * @param[in] right_amount    Amount instance
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount
operator+(const Amount &left_amount, const Amount &right_amount);
/**
 * @brief Addition operator(Amount + int64_t)
 * @param[in] amount            Amount instance
 * @param[in] satoshi_amount    amount in satoshi units
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount
operator+(const Amount &amount, const int64_t satoshi_amount);
/**
 * @brief Addition operator(int64_t + Amount)
 * @param[in] satoshi_amount    amount in satoshi units
 * @param[in] amount            Amount instance
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount
operator+(const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief Subtraction operator(Amount - Amount)
 * @param[in] left_amount           Amount instance
 * @param[in] right_amount          Amount instance
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount
operator-(const Amount &left_amount, const Amount &right_amount);
/**
 * @brief Subtraction operator(int64_t - Amount)
 * @param[in] amount            Amount instance
 * @param[in] satoshi_amount    amount in satoshi units
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount
operator-(const Amount &amount, const int64_t satoshi_amount);
/**
 * @brief Subtraction operator(Amount - int64_t)
 * @param[in] satoshi_amount    amount in satoshi units
 * @param[in] amount            Amount instance
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount
operator-(const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief Multiplication operator(Amount * int64_t)
 * @param[in] amount        Amount instance
 * @param[in] value         multiplier
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount operator*(const Amount &amount, const int64_t value);
/**
 * @brief Multiplication operator(int64_t * Amount)
 * @param[in] value         multiplier
 * @param[in] amount        Amount instance
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount operator*(const int64_t value, const Amount &amount);
/**
 * @brief Division operator(Amount / int64_t)
 * @param[in] amount        Amount instance
 * @param[in] value         divisor
 * @return Amount instance
 */
CFD_CORE_EXPORT Amount operator/(const Amount &amount, const int64_t value);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_AMOUNT_H_
