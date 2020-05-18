// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_amount.h
 *
 * @brief Amount関連クラス定義
 *
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_AMOUNT_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_AMOUNT_H_

#include <cstdint>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"

/**
 * @brief cfd名前空間
 */
namespace cfd {
/**
 * @brief cfd::core名前空間
 */
namespace core {

//! bitcoinとsatoshi単位の変換に用いる因数(10^8)
static constexpr int64_t kCoinBase = 100000000;
/**
 * @brief satoshi単位の最大値
 * @details 厳密には流通通貨の最大値とは異なるが、bitcoin coreに合わせて限度額を設定
 * @see https://github.com/bitcoin/bitcoin/blob/e756eca9e8bf39f0a891f1760df0a317ecb7fee8/src/amount.h#L25
 */
static constexpr int64_t kMaxAmount = 21000000 * kCoinBase;

/**
 * @brief BitcoinのAmountを表現するクラス
 */
class CFD_CORE_EXPORT Amount {
 public:
  /**
   * \~japanese
   * @brief satoshi単位のAmountからAmountインスタンスを生成する.
   * @param[in] amount satoshi単位のAmount
   * @return Amountインスタンス
   * @exception CfdException 不正な値が渡された場合
   * \~english
   * @brief Create Amount instance by amount satoshi units
   * @param[in] amount amount in satoshi units
   * @return instance of Amount class
   * @exception CfdException if invalid value passed
   */
  static Amount CreateBySatoshiAmount(int64_t amount);

  /**
   * \~japanese
   * @brief bitcoin単位のAmountからAmountインスタンスを生成する
   * @param[in] coin_amount bitcoin単位のAmount
   * @return Amountインスタンス
   * @exception CfdException 不正な値が渡された場合
   * \~english
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
   * @brief 自身のインスタンスからsatoshi単位のAmount額を取得する.
   * @return satoshi単位のAmountの数値
   */
  int64_t GetSatoshiValue() const;

  /**
   * @brief 自身のインスタンスからbitcoin単位のAmount額を取得する.
   * @details double精度の誤差が生じる可能性があるため注意.
   * @return bitcoin単位のAmountの数値
   */
  double GetCoinValue() const;
  /**
   * @brief ByteDataをBigEndianで取得する.
   * @return satoshiのByteData
   */
  ByteData GetByteData() const;

  // operator overloading
  /**
   * @brief 等価比較オペレータ
   * @param[in] amount  被演算子 比較対象とするAmountインスタンス
   * @retval true 等価
   * @retval false 不等価
   * @return 等価であればtrue, それ以外はfalse
   */
  bool operator==(const Amount &amount) const;
  /**
   * @brief 等価比較オペレータ
   * @param[in] satoshi_amount  被演算子 比較対象とするsatoshi単位のAmount額
   * @retval true 等価
   * @retval false 不等価
   */
  bool operator==(const int64_t satoshi_amount) const;
  /**
   * @brief 不等価比較オペレータ
   * @param[in] amount  被演算子 比較対象とするAmountインスタンス
   * @retval true 不等価
   * @retval false 等価
   */
  bool operator!=(const Amount &amount) const;
  /**
   * @brief 不等価比較オペレータ
   * @param[in] satoshi_amount  被演算子 比較対象とするsatoshi単位のAmount額
   * @retval true 不等価
   * @retval false 等価
   */
  bool operator!=(const int64_t satoshi_amount) const;
  /**
   * @brief 加算代入オペレータ(Amount += Amount)
   * @param[in] amount  加数 Amountインスタンス
   * @return 計算結果 Amountインスタンス
   */
  Amount operator+=(const Amount &amount);
  /**
   * @brief 加算代入オペレータ(Amount += int64_t)
   * @param[in] satoshi_amount  加数 satoshi単位のAmount額
   * @return 計算結果 Amountインスタンス
   */
  Amount operator+=(const int64_t satoshi_amount);
  /**
   * @brief 減算代入オペレータ(Amount -= Amount)
   * @param[in] amount  減数 Amountインスタンス
   * @return 計算結果 Amountインスタンス
   */
  Amount operator-=(const Amount &amount);
  /**
   * @brief 減算代入オペレータ(Amount -= int64_t)
   * @param[in] satoshi_amount  減数 satoshi単位のAmount額
   * @return 計算結果 Amountインスタンス
   */
  Amount operator-=(const int64_t satoshi_amount);
  /**
   * @brief 乗算代入オペレータ(Amount *= int64_t)
   * @param[in] value     乗数
   * @return 計算結果 Amountインスタンス
   */
  Amount operator*=(const int64_t value);
  /**
   * @brief 除算代入オペレータ(Amount /= int64_t)
   * @param[in] value     除数
   * @return 計算結果 Amountインスタンス
   */
  Amount operator/=(const int64_t value);

  /**
   * @brief コンストラクタ.
   *
   * リスト要素指定時の初期化用.
   */
  Amount();

 private:
  //! satoshi単位のAmount
  int64_t amount_;
  //! ignore valid check flag.
  bool ignore_check_;

  /**
   * @brief 引数で与えられたAmount額が不正なものでないかを検証する.
   * @param[in] amount satoshi単位のAmount
   * @retval true 正常Amount額
   * @retval false 不正Amount額
   */
  static bool IsValidAmount(int64_t amount) {
    return (amount >= 0 && amount <= kMaxAmount);
  }

  /**
   * @brief 引数で与えられたsatoshi単位のAmountが不正な値でないかを検証する.
   * @param[in] satoshi_amount satoshi単位のAmount
   * @exception CfdException 不正な値が渡された場合
   */
  static void CheckValidAmount(int64_t satoshi_amount);
};

/**
 * @brief 等価比較オペレータ
 * @param[in] satoshi_amount  satoshi単位のAmount額
 * @param[in] amount          比較対象Amountインスタンス
 * @retval true 等価
 * @retval false 不等価
 */
CFD_CORE_EXPORT bool operator==(
    const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief 不等価比較オペレータ
 * @param[in] satoshi_amount  satoshi単位のAmount額
 * @param[in] amount          比較対象Amountインスタンス
 * @retval true 不等価
 * @retval false 等価
 */
CFD_CORE_EXPORT bool operator!=(
    const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is less than rhs
 * @retval false lhs is greater than or equal rhs
 */
CFD_CORE_EXPORT bool operator<(const Amount &lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(int64_t)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is less than rhs
 * @retval false lhs is greater than or equal rhs
 */
CFD_CORE_EXPORT bool operator<(const int64_t lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(int64_t)
 * @retval true lhs is less than rhs
 * @retval false lhs is greater than or equal rhs
 */
CFD_CORE_EXPORT bool operator<(const Amount &lhs, const int64_t rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is greater than rhs
 * @retval false lhs is less than or equal rhs
 */
CFD_CORE_EXPORT bool operator>(const Amount &lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(int64_t)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is greater than rhs
 * @retval false lhs is less than or equal rhs
 */
CFD_CORE_EXPORT bool operator>(const int64_t lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(int64_t)
 * @retval true lhs is greater than rhs
 * @retval false lhs is less than or equal rhs
 */
CFD_CORE_EXPORT bool operator>(const Amount &lhs, const int64_t rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is less than or equal rhs
 * @retval false lhs is greater than rhs
 */
CFD_CORE_EXPORT bool operator<=(const Amount &lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(int64_t)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is less than or equal rhs
 * @retval false lhs is greater than rhs
 */
CFD_CORE_EXPORT bool operator<=(const int64_t lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(int64_t)
 * @retval true lhs is less than or equal rhs
 * @retval false lhs is greater than rhs
 */
CFD_CORE_EXPORT bool operator<=(const Amount &lhs, const int64_t rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is greater than or equal rhs
 * @retval false lhs is less than rhs
 */
CFD_CORE_EXPORT bool operator>=(const Amount &lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(int64_t)
 * @param[in] rhs   比較数(Amount)
 * @retval true lhs is greater than or equal rhs
 * @retval false lhs is less than rhs
 */
CFD_CORE_EXPORT bool operator>=(const int64_t lhs, const Amount &rhs);
/**
 * @brief 二方比較オペレータ
 * @param[in] lhs   被比較数(Amount)
 * @param[in] rhs   比較数(int64_t)
 * @retval true lhs is greater than or equal rhs
 * @retval false lhs is less than rhs
 */
CFD_CORE_EXPORT bool operator>=(const Amount &lhs, const int64_t rhs);
/**
 * @brief 加算オペレータ(Amount + Amount)
 * @param[in] left_amount    被加数 Amountインスタンス
 * @param[in] right_amount    加数 Amountインスタンス
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount
operator+(const Amount &left_amount, const Amount &right_amount);
/**
 * @brief 加算オペレータ(Amount + int64_t)
 * @param[in] amount            被加数 Amountインスタンス
 * @param[in] satoshi_amount    加数 satoshi単位のAmount額
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount
operator+(const Amount &amount, const int64_t satoshi_amount);
/**
 * @brief 加算オペレータ(int64_t + Amount)
 * @param[in] satoshi_amount    被加数 satoshi単位のAmount額
 * @param[in] amount            加数 Amountインスタンス
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount
operator+(const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief 減算オペレータ(Amount - Amount)
 * @param[in] left_amount           被減数 Amountインスタンス
 * @param[in] right_amount           減数 Amountインスタンス
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount
operator-(const Amount &left_amount, const Amount &right_amount);
/**
 * @brief 減算オペレータ(int64_t - Amount)
 * @param[in] amount            被減数 Amountインスタンス
 * @param[in] satoshi_amount    減数 satoshi単位のAmount額
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount
operator-(const Amount &amount, const int64_t satoshi_amount);
/**
 * @brief 減算オペレータ(Amount - int64_t)
 * @param[in] satoshi_amount    被減数 satoshi単位のAmount額
 * @param[in] amount            減数 Amountインスタンス
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount
operator-(const int64_t satoshi_amount, const Amount &amount);
/**
 * @brief 乗算オペレータ(Amount * int64_t)
 * @param[in] amount        被乗数 Amountインスタンス
 * @param[in] value         乗数
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount operator*(const Amount &amount, const int64_t value);
/**
 * @brief 乗算オペレータ(int64_t * Amount)
 * @param[in] value         乗数
 * @param[in] amount        被演算子 Amountインスタンス
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount operator*(const int64_t value, const Amount &amount);
/**
 * @brief 除算オペレータ(Amount / int64_t)
 * @param[in] amount        被除数 Amountインスタンス
 * @param[in] value         除数
 * @return 計算結果 Amountインスタンス
 */
CFD_CORE_EXPORT Amount operator/(const Amount &amount, const int64_t value);

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_AMOUNT_H_
