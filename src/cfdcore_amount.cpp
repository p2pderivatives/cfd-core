// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_amount.cpp
 *
 * @brief Amountを表現するクラス
 *
 */
#include <algorithm>
#include <cmath>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"

namespace cfd {
namespace core {

using logger::warn;

Amount::Amount() : amount_(0) {
  // do nothing
}

Amount::Amount(int64_t amount) : amount_(amount) {
  // amountのvalidationは、CreateBySatoshiAmountなどで実施
}

void Amount::CheckValidAmount(int64_t satoshi_amount) {
  if (!IsValidAmount(satoshi_amount)) {
    warn(CFD_LOG_SOURCE, "Amount out of range. amount={}.", satoshi_amount);
    throw CfdException(kCfdOutOfRangeError, "Amount out of range.");
  }
}

void Amount::CheckValidAmount(double coin_amount) {
  int64_t satoshi_amount = static_cast<int64_t>(coin_amount * kCoinBase);
  if (!IsValidAmount(satoshi_amount)) {
    warn(
        CFD_LOG_SOURCE, "Coin amount out of range. amount={}.",
        satoshi_amount);
    throw CfdException(kCfdOutOfRangeError, "Coin amount out of range.");
  }
}

Amount Amount::CreateBySatoshiAmount(int64_t satoshi_amount) {
  CheckValidAmount(satoshi_amount);
  return Amount(satoshi_amount);
}

Amount Amount::CreateByCoinAmount(double coin_amount) {
  CheckValidAmount(coin_amount);

  int64_t satoshi_amount = static_cast<int64_t>(coin_amount * kCoinBase);
  return Amount(satoshi_amount);
}

int64_t Amount::GetSatoshiValue() const { return amount_; }

double Amount::GetCoinValue() const {
  return (static_cast<double>(amount_) / kCoinBase);
}

ByteData Amount::GetByteData() const {
  std::vector<uint8_t> bytes(sizeof(amount_));
  memcpy(bytes.data(), &amount_, bytes.size());
#if defined(__BYTE_ORDER) && defined(__BIG_ENDIAN)
#if __BYTE_ORDER == __BIG_ENDIAN
  // big -> little
  std::reverse(bytes.begin(), bytes.end());
#endif  // __BYTE_ORDER == __BIG_ENDIAN
#else
#if defined(__BIG_ENDIAN__)
  std::reverse(bytes.begin(), bytes.end());
#endif  // __BIG_ENDIAN__
#endif
  return ByteData(bytes);
}

// member operator overloading
bool Amount::operator==(const Amount& amount) const {
  return amount_ == amount.amount_;
}
bool Amount::operator==(const int64_t satoshi_amount) const {
  return amount_ == satoshi_amount;
}
bool Amount::operator!=(const Amount& amount) const {
  return amount_ != amount.amount_;
}
bool Amount::operator!=(const int64_t satoshi_amount) const {
  return amount_ != satoshi_amount;
}
Amount Amount::operator+=(const int64_t satoshi_amount) {
  amount_ += satoshi_amount;
  CheckValidAmount(amount_);
  return *this;
}
Amount Amount::operator+=(const Amount& amount) {
  amount_ += amount.amount_;
  return *this;
}
Amount Amount::operator-=(const int64_t satoshi_amount) {
  amount_ -= satoshi_amount;
  CheckValidAmount(amount_);
  return *this;
}
Amount Amount::operator-=(const Amount& amount) {
  amount_ -= amount.amount_;
  return *this;
}
Amount Amount::operator*=(const int64_t value) {
  amount_ *= value;
  CheckValidAmount(amount_);
  return *this;
}
Amount Amount::operator/=(const int64_t value) {
  double calc_amount = static_cast<double>(amount_) / value;
  amount_ = static_cast<int64_t>(std::round(calc_amount));
  CheckValidAmount(amount_);
  return *this;
}

// global operator overloading
bool operator==(int64_t satoshi_amount, const Amount& amount) {
  return amount == satoshi_amount;
}
bool operator!=(int64_t satoshi_amount, const Amount& amount) {
  return amount != satoshi_amount;
}
Amount operator+(const Amount& left_amount, const Amount& right_amount) {
  return Amount::CreateBySatoshiAmount(
      left_amount.GetSatoshiValue() + right_amount.GetSatoshiValue());
}
Amount operator+(const Amount& amount, const int64_t satoshi_amount) {
  return Amount::CreateBySatoshiAmount(amount.GetSatoshiValue()) +=
         satoshi_amount;
}
Amount operator+(const int64_t satoshi_amount, const Amount& amount) {
  return Amount::CreateBySatoshiAmount(amount.GetSatoshiValue()) +=
         satoshi_amount;
}
Amount operator-(const Amount& left_amount, const Amount& right_amount) {
  return Amount::CreateBySatoshiAmount(
      left_amount.GetSatoshiValue() - right_amount.GetSatoshiValue());
}
Amount operator-(const Amount& amount, const int64_t satoshi_amount) {
  return Amount::CreateBySatoshiAmount(amount.GetSatoshiValue()) -=
         satoshi_amount;
}
Amount operator-(const int64_t satoshi_amount, const Amount& amount) {
  return Amount::CreateBySatoshiAmount(
      satoshi_amount - amount.GetSatoshiValue());
}
Amount operator*(const Amount& amount, const int64_t value) {
  return Amount::CreateBySatoshiAmount(amount.GetSatoshiValue()) *= value;
}
Amount operator*(const int64_t value, const Amount& amount) {
  return Amount::CreateBySatoshiAmount(amount.GetSatoshiValue()) *= value;
}
Amount operator/(const Amount& amount, const int64_t value) {
  return Amount::CreateBySatoshiAmount(amount.GetSatoshiValue()) /= value;
}

}  // namespace core
}  // namespace cfd
