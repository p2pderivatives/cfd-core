// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_hdwallet.cpp
 *
 * @brief-eng implementation of BIP32/BIP39/BIP44 classes
 * @brief-jp BIP32/BIP39/BIP44関連クラスの実装
 */

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::warn;

/// empty seed string (64byte)
static constexpr const char* kEmptySeedStr =
    "00000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000";  // NOLINT

HDWallet::HDWallet() : seed_(ByteData(kEmptySeedStr)) {
  // do nothing
}

HDWallet::HDWallet(const ByteData& seed) : seed_(seed) {
  // do nothing
}

HDWallet::HDWallet(
    std::vector<std::string> mnemonic, std::string passphrase,
    bool use_ideographic_space)
    : seed_(ByteData(kEmptySeedStr)) {
  seed_ = ConvertMnemonicToSeed(mnemonic, passphrase, use_ideographic_space);
}

ByteData HDWallet::GetSeed() const { return seed_; }

std::vector<std::string> HDWallet::GetMnemonicWordlist(
    const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::GetMnemonicWordlist(language);
}

std::vector<std::string> HDWallet::ConvertEntropyToMnemonic(
    const ByteData& entropy, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertEntropyToMnemonic(entropy, language);
}

ByteData HDWallet::ConvertMnemonicToEntropy(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::ConvertMnemonicToEntropy(mnemonic, language);
}

bool HDWallet::CheckValidMnemonic(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  if (!CheckSupportedLanguages(language)) {
    warn(
        CFD_LOG_SOURCE, "Not support language passed. language=[{}]",
        language);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Not support language passed.");
  }

  return WallyUtil::CheckValidMnemonic(mnemonic, language);
}

bool HDWallet::CheckSupportedLanguages(const std::string& language) {
  std::vector<std::string> slangs = WallyUtil::GetSupportedMnemonicLanguages();
  return (
      std::find(slangs.cbegin(), slangs.cend(), language) != slangs.cend());
}

ByteData HDWallet::ConvertMnemonicToSeed(
    const std::vector<std::string>& mnemonic, const std::string& passphrase,
    bool use_ideographic_space) {
  return WallyUtil::ConvertMnemonicToSeed(
      mnemonic, passphrase, use_ideographic_space);
}

}  // namespace core
}  // namespace cfd
