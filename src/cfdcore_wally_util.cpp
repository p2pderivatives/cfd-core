// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_wally_util.cpp
 *
 * @brief libwally internal utility.
 *
 */
#include <algorithm>
#include <exception>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_secp256k1.h"   // NOLINT
#include "cfdcore_wally_util.h"  // NOLINT

#include "wally_address.h"      // NOLINT
#include "wally_bip32.h"        // NOLINT
#include "wally_bip38.h"        // NOLINT
#include "wally_bip39.h"        // NOLINT
#include "wally_core.h"         // NOLINT
#include "wally_crypto.h"       // NOLINT
#include "wally_script.h"       // NOLINT
#include "wally_transaction.h"  // NOLINT

namespace cfd {
namespace core {

using logger::warn;

//////////////////////////////////
/// inner definitions
//////////////////////////////////

/// length of bip39 wordlist array
static constexpr size_t kWordlistLength = BIP39_WORDLIST_LEN;
/// length of bytes for bip39 seed binary
static constexpr size_t kSeedBytesLen = BIP39_SEED_LEN_512;
/// delimiter for libwally mnemonic_sentence
static const char* kMnemonicDelimiter = u8"\u0020";
/// delimiter for libwally mnemonic_sentence (jp language specific)
static const char* kMnemonicIdeographicDelimiter = u8"\u3000";

/**
 * @brief get libwally words object
 * @param[in] language  language to use wordlist.
 * @return pointer of words struct, is defined by libwally-core
 * @throws CfdException libwally-core internal error.
 */
words* Bip39GetWordlist(const std::string& language) {
  words* wordlist[1];
  int ret = bip39_get_wordlist(language.data(), wordlist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Get wordlist error. ret=[{}]", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Get wordlist error.");
  }
  return wordlist[0];
}

//////////////////////////////////
/// WallyUtil
//////////////////////////////////
std::string WallyUtil::ConvertStringAndFree(char* wally_string) {
  try {
    std::string result = std::string(wally_string);
    wally_free_string(wally_string);
    return result;
  } catch (const std::exception& except) {
    wally_free_string(wally_string);
    warn(CFD_LOG_SOURCE, "system error. except={}.", except.what());
    throw except;
  } catch (...) {
    wally_free_string(wally_string);
    warn(CFD_LOG_SOURCE, "unknown error.");
    throw CfdException();
  }
}

ByteData WallyUtil::CombinePubkeySecp256k1Ec(
    const std::vector<ByteData>& pubkey_list) {
  struct secp256k1_context_struct* context = wally_get_secp_context();

  Secp256k1 secp256k1(context);
  return secp256k1.CombinePubkeySecp256k1Ec(pubkey_list);
}

ByteData WallyUtil::CompressPubkey(const ByteData& uncompressed_pubkey) {
  struct secp256k1_context_struct* context = wally_get_secp_context();

  Secp256k1 secp256k1(context);
  return secp256k1.CompressPubkeySecp256k1Ec(uncompressed_pubkey);
}

ByteData WallyUtil::AddTweakPrivkey(
    const ByteData& privkey, const ByteData256& tweak) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.AddTweakPrivkeySecp256k1Ec(
      privkey, ByteData(tweak.GetBytes()));
}

ByteData WallyUtil::MulTweakPrivkey(
    const ByteData& privkey, const ByteData256& tweak) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.MulTweakPrivkeySecp256k1Ec(
      privkey, ByteData(tweak.GetBytes()));
}

ByteData WallyUtil::AddTweakPubkey(
    const ByteData& pubkey, const ByteData256& tweak, bool is_tweak_check) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.AddTweakPubkeySecp256k1Ec(
      pubkey, ByteData(tweak.GetBytes()), is_tweak_check);
}

ByteData WallyUtil::MulTweakPubkey(
    const ByteData& pubkey, const ByteData256& tweak) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.MulTweakPubkeySecp256k1Ec(
      pubkey, ByteData(tweak.GetBytes()));
}

std::vector<uint8_t> WallyUtil::CreateScriptDataFromBytes(
    const std::vector<uint8_t>& bytes, int32_t flags) {
  size_t write_max_size = bytes.size() + kMaxVarIntSize;
  std::vector<uint8_t> ret_bytes(write_max_size);
  size_t written = 0;

  int ret = wally_script_push_from_bytes(
      bytes.data(), bytes.size(), flags, ret_bytes.data(), write_max_size,
      &written);
  if (ret == WALLY_OK && write_max_size < written) {
    // サイズ不足の場合はresizeしてリトライ
    ret_bytes.resize(written);
    ret = wally_script_push_from_bytes(
        bytes.data(), bytes.size(), flags, ret_bytes.data(), ret_bytes.size(),
        &written);
  }

  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Script push error.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Script push error.");
  }
  ret_bytes.resize(written);
  return ret_bytes;
}

ByteData WallyUtil::NegatePrivkey(const ByteData& privkey) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.NegatePrivkeySecp256k1Ec(privkey);
}

ByteData WallyUtil::NegatePubkey(const ByteData& pubkey) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.NegatePubkeySecp256k1Ec(pubkey);
}

void WallyUtil::RangeProofInfo(
    const ByteData& bytes, int* exponent, int* mantissa, uint64_t* min_value,
    uint64_t* max_value) {
  struct secp256k1_context_struct* context = wally_get_secp_context();

  Secp256k1 secp256k1(context);
  secp256k1.RangeProofInfoSecp256k1(
      bytes, exponent, mantissa, min_value, max_value);
}

ByteData WallyUtil::SignWhitelist(
    const ByteData& offline_pubkey, const ByteData256& online_privkey,
    const ByteData256& tweak_sum, const std::vector<ByteData>& online_keys,
    const std::vector<ByteData>& offline_keys, uint32_t whitelist_index) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.SignWhitelistSecp256k1Ec(
      offline_pubkey, online_privkey, tweak_sum, online_keys, offline_keys,
      whitelist_index);
}

ByteData WallyUtil::CalculateSchnorrsig(
    const Privkey& oracle_privkey, const Privkey& k_value,
    const ByteData256& message) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.CalculateSchnorrsigSecp256k1(
      oracle_privkey.GetData(), k_value.GetData(), message, 1, nullptr);
}

bool WallyUtil::VerifySchnorrsig(
    const Pubkey& pubkey, const ByteData& signature,
    const ByteData256& message) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return secp256k1.VerifySchnorrsigSecp256k1(
      pubkey.GetData(), signature, message);
}

Pubkey WallyUtil::GetSchnorrPubkey(
    const Pubkey& oracle_pubkey, const Pubkey& oracle_r_point,
    const ByteData256& message) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return Pubkey(secp256k1.GetSchnorrPubkeySecp256k1(
      oracle_pubkey.GetData(), oracle_r_point.GetData(), message));
}

Pubkey WallyUtil::GetSchnorrPublicNonce(const Privkey& privkey) {
  struct secp256k1_context_struct* context = wally_get_secp_context();
  Secp256k1 secp256k1(context);
  return Pubkey(secp256k1.GetSchnorrPublicNonceSecp256k1(privkey.GetData()));
}

std::vector<std::string> WallyUtil::GetMnemonicWordlist(
    const std::string& language) {
  words* wally_wordlist = Bip39GetWordlist(language);

  std::vector<std::string> wordlist;
  wordlist.reserve(kWordlistLength);
  for (size_t i = 0; i < kWordlistLength; ++i) {
    std::string word = GetMnemonicWord(wally_wordlist, i);
    wordlist.push_back(word);
  }

  return wordlist;
}

ByteData WallyUtil::ConvertMnemonicToSeed(
    const std::vector<std::string>& mnemonic, const std::string& passphrase,
    bool use_ideographic_space) {
  std::string delimitor = kMnemonicDelimiter;
  if (use_ideographic_space) {
    delimitor = kMnemonicIdeographicDelimiter;
  }
  std::string mnemonic_sentence = StringUtil::Join(mnemonic, delimitor);
  std::vector<uint8_t> seed_bytes(kByteData512Length);
  size_t out_size = 0;
  int ret = bip39_mnemonic_to_seed(
      mnemonic_sentence.c_str(), passphrase.c_str(), seed_bytes.data(),
      kSeedBytesLen, &out_size);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Convert mnemonic to seed error. ret=[{}]", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Convert mnemonic to seed error.");
  }

  seed_bytes.resize(out_size);
  ByteData seed(seed_bytes);

  return seed;
}

std::vector<std::string> WallyUtil::ConvertEntropyToMnemonic(
    const ByteData& entropy, const std::string& language) {
  words* wally_wordlist = Bip39GetWordlist(language);

  std::vector<uint8_t> entropy_bytes = entropy.GetBytes();
  char* mnemonic_bytes = NULL;
  int ret = bip39_mnemonic_from_bytes(
      wally_wordlist, entropy_bytes.data(), entropy_bytes.size(),
      &mnemonic_bytes);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Convert entropy to mnemonic error. ret=[{}]", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Convert entropy to mnemonic error.");
  }

  std::string mnemonic_sentence =
      WallyUtil::ConvertStringAndFree(mnemonic_bytes);
  std::vector<std::string> mnemonic =
      StringUtil::Split(mnemonic_sentence, kMnemonicDelimiter);

  return mnemonic;
}

ByteData WallyUtil::ConvertMnemonicToEntropy(
    const std::vector<std::string>& mnemonic, const std::string& language,
    bool use_ideographic_space) {
  words* wally_wordlist = Bip39GetWordlist(language);

  std::string delimitor = kMnemonicDelimiter;
  if (use_ideographic_space) {
    delimitor = kMnemonicIdeographicDelimiter;
  }
  std::string mnemonic_sentence = StringUtil::Join(mnemonic, delimitor);

  std::vector<uint8_t> entropy_bytes(kByteData512Length);
  size_t out_size = 0;
  int ret = bip39_mnemonic_to_bytes(
      wally_wordlist, mnemonic_sentence.c_str(), entropy_bytes.data(),
      entropy_bytes.size(), &out_size);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Convert mnemonic to entropy error. ret=[{}]", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Convert mnemonic to entropy error.");
  }

  entropy_bytes.resize(out_size);
  ByteData entropy(entropy_bytes);

  return entropy;
}

std::vector<std::string> WallyUtil::GetSupportedMnemonicLanguages() {
  char* wally_lang = NULL;
  int ret = bip39_get_languages(&wally_lang);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Get languages error. ret=[{}]", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Get languages error.");
  }

  // free and get string
  std::string lang = ConvertStringAndFree(wally_lang);
  return StringUtil::Split(std::string(lang), kMnemonicDelimiter);
}

bool WallyUtil::CheckValidMnemonic(
    const std::vector<std::string>& mnemonic, const std::string& language) {
  words* wally_wordlist = Bip39GetWordlist(language);
  std::string mnemonic_sentence =
      StringUtil::Join(mnemonic, kMnemonicDelimiter);

  int ret = bip39_mnemonic_validate(wally_wordlist, mnemonic_sentence.c_str());
  if (ret != WALLY_OK) return false;
  return true;
}

std::string WallyUtil::GetMnemonicWord(
    const words* wordlist, const size_t index) {
  if (kWordlistLength <= index) {
    warn(
        CFD_LOG_SOURCE, "GetMnemonicWord invalid index error. index=[{}]",
        index);
    throw CfdException(
        CfdError::kCfdOutOfRangeError, "GetMnemonicWord invalid index error.");
  }

  char* wally_word = NULL;
  int ret = bip39_get_word(wordlist, index, &wally_word);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "Get languages error. ret=[{}]", ret);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Get languages error.");
  }

  std::string word = ConvertStringAndFree(wally_word);
  return word;
}

}  // namespace core
}  // namespace cfd
