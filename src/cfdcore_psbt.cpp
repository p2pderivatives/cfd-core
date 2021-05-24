// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_psbt.cpp
 *
 * @brief This file is implements Partially Signed Bitcoin Transaction.
 */
#include "cfdcore/cfdcore_psbt.h"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_secp256k1.h"             // NOLINT
#include "cfdcore_transaction_internal.h"  // NOLINT
#include "cfdcore_wally_util.h"            // NOLINT

namespace cfd {
namespace core {

using logger::CfdSourceLocation;
using logger::info;
using logger::warn;

// -----------------------------------------------------------------------------
// File constants
// -----------------------------------------------------------------------------
static const uint8_t kPsbtSeparator = 0;  //!< psbt map separator
//! global xpub key size
static const size_t kPsbtGlobalXpubSize = BIP32_SERIALIZED_LEN + 1;

// -----------------------------------------------------------------------------
// Internal
// -----------------------------------------------------------------------------
/**
 * @brief set psbt bip32 key map
 * @param[in] key_list  bip32 key path list
 * @param[in] map_obj   map object.
 */
static void SetKeyPathMap(
    const std::vector<KeyData> &key_list, struct wally_map *map_obj) {
  int ret;
  for (auto &key : key_list) {
    auto key_vec = key.GetPubkey().GetData().GetBytes();
    std::vector<uint8_t> fingerprint(4);
    auto fp = key.GetFingerprint();
    auto path = key.GetChildNumArray();
    if (fp.IsEmpty() && path.empty()) {
      fingerprint = key.GetPubkey().GetFingerprint().GetBytes();
    } else if (fp.GetDataSize() >= 4) {
      fingerprint = fp.GetBytes();
    }

    ret = wally_map_add_keypath_item(
        map_obj, key_vec.data(), key_vec.size(), fingerprint.data(), 4,
        path.data(), path.size());
    if (ret != WALLY_OK) {
      wally_map_free(map_obj);
      warn(CFD_LOG_SOURCE, "wally_map_add_keypath_item NG[{}]", ret);
      throw CfdException(kCfdMemoryFullError, "psbt add keypath error.");
    }
  }
}

/**
 * @brief validate psbt utxo data.
 * @param[in] txid    utxo txid
 * @param[in] vout    utxo vout
 * @param[in] out_script          locking script (script pubkey)
 * @param[in] redeem_script       redeem script
 * @param[in] key_list            key list
 * @param[out] new_redeem_script  output redeem script
 * @retval true   witness
 * @retval false  not witness
 */
bool ValidatePsbtUtxo(
    const Txid &txid, uint32_t vout, const Script &out_script,
    const Script &redeem_script, const std::vector<KeyData> &key_list,
    Script *new_redeem_script) {
  bool has_check_script = false;
  bool is_witness = false;

  if (out_script.IsP2pkhScript() || out_script.IsP2wpkhScript()) {
    if (!redeem_script.IsEmpty()) {
      warn(
          CFD_LOG_SOURCE, "pubkey isn't use redeemScript. txid:{},{}",
          txid.GetHex(), vout);
      throw CfdException(
          kCfdIllegalArgumentError, "pubkey isn't use redeemScript.");
    }

    is_witness = out_script.IsP2wpkhScript();
    if (key_list.size() > 1) {
      warn(
          CFD_LOG_SOURCE, "set many key. using key is one.", txid.GetHex(),
          vout);
      throw CfdException(
          kCfdIllegalArgumentError, "set many key. using key is one.");
    } else if (key_list.size() == 1) {
      auto pubkey = key_list[0].GetPubkey();
      if (is_witness) {
        if (!ScriptUtil::CreateP2wpkhLockingScript(pubkey).Equals(
                out_script)) {
          warn(
              CFD_LOG_SOURCE, "unmatch pubkey. txid:{},{}", txid.GetHex(),
              vout);
          throw CfdException(kCfdIllegalArgumentError, "unmatch pubkey.");
        }
      } else {
        if (!ScriptUtil::CreateP2pkhLockingScript(pubkey).Equals(out_script)) {
          warn(
              CFD_LOG_SOURCE, "unmatch pubkey. txid:{},{}", txid.GetHex(),
              vout);
          throw CfdException(kCfdIllegalArgumentError, "unmatch pubkey.");
        }
      }
    }
  } else if (out_script.IsP2shScript()) {
    if (redeem_script.IsEmpty() || redeem_script.IsP2wpkhScript()) {
      if (redeem_script.IsP2wpkhScript()) {
        auto p2sh_wpkh_script =
            ScriptUtil::CreateP2shLockingScript(redeem_script);
        if (!p2sh_wpkh_script.Equals(out_script)) {
          warn(
              CFD_LOG_SOURCE, "unmatch scriptPubkey. txid:{},{}",
              txid.GetHex(), vout);
          throw CfdException(
              kCfdIllegalArgumentError, "unmatch scriptPubkey.");
        }
        is_witness = true;
      }

      if (key_list.size() > 1) {
        warn(
            CFD_LOG_SOURCE, "set many key. using key is one.", txid.GetHex(),
            vout);
        throw CfdException(
            kCfdIllegalArgumentError, "set many key. using key is one.");
      } else if (key_list.size() == 1) {
        auto pubkey = key_list[0].GetPubkey();
        auto wpkh_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
        auto sh_script = ScriptUtil::CreateP2shLockingScript(wpkh_script);
        if (!sh_script.Equals(out_script)) {
          warn(
              CFD_LOG_SOURCE, "unmatch pubkey. txid:{},{}", txid.GetHex(),
              vout);
          throw CfdException(kCfdIllegalArgumentError, "unmatch pubkey.");
        }
        if (new_redeem_script != nullptr) *new_redeem_script = wpkh_script;
        is_witness = true;
      }
    } else {
      Address p2sh_addr(NetType::kMainnet, redeem_script);
      Address p2wsh_addr(
          NetType::kMainnet, WitnessVersion::kVersion0, redeem_script);
      auto wsh_script = p2wsh_addr.GetLockingScript();
      auto p2sh_wsh_script = ScriptUtil::CreateP2shLockingScript(wsh_script);
      if (p2sh_addr.GetLockingScript().Equals(out_script)) {
        has_check_script = true;
      } else if (p2sh_wsh_script.Equals(out_script)) {
        has_check_script = true;
        is_witness = true;
      } else {
        warn(
            CFD_LOG_SOURCE, "unknown scriptPubkey. txid:{},{}", txid.GetHex(),
            vout);
        throw CfdException(kCfdIllegalArgumentError, "unknown scriptPubkey.");
      }
    }
  } else if (out_script.IsP2wshScript()) {
    Address addr(NetType::kMainnet, WitnessVersion::kVersion0, redeem_script);
    if (!addr.GetLockingScript().Equals(out_script)) {
      warn(
          CFD_LOG_SOURCE, "unmatch scriptPubkey. txid:{},{}", txid.GetHex(),
          vout);
      throw CfdException(kCfdIllegalArgumentError, "unmatch scriptPubkey.");
    }
    has_check_script = true;
    is_witness = true;
  } else {
    warn(
        CFD_LOG_SOURCE, "unknown scriptPubkey. txid:{},{}", txid.GetHex(),
        vout);
    throw CfdException(kCfdIllegalArgumentError, "unknown scriptPubkey.");
  }

  if (has_check_script) {
    uint32_t count = 0;
    std::vector<Pubkey> pubkeys;
    if (redeem_script.IsMultisigScript()) {
      pubkeys = ScriptUtil::ExtractPubkeysFromMultisigScript(redeem_script);
    } else {
      auto items = redeem_script.GetElementList();
      for (auto item : items) {
        if (item.IsBinary() && Pubkey::IsValid(item.GetBinaryData())) {
          pubkeys.emplace_back(item.GetBinaryData());
        }
      }
    }
    if (!key_list.empty()) {
      for (auto key : key_list) {
        auto cur_pubkey = key.GetPubkey();
        for (auto pubkey : pubkeys) {
          if (pubkey.Equals(cur_pubkey)) {
            ++count;
            break;
          }
        }
      }
      if (count != key_list.size()) {
        warn(
            CFD_LOG_SOURCE, "unmatch key count. [{}:{}]", count,
            key_list.size());
        throw CfdException(kCfdIllegalArgumentError, "psbt key valid error.");
      }
    }
  }
  return is_witness;
}

/**
 * @brief set input script and key list.
 * @param[in,out] input       psbt input
 * @param[in] is_witness      witness flag
 * @param[in] redeem_script   redeem script
 * @param[in] key_list        bip32 key list.
 * @param[in] locking_script  locking script
 */
void SetPsbtTxInScriptAndKeyList(
    struct wally_psbt_input *input, bool is_witness,
    const Script &redeem_script, const std::vector<KeyData> &key_list,
    const Script &locking_script) {
  int ret;
  if (!redeem_script.IsEmpty()) {
    auto script_val = redeem_script.GetData().GetBytes();
    if (is_witness && (!redeem_script.IsP2wpkhScript())) {
      ret = wally_psbt_input_set_witness_script(
          input, script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        warn(
            CFD_LOG_SOURCE, "wally_psbt_input_set_witness_script NG[{}]", ret);
        throw CfdException(
            kCfdIllegalArgumentError, "psbt add witness script error.");
      }
      if (locking_script.IsP2shScript()) {
        script_val = ScriptUtil::CreateP2wshLockingScript(redeem_script)
                         .GetData()
                         .GetBytes();
      } else {
        script_val.clear();
      }
    }
    if (!script_val.empty()) {
      ret = wally_psbt_input_set_redeem_script(
          input, script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_psbt_input_set_redeem_script NG[{}]", ret);
        throw CfdException(
            kCfdIllegalArgumentError, "psbt add redeem script error.");
      }
    }
  }

  if (!key_list.empty()) {
    SetKeyPathMap(key_list, &input->keypaths);
    ret = wally_map_sort(&input->keypaths, 0);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
      throw CfdException(kCfdInternalError, "psbt input sort keypaths error.");
    }
  }
}

/**
 * @brief compare psbt data.
 * @param[in,out] src   source buffer
 * @param[in] src_len   source buffer length
 * @param[in] dest      destination buffer
 * @param[in] dest_len  destination buffer length
 * @param[in] item_name   field name
 * @param[in] key         key name
 * @param[in] ignore_duplicate_error  ignore duplicate error
 * @retval true   match
 * @retval false  unmatch
 */
bool ComparePsbtData(
    uint8_t *src, size_t src_len, const uint8_t *dest, size_t dest_len,
    const std::string &item_name, const std::string &key,
    bool ignore_duplicate_error) {
  bool is_compare = false;
  if ((src_len == dest_len) && (memcmp(src, dest, src_len) == 0)) {
    is_compare = true;
  } else if (ignore_duplicate_error) {
    // do nothing
  } else {
    if (key.empty()) {
      warn(CFD_LOG_SOURCE, "psbt {} already exist.", item_name);
    } else {
      warn(CFD_LOG_SOURCE, "psbt {} already exist. key[{}]", item_name, key);
    }
    throw CfdException(
        kCfdIllegalArgumentError, "psbt " + item_name + " duplicated error.");
  }
  return is_compare;
}

/**
 * @brief match wally tx.
 * @param[in] src    source
 * @param[in] dest   destination
 * @retval true   match
 * @retval false  unmatch
 */
bool MatchWallyTx(struct wally_tx *src, struct wally_tx *dest) {
  std::vector<uint8_t> src_txid(WALLY_TXHASH_LEN);
  std::vector<uint8_t> dest_txid(WALLY_TXHASH_LEN);
  int ret = wally_tx_get_txid(src, src_txid.data(), src_txid.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_txid NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt get txid error.");
  }
  ret = wally_tx_get_txid(dest, dest_txid.data(), dest_txid.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_get_txid NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt get txid error.");
  }
  return (src_txid == dest_txid);
}

/**
 * @brief merge wally map.
 * @param[in,out] src   source
 * @param[in] dst       destination
 * @param[in] item_name   field name
 * @param[in] ignore_duplicate_error    ignore duplicate error flag.
 */
void MergeWallyMap(
    struct wally_map *src, const struct wally_map *dst,
    const std::string &item_name, bool ignore_duplicate_error) {
  bool is_find;
  int ret;
  std::vector<size_t> regist_indexes;
  for (size_t dst_idx = 0; dst_idx < dst->num_items; ++dst_idx) {
    auto dst_item = &dst->items[dst_idx];
    is_find = false;
    for (size_t src_idx = 0; src_idx < src->num_items; ++src_idx) {
      auto src_item = &src->items[src_idx];
      if ((src_item->key_len == dst_item->key_len) &&
          (memcmp(src_item->key, dst_item->key, src_item->key_len) == 0)) {
        is_find = true;
        ByteData key(src_item->key, static_cast<uint32_t>(src_item->key_len));
        ComparePsbtData(
            src_item->value, src_item->value_len, dst_item->value,
            dst_item->value_len, item_name, key.GetHex(),
            ignore_duplicate_error);
        break;
      }
    }
    if (!is_find) regist_indexes.push_back(dst_idx);
  }
  if (!regist_indexes.empty()) {
    for (auto dst_idx : regist_indexes) {
      auto dst_item = &dst->items[dst_idx];
      ret = wally_map_add(
          src, dst_item->key, dst_item->key_len, dst_item->value,
          dst_item->value_len);
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
        throw CfdException(
            kCfdMemoryFullError, "psbt add " + item_name + " error.");
      }
    }

    ret = wally_map_sort(src, 0);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
      throw CfdException(kCfdInternalError, "psbt sort map error.");
    }
  }
}

/**
 * @brief alloc wally buffer.
 * @param[in] source    source
 * @param[in] length    source length
 * @return alloc buffer address
 */
uint8_t *AllocWallyBuffer(const uint8_t *source, size_t length) {
  wally_malloc_t malloc_func = nullptr;

  int ret;
  if (malloc_func == nullptr) {
    struct wally_operations ops;
    memset(&ops, 0, sizeof(ops));
    ops.struct_size = sizeof(ops);
    ret = wally_get_operations(&ops);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_get_operations NG[{}]", ret);
      throw CfdException(kCfdInternalError, "OperationFunctions get error.");
    }
    malloc_func = ops.malloc_fn;
  }
  void *addr = malloc_func(length);
  if (addr == nullptr) {
    warn(CFD_LOG_SOURCE, "wally malloc NG.");
    throw CfdException(kCfdMemoryFullError, "malloc error.");
  }
  memcpy(addr, source, length);
  return static_cast<uint8_t *>(addr);
}

/**
 * @brief free wally buffer
 * @param[in] source   buffer
 */
void FreeWallyBuffer(void *source) {
  wally_free_t free_func = nullptr;

  int ret;
  if (free_func == nullptr) {
    struct wally_operations ops;
    memset(&ops, 0, sizeof(ops));
    ops.struct_size = sizeof(ops);
    ret = wally_get_operations(&ops);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_get_operations NG[{}]", ret);
      throw CfdException(kCfdInternalError, "OperationFunctions get error.");
    }
    free_func = ops.free_fn;
  }
  free_func(source);
}

/**
 * @brief merge input item.
 * @param[in,out] psbt     source psbt input.
 * @param[in] psbt_dest    destination psbt input.
 * @param[in] ignore_duplicate_error   ignore duplicate error flag
 * @param[in] item_name   field name
 */
void MergePsbtInputItem(
    struct wally_psbt_input *psbt, const struct wally_psbt_input *psbt_dest,
    bool ignore_duplicate_error, const std::string &item_name) {
  int ret;
  if (psbt_dest->utxo != nullptr) {
    if (psbt->utxo == nullptr) {
      ret = wally_psbt_input_set_utxo(psbt, psbt_dest->utxo);
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_psbt_input_set_utxo NG[{}]", ret);
        throw CfdException(kCfdIllegalArgumentError, "psbt set utxo error.");
      }
    } else if (MatchWallyTx(psbt->utxo, psbt_dest->utxo)) {
      // match
    } else if (ignore_duplicate_error) {
      // do nothing
    } else {
      warn(CFD_LOG_SOURCE, "psbt txin utxo already exist.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt txin utxo duplicated error.");
    }
  }
  if (psbt_dest->witness_utxo != nullptr) {
    if (psbt->witness_utxo == nullptr) {
      ret = wally_psbt_input_set_witness_utxo(psbt, psbt_dest->witness_utxo);
      if (ret != WALLY_OK) {
        warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_utxo NG[{}]", ret);
        throw CfdException(
            kCfdIllegalArgumentError, "psbt set witness utxo error.");
      }
    } else if (
        (psbt->witness_utxo->satoshi == psbt_dest->witness_utxo->satoshi) &&
        ComparePsbtData(
            psbt->witness_utxo->script, psbt->witness_utxo->script_len,
            psbt_dest->witness_utxo->script,
            psbt_dest->witness_utxo->script_len, item_name, "scriptPubkey",
            ignore_duplicate_error)) {
      // match
    } else if (ignore_duplicate_error) {
      // do nothing
    } else {
      warn(CFD_LOG_SOURCE, "psbt txin witness utxo already exist.");
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt txin witness utxo duplicated error.");
    }
  }
  if (psbt_dest->sighash > 0) {
    if (psbt->sighash == 0) {
      psbt->sighash = psbt_dest->sighash;
    } else if (psbt->sighash == psbt_dest->sighash) {
      // match
    } else if (ignore_duplicate_error) {
      // do nothing
    } else {
      std::string field_name = "txin sighashtype";
      warn(CFD_LOG_SOURCE, "psbt {} already exist.", field_name);
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt " + field_name + " duplicated error.");
    }
  }
  if (psbt_dest->redeem_script_len > 0) {
    if (psbt->redeem_script_len == 0) {
      psbt->redeem_script = AllocWallyBuffer(
          psbt_dest->redeem_script, psbt_dest->redeem_script_len);
      psbt->redeem_script_len = psbt_dest->redeem_script_len;
    } else {
      ComparePsbtData(
          psbt->redeem_script, psbt->redeem_script_len,
          psbt_dest->redeem_script, psbt_dest->redeem_script_len,
          "txin redeem script", "", ignore_duplicate_error);
    }
  }
  if (psbt_dest->witness_script_len > 0) {
    if (psbt->witness_script_len == 0) {
      psbt->witness_script = AllocWallyBuffer(
          psbt_dest->witness_script, psbt_dest->witness_script_len);
      psbt->witness_script_len = psbt_dest->witness_script_len;
    } else {
      ComparePsbtData(
          psbt->witness_script, psbt->witness_script_len,
          psbt_dest->witness_script, psbt_dest->witness_script_len,
          "txin witness script", "", ignore_duplicate_error);
    }
  }
  MergeWallyMap(
      &psbt->keypaths, &psbt_dest->keypaths, "txin keypaths",
      ignore_duplicate_error);
  MergeWallyMap(
      &psbt->signatures, &psbt_dest->signatures, "txin signatures",
      ignore_duplicate_error);
  MergeWallyMap(
      &psbt->unknowns, &psbt_dest->unknowns, "txin unknowns",
      ignore_duplicate_error);
}

/**
 * @brief merge output item.
 * @param[in,out] psbt     source psbt output.
 * @param[in] psbt_dest    destination psbt output.
 * @param[in] ignore_duplicate_error   ignore duplicate error flag
 */
void MergePsbtOutputItem(
    struct wally_psbt_output *psbt, const struct wally_psbt_output *psbt_dest,
    bool ignore_duplicate_error) {
  if (psbt_dest->redeem_script_len > 0) {
    if (psbt->redeem_script_len == 0) {
      psbt->redeem_script = AllocWallyBuffer(
          psbt_dest->redeem_script, psbt_dest->redeem_script_len);
      psbt->redeem_script_len = psbt_dest->redeem_script_len;
    } else {
      ComparePsbtData(
          psbt->redeem_script, psbt->redeem_script_len,
          psbt_dest->redeem_script, psbt_dest->redeem_script_len,
          "txout redeem script", "", ignore_duplicate_error);
    }
  }
  if (psbt_dest->witness_script_len > 0) {
    if (psbt->witness_script_len == 0) {
      psbt->witness_script = AllocWallyBuffer(
          psbt_dest->witness_script, psbt_dest->witness_script_len);
      psbt->witness_script_len = psbt_dest->witness_script_len;
    } else {
      ComparePsbtData(
          psbt->witness_script, psbt->witness_script_len,
          psbt_dest->witness_script, psbt_dest->witness_script_len,
          "txout witness script", "", ignore_duplicate_error);
    }
  }
  MergeWallyMap(
      &psbt->keypaths, &psbt_dest->keypaths, "txout keypaths",
      ignore_duplicate_error);
  MergeWallyMap(
      &psbt->unknowns, &psbt_dest->unknowns, "txout unknowns",
      ignore_duplicate_error);
}

/**
 * @brief merge input list.
 * @param[in,out] psbt     source psbt.
 * @param[in] psbt_dest    destination psbt.
 * @param[in] ignore_duplicate_error   ignore duplicate error flag
 */
void MergePsbtInputs(
    struct wally_psbt *psbt, const struct wally_psbt *psbt_dest,
    bool ignore_duplicate_error) {
  bool is_find;
  int ret;
  std::vector<size_t> append_indexes;
  for (size_t dst_idx = 0; dst_idx < psbt_dest->num_inputs; ++dst_idx) {
    auto dest_txin = &psbt_dest->tx->inputs[dst_idx];
    is_find = false;
    for (size_t src_idx = 0; src_idx < psbt->num_inputs; ++src_idx) {
      auto src_txin = &psbt->tx->inputs[src_idx];
      if ((src_txin->index == dest_txin->index) &&
          (memcmp(
               src_txin->txhash, dest_txin->txhash,
               sizeof(src_txin->txhash)) == 0)) {
        is_find = true;
        Txid txid(ByteData256(ByteData(
            src_txin->txhash,
            static_cast<uint32_t>(sizeof(src_txin->txhash)))));
        std::string item_key =
            txid.GetHex() + "," + std::to_string(src_txin->index);
        if (src_txin->sequence == dest_txin->sequence) {
          // do nothing
        } else if (ignore_duplicate_error) {
          // do nothing
        } else {
          warn(CFD_LOG_SOURCE, "psbt sequence duplicate. [{}]", item_key);
          throw CfdException(
              kCfdIllegalArgumentError, "psbt sequence duplicate error.");
        }
        MergePsbtInputItem(
            &psbt->inputs[src_idx], &psbt_dest->inputs[dst_idx],
            ignore_duplicate_error, item_key);
        break;
      }
    }
    if (!is_find) append_indexes.push_back(dst_idx);
  }

  uint32_t index;
  for (auto dst_idx : append_indexes) {
    index = static_cast<uint32_t>(psbt->num_inputs);
    ret = wally_psbt_add_input_at(
        psbt, index, WALLY_PSBT_FLAG_NON_FINAL,
        &psbt_dest->tx->inputs[dst_idx]);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_add_input_at NG[{}]", ret);
      throw CfdException(
          kCfdMemoryFullError, "psbt add global unkonwns error.");
    }
    auto dest_txin = &psbt_dest->tx->inputs[dst_idx];
    Txid txid(ByteData256(ByteData(
        dest_txin->txhash, static_cast<uint32_t>(sizeof(dest_txin->txhash)))));
    std::string item_key =
        txid.GetHex() + "," + std::to_string(dest_txin->index);
    MergePsbtInputItem(
        &psbt->inputs[index], &psbt_dest->inputs[dst_idx],
        ignore_duplicate_error, item_key);
  }
}

/**
 * @brief merge output list.
 * @param[in,out] psbt     source psbt.
 * @param[in] psbt_dest    destination psbt.
 * @param[in] ignore_duplicate_error   ignore duplicate error flag
 */
void MergePsbtOutputs(
    struct wally_psbt *psbt, const struct wally_psbt *psbt_dest,
    bool ignore_duplicate_error) {
  bool is_find;
  int ret;
  std::vector<size_t> append_indexes;
  size_t start_idx = 0;
  for (size_t dst_idx = 0; dst_idx < psbt_dest->num_outputs; ++dst_idx) {
    auto dest_txout = &psbt_dest->tx->outputs[dst_idx];
    is_find = false;
    for (size_t src_idx = start_idx; src_idx < psbt->num_outputs; ++src_idx) {
      auto src_txout = &psbt->tx->outputs[src_idx];
      if ((src_txout->satoshi == dest_txout->satoshi) &&
          (src_txout->script_len == dest_txout->script_len) &&
          (memcmp(
               src_txout->script, dest_txout->script,
               sizeof(src_txout->script_len)) == 0)) {
        is_find = true;
        start_idx = src_idx + 1;
        MergePsbtOutputItem(
            &psbt->outputs[src_idx], &psbt_dest->outputs[dst_idx],
            ignore_duplicate_error);
        break;
      }
    }
    if (!is_find) append_indexes.push_back(dst_idx);
  }

  uint32_t index;
  for (auto dst_idx : append_indexes) {
    index = static_cast<uint32_t>(psbt->num_outputs);
    ret = wally_psbt_add_output_at(
        psbt, index, 0, &psbt_dest->tx->outputs[dst_idx]);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_add_output_at NG[{}]", ret);
      throw CfdException(
          kCfdMemoryFullError, "psbt add global unkonwns error.");
    }
    MergePsbtOutputItem(
        &psbt->outputs[index], &psbt_dest->outputs[dst_idx],
        ignore_duplicate_error);
  }
}

/**
 * @brief merge psbt.
 * @param[in] src   source psbt
 * @param[in] dest  destination psbt
 * @param[in] ignore_duplicate_error  ignore duplicate error
 * @return merged psbt
 */
struct wally_psbt *MergePsbt(
    const void *src, const void *dest, bool ignore_duplicate_error) {
  const struct wally_psbt *psbt_src =
      static_cast<const struct wally_psbt *>(src);
  const struct wally_psbt *psbt_dest =
      static_cast<const struct wally_psbt *>(dest);

  if ((psbt_src->tx == nullptr) ||
      (psbt_src->num_inputs != psbt_src->tx->num_inputs) ||
      (psbt_src->num_outputs != psbt_src->tx->num_outputs)) {
    warn(CFD_LOG_SOURCE, "psbt src format error.");
    throw CfdException(kCfdIllegalArgumentError, "psbt src format error.");
  }
  if ((psbt_dest->tx == nullptr) ||
      (psbt_dest->num_inputs != psbt_dest->tx->num_inputs) ||
      (psbt_dest->num_outputs != psbt_dest->tx->num_outputs)) {
    warn(CFD_LOG_SOURCE, "psbt dest format error.");
    throw CfdException(kCfdIllegalArgumentError, "psbt dest format error.");
  }

  struct wally_psbt *psbt = nullptr;
  int ret = wally_psbt_clone_alloc(psbt_src, 0, &psbt);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_clone_alloc NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt clone error.");
  }

  try {
    if (memcmp(psbt->magic, psbt_dest->magic, sizeof(psbt->magic)) != 0) {
      warn(CFD_LOG_SOURCE, "psbt unmatch magic.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt unmatch magic error.");
    }
    if (psbt->version != psbt_dest->version) {
      warn(
          CFD_LOG_SOURCE, "psbt unmatch version: [{},{}]", psbt->version,
          psbt_dest->version);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt unmatch version error.");
    }
    MergeWallyMap(
        &psbt->unknowns, &psbt_dest->unknowns, "global unknowns",
        ignore_duplicate_error);

    MergePsbtInputs(psbt, psbt_dest, ignore_duplicate_error);
    MergePsbtOutputs(psbt, psbt_dest, ignore_duplicate_error);
  } catch (const CfdException &except) {
    wally_psbt_free(psbt);
    throw except;
  }
  return psbt;
}

/**
 * @brief write psbt output.
 * @param[in,out] builder   serialize object
 * @param[in] output        psbt output
 */
static void WritePsbtOutput(
    Serializer *builder, const struct wally_psbt_output *output) {
  if (output->redeem_script_len != 0) {
    builder->AddDirectByte(1);
    builder->AddVariableInt(Psbt::kPsbtOutputRedeemScript);
    builder->AddVariableBuffer(
        output->redeem_script,
        static_cast<uint32_t>(output->redeem_script_len));
  }
  if (output->witness_script_len != 0) {
    builder->AddDirectByte(1);
    builder->AddVariableInt(Psbt::kPsbtOutputWitnessScript);
    builder->AddVariableBuffer(
        output->witness_script,
        static_cast<uint32_t>(output->witness_script_len));
  }
  for (size_t i = 0; i < output->keypaths.num_items; ++i) {
    auto *item = &output->keypaths.items[i];
    builder->AddPrefixBuffer(
        Psbt::kPsbtOutputBip32Derivation, item->key,
        static_cast<uint32_t>(item->key_len));
    builder->AddVariableBuffer(
        item->value, static_cast<uint32_t>(item->value_len));
  }
  for (size_t i = 0; i < output->unknowns.num_items; ++i) {
    auto *item = &output->unknowns.items[i];
    builder->AddVariableBuffer(
        item->key, static_cast<uint32_t>(item->key_len));
    builder->AddVariableBuffer(
        item->value, static_cast<uint32_t>(item->value_len));
  }
  builder->AddDirectByte(kPsbtSeparator);
}

/**
 * @brief create psbt output only object.
 * @param[in] psbt   psbt object
 * @return psbt binary data.
 */
ByteData CreatePsbtOutputOnlyData(const struct wally_psbt *psbt) {
  Serializer builder;
  builder.AddDirectBytes(psbt->magic, sizeof(psbt->magic));

  builder.AddDirectByte(1);
  builder.AddVariableInt(Psbt::kPsbtGlobalUnsignedTx);
  auto tx = ConvertBitcoinTxFromWally(psbt->tx, false).GetBytes();
  builder.AddVariableBuffer(tx.data(), static_cast<uint32_t>(tx.size()));

  if (psbt->version > 0) {
    builder.AddDirectByte(1);
    builder.AddVariableInt(Psbt::kPsbtGlobalVersion);
    std::vector<uint8_t> data(sizeof(psbt->version));
    memcpy(data.data(), &psbt->version, data.size());
    // TODO(k-matsuzawa) need endian support.
    builder.AddVariableBuffer(data.data(), sizeof(psbt->version));
  }

  for (size_t i = 0; i < psbt->unknowns.num_items; ++i) {
    auto *item = &psbt->unknowns.items[i];
    builder.AddVariableBuffer(item->key, static_cast<uint32_t>(item->key_len));
    builder.AddVariableBuffer(
        item->value, static_cast<uint32_t>(item->value_len));
  }
  builder.AddDirectByte(kPsbtSeparator);

  // input is unsupport.

  for (size_t i = 0; i < psbt->num_outputs; ++i) {
    WritePsbtOutput(&builder, &psbt->outputs[i]);
  }
  return builder.Output();
}

/**
 * @brief find psbt map data.
 * @param[in] map_object    map
 * @param[in] key           key data
 * @param[in] field_name    field name
 * @param[out] index        index
 */
static void FindPsbtMap(
    const struct wally_map *map_object, const std::vector<uint8_t> &key,
    const std::string &field_name, size_t *index = nullptr) {
  size_t exist = 0;
  int ret = wally_map_find(map_object, key.data(), key.size(), &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(
        kCfdInternalError, "psbt find " + field_name + " error.");
  }
  if ((index == nullptr) && (exist != 0)) {
    warn(CFD_LOG_SOURCE, "{} duplicates.", field_name);
    throw CfdException(
        kCfdIllegalArgumentError, "psbt " + field_name + " duplicates error.");
  } else if (index != nullptr) {
    if (exist == 0) {
      warn(CFD_LOG_SOURCE, "{} not found.", field_name);
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt " + field_name + " not found error.");
    }
    *index = exist - 1;
  }
}

/**
 * @brief set psbt global data.
 * @param[in] key     key
 * @param[in] value   value
 * @param[in,out] psbt  psbt object
 * @return key type
 */
static uint8_t SetPsbtGlobal(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &value,
    struct wally_psbt *psbt) {
  if (psbt == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  }
  int ret;
  bool has_key_1byte = (key.size() == 1);
  if (key[0] == Psbt::kPsbtGlobalUnsignedTx) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    warn(CFD_LOG_SOURCE, "setting global tx is not supported.");
    throw CfdException(
        kCfdIllegalArgumentError,
        "psbt setting global tx is not supported error.");
  } else if (key[0] == Psbt::kPsbtGlobalVersion) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    warn(CFD_LOG_SOURCE, "setting global version is not supported.");
    throw CfdException(
        kCfdIllegalArgumentError,
        "psbt setting global version is not supported error.");
  } else {
    FindPsbtMap(&psbt->unknowns, key, "global unknowns");
    ret = wally_map_add(
        &psbt->unknowns, key.data(), key.size(), value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt add global unknowns error.");
    }
  }
  return key[0];
}

/**
 * @brief Get psbt global data.
 * @param[in] key_data    key
 * @param[in] psbt        psbt object
 * @param[out] is_find    psbt key find
 * @return value
 */
static ByteData GetPsbtGlobal(
    const ByteData &key_data, struct wally_psbt *psbt, bool *is_find) {
  if (psbt == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  }
  if (is_find != nullptr) *is_find = false;
  const auto key = key_data.GetBytes();
  bool has_key_1byte = (key.size() == 1);
  if (key[0] == Psbt::kPsbtGlobalUnsignedTx) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (is_find != nullptr) *is_find = true;
    Transaction tx(ConvertBitcoinTxFromWally(psbt->tx, false));
    return tx.GetData();
  } else if (key[0] == Psbt::kPsbtGlobalVersion) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (is_find != nullptr) *is_find = true;
    // TODO(k-matsuzawa) need endian support.
    Serializer builder;
    builder.AddDirectNumber(psbt->version);
    return builder.Output();
  } else {
    size_t index = 0;
    try {
      FindPsbtMap(&psbt->unknowns, key, "global unknowns", &index);
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          psbt->unknowns.items[index].value,
          static_cast<uint32_t>(psbt->unknowns.items[index].value_len));
    } catch (const CfdException &except) {
      if ((is_find == nullptr) ||
          (except.GetErrorCode() != kCfdIllegalArgumentError)) {
        throw except;
      }
    }
  }
  return ByteData();
}

/**
 * @brief set psbt input data.
 * @param[in] key     key
 * @param[in] value   value
 * @param[in,out] input  psbt input
 * @return key type
 */
static uint8_t SetPsbtInput(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &value,
    struct wally_psbt_input *input) {
  int ret;
  bool has_key_1byte = (key.size() == 1);
  if (key[0] == Psbt::kPsbtInputNonWitnessUtxo) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    Transaction tx(value);
    struct wally_tx *wally_tx_obj = nullptr;
    ret = wally_tx_from_hex(tx.GetHex().c_str(), 0, &wally_tx_obj);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}]", ret);
      throw CfdException(kCfdIllegalArgumentError, "psbt tx from hex error.");
    } else if (
        (wally_tx_obj->num_inputs == 0) || (wally_tx_obj->num_outputs == 0)) {
      wally_tx_free(wally_tx_obj);
      warn(CFD_LOG_SOURCE, "invalind utxo transaction format.");
      throw CfdException(kCfdIllegalArgumentError, "psbt invalid tx error.");
    }

    ret = wally_psbt_input_set_utxo(input, wally_tx_obj);
    wally_tx_free(wally_tx_obj);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_utxo NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set input utxo error.");
    }
  } else if (key[0] == Psbt::kPsbtInputWitnessUtxo) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    // TODO(k-matsuzawa) need endian support.
    Deserializer parser(value);
    uint64_t amount = parser.ReadUint64();
    auto script = parser.ReadVariableBuffer();
    struct wally_tx_output txout;
    memset(&txout, 0, sizeof(txout));
    txout.satoshi = static_cast<uint64_t>(amount);
    txout.script = script.data();
    txout.script_len = script.size();
    ret = wally_psbt_input_set_witness_utxo(input, &txout);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_utxo NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set output witnessUtxo error.");
    }
  } else if (key[0] == Psbt::kPsbtInputPartialSig) {
    std::vector<uint8_t> pubkey(key.size() - 1);
    if (pubkey.size() != 0) {
      memcpy(pubkey.data(), &key.data()[1], pubkey.size());
    }
    Pubkey pk(pubkey);
    auto pk_bytes = pk.GetData().GetBytes();
    FindPsbtMap(&input->signatures, pk_bytes, "input signatures");

    ret = wally_map_add(
        &input->signatures, pk_bytes.data(), pk_bytes.size(), value.data(),
        value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set input signatures error.");
    }
  } else if (key[0] == Psbt::kPsbtInputSighashType) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (value.size() < 4) {
      warn(CFD_LOG_SOURCE, "psbt invalid value format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid value format error.");
    }
    // TODO(k-matsuzawa) need endian support.
    uint32_t sighash = 0;
    memcpy(&sighash, value.data(), sizeof(sighash));
    ret = wally_psbt_input_set_sighash(input, sighash);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_sighash NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set input sighash error.");
    }
  } else if (key[0] == Psbt::kPsbtInputRedeemScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    ret =
        wally_psbt_input_set_redeem_script(input, value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_redeem_script NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set input redeemScript error.");
    }
  } else if (key[0] == Psbt::kPsbtInputWitnessScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    ret =
        wally_psbt_input_set_witness_script(input, value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_script NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set input witnessScript error.");
    }
  } else if (key[0] == Psbt::kPsbtInputBip32Derivation) {
    std::vector<uint8_t> pubkey(key.size() - 1);
    if (pubkey.size() != 0) {
      memcpy(pubkey.data(), &key.data()[1], pubkey.size());
    }
    Pubkey pk(pubkey);
    auto pk_bytes = pk.GetData().GetBytes();
    FindPsbtMap(&input->keypaths, pk_bytes, "input bip32 pubkey");

    if (value.size() < 4) {
      warn(CFD_LOG_SOURCE, "psbt invalid value format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid value format error.");
    }
    size_t path_len = value.size() - 4;
    std::vector<uint32_t> path(path_len / 4);
    if (path_len != 0) {
      // TODO(k-matsuzawa) need endian support.
      memcpy(path.data(), &value.data()[4], path_len);
    }
    ret = wally_map_add_keypath_item(
        &input->keypaths, pk_bytes.data(), pk_bytes.size(), value.data(), 4,
        path.data(), path.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_add_keypath_item NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set input pubkey error.");
    }
  } else if (key[0] == Psbt::kPsbtInputFinalScriptsig) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    ret = wally_psbt_input_set_final_scriptsig(
        input, value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_scriptsig NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set input final scriptsig error.");
    }
  } else if (key[0] == Psbt::kPsbtInputFinalScriptWitness) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    Deserializer parser(value);
    uint64_t num = parser.ReadVariableInt();
    std::vector<std::vector<uint8_t>> stack_list(num);
    for (uint64_t idx = 0; idx < num; ++idx) {
      stack_list[idx] = parser.ReadVariableBuffer();
    }

    struct wally_tx_witness_stack *stack = nullptr;
    ret = wally_tx_witness_stack_init_alloc(num, &stack);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_init_alloc NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt alloc witness stack error.");
    }
    for (const auto &stack_data : stack_list) {
      ret = wally_tx_witness_stack_add(
          stack, stack_data.data(), stack_data.size());
      if (ret != WALLY_OK) {
        wally_tx_witness_stack_free(stack);
        warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_add NG[{}]", ret);
        throw CfdException(
            kCfdIllegalArgumentError, "psbt add witness stack error.");
      }
    }
    ret = wally_psbt_input_set_final_witness(input, stack);
    wally_tx_witness_stack_free(stack);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_witness NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt set input final witnessStack error.");
    }
  } else {
    FindPsbtMap(&input->unknowns, key, "input unknowns");
    ret = wally_map_add(
        &input->unknowns, key.data(), key.size(), value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt add input unknowns error.");
    }
  }
  return key[0];
}

/**
 * @brief Get psbt input data.
 * @param[in] key_data    key
 * @param[in] input       psbt input
 * @param[out] is_find    psbt key find
 * @return value
 */
static ByteData GetPsbtInput(
    const ByteData &key_data, const struct wally_psbt_input *input,
    bool *is_find) {
  const auto key = key_data.GetBytes();
  if (is_find != nullptr) *is_find = false;
  bool has_key_1byte = (key.size() == 1);
  if (key[0] == Psbt::kPsbtInputNonWitnessUtxo) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (input->utxo != nullptr) {
      if (is_find != nullptr) *is_find = true;
      Transaction tx(ConvertBitcoinTxFromWally(input->utxo, false));
      return tx.GetData();
    } else if (is_find == nullptr) {
      warn(CFD_LOG_SOURCE, "psbt target {} not found.", key_data.GetHex());
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtInputWitnessUtxo) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    // TODO(k-matsuzawa) need endian support.
    if (input->witness_utxo != nullptr) {
      if (is_find != nullptr) *is_find = true;
      Serializer builder;
      builder.AddDirectNumber(input->witness_utxo->satoshi);
      builder.AddVariableBuffer(ByteData(
          input->witness_utxo->script,
          static_cast<uint32_t>(input->witness_utxo->script_len)));
      return builder.Output();
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtInputPartialSig) {
    std::vector<uint8_t> pubkey(key.size() - 1);
    if (pubkey.size() != 0) {
      memcpy(pubkey.data(), &key.data()[1], pubkey.size());
    }
    Pubkey pk(pubkey);
    auto pk_bytes = pk.GetData().GetBytes();
    size_t index = 0;
    try {
      FindPsbtMap(&input->signatures, pk_bytes, "input signatures", &index);
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          input->signatures.items[index].value,
          static_cast<uint32_t>(input->signatures.items[index].value_len));
    } catch (const CfdException &except) {
      if ((is_find == nullptr) ||
          (except.GetErrorCode() != kCfdIllegalArgumentError)) {
        throw except;
      }
    }
  } else if (key[0] == Psbt::kPsbtInputSighashType) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (input->sighash != 0) {
      if (is_find != nullptr) *is_find = true;
      // TODO(k-matsuzawa) need endian support.
      Serializer builder;
      builder.AddDirectNumber(input->sighash);
      return builder.Output();
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtInputRedeemScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (input->redeem_script_len != 0) {
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          input->redeem_script,
          static_cast<uint32_t>(input->redeem_script_len));
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtInputWitnessScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (input->witness_script_len != 0) {
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          input->witness_script,
          static_cast<uint32_t>(input->witness_script_len));
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtInputBip32Derivation) {
    std::vector<uint8_t> pubkey(key.size() - 1);
    if (pubkey.size() != 0) {
      memcpy(pubkey.data(), &key.data()[1], pubkey.size());
    }
    Pubkey pk(pubkey);
    auto pk_bytes = pk.GetData().GetBytes();
    size_t index = 0;
    try {
      FindPsbtMap(&input->keypaths, pk_bytes, "input bip32 pubkey", &index);
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          input->keypaths.items[index].value,
          static_cast<uint32_t>(input->keypaths.items[index].value_len));
    } catch (const CfdException &except) {
      if ((is_find == nullptr) ||
          (except.GetErrorCode() != kCfdIllegalArgumentError)) {
        throw except;
      }
    }
  } else if (key[0] == Psbt::kPsbtInputFinalScriptsig) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (input->final_scriptsig_len != 0) {
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          input->final_scriptsig,
          static_cast<uint32_t>(input->final_scriptsig_len));
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtInputFinalScriptWitness) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (input->final_witness != nullptr) {
      if (is_find != nullptr) *is_find = true;
      Serializer builder;
      size_t num = input->final_witness->num_items;
      builder.AddVariableInt(num);
      for (uint64_t idx = 0; idx < num; ++idx) {
        builder.AddVariableBuffer(ByteData(
            input->final_witness->items[idx].witness,
            static_cast<uint32_t>(
                input->final_witness->items[idx].witness_len)));
      }
      return builder.Output();
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else {
    size_t index = 0;
    try {
      FindPsbtMap(&input->unknowns, key, "input unknowns", &index);
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          input->unknowns.items[index].value,
          static_cast<uint32_t>(input->unknowns.items[index].value_len));
    } catch (const CfdException &except) {
      if ((is_find == nullptr) ||
          (except.GetErrorCode() != kCfdIllegalArgumentError)) {
        throw except;
      }
    }
  }
  return ByteData();
}

/**
 * @brief set psbt output data.
 * @param[in] key     key
 * @param[in] value   value
 * @param[in,out] output  psbt output
 * @return key type
 */
static uint8_t SetPsbtOutput(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &value,
    struct wally_psbt_output *output) {
  int ret;
  bool has_key_1byte = (key.size() == 1);
  if (key[0] == Psbt::kPsbtOutputRedeemScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (output->redeem_script != nullptr) {
      warn(CFD_LOG_SOURCE, "output redeemScript duplicates.");
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt output redeemScript duplicates error.");
    }
    ret = wally_psbt_output_set_redeem_script(
        output, value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_output_set_redeem_script NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set output redeemScript error.");
    }
  } else if (key[0] == Psbt::kPsbtOutputWitnessScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (output->witness_script != nullptr) {
      warn(CFD_LOG_SOURCE, "output witnessScript duplicates.");
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt output witnessScript duplicates error.");
    }
    ret = wally_psbt_output_set_witness_script(
        output, value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_output_set_witness_script NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set output witnessScript error.");
    }
  } else if (key[0] == Psbt::kPsbtOutputBip32Derivation) {
    std::vector<uint8_t> pubkey(key.size() - 1);
    if (pubkey.size() != 0) {
      memcpy(pubkey.data(), &key.data()[1], pubkey.size());
    }
    Pubkey pk(pubkey);
    auto pk_bytes = pk.GetData().GetBytes();
    FindPsbtMap(&output->keypaths, pk_bytes, "output bip32 pubkey");

    if (value.size() < 4) {
      warn(CFD_LOG_SOURCE, "psbt invalid value format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid value format error.");
    }
    size_t path_len = value.size() - 4;
    std::vector<uint32_t> path(path_len / 4);
    if (path_len != 0) {
      // TODO(k-matsuzawa) need endian support.
      memcpy(path.data(), &value.data()[4], path_len);
    }
    ret = wally_map_add_keypath_item(
        &output->keypaths, pk_bytes.data(), pk_bytes.size(), value.data(), 4,
        path.data(), path.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_add_keypath_item NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set output pubkey error.");
    }
  } else {
    FindPsbtMap(&output->unknowns, key, "output unknowns");
    ret = wally_map_add(
        &output->unknowns, key.data(), key.size(), value.data(), value.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt add output unknowns error.");
    }
  }
  return key[0];
}

/**
 * @brief Get psbt output data.
 * @param[in] key_data    key
 * @param[in] output      psbt output
 * @param[out] is_find    psbt key find
 * @return value
 */
static ByteData GetPsbtOutput(
    const ByteData &key_data, struct wally_psbt_output *output,
    bool *is_find) {
  if (is_find != nullptr) *is_find = false;
  const auto key = key_data.GetBytes();
  bool has_key_1byte = (key.size() == 1);
  if (key[0] == Psbt::kPsbtOutputRedeemScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (output->redeem_script_len != 0) {
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          output->redeem_script,
          static_cast<uint32_t>(output->redeem_script_len));
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtOutputWitnessScript) {
    if (!has_key_1byte) {
      warn(CFD_LOG_SOURCE, "psbt invalid key format.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid key format error.");
    }
    if (output->witness_script_len != 0) {
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          output->witness_script,
          static_cast<uint32_t>(output->witness_script_len));
    } else if (is_find == nullptr) {
      throw CfdException(
          kCfdIllegalArgumentError,
          "psbt target key " + key_data.GetHex() + " not found error.");
    }
  } else if (key[0] == Psbt::kPsbtOutputBip32Derivation) {
    std::vector<uint8_t> pubkey(key.size() - 1);
    if (pubkey.size() != 0) {
      memcpy(pubkey.data(), &key.data()[1], pubkey.size());
    }
    Pubkey pk(pubkey);
    auto pk_bytes = pk.GetData().GetBytes();
    size_t index = 0;
    try {
      FindPsbtMap(&output->keypaths, pk_bytes, "output bip32 pubkey", &index);
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          output->keypaths.items[index].value,
          static_cast<uint32_t>(output->keypaths.items[index].value_len));
    } catch (const CfdException &except) {
      if ((is_find == nullptr) ||
          (except.GetErrorCode() != kCfdIllegalArgumentError)) {
        throw except;
      }
    }
  } else {
    size_t index = 0;
    try {
      FindPsbtMap(&output->unknowns, key, "output unknowns", &index);
      if (is_find != nullptr) *is_find = true;
      return ByteData(
          output->unknowns.items[index].value,
          static_cast<uint32_t>(output->unknowns.items[index].value_len));
    } catch (const CfdException &except) {
      if ((is_find == nullptr) ||
          (except.GetErrorCode() != kCfdIllegalArgumentError)) {
        throw except;
      }
    }
  }
  return ByteData();
}

/**
 * @brief parse psbt output data.
 * @param[in] parser     deserialize object
 * @param[in,out] output  psbt output
 */
static void ParsePsbtOutput(
    Deserializer *parser, struct wally_psbt_output *output) {
  int ret;
  std::vector<uint8_t> key;
  do {
    key = parser->ReadVariableBuffer();
    if (!key.empty()) {
      std::vector<uint8_t> buf = parser->ReadVariableBuffer();
      SetPsbtOutput(key, buf, output);
    }
  } while (!key.empty());

  ret = wally_map_sort(&output->keypaths, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt output sort keypaths error.");
  }

  ret = wally_map_sort(&output->unknowns, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt output sort unknowns error.");
  }
}

/**
 * @brief parse psbt data.
 * @param[in] data     psbt binary data
 * @return psbt object
 */
struct wally_psbt *ParsePsbtData(const ByteData &data) {
  static const uint8_t kPsbtMagic[] = {'p', 's', 'b', 't', 0xff};

  struct wally_psbt *psbt = nullptr;
  std::vector<uint8_t> bytes = data.GetBytes();
  int ret = wally_psbt_from_bytes(bytes.data(), bytes.size(), &psbt);
  if (ret == WALLY_OK) {
    if ((psbt->num_inputs != 0) || (psbt->num_outputs != 0)) {
      return psbt;
    }
    std::vector<uint8_t> tmp_buf(bytes.size());
    size_t tmp_size = 0;
    ret = wally_psbt_to_bytes(
        psbt, 0, tmp_buf.data(), tmp_buf.size(), &tmp_size);
    if ((ret == WALLY_OK) && (tmp_size == bytes.size())) {
      // It was able to convert the data correctly.
      return psbt;
    }
    wally_psbt_free(psbt);
    psbt = nullptr;
  } else if (ret != WALLY_EINVAL) {
    warn(CFD_LOG_SOURCE, "wally_psbt_from_bytes NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt from bytes error.");
  }

  Deserializer parser(data);
  uint8_t magic[sizeof(kPsbtMagic)];
  memset(magic, 0, sizeof(magic));
  if (bytes.size() > 5) parser.ReadArray(magic, sizeof(magic));
  if (memcmp(magic, kPsbtMagic, sizeof(magic)) != 0) {
    warn(CFD_LOG_SOURCE, "psbt unmatch magic.");
    throw CfdException(kCfdInternalError, "psbt unmatch magic error.");
  }
  ret = wally_psbt_init_alloc(0, 0, 0, 0, &psbt);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_init_alloc NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt alloc error.");
  }

  try {
    memcpy(psbt->magic, magic, sizeof(psbt->magic));

    std::vector<uint8_t> key;
    do {
      key = parser.ReadVariableBuffer();
      if (!key.empty()) {
        std::vector<uint8_t> buf = parser.ReadVariableBuffer();
        bool has_key_1byte = (key.size() == 1);
        if (key[0] == Psbt::kPsbtGlobalUnsignedTx) {
          if (!has_key_1byte) {
            warn(CFD_LOG_SOURCE, "psbt invalid key format.");
            throw CfdException(
                kCfdIllegalArgumentError, "psbt invalid key format error.");
          }
          if (psbt->tx != nullptr) {
            warn(CFD_LOG_SOURCE, "global tx duplicates.");
            throw CfdException(
                kCfdIllegalArgumentError, "psbt global tx duplicates error.");
          }

          Transaction transaction(buf);
          if (transaction.GetTxInCount() != 0) {
            // failed to psbt format check on libwally-core.
            warn(CFD_LOG_SOURCE, "psbt format error.");
            throw CfdException(kCfdIllegalArgumentError, "psbt format error.");
          }
          auto txouts = transaction.GetTxOutList();
          struct wally_tx tx;
          memset(&tx, 0, sizeof(tx));
          tx.version = transaction.GetVersion();
          tx.locktime = transaction.GetLockTime();
          ret = wally_psbt_set_global_tx(psbt, &tx);
          if (ret != WALLY_OK) {
            warn(CFD_LOG_SOURCE, "wally_psbt_set_global_tx NG[{}]", ret);
            throw CfdException(kCfdInternalError, "psbt set tx error.");
          }
          for (uint32_t index = 0; index < txouts.size(); ++index) {
            const auto &txout = txouts[index];
            auto script_val = txout.GetLockingScript().GetData().GetBytes();
            struct wally_tx_output output;
            memset(&output, 0, sizeof(output));
            output.satoshi =
                static_cast<uint64_t>(txout.GetValue().GetSatoshiValue());
            output.script = script_val.data();
            output.script_len = script_val.size();
            ret = wally_psbt_add_output_at(psbt, index, 0, &output);
            if (ret != WALLY_OK) {
              warn(CFD_LOG_SOURCE, "wally_psbt_add_output_at NG[{}]", ret);
              throw CfdException(kCfdInternalError, "psbt set txout error.");
            }
          }
        } else if (key[0] == Psbt::kPsbtGlobalVersion) {
          if (!has_key_1byte) {
            warn(CFD_LOG_SOURCE, "psbt invalid key format.");
            throw CfdException(
                kCfdIllegalArgumentError, "psbt invalid key format error.");
          }
          if (psbt->version > 0) {
            warn(CFD_LOG_SOURCE, "psbt version duplicates.");
            throw CfdException(
                kCfdIllegalArgumentError, "psbt version duplicates error.");
          }
          if (buf.size() != sizeof(psbt->version)) {
            warn(CFD_LOG_SOURCE, "psbt invlid version size.");
            throw CfdException(
                kCfdIllegalArgumentError, "psbt invlid version size error.");
          }
          memcpy(&psbt->version, buf.data(), sizeof(psbt->version));
          if (psbt->version > Psbt::GetDefaultVersion()) {
            warn(
                CFD_LOG_SOURCE, "psbt unsupported version[{}]", psbt->version);
            throw CfdException(
                kCfdIllegalArgumentError, "psbt unsupported version error.");
          }
        } else {
          ret = wally_map_add(
              &psbt->unknowns, key.data(), key.size(), buf.data(), buf.size());
          if (ret != WALLY_OK) {
            warn(CFD_LOG_SOURCE, "wally_map_add NG[{}]", ret);
            throw CfdException(
                kCfdIllegalArgumentError, "psbt add unknowns error.");
          }
        }
      }
    } while (!key.empty());

    if (psbt->tx == nullptr) {
      warn(CFD_LOG_SOURCE, "psbt global tx not found.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt global tx not found error.");
    }

    ret = wally_map_sort(&psbt->unknowns, 0);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
      throw CfdException(kCfdInternalError, "psbt sort unknowns error.");
    }

    if (psbt->tx->num_inputs != 0) {
      warn(CFD_LOG_SOURCE, "psbt exist input. please use libwally-core.");
      throw CfdException(kCfdIllegalArgumentError, "psbt exist input.");
    }

    for (size_t i = 0; i < psbt->tx->num_outputs; ++i) {
      ParsePsbtOutput(&parser, &psbt->outputs[i]);
    }

    uint32_t offset = parser.GetReadSize();
    if (bytes.size() != offset) {
      warn(CFD_LOG_SOURCE, "psbt analyze error.");
      throw CfdException(kCfdIllegalArgumentError, "psbt analyze error.");
    }
    return psbt;
  } catch (const CfdError &except) {
    wally_psbt_free(psbt);
    throw except;
  } catch (const std::exception &except) {
    wally_psbt_free(psbt);
    warn(CFD_LOG_SOURCE, "unknown exception.");
    throw CfdException(kCfdUnknownError, std::string(except.what()));
  } catch (...) {
    wally_psbt_free(psbt);
    warn(CFD_LOG_SOURCE, "unknown error.");
    throw CfdException();
  }
}

// -----------------------------------------------------------------------------
// Psbt
// -----------------------------------------------------------------------------
Psbt::Psbt() : Psbt(Psbt::GetDefaultVersion(), 2, static_cast<uint32_t>(0)) {
  // do nothing
}

Psbt::Psbt(uint32_t version, uint32_t lock_time)
    : Psbt(Psbt::GetDefaultVersion(), version, lock_time) {
  // constructor
}

Psbt::Psbt(uint32_t psbt_version, uint32_t version, uint32_t lock_time) {
  struct wally_psbt *psbt_pointer = nullptr;
  int ret = wally_psbt_init_alloc(psbt_version, 0, 0, 0, &psbt_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_init_alloc NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt data generate error.");
  }

  struct wally_tx tx;
  memset(&tx, 0, sizeof(tx));
  tx.version = version;
  tx.locktime = lock_time;
  ret = wally_psbt_set_global_tx(psbt_pointer, &tx);
  if (ret != WALLY_OK) {
    wally_psbt_free(psbt_pointer);  // free
    warn(CFD_LOG_SOURCE, "wally_psbt_set_global_tx NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt set tx error.");
  }
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

Psbt::Psbt(const std::string &base64)
    : Psbt(CryptoUtil::DecodeBase64(base64)) {
  // do nothing
}

Psbt::Psbt(const ByteData &byte_data) {
  struct wally_psbt *psbt_pointer = ParsePsbtData(byte_data);
  size_t is_elements = 0;
  int ret = wally_psbt_is_elements(psbt_pointer, &is_elements);
  if (ret != WALLY_OK) {
    wally_psbt_free(psbt_pointer);
    warn(CFD_LOG_SOURCE, "wally_psbt_is_elements NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt elements check error.");
  }
  if (is_elements != 0) {
    wally_psbt_free(psbt_pointer);
    warn(CFD_LOG_SOURCE, "psbt elements format.");
    throw CfdException(kCfdInternalError, "psbt bitcoin tx format error.");
  }
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

Psbt::Psbt(const Transaction &transaction)
    : Psbt(Psbt::GetDefaultVersion(), transaction) {
  // constructor
}

Psbt::Psbt(uint32_t psbt_version, const Transaction &transaction) {
  std::string tx_hex = transaction.GetHex();
  auto txin_list = transaction.GetTxInList();
  auto txout_list = transaction.GetTxOutList();
  struct wally_tx *tx = nullptr;
  int ret = wally_tx_from_hex(tx_hex.data(), 0, &tx);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}]", ret);
    if (txin_list.empty() || txout_list.empty()) {
      // fall-through
    } else {
      throw CfdException(kCfdInternalError, "psbt tx from hex error.");
    }
  } else if (
      (tx->num_inputs != txin_list.size()) ||
      (tx->num_outputs != txout_list.size())) {
    // free and direct creating.
    wally_tx_free(tx);
    tx = nullptr;
  }

  struct wally_psbt *psbt_pointer = nullptr;
  ret = wally_psbt_init_alloc(
      psbt_version, txin_list.size(), txout_list.size(), 0, &psbt_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_init_alloc NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt data generate error.");
  }

  if (tx == nullptr) {
    ret = wally_tx_init_alloc(
        transaction.GetVersion(), transaction.GetLockTime(), txin_list.size(),
        txout_list.size(), &tx);
    if (ret != WALLY_OK) {
      wally_psbt_free(psbt_pointer);  // free
      warn(CFD_LOG_SOURCE, "wally_psbt_set_global_tx NG[{}]", ret);
      throw CfdException(kCfdInternalError, "psbt set tx error.");
    }

    for (auto txin : txin_list) {
      auto txid_val = txin.GetTxid().GetData().GetBytes();
      ret = wally_tx_add_raw_input(
          tx, txid_val.data(), txid_val.size(), txin.GetVout(),
          txin.GetSequence(), nullptr, 0, nullptr, 0);
      if (ret != WALLY_OK) {
        wally_tx_free(tx);
        wally_psbt_free(psbt_pointer);  // free
        warn(CFD_LOG_SOURCE, "wally_tx_add_raw_input NG[{}]", ret);
        throw CfdException(kCfdInternalError, "psbt set tx input error.");
      }
    }
    for (auto txout : txout_list) {
      auto script_val = txout.GetLockingScript().GetData().GetBytes();
      ret = wally_tx_add_raw_output(
          tx, static_cast<uint64_t>(txout.GetValue().GetSatoshiValue()),
          script_val.data(), script_val.size(), 0);
      if (ret != WALLY_OK) {
        wally_tx_free(tx);
        wally_psbt_free(psbt_pointer);  // free
        warn(CFD_LOG_SOURCE, "wally_tx_add_raw_output NG[{}]", ret);
        throw CfdException(kCfdInternalError, "psbt set tx output error.");
      }
    }
  }

  ret = wally_psbt_set_global_tx(psbt_pointer, tx);
  wally_tx_free(tx);
  if (ret != WALLY_OK) {
    wally_psbt_free(psbt_pointer);  // free
    warn(CFD_LOG_SOURCE, "wally_psbt_set_global_tx NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt set tx error.");
  }
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

Psbt::Psbt(const Psbt &psbt) : Psbt(psbt.GetData()) {
  // copy constructor
}

Psbt &Psbt::operator=(const Psbt &psbt) & {
  if (this != &psbt) {
    struct wally_psbt *psbt_pointer = nullptr;
    struct wally_psbt *psbt_src_pointer = nullptr;
    psbt_src_pointer =
        static_cast<struct wally_psbt *>(psbt.wally_psbt_pointer_);
    int ret = wally_psbt_clone_alloc(psbt_src_pointer, 0, &psbt_pointer);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_clone_alloc NG[{}]", ret);
      throw CfdException(kCfdInternalError, "psbt clone error.");
    }
    FreeWallyPsbtAddress(wally_psbt_pointer_);  // free
    wally_psbt_pointer_ = psbt_pointer;
    base_tx_ = RebuildTransaction(wally_psbt_pointer_);
  }
  return *this;
}

void Psbt::FreeWallyPsbtAddress(const void *wally_psbt_pointer) {
  if (wally_psbt_pointer != nullptr) {
    struct wally_psbt *psbt_pointer = nullptr;
    // ignore const
    memcpy(&psbt_pointer, &wally_psbt_pointer, sizeof(void *));
    wally_psbt_free(psbt_pointer);
  }
}

Transaction Psbt::RebuildTransaction(const void *wally_psbt_pointer) {
  Transaction tx;
  if (wally_psbt_pointer != nullptr) {
    const struct wally_psbt *psbt_pointer;
    psbt_pointer = static_cast<const struct wally_psbt *>(wally_psbt_pointer);
    if (psbt_pointer->tx != nullptr) {
      tx = Transaction(ConvertBitcoinTxFromWally(psbt_pointer->tx, false));
    }
  }
  return tx;
}

uint32_t Psbt::GetDefaultVersion() { return WALLY_PSBT_HIGHEST_VERSION; }

ByteData Psbt::CreateRecordKey(uint8_t type) { return ByteData(type); }

ByteData Psbt::CreateFixRecordKey(
    uint8_t type, const ByteData &fixed_size_key) {
  return ByteData(type).Concat(fixed_size_key);
}

ByteData Psbt::CreateRecordKey(uint8_t type, const ByteData &key_bytes) {
  return ByteData(type).Concat(key_bytes.Serialize());
}

ByteData Psbt::CreateRecordKey(uint8_t type, const std::string &key) {
  return CreateRecordKey(
      type, ByteData(
                reinterpret_cast<const uint8_t *>(key.data()),
                static_cast<uint32_t>(strlen(key.c_str()))));
}

ByteData Psbt::CreateRecordKey(
    uint8_t type, const ByteData &prefix, uint8_t sub_type) {
  return ByteData(type).Concat(prefix.Serialize(), ByteData(sub_type));
}

ByteData Psbt::CreateRecordKey(
    uint8_t type, const std::string &prefix, uint8_t sub_type) {
  return CreateRecordKey(
      type,
      ByteData(
          reinterpret_cast<const uint8_t *>(prefix.data()),
          static_cast<uint32_t>(strlen(prefix.c_str()))),
      sub_type);
}

ByteData Psbt::CreateRecordKey(
    uint8_t type, const ByteData &prefix, uint8_t sub_type,
    const ByteData &sub_key_bytes) {
  return ByteData(type).Concat(
      prefix.Serialize(), ByteData(sub_type), sub_key_bytes.Serialize());
}

ByteData Psbt::CreateRecordKey(
    uint8_t type, const std::string &prefix, uint8_t sub_type,
    const std::string &sub_key) {
  return CreateRecordKey(
      type,
      ByteData(
          reinterpret_cast<const uint8_t *>(prefix.data()),
          static_cast<uint32_t>(strlen(prefix.c_str()))),
      sub_type,
      ByteData(
          reinterpret_cast<const uint8_t *>(sub_key.data()),
          static_cast<uint32_t>(strlen(sub_key.c_str()))));
}

ByteData Psbt::CreatePubkeyRecordKey(uint8_t type, const Pubkey &pubkey) {
  return ByteData(type).Concat(pubkey.GetData());
}

std::string Psbt::GetBase64() const {
  return CryptoUtil::EncodeBase64(GetData());
}

ByteData Psbt::GetData() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t size = 0;

  if ((psbt_pointer != nullptr) && (psbt_pointer->num_inputs == 0)) {
    return CreatePsbtOutputOnlyData(psbt_pointer);
  }

  std::vector<uint8_t> bytes(GetDataSize());
  int ret =
      wally_psbt_to_bytes(psbt_pointer, 0, bytes.data(), bytes.size(), &size);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_to_bytes NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt to bytes error.");
  }
  return ByteData(bytes.data(), static_cast<uint32_t>(size));
}

uint32_t Psbt::GetDataSize() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t size = 0;

  if ((psbt_pointer != nullptr) && (psbt_pointer->num_inputs == 0)) {
    auto data = CreatePsbtOutputOnlyData(psbt_pointer);
    return static_cast<uint32_t>(data.GetDataSize());
  }

  int ret = wally_psbt_get_length(psbt_pointer, 0, &size);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_get_length NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt get length error.");
  }
  return static_cast<uint32_t>(size);
}

bool Psbt::IsFinalized() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t data = 0;
  int ret = wally_psbt_is_finalized(psbt_pointer, &data);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_is_finalized NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt check finalized error.");
  }
  return (data == 1);
}

bool Psbt::IsFinalizedInput(uint32_t index) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  size_t data = 0;
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  }

  if ((psbt_pointer->inputs == nullptr) ||
      (psbt_pointer->num_inputs <= index)) {
    warn(CFD_LOG_SOURCE, "psbt input out-of-range.");
    throw CfdException(kCfdOutOfRangeError, "psbt input out-of-range.");
  }

  int ret = wally_psbt_input_is_finalized(&psbt_pointer->inputs[index], &data);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_is_finalized NG[{}]", ret);
    throw CfdException(
        kCfdIllegalStateError, "psbt input check finalized error.");
  }
  return (data == 1);
}

void Psbt::Finalize() {
  if (!IsFinalized()) {
    struct wally_psbt *psbt_pointer;
    psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
    int ret = wally_psbt_finalize(psbt_pointer);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_finalize NG[{}]", ret);
      throw CfdException(kCfdIllegalStateError, "psbt finalize error.");
    }
  }
}

ByteData Psbt::Extract() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  struct wally_tx *tx = nullptr;
  int ret = wally_psbt_extract(psbt_pointer, &tx);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_extract NG[{}]", ret);
    throw CfdException(kCfdIllegalStateError, "psbt extract error.");
  }
  try {
    auto tx_bytes = ConvertBitcoinTxFromWally(tx, false);
    wally_tx_free(tx);
    return tx_bytes;
  } catch (const CfdException &except) {
    wally_tx_free(tx);
    throw except;
  }
}

Transaction Psbt::ExtractTransaction() const { return Transaction(Extract()); }

Transaction Psbt::GetTransaction() const { return base_tx_; }

void Psbt::Combine(const Psbt &transaction) {
  std::vector<uint8_t> bytes = transaction.GetData().GetBytes();
  struct wally_psbt *src_pointer = nullptr;
  int ret = wally_psbt_from_bytes(bytes.data(), bytes.size(), &src_pointer);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_from_bytes NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt from bytes error.");
  }

  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  ret = wally_psbt_combine(psbt_pointer, src_pointer);
  wally_psbt_free(src_pointer);  // free
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_combine NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt combine error.");
  }
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

void Psbt::Sign(const Privkey &privkey, bool has_grind_r) {
  std::vector<uint8_t> key = privkey.GetData().GetBytes();
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  int ret = wally_psbt_sign(
      psbt_pointer, key.data(), key.size(),
      (has_grind_r) ? EC_FLAG_GRIND_R : 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_sign NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt sign error.");
  }
}

void Psbt::Join(const Psbt &transaction, bool ignore_duplicate_error) {
  struct wally_psbt *psbt_pointer = MergePsbt(
      wally_psbt_pointer_, transaction.wally_psbt_pointer_,
      ignore_duplicate_error);
  FreeWallyPsbtAddress(wally_psbt_pointer_);  // free
  wally_psbt_pointer_ = psbt_pointer;
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
}

uint32_t Psbt::GetTxInCount() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->tx == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt base tx is null");
    throw CfdException(kCfdIllegalStateError, "psbt base tx is null.");
  }
  return static_cast<uint32_t>(psbt_pointer->tx->num_inputs);
}

uint32_t Psbt::GetTxOutCount() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->tx == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt base tx is null");
    throw CfdException(kCfdIllegalStateError, "psbt base tx is null.");
  }
  return static_cast<uint32_t>(psbt_pointer->tx->num_outputs);
}

uint32_t Psbt::AddTxIn(const TxIn &txin) {
  return AddTxIn(txin.GetTxid(), txin.GetVout(), txin.GetSequence());
}

uint32_t Psbt::AddTxIn(const TxInReference &txin) {
  return AddTxIn(txin.GetTxid(), txin.GetVout(), txin.GetSequence());
}

uint32_t Psbt::AddTxIn(const Txid &txid, uint32_t vout, uint32_t sequence) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint32_t index = static_cast<uint32_t>(psbt_pointer->num_inputs);
  struct wally_tx_input *input = nullptr;
  std::vector<uint8_t> txhash = txid.GetData().GetBytes();

  int ret = wally_tx_input_init_alloc(
      txhash.data(), txhash.size(), vout, sequence, nullptr, 0, nullptr,
      &input);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_input_init_alloc NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt alloc input error.");
  }

  ret = wally_psbt_add_input_at(
      psbt_pointer, index, WALLY_PSBT_FLAG_NON_FINAL, input);
  wally_tx_input_free(input);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_add_input_at NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add input error.");
  }
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
  return index;
}

void Psbt::SetTxInUtxo(
    uint32_t index, const Transaction &tx, const KeyData &key) {
  SetTxInUtxo(index, tx, Script(), key);
}

void Psbt::SetTxInUtxo(
    uint32_t index, const Transaction &tx, const Script &redeem_script,
    const KeyData &key) {
  std::vector<KeyData> list;
  if (key.IsValid()) list.push_back(key);
  SetTxInUtxo(index, tx, redeem_script, list);
}

void Psbt::SetTxInUtxo(
    uint32_t index, const Transaction &tx, const Script &redeem_script,
    const std::vector<KeyData> &key_list) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint8_t *txhash = psbt_pointer->tx->inputs[index].txhash;
  uint32_t vout = psbt_pointer->tx->inputs[index].index;
  auto txid = tx.GetTxid();
  auto tx_txid = txid.GetData().GetBytes();
  if ((memcmp(txhash, tx_txid.data(), tx_txid.size()) != 0) ||
      (vout >= tx.GetTxOutCount())) {
    warn(CFD_LOG_SOURCE, "unmatch outpoint.");
    throw CfdException(kCfdIllegalArgumentError, "unmatch outpoint.");
  }

  auto txout = tx.GetTxOut(vout);
  Script new_redeem_script = redeem_script;
  bool is_witness = ValidatePsbtUtxo(
      txid, vout, txout.GetLockingScript(), redeem_script, key_list,
      &new_redeem_script);

  struct wally_tx *wally_tx_obj = nullptr;
  int ret = wally_tx_from_hex(tx.GetHex().c_str(), 0, &wally_tx_obj);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_from_hex NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt tx from hex error.");
  } else if (
      (wally_tx_obj->num_inputs == 0) || (wally_tx_obj->num_outputs == 0)) {
    wally_tx_free(wally_tx_obj);
    warn(CFD_LOG_SOURCE, "invalind utxo transaction format.");
    throw CfdException(kCfdIllegalArgumentError, "psbt invalid tx error.");
  }

  ret = wally_psbt_input_set_utxo(&psbt_pointer->inputs[index], wally_tx_obj);
  if (ret != WALLY_OK) {
    wally_tx_free(wally_tx_obj);
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_utxo NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add utxo error.");
  }
  if (is_witness) {
    ret = wally_psbt_input_set_witness_utxo(
        &psbt_pointer->inputs[index], &wally_tx_obj->outputs[vout]);
    if (ret != WALLY_OK) {
      wally_tx_free(wally_tx_obj);
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_utxo NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt add witness utxo error.");
    }
  }
  wally_tx_free(wally_tx_obj);

  SetPsbtTxInScriptAndKeyList(
      &psbt_pointer->inputs[index], is_witness, new_redeem_script, key_list,
      txout.GetLockingScript());
}

void Psbt::SetTxInUtxo(
    uint32_t index, const TxOutReference &txout, const KeyData &key) {
  SetTxInUtxo(index, txout, Script(), key);
}

void Psbt::SetTxInUtxo(
    uint32_t index, const TxOutReference &txout, const Script &redeem_script,
    const KeyData &key) {
  std::vector<KeyData> list;
  if (key.IsValid()) list.push_back(key);
  SetTxInUtxo(index, txout, redeem_script, list);
}

void Psbt::SetTxInUtxo(
    uint32_t index, const TxOutReference &txout, const Script &redeem_script,
    const std::vector<KeyData> &key_list) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint8_t *txhash = psbt_pointer->tx->inputs[index].txhash;
  uint32_t vout = psbt_pointer->tx->inputs[index].index;
  Txid txid(ByteData256(
      ByteData(txhash, sizeof(psbt_pointer->tx->inputs[index].txhash))));

  auto script = txout.GetLockingScript();
  Script new_redeem_script = redeem_script;
  bool is_witness = ValidatePsbtUtxo(
      txid, vout, script, redeem_script, key_list, &new_redeem_script);
  if (!is_witness) {
    warn(CFD_LOG_SOURCE, "non witness output is not supported.");
    throw CfdException(kCfdIllegalArgumentError, "psbt utxo type error.");
  }

  struct wally_tx_output *output = nullptr;
  auto script_val = script.GetData().GetBytes();
  int ret = wally_tx_output_init_alloc(
      static_cast<uint64_t>(txout.GetValue().GetSatoshiValue()),
      script_val.data(), script_val.size(), &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_output_init_alloc NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt alloc output error.");
  }

  ret =
      wally_psbt_input_set_witness_utxo(&psbt_pointer->inputs[index], output);
  wally_tx_output_free(output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_utxo NG[{}]", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "psbt add witness utxo error.");
  }

  SetPsbtTxInScriptAndKeyList(
      &psbt_pointer->inputs[index], is_witness, new_redeem_script, key_list,
      script);
}

void Psbt::SetTxInWitnessUtxoDirect(
    uint32_t index, const TxOutReference &txout) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  struct wally_tx_output *output = nullptr;
  auto script = txout.GetLockingScript();
  auto script_val = script.GetData().GetBytes();
  int ret = wally_tx_output_init_alloc(
      static_cast<uint64_t>(txout.GetValue().GetSatoshiValue()),
      script_val.data(), script_val.size(), &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_output_init_alloc NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt alloc output error.");
  }

  ret =
      wally_psbt_input_set_witness_utxo(&psbt_pointer->inputs[index], output);
  wally_tx_output_free(output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_witness_utxo NG[{}]", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "psbt add witness utxo error.");
  }
}

void Psbt::SetTxInBip32KeyDirect(uint32_t index, const KeyData &key_data) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  std::vector<KeyData> key_list = {key_data};
  SetKeyPathMap(key_list, &psbt_pointer->inputs[index].keypaths);
  int ret = wally_map_sort(&psbt_pointer->inputs[index].keypaths, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt input sort keypaths error.");
  }
}

void Psbt::SetTxInSignature(
    uint32_t index, const KeyData &key, const ByteData &signature) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto pubkey = key.GetPubkey().GetData().GetBytes();
  auto sig = signature.GetBytes();

  int ret = wally_psbt_input_add_signature(
      &psbt_pointer->inputs[index], pubkey.data(), pubkey.size(), sig.data(),
      sig.size());
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_add_signature NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add input sig error.");
  }
}

void Psbt::SetTxInSighashType(
    uint32_t index, const SigHashType &sighash_type) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint32_t sighash = sighash_type.GetSigHashFlag();

  int ret =
      wally_psbt_input_set_sighash(&psbt_pointer->inputs[index], sighash);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_input_set_sighash NG[{}]", ret);
    throw CfdException(
        kCfdIllegalArgumentError, "psbt set input sighash error.");
  }
}

void Psbt::SetTxInFinalScript(
    uint32_t index, const std::vector<ByteData> &unlocking_script) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (unlocking_script.empty()) {
    warn(CFD_LOG_SOURCE, "unlocking script is empty.");
    throw CfdException(
        kCfdIllegalArgumentError, "psbt unlocking script is empty.");
  }
  bool is_witness = false;
  auto redeem_script = GetTxInRedeemScript(index, true);

  auto utxo = GetTxInUtxo(index, true, &is_witness);
  bool is_wsh = false;
  int ret;
  if (is_witness) {
    auto last_stack = unlocking_script.back();
    if (redeem_script.GetData().Equals(last_stack)) {
      is_wsh = true;
    } else if (Pubkey::IsValid(last_stack)) {
      // p2wpkh
    } else {
      warn(CFD_LOG_SOURCE, "invalid unlocking_script.");
      throw CfdException(
          kCfdIllegalArgumentError, "psbt invalid unlocking_script error.");
    }

    struct wally_tx_witness_stack *stacks = nullptr;
    ret = wally_tx_witness_stack_init_alloc(unlocking_script.size(), &stacks);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_init_alloc NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt init witness stack error.");
    }
    for (auto script : unlocking_script) {
      auto script_val = script.GetBytes();
      ret = wally_tx_witness_stack_add(
          stacks, script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        wally_tx_witness_stack_free(stacks);
        warn(CFD_LOG_SOURCE, "wally_tx_witness_stack_add NG[{}]", ret);
        throw CfdException(
            kCfdIllegalArgumentError, "psbt add witness stack error.");
      }
    }

    ret = wally_psbt_input_set_final_witness(
        &psbt_pointer->inputs[index], stacks);
    wally_tx_witness_stack_free(stacks);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_witness NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set witness script error.");
    }
  } else {
    Script script_sig;
    if (unlocking_script.size() == 1) {
      script_sig = Script(unlocking_script[0]);
    } else {
      ScriptBuilder build;
      for (auto script : unlocking_script) {
        auto script_val = script.GetBytes();
        if (script_val.size() == 1) {
          build.AppendOperator(static_cast<ScriptType>(script_val[0]));
        } else {
          build.AppendData(script);
        }
      }
      script_sig = build.Build();
    }
    auto sig_val = script_sig.GetData().GetBytes();
    ret = wally_psbt_input_set_final_scriptsig(
        &psbt_pointer->inputs[index], sig_val.data(), sig_val.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_scriptsig NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set scriptsig error.");
    }
  }

  if (is_witness && utxo.GetLockingScript().IsP2shScript()) {
    Script locking_script;
    if (is_wsh) {
      locking_script = ScriptUtil::CreateP2wshLockingScript(redeem_script);
    } else if (redeem_script.IsEmpty()) {
      auto key = GetTxInKeyData(index, true);
      locking_script = ScriptUtil::CreateP2wpkhLockingScript(key.GetPubkey());
    } else {
      locking_script = redeem_script;  // p2wpkh locking script
    }
    ScriptBuilder builder;
    builder.AppendData(locking_script.GetData());
    auto sig_val = builder.Build().GetData().GetBytes();
    ret = wally_psbt_input_set_final_scriptsig(
        &psbt_pointer->inputs[index], sig_val.data(), sig_val.size());
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_psbt_input_set_final_scriptsig NG[{}]", ret);
      throw CfdException(
          kCfdIllegalArgumentError, "psbt set scriptsig error.");
    }
  }
}

void Psbt::SetTxInRecord(
    uint32_t index, const ByteData &key, const ByteData &value) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (key.IsEmpty()) {
    warn(CFD_LOG_SOURCE, "psbt empty key error.");
    throw CfdException(kCfdIllegalArgumentError, "psbt empty key error.");
  }

  auto key_vec = key.GetBytes();
  auto val_vec = value.GetBytes();
  uint8_t type = SetPsbtInput(key_vec, val_vec, &psbt_pointer->inputs[index]);

  struct wally_map *map_ptr = nullptr;
  if (type <= Psbt::kPsbtInputFinalScriptWitness) {
    if (type == Psbt::kPsbtInputPartialSig) {
      map_ptr = &psbt_pointer->inputs[index].signatures;
    } else if (type == Psbt::kPsbtInputBip32Derivation) {
      map_ptr = &psbt_pointer->inputs[index].keypaths;
    }
  } else {
    map_ptr = &psbt_pointer->inputs[index].unknowns;
  }
  if (map_ptr != nullptr) {
    int ret = wally_map_sort(map_ptr, 0);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
      throw CfdException(kCfdInternalError, "psbt input sort unknowns error.");
    }
  }
}

Transaction Psbt::GetTxInUtxoFull(
    uint32_t index, bool ignore_error, bool *is_witness) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].utxo != nullptr) {
    if (is_witness != nullptr) {
      *is_witness = (psbt_pointer->inputs[index].witness_utxo != nullptr);
    }
    return Transaction(
        ConvertBitcoinTxFromWally(psbt_pointer->inputs[index].utxo, false));
  } else if (ignore_error) {
    return Transaction();
  } else {
    warn(CFD_LOG_SOURCE, "utxo full data not found.");
    throw CfdException(
        kCfdIllegalStateError, "psbt utxo full data not found error.");
  }
}

TxOut Psbt::GetTxInUtxo(
    uint32_t index, bool ignore_error, bool *is_witness) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].witness_utxo != nullptr) {
    if (is_witness != nullptr) *is_witness = true;
    return TxOut(
        Amount(static_cast<int64_t>(
            psbt_pointer->inputs[index].witness_utxo->satoshi)),
        Script(ByteData(
            psbt_pointer->inputs[index].witness_utxo->script,
            static_cast<uint32_t>(
                psbt_pointer->inputs[index].witness_utxo->script_len))));
  } else if (psbt_pointer->inputs[index].utxo != nullptr) {
    if (is_witness != nullptr) {
      *is_witness = (psbt_pointer->inputs[index].witness_utxo != nullptr);
    }
    uint32_t vout = psbt_pointer->tx->inputs[index].index;
    return TxOut(
        Amount(static_cast<int64_t>(
            psbt_pointer->inputs[index].utxo->outputs[vout].satoshi)),
        Script(ByteData(
            psbt_pointer->inputs[index].utxo->outputs[vout].script,
            static_cast<uint32_t>(
                psbt_pointer->inputs[index].utxo->outputs[vout].script_len))));
  } else if (ignore_error) {
    return TxOut();
  } else {
    warn(CFD_LOG_SOURCE, "utxo not found.");
    throw CfdException(kCfdIllegalStateError, "psbt utxo not found error.");
  }
}

Script Psbt::GetTxInRedeemScript(
    uint32_t index, bool ignore_error, bool *is_witness) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].witness_script != nullptr) {
    if (is_witness != nullptr) *is_witness = true;
    return Script(ByteData(
        psbt_pointer->inputs[index].witness_script,
        static_cast<uint32_t>(
            psbt_pointer->inputs[index].witness_script_len)));
  } else if (psbt_pointer->inputs[index].redeem_script != nullptr) {
    if (is_witness != nullptr) *is_witness = false;
    return Script(ByteData(
        psbt_pointer->inputs[index].redeem_script,
        static_cast<uint32_t>(psbt_pointer->inputs[index].redeem_script_len)));
  } else if (ignore_error) {
    return Script();
  } else {
    warn(CFD_LOG_SOURCE, "script not found.");
    throw CfdException(kCfdIllegalStateError, "psbt script not found error.");
  }
}

Script Psbt::GetTxInRedeemScriptDirect(
    uint32_t index, bool ignore_error, bool is_witness) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (is_witness && (psbt_pointer->inputs[index].witness_script != nullptr)) {
    return Script(ByteData(
        psbt_pointer->inputs[index].witness_script,
        static_cast<uint32_t>(
            psbt_pointer->inputs[index].witness_script_len)));
  } else if (
      (!is_witness) &&
      (psbt_pointer->inputs[index].redeem_script != nullptr)) {
    return Script(ByteData(
        psbt_pointer->inputs[index].redeem_script,
        static_cast<uint32_t>(psbt_pointer->inputs[index].redeem_script_len)));
  } else if (ignore_error) {
    return Script();
  } else {
    warn(CFD_LOG_SOURCE, "script not found.");
    throw CfdException(kCfdIllegalStateError, "psbt script not found error.");
  }
}

std::vector<KeyData> Psbt::GetTxInKeyDataList(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  size_t key_max = psbt_pointer->inputs[index].keypaths.num_items;
  std::vector<KeyData> arr;
  arr.reserve(key_max);
  struct wally_map_item *item;
  for (size_t key_index = 0; key_index < key_max; ++key_index) {
    item = &psbt_pointer->inputs[index].keypaths.items[key_index];
    ByteData key(item->key, static_cast<uint32_t>(item->key_len));
    Pubkey pubkey(key);
    ByteData fingerprint;
    std::vector<uint32_t> path;
    if (((item->value_len % 4) == 0) && (item->value_len > 0)) {
      fingerprint = ByteData(item->value, 4);

      // TODO(k-matsuzawa) Need endian support.
      size_t arr_max = item->value_len / 4;
      uint32_t *val_arr = reinterpret_cast<uint32_t *>(item->value);
      for (size_t arr_index = 1; arr_index < arr_max; ++arr_index) {
        path.push_back(val_arr[arr_index]);
      }
    }
    arr.emplace_back(KeyData(pubkey, path, fingerprint));
  }
  return arr;
}

KeyData Psbt::GetTxInKeyData(uint32_t index, bool ignore_error) const {
  std::vector<KeyData> keys = GetTxInKeyDataList(index);
  if (!keys.empty()) {
    return keys[0];
  } else if (ignore_error) {
    return KeyData();
  } else {
    warn(CFD_LOG_SOURCE, "key not found.");
    throw CfdException(kCfdIllegalStateError, "psbt key not found error.");
  }
}

std::vector<Pubkey> Psbt::GetTxInSignaturePubkeyList(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  size_t key_max = psbt_pointer->inputs[index].signatures.num_items;
  std::vector<Pubkey> arr;
  arr.reserve(key_max);
  struct wally_map_item *item;
  for (size_t key_index = 0; key_index < key_max; ++key_index) {
    item = &psbt_pointer->inputs[index].signatures.items[key_index];
    ByteData key(item->key, static_cast<uint32_t>(item->key_len));
    Pubkey pubkey(key);
    arr.emplace_back(pubkey);
  }
  return arr;
}

ByteData Psbt::GetTxInSignature(uint32_t index, const Pubkey &pubkey) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = pubkey.GetData().GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(
      &psbt_pointer->inputs[index].signatures, key_vec.data(), key_vec.size(),
      &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find signature key error.");
  }
  if (exist == 0) {
    warn(CFD_LOG_SOURCE, "target key not found.");
    throw CfdException(
        kCfdIllegalStateError, "psbt signature target key not found.");
  }
  uint32_t map_index = static_cast<uint32_t>(exist) - 1;
  return ByteData(
      psbt_pointer->inputs[index].signatures.items[map_index].value,
      static_cast<uint32_t>(
          psbt_pointer->inputs[index].signatures.items[map_index].value_len));
}

bool Psbt::IsFindTxInSignature(uint32_t index, const Pubkey &pubkey) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  auto key_vec = pubkey.GetData().GetBytes();
  size_t exist = 0;
  int ret = wally_map_find(
      &psbt_pointer->inputs[index].signatures, key_vec.data(), key_vec.size(),
      &exist);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_find NG[{}]", ret);
    throw CfdException(kCfdMemoryFullError, "psbt find signature key error.");
  }
  return (exist == 0) ? false : true;
}

SigHashType Psbt::GetTxInSighashType(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->inputs[index].sighash != 0) {
    SigHashType sighash_type;
    sighash_type.SetFromSigHashFlag(
        static_cast<uint8_t>(psbt_pointer->inputs[index].sighash));
    return sighash_type;
  } else {
    warn(CFD_LOG_SOURCE, "sighash not found.");
    throw CfdException(kCfdIllegalStateError, "psbt sighash not found error.");
  }
}

bool Psbt::IsFindTxInSighashType(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  return psbt_pointer->inputs[index].sighash != 0;
}

std::vector<ByteData> Psbt::GetTxInFinalScript(
    uint32_t index, bool is_witness_stack) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  std::vector<ByteData> result;

  if (is_witness_stack) {
    auto stacks = psbt_pointer->inputs[index].final_witness;
    if (stacks != nullptr) {
      for (size_t stack_idx = 0; stack_idx < stacks->num_items; ++stack_idx) {
        result.emplace_back(ByteData(
            stacks->items[stack_idx].witness,
            static_cast<uint32_t>(stacks->items[stack_idx].witness_len)));
      }
    }
  } else {
    result.emplace_back(ByteData(
        psbt_pointer->inputs[index].final_scriptsig,
        static_cast<uint32_t>(
            psbt_pointer->inputs[index].final_scriptsig_len)));
  }
  return result;
}

ByteData Psbt::GetTxInRecord(uint32_t index, const ByteData &key) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  return GetPsbtInput(key, &psbt_pointer->inputs[index], nullptr);
}

bool Psbt::IsFindTxInRecord(uint32_t index, const ByteData &key) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  bool is_find = false;
  GetPsbtInput(key, &psbt_pointer->inputs[index], &is_find);
  return is_find;
}

std::vector<ByteData> Psbt::GetTxInRecordKeyList(uint32_t index) const {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  std::vector<ByteData> result;
  auto input = &psbt_pointer->inputs[index];
  for (size_t idx = 0; idx < input->unknowns.num_items; ++idx) {
    auto item = &input->unknowns.items[idx];
    result.emplace_back(
        ByteData(item->key, static_cast<uint32_t>(item->key_len)));
  }
  return result;
}

void Psbt::ClearTxInSignData(uint32_t index) {
  CheckTxInIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  struct wally_psbt_input *input = &psbt_pointer->inputs[index];

  if (input->redeem_script != nullptr) {
    memset(input->redeem_script, 0, input->redeem_script_len);
    FreeWallyBuffer(input->redeem_script);
    input->redeem_script_len = 0;
    input->redeem_script = nullptr;
  }
  if (input->witness_script != nullptr) {
    memset(input->witness_script, 0, input->witness_script_len);
    FreeWallyBuffer(input->witness_script);
    input->witness_script_len = 0;
    input->witness_script = nullptr;
  }
  for (size_t idx = 0; idx < input->keypaths.num_items; ++idx) {
    auto keypath = &input->keypaths.items[idx];
    memset(keypath->key, 0, keypath->key_len);
    memset(keypath->value, 0, keypath->value_len);
    FreeWallyBuffer(keypath->key);
    FreeWallyBuffer(keypath->value);
    memset(keypath, 0, sizeof(*keypath));
  }
  input->keypaths.num_items = 0;
  for (size_t idx = 0; idx < input->signatures.num_items; ++idx) {
    auto sig = &input->signatures.items[idx];
    memset(sig->key, 0, sig->key_len);
    memset(sig->value, 0, sig->value_len);
    FreeWallyBuffer(sig->key);
    FreeWallyBuffer(sig->value);
    memset(sig, 0, sizeof(*sig));
  }
  input->signatures.num_items = 0;
  input->sighash = 0;
}

uint32_t Psbt::AddTxOut(const TxOut &txout) {
  return AddTxOut(txout.GetLockingScript(), txout.GetValue());
}

uint32_t Psbt::AddTxOut(const TxOutReference &txout) {
  return AddTxOut(txout.GetLockingScript(), txout.GetValue());
}

uint32_t Psbt::AddTxOut(const Script &locking_script, const Amount &amount) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  uint32_t index = static_cast<uint32_t>(psbt_pointer->num_outputs);
  auto script = locking_script.GetData().GetBytes();
  struct wally_tx_output *output = nullptr;

  int ret = wally_tx_output_init_alloc(
      static_cast<uint64_t>(amount.GetSatoshiValue()), script.data(),
      script.size(), &output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_tx_output_init_alloc NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt alloc output error.");
  }

  ret = wally_psbt_add_output_at(psbt_pointer, index, 0, output);
  wally_tx_output_free(output);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_psbt_add_output_at NG[{}]", ret);
    throw CfdException(kCfdIllegalArgumentError, "psbt add output error.");
  }
  base_tx_ = RebuildTransaction(wally_psbt_pointer_);
  return index;
}

void Psbt::SetTxOutData(uint32_t index, const KeyData &key) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  std::vector<KeyData> arr = GetTxOutKeyDataList(index);
  Pubkey pubkey = key.GetPubkey();
  for (auto &item : arr) {
    if (pubkey.Equals(item.GetPubkey())) return;
  }

  struct wally_tx_output *txout = &psbt_pointer->tx->outputs[index];
  Script locking_script(
      ByteData(txout->script, static_cast<uint32_t>(txout->script_len)));
  Script redeem_script;
  Script script;

  if (locking_script.IsP2pkhScript()) {
    script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
  } else if (locking_script.IsP2wpkhScript()) {
    script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
  } else if (locking_script.IsP2shScript()) {
    auto wpkh_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
    script = ScriptUtil::CreateP2shLockingScript(wpkh_script);
    redeem_script = wpkh_script;
  }
  if (!locking_script.Equals(script)) {
    warn(CFD_LOG_SOURCE, "unmatch pubkey.");
    throw CfdException(kCfdIllegalArgumentError, "psbt unmatch pubkey error.");
  }

  if (!GetTxOutScript(index, true).IsEmpty()) redeem_script = Script();
  SetTxOutData(index, redeem_script, key);
}

void Psbt::SetTxOutData(
    uint32_t index, const Script &redeem_script, const KeyData &key) {
  SetTxOutData(index, redeem_script, std::vector<KeyData>{key});
}

void Psbt::SetTxOutData(
    uint32_t index, const Script &redeem_script,
    const std::vector<KeyData> &key_list) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  struct wally_tx_output *txout = &psbt_pointer->tx->outputs[index];
  Script script(
      ByteData(txout->script, static_cast<uint32_t>(txout->script_len)));
  ByteData256 empty_bytes;
  Txid txid(empty_bytes);
  Script new_redeem_script = redeem_script;
  bool is_witness = ValidatePsbtUtxo(
      txid, index, script, redeem_script, key_list, &new_redeem_script);

  int ret;
  if (!new_redeem_script.IsEmpty()) {
    auto script_val = new_redeem_script.GetData().GetBytes();
    if (is_witness && (!new_redeem_script.IsP2wpkhScript())) {
      ret = wally_psbt_output_set_witness_script(
          &psbt_pointer->outputs[index], script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        warn(
            CFD_LOG_SOURCE, "wally_psbt_output_set_witness_script NG[{}]",
            ret);
        throw CfdException(
            kCfdIllegalArgumentError, "psbt add output witness script error.");
      }
      if (script.IsP2shScript()) {
        script_val = ScriptUtil::CreateP2wshLockingScript(new_redeem_script)
                         .GetData()
                         .GetBytes();
      } else {
        script_val.clear();
      }
    }
    if (!script_val.empty()) {
      ret = wally_psbt_output_set_redeem_script(
          &psbt_pointer->outputs[index], script_val.data(), script_val.size());
      if (ret != WALLY_OK) {
        warn(
            CFD_LOG_SOURCE, "wally_psbt_output_set_redeem_script NG[{}]", ret);
        throw CfdException(
            kCfdIllegalArgumentError, "psbt add output redeem script error.");
      }
    }
  }

  if (!key_list.empty()) {
    SetKeyPathMap(key_list, &psbt_pointer->outputs[index].keypaths);
    ret = wally_map_sort(&psbt_pointer->outputs[index].keypaths, 0);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
      throw CfdException(
          kCfdInternalError, "psbt output sort keypaths error.");
    }
  }
}

void Psbt::SetTxOutRecord(
    uint32_t index, const ByteData &key, const ByteData &value) {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (key.IsEmpty()) {
    warn(CFD_LOG_SOURCE, "psbt empty key error.");
    throw CfdException(kCfdIllegalArgumentError, "psbt empty key error.");
  }

  auto key_vec = key.GetBytes();
  auto val_vec = value.GetBytes();
  uint8_t type =
      SetPsbtOutput(key_vec, val_vec, &psbt_pointer->outputs[index]);

  struct wally_map *map_ptr = nullptr;
  switch (type) {
    case kPsbtOutputRedeemScript:
      // fall-through
    case kPsbtOutputWitnessScript:
      break;
    case kPsbtOutputBip32Derivation:
      map_ptr = &psbt_pointer->outputs[index].keypaths;
      break;
    default:
      map_ptr = &psbt_pointer->outputs[index].unknowns;
      break;
  }
  if (map_ptr != nullptr) {
    int ret = wally_map_sort(map_ptr, 0);
    if (ret != WALLY_OK) {
      warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
      throw CfdException(
          kCfdInternalError, "psbt output sort unknowns error.");
    }
  }
}

Script Psbt::GetTxOutScript(
    uint32_t index, bool ignore_error, bool *is_witness) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  if (psbt_pointer->outputs[index].witness_script != nullptr) {
    if (is_witness != nullptr) *is_witness = true;
    return Script(ByteData(
        psbt_pointer->outputs[index].witness_script,
        static_cast<uint32_t>(
            psbt_pointer->outputs[index].witness_script_len)));
  } else if (psbt_pointer->outputs[index].redeem_script != nullptr) {
    if (is_witness != nullptr) *is_witness = false;
    return Script(ByteData(
        psbt_pointer->outputs[index].redeem_script,
        static_cast<uint32_t>(
            psbt_pointer->outputs[index].redeem_script_len)));
  } else if (ignore_error) {
    return Script();
  } else {
    warn(CFD_LOG_SOURCE, "script not found.");
    throw CfdException(kCfdIllegalStateError, "psbt script not found error.");
  }
}

KeyData Psbt::GetTxOutKeyData(uint32_t index, bool ignore_error) const {
  auto arr = GetTxOutKeyDataList(index);
  if (arr.size() > 0) {
    return arr[0];
  } else if (ignore_error) {
    return KeyData();
  } else {
    warn(CFD_LOG_SOURCE, "key not found.");
    throw CfdException(kCfdIllegalStateError, "psbt key not found error.");
  }
}

std::vector<KeyData> Psbt::GetTxOutKeyDataList(uint32_t index) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);

  size_t key_max = psbt_pointer->outputs[index].keypaths.num_items;
  std::vector<KeyData> arr;
  arr.reserve(key_max);
  struct wally_map_item *item;
  for (size_t key_index = 0; key_index < key_max; ++key_index) {
    item = &psbt_pointer->outputs[index].keypaths.items[key_index];
    ByteData key(item->key, static_cast<uint32_t>(item->key_len));
    Pubkey pubkey(key);
    ByteData fingerprint;
    std::vector<uint32_t> path;
    if (((item->value_len % 4) == 0) && (item->value_len > 0)) {
      fingerprint = ByteData(item->value, 4);

      // TODO(k-matsuzawa) Need endian support.
      size_t arr_max = item->value_len / 4;
      uint32_t *val_arr = reinterpret_cast<uint32_t *>(item->value);
      for (size_t arr_index = 1; arr_index < arr_max; ++arr_index) {
        path.push_back(val_arr[arr_index]);
      }
    }
    arr.emplace_back(KeyData(pubkey, path, fingerprint));
  }
  return arr;
}

ByteData Psbt::GetTxOutRecord(uint32_t index, const ByteData &key) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  return GetPsbtOutput(key, &psbt_pointer->outputs[index], nullptr);
}

bool Psbt::IsFindTxOutRecord(uint32_t index, const ByteData &key) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  bool is_find = false;
  GetPsbtOutput(key, &psbt_pointer->outputs[index], &is_find);
  return is_find;
}

std::vector<ByteData> Psbt::GetTxOutRecordKeyList(uint32_t index) const {
  CheckTxOutIndex(index, __LINE__, __FUNCTION__);
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  std::vector<ByteData> result;
  auto output = &psbt_pointer->outputs[index];
  for (size_t idx = 0; idx < output->unknowns.num_items; ++idx) {
    auto item = &output->unknowns.items[idx];
    result.emplace_back(
        ByteData(item->key, static_cast<uint32_t>(item->key_len)));
  }
  return result;
}

uint32_t Psbt::GetPsbtVersion() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  }
  return psbt_pointer->version;
}

void Psbt::SetGlobalXpubkey(const KeyData &key) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  }

  if (!key.HasExtPubkey()) {
    warn(CFD_LOG_SOURCE, "psbt global xpub can set only ExtPubkey.");
    throw CfdException(
        kCfdIllegalArgumentError, "psbt global xpub can set only ExtPubkey.");
  }
  uint8_t xpub_key = Psbt::kPsbtGlobalXpub;
  ByteData key_top(&xpub_key, 1);
  ByteData key_data = key_top.Concat(key.GetExtPubkey().GetData());

  auto fingerprint = key.GetFingerprint().GetBytes();
  auto num_list = key.GetChildNumArray();
  if (fingerprint.size() < 4) {
    warn(CFD_LOG_SOURCE, "psbt fingerprint size low 4 byte.");
    throw CfdException(
        kCfdIllegalArgumentError, "psbt fingerprint size low 4 byte.");
  }
  // if (num_list.empty()) {
  //   warn(CFD_LOG_SOURCE, "psbt empty bip32 path.");
  //   throw CfdException(kCfdIllegalArgumentError, "psbt empty bip32 path.");
  // }
  Serializer builder(4 + (static_cast<uint32_t>(num_list.size()) * 4));
  builder.AddDirectBytes(fingerprint.data(), 4);
  for (const auto child_num : num_list) {
    builder.AddDirectNumber(child_num);
  }
  SetGlobalRecord(key_data, builder.Output());
}

KeyData Psbt::GetGlobalXpubkeyBip32(const ExtPubkey &key) const {
  uint8_t xpub_key = Psbt::kPsbtGlobalXpub;
  ByteData key_top(&xpub_key, 1);
  ByteData key_data = key_top.Concat(key.GetData());
  auto data = GetGlobalRecord(key_data);

  ByteData fingerprint;
  std::vector<uint32_t> path;
  if (((data.GetDataSize() % 4) == 0) && (data.GetDataSize() > 0)) {
    auto data_arr = data.GetBytes();
    fingerprint = ByteData(data_arr.data(), 4);

    // TODO(k-matsuzawa) Need endian support.
    size_t arr_max = data_arr.size() / 4;
    uint32_t *val_arr = reinterpret_cast<uint32_t *>(data_arr.data());
    for (size_t arr_index = 1; arr_index < arr_max; ++arr_index) {
      path.push_back(val_arr[arr_index]);
    }
  }
  return KeyData(key, path, fingerprint);
}

bool Psbt::IsFindGlobalXpubkey(const ExtPubkey &key) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  bool is_find = false;
  uint8_t xpub_key = Psbt::kPsbtGlobalXpub;
  ByteData key_top(&xpub_key, 1);
  ByteData key_data = key_top.Concat(key.GetData());
  GetPsbtGlobal(key_data, psbt_pointer, &is_find);
  return is_find;
}

std::vector<KeyData> Psbt::GetGlobalXpubkeyDataList() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  }

  size_t key_max = psbt_pointer->unknowns.num_items;
  std::vector<KeyData> arr;
  arr.reserve(key_max);
  struct wally_map_item *item;
  for (size_t key_index = 0; key_index < key_max; ++key_index) {
    item = &psbt_pointer->unknowns.items[key_index];
    if (item->key_len != kPsbtGlobalXpubSize) continue;
    if (item->key[0] != Psbt::kPsbtGlobalXpub) continue;
    ByteData key(&item->key[1], static_cast<uint32_t>(item->key_len) - 1);
    ExtPubkey ext_pubkey(key);

    ByteData fingerprint;
    std::vector<uint32_t> path;
    if (((item->value_len % 4) == 0) && (item->value_len > 0)) {
      fingerprint = ByteData(item->value, 4);

      // TODO(k-matsuzawa) Need endian support.
      size_t arr_max = item->value_len / 4;
      uint32_t *val_arr = reinterpret_cast<uint32_t *>(item->value);
      for (size_t arr_index = 1; arr_index < arr_max; ++arr_index) {
        path.push_back(val_arr[arr_index]);
      }
    }
    arr.emplace_back(KeyData(ext_pubkey, path, fingerprint));
  }
  return arr;
}

void Psbt::SetGlobalRecord(const ByteData &key, const ByteData &value) {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (key.IsEmpty()) {
    warn(CFD_LOG_SOURCE, "psbt empty key error.");
    throw CfdException(kCfdIllegalArgumentError, "psbt empty key error.");
  }
  auto key_vec = key.GetBytes();
  auto val_vec = value.GetBytes();

  SetPsbtGlobal(key_vec, val_vec, psbt_pointer);

  int ret = wally_map_sort(&psbt_pointer->unknowns, 0);
  if (ret != WALLY_OK) {
    warn(CFD_LOG_SOURCE, "wally_map_sort NG[{}]", ret);
    throw CfdException(kCfdInternalError, "psbt sort unknowns error.");
  }
}

ByteData Psbt::GetGlobalRecord(const ByteData &key) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  return GetPsbtGlobal(key, psbt_pointer, nullptr);
}

bool Psbt::IsFindGlobalRecord(const ByteData &key) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  bool is_find = false;
  GetPsbtGlobal(key, psbt_pointer, &is_find);
  return is_find;
}

std::vector<ByteData> Psbt::GetGlobalRecordKeyList() const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  std::vector<ByteData> result;
  for (size_t idx = 0; idx < psbt_pointer->unknowns.num_items; ++idx) {
    auto item = &psbt_pointer->unknowns.items[idx];
    result.emplace_back(
        ByteData(item->key, static_cast<uint32_t>(item->key_len)));
  }
  return result;
}

void Psbt::CheckTxInIndex(uint32_t index, int line, const char *caller) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->tx == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt base tx is null");
    throw CfdException(kCfdIllegalStateError, "psbt base tx is null.");
  } else if (psbt_pointer->num_inputs <= index) {
    CfdSourceLocation location = {CFD_LOG_FILE, line, caller};
    warn(location, "psbt vin[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "psbt vin out_of_range error.");
  } else if (psbt_pointer->tx->num_inputs <= index) {
    CfdSourceLocation location = {CFD_LOG_FILE, line, caller};
    warn(location, "tx vin[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "tx vin out_of_range error.");
  }
}

void Psbt::CheckTxOutIndex(
    uint32_t index, int line, const char *caller) const {
  struct wally_psbt *psbt_pointer;
  psbt_pointer = static_cast<struct wally_psbt *>(wally_psbt_pointer_);
  if (psbt_pointer == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt pointer is null");
    throw CfdException(kCfdIllegalStateError, "psbt pointer is null.");
  } else if (psbt_pointer->tx == nullptr) {
    warn(CFD_LOG_SOURCE, "psbt base tx is null");
    throw CfdException(kCfdIllegalStateError, "psbt base tx is null.");
  } else if (psbt_pointer->num_outputs <= index) {
    CfdSourceLocation location = {CFD_LOG_FILE, line, caller};
    warn(location, "psbt vout[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "psbt vout out_of_range error.");
  } else if (psbt_pointer->tx->num_outputs <= index) {
    CfdSourceLocation location = {CFD_LOG_FILE, line, caller};
    warn(location, "tx vout[{}] out_of_range.", index);
    throw CfdException(kCfdOutOfRangeError, "tx vout out_of_range error.");
  }
}

}  // namespace core
}  // namespace cfd
