// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_taproot.cpp
 *
 * @brief This file implements for taproot utility class.
 */

#include "cfdcore/cfdcore_taproot.h"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_iterator.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::warn;

// ----------------------------------------------------------------------------
// TapBranch
// ----------------------------------------------------------------------------
TapBranch::TapBranch() : has_leaf_(false), leaf_version_(0) {}

TapBranch::TapBranch(const ByteData256& commitment)
    : has_leaf_(false), leaf_version_(0) {
  root_commitment_ = commitment;
}

TapBranch::TapBranch(const TapBranch& tap_tree) {
  has_leaf_ = tap_tree.has_leaf_;
  leaf_version_ = tap_tree.leaf_version_;
  script_ = tap_tree.script_;
  root_commitment_ = tap_tree.root_commitment_;
  branch_list_ = tap_tree.branch_list_;
}

void TapBranch::AddBranch(const SchnorrPubkey& pubkey) {
  AddBranch(pubkey.GetByteData256());
}

void TapBranch::AddBranch(const ByteData256& commitment) {
  branch_list_.emplace_back(commitment);
  if (branch_list_.size() > TaprootScriptTree::kTaprootControlMaxNodeCount) {
    throw CfdException(
        CfdError::kCfdIllegalStateError, "tapbranch maximum over.");
  }
}

void TapBranch::AddBranch(const TapBranch& branch) {
  branch_list_.emplace_back(branch);
  if (branch_list_.size() > TaprootScriptTree::kTaprootControlMaxNodeCount) {
    throw CfdException(
        CfdError::kCfdIllegalStateError, "tapbranch maximum over.");
  }
}

TapBranch& TapBranch::operator=(const TapBranch& object) {
  if (this != &object) {
    has_leaf_ = object.has_leaf_;
    leaf_version_ = object.leaf_version_;
    script_ = object.script_;
    root_commitment_ = object.root_commitment_;
    branch_list_ = object.branch_list_;
  }
  return *this;
}

ByteData256 TapBranch::GetBaseHash() const {
  if (!has_leaf_) return root_commitment_;

  static auto kTaggedHash = HashUtil::Sha256("TapLeaf");
  return (HashUtil(HashUtil::kSha256)
          << kTaggedHash << kTaggedHash << ByteData(leaf_version_)
          << script_.GetData().Serialize())
      .Output256();
}

ByteData256 TapBranch::GetCurrentBranchHash() const {
  return GetBranchHash(static_cast<uint8_t>(branch_list_.size()));
}

ByteData256 TapBranch::GetBranchHash(uint8_t depth) const {
  ByteData256 hash = GetBaseHash();
  if (branch_list_.empty()) return hash;

  static auto kTaggedHash = HashUtil::Sha256("TapBranch");
  ByteData tapbranch_base = kTaggedHash.Concat(kTaggedHash);
  auto nodes = GetNodeList();
  uint8_t index = 0;
  for (const auto& node : nodes) {
    if (index > depth) break;
    auto hasher = HashUtil(HashUtil::kSha256) << tapbranch_base;
    const auto& node_bytes = node.GetBytes();
    const auto& hash_bytes = hash.GetBytes();
    if (std::lexicographical_compare(
            hash_bytes.begin(), hash_bytes.end(), node_bytes.begin(),
            node_bytes.end())) {
      hash = (hasher << hash << node).Output256();
    } else {
      hash = (hasher << node << hash).Output256();
    }
    ++index;
  }
  return hash;
}

bool TapBranch::HasTapLeaf() const { return has_leaf_; }

uint8_t TapBranch::GetLeafVersion() const { return leaf_version_; }

Script TapBranch::GetScript() const { return script_; }

std::vector<TapBranch> TapBranch::GetBranchList() const {
  return branch_list_;
}

std::vector<ByteData256> TapBranch::GetNodeList() const {
  std::vector<ByteData256> list;
  for (const auto& branch : branch_list_) {
    list.emplace_back(branch.GetCurrentBranchHash());
  }
  return list;
}

bool TapBranch::IsFindTapScript(const Script& tapscript) const {
  if (has_leaf_ && script_.Equals(tapscript)) return true;

  for (const auto& branch : branch_list_) {
    if (branch.IsFindTapScript(tapscript)) return true;
  }
  return false;
}

std::string TapBranch::ToString() const {
  std::string buf;
  if (has_leaf_) {
    std::string ver_str;
    if (leaf_version_ != TaprootScriptTree::kTapScriptLeafVersion) {
      ver_str = "," + ByteData(leaf_version_).GetHex();
    }
    buf = "tl(" + script_.GetHex() + ver_str + ")";
  } else if (branch_list_.empty() && root_commitment_.IsEmpty()) {
    return "";
  } else {
    buf = root_commitment_.GetHex();
  }
  if (branch_list_.empty()) return buf;

  ByteData256 hash = GetBaseHash();
  static auto kTaggedHash = HashUtil::Sha256("TapBranch");
  ByteData tapbranch_base = kTaggedHash.Concat(kTaggedHash);
  auto nodes = GetNodeList();
  for (const auto& branch : branch_list_) {
    auto hasher = HashUtil(HashUtil::kSha256) << tapbranch_base;
    const auto node = branch.GetCurrentBranchHash();
    const auto& node_bytes = node.GetBytes();
    const auto& hash_bytes = hash.GetBytes();
    if (std::lexicographical_compare(
            hash_bytes.begin(), hash_bytes.end(), node_bytes.begin(),
            node_bytes.end())) {
      hash = (hasher << hash << node).Output256();
      buf = "{" + buf + "," + branch.ToString() + "}";
    } else {
      hash = (hasher << node << hash).Output256();
      buf = "{" + branch.ToString() + "," + buf + "}";
    }
  }
  return buf;
}

TapBranch TapBranch::ChangeTapLeaf(
    const Script& tapscript,
    const std::vector<ByteData256>& target_nodes) const {
  if (!IsFindTapScript(tapscript)) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "This tapscript not exist in this tree.");
  }
  auto nodes = GetNodeList();
  if (has_leaf_ && script_.Equals(tapscript)) {
    if (target_nodes.empty() || (target_nodes == nodes)) return *this;
  }

  auto reverse_nodes = target_nodes;
  if (!reverse_nodes.empty()) {
    std::reverse(reverse_nodes.begin(), reverse_nodes.end());
  }
  std::string reverse_nodes_str;
  for (const auto& node : reverse_nodes) reverse_nodes_str += node.GetHex();

  std::vector<size_t> target_branch_indexes;
  std::vector<size_t> checked_nodes_size_list;

  std::vector<TapBranch> new_branches;
  for (size_t index = 0; index < branch_list_.size(); ++index) {
    const auto& branch = branch_list_[index];
    if (branch.IsFindTapScript(tapscript)) {
      std::vector<ByteData256> check_nodes;
      if (reverse_nodes.empty()) {
        target_branch_indexes.emplace_back(index);
        checked_nodes_size_list.emplace_back(0);
      } else {
        auto branch_nodes = branch.GetNodeList();
        for (size_t idx = nodes.size() - 1; idx > index; --idx) {
          check_nodes.emplace_back(nodes[idx]);
        }
        if (index == 0) {
          check_nodes.emplace_back(GetBaseHash());
        } else {
          check_nodes.emplace_back(
              GetBranchHash(static_cast<uint8_t>(index - 1)));
        }

        std::string check_nodes_str;
        for (const auto& node : check_nodes) {
          auto hex = node.GetHex();
          check_nodes_str += hex;
        }

        bool has_match = true;
        for (size_t idx = 0; idx < check_nodes.size(); ++idx) {
          if (!reverse_nodes[idx].Equals(check_nodes[idx])) {
            has_match = false;
            break;
          }
        }
        if (has_match) {
          target_branch_indexes.emplace_back(index);
          checked_nodes_size_list.emplace_back(check_nodes.size());
        }
      }
    }
  }

  for (size_t index = 0; index < target_branch_indexes.size(); ++index) {
    const auto& target_index = target_branch_indexes[index];
    const auto& checked_size = checked_nodes_size_list[index];
    std::vector<ByteData256> check_nodes;
    if (!target_nodes.empty()) {
      size_t copy_len = target_nodes.size() - checked_size;
      for (size_t idx = 0; idx < copy_len; ++idx) {
        check_nodes.emplace_back(target_nodes[idx]);
      }
    }

    try {
      auto new_branch =
          branch_list_[target_index].ChangeTapLeaf(tapscript, check_nodes);
      // ignore invalid target.
      if (new_branch.GetBaseHash().IsEmpty()) continue;

      auto based_branch = *this;
      std::vector<TapBranch> copy_branches;
      for (size_t idx = 0; idx < target_index; ++idx) {
        copy_branches.emplace_back(branch_list_[idx]);
      }
      based_branch.branch_list_ = copy_branches;

      new_branch.AddBranch(based_branch);
      for (size_t idx = target_index + 1; idx < branch_list_.size(); ++idx) {
        new_branch.AddBranch(branch_list_[idx]);
      }
      new_branches.emplace_back(new_branch);
    } catch (const CfdException&) {
      // target not found
    }
  }
  if (new_branches.empty()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "The specified tapscript does not exist under this branch.");
  }
  return new_branches[0];  // response is top data.
}

TapBranch TapBranch::FromString(const std::string& text) {
  static auto check_tapleaf_func = [](const std::string& text,
                                      TapBranch* branch) -> bool {
    if (text.size() < 6) return false;
    std::string head = text.substr(0, 3);
    if ((head == "tl(") && (*(text.end() - 1) == ')')) {
      size_t leaf_ver_offset = text.find(',');
      if (leaf_ver_offset == std::string::npos) {
        *branch = TaprootScriptTree(Script(text.substr(3, text.length() - 4)));
      } else {
        auto script_str = text.substr(3, leaf_ver_offset - 3);
        auto leaf_ver_str = text.substr(leaf_ver_offset + 1, 2);
        char* err = nullptr;
        auto leaf_version = strtol(leaf_ver_str.c_str(), &err, 16);
        if (((err != nullptr) && (*err != '\0')) || (leaf_version < 0) ||
            (leaf_version > std::numeric_limits<uint8_t>::max())) {
          throw CfdException(
              CfdError::kCfdIllegalArgumentError, "Invalid leaf version.");
        }
        *branch = TaprootScriptTree(
            static_cast<uint8_t>(leaf_version), Script(script_str));
      }
      return true;
    }
    return false;
  };

  static auto analyze_func = [](const std::string& target) -> TapBranch {
    TapBranch result;
    if (*target.begin() == '{') {
      result = TapBranch::FromString(target);  // analyze branch
    } else if (!check_tapleaf_func(target, &result)) {
      result = TapBranch(ByteData256(target));
    }
    return result;
  };

  static auto collect_items_func =
      [](const std::string& text) -> std::vector<std::string> {
    std::vector<std::string> result;
    uint8_t depth = 0;
    size_t start_block_index = 0;
    size_t end_block_index = 0;
    size_t split_index = 0;
    for (size_t idx = 0; idx < text.size(); ++idx) {
      const char& str = text[idx];
      if (str == '{') {
        if (depth == 0) start_block_index = idx + 1;
        ++depth;
        if (depth == std::numeric_limits<uint8_t>::max()) {
          throw CfdException(
              CfdError::kCfdIllegalArgumentError, "Invalid tree format.");
        }
      } else if (str == '}') {
        if (depth == 0) {
          throw CfdException(
              CfdError::kCfdIllegalArgumentError, "Invalid tree format.");
        }
        --depth;
        if (depth == 0) {
          if (split_index == 0) {
            throw CfdException(
                CfdError::kCfdIllegalArgumentError,
                "Invalid tree format. empty split block.");
          }
          end_block_index = idx;
          size_t offset = (split_index == 0) ? start_block_index : split_index;
          if (end_block_index <= offset) {
            throw CfdException(
                CfdError::kCfdIllegalArgumentError, "Invalid tree item.");
          }
          result.emplace_back(text.substr(offset, idx - offset));
        }
      } else if (str == ',') {
        if (depth == 1) {
          size_t offset = (split_index == 0) ? start_block_index : split_index;
          if ((offset + 3) < text.size()) {
            auto head = text.substr(offset, 3);
            char prev_str = 0;
            if (idx > 0) prev_str = text[idx - 1];
            // ignore leaf ver
            if ((head == "tl(") && (prev_str != ')')) continue;
          }

          if (split_index != 0) {
            throw CfdException(
                CfdError::kCfdIllegalArgumentError,
                "Invalid tree splitformat.");
          }
          result.emplace_back(text.substr(offset, idx - offset));
          split_index = idx + 1;
        }
      }
    }

    if (result.empty()) {
      // do nothing
    } else if ((result.size() != 2) || ((end_block_index + 1) < text.size())) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Invalid tree format.");
    }
    return result;
  };

  if (text.find(' ') != std::string::npos) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Contains invalid charactor.");
  }

  TapBranch result;
  auto text_list = collect_items_func(text);
  if (text_list.empty()) {
    result = analyze_func(text);
  } else {
    auto branch1 = analyze_func(text_list.at(0));
    auto branch2 = analyze_func(text_list.at(1));
    if ((!branch1.has_leaf_) && (branch2.has_leaf_)) {
      branch2.AddBranch(branch1);
      result = branch2;
    } else {
      branch1.AddBranch(branch2);
      result = branch1;
    }
  }

  return result;
}

ByteData256 TapBranch::GetTapTweak(
    const SchnorrPubkey& internal_pubkey) const {
  ByteData256 hash = GetCurrentBranchHash();
  static auto kTaggedHash = HashUtil::Sha256("TapTweak");
  auto hasher = HashUtil(HashUtil::kSha256)
                << kTaggedHash << kTaggedHash << internal_pubkey.GetData();
  if (!hash.IsEmpty()) hasher << hash;
  return hasher.Output256();
}

SchnorrPubkey TapBranch::GetTweakedPubkey(
    const SchnorrPubkey& internal_pubkey, bool* parity) const {
  ByteData256 hash = GetTapTweak(internal_pubkey);
  return internal_pubkey.CreateTweakAdd(hash, parity);
}

Privkey TapBranch::GetTweakedPrivkey(
    const Privkey& internal_privkey, bool* parity) const {
  bool is_parity = false;
  auto internal_pubkey =
      SchnorrPubkey::FromPrivkey(internal_privkey, &is_parity);
  Privkey privkey = internal_privkey;
  if (is_parity) privkey = internal_privkey.CreateNegate();

  ByteData256 hash = GetTapTweak(internal_pubkey);
  internal_pubkey.CreateTweakAdd(hash, &is_parity);
  if (parity != nullptr) *parity = is_parity;
  return privkey.CreateTweakAdd(hash);
}

// ----------------------------------------------------------------------------
// TaprootScriptTree
// ----------------------------------------------------------------------------
TaprootScriptTree::TaprootScriptTree() : TapBranch() {
  has_leaf_ = true;
  leaf_version_ = kTapScriptLeafVersion;
}

TaprootScriptTree::TaprootScriptTree(const Script& script)
    : TaprootScriptTree(kTapScriptLeafVersion, script) {}

TaprootScriptTree::TaprootScriptTree(
    uint8_t leaf_version, const Script& script)
    : TapBranch() {
  has_leaf_ = true;
  leaf_version_ = leaf_version;
  script_ = script;
  if (!TaprootUtil::IsValidLeafVersion(leaf_version)) {
    warn(CFD_LOG_SOURCE, "Unsupported leaf version. [{}]", leaf_version);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unsupported leaf version.");
  }
}

TaprootScriptTree::TaprootScriptTree(const TapBranch& leaf_branch)
    : TapBranch(leaf_branch) {
  if (!leaf_branch.HasTapLeaf()) {
    warn(CFD_LOG_SOURCE, "object is not tapleaf.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "object is not tapleaf.");
  }
  if (!TaprootUtil::IsValidLeafVersion(leaf_branch.GetLeafVersion())) {
    warn(
        CFD_LOG_SOURCE, "Unsupported leaf version. [{}]",
        leaf_branch.GetLeafVersion());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unsupported leaf version.");
  }
  has_leaf_ = true;
  leaf_version_ = leaf_branch.GetLeafVersion();
  script_ = leaf_branch.GetScript();
  branch_list_ = leaf_branch.GetBranchList();
  nodes_ = leaf_branch.GetNodeList();
}

TaprootScriptTree::TaprootScriptTree(const TaprootScriptTree& tap_tree)
    : TapBranch(tap_tree) {
  if (!TaprootUtil::IsValidLeafVersion(tap_tree.leaf_version_)) {
    warn(
        CFD_LOG_SOURCE, "Unsupported leaf version. [{}]",
        tap_tree.leaf_version_);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unsupported leaf version.");
  }
  has_leaf_ = tap_tree.has_leaf_;
  leaf_version_ = tap_tree.leaf_version_;
  script_ = tap_tree.script_;
  root_commitment_ = tap_tree.root_commitment_;
  branch_list_ = tap_tree.branch_list_;
  nodes_ = tap_tree.nodes_;
}

TaprootScriptTree& TaprootScriptTree::operator=(
    const TaprootScriptTree& object) & {
  if (this != &object) {
    has_leaf_ = object.has_leaf_;
    leaf_version_ = object.leaf_version_;
    script_ = object.script_;
    root_commitment_ = object.root_commitment_;
    branch_list_ = object.branch_list_;
    nodes_ = object.nodes_;
  }
  return *this;
}

void TaprootScriptTree::AddBranch(const ByteData256& commitment) {
  TapBranch::AddBranch(commitment);
  nodes_.emplace_back(commitment);
}

void TaprootScriptTree::AddBranch(const TapBranch& branch) {
  TapBranch::AddBranch(branch);
  nodes_.emplace_back(branch.GetCurrentBranchHash());
}

void TaprootScriptTree::AddBranch(const TaprootScriptTree& tree) {
  TapBranch::AddBranch(tree);
  nodes_.emplace_back(tree.GetCurrentBranchHash());
}

bool TaprootScriptTree::IsValid() const { return !script_.IsEmpty(); }

ByteData256 TaprootScriptTree::GetTapLeafHash() const { return GetBaseHash(); }

std::vector<ByteData256> TaprootScriptTree::GetNodeList() const {
  return nodes_;
}

TaprootScriptTree TaprootScriptTree::FromString(
    const std::string& text, const Script& tapscript,
    const std::vector<ByteData256>& target_nodes) {
  auto branch = TapBranch::FromString(text);
  auto check_nodes = target_nodes;
  if (!check_nodes.empty()) {
    TaprootScriptTree target_leaf(tapscript);
    if (check_nodes.back().Equals(target_leaf.GetTapLeafHash())) {
      check_nodes.erase(check_nodes.end() - 1);
    }
  }
  branch = branch.ChangeTapLeaf(tapscript, check_nodes);
  return TaprootScriptTree(branch);
}

// ----------------------------------------------------------------------------
// TaprootUtil
// ----------------------------------------------------------------------------
bool TaprootUtil::IsValidLeafVersion(uint8_t leaf_version) {
  // BIP-0341
  static const uint32_t kValidLeafVersions[] = {0x66, 0x7e, 0x80, 0x84, 0x96,
                                                0x98, 0xba, 0xbc, 0xbe};
  for (auto valid_ver : kValidLeafVersions) {
    if (leaf_version == valid_ver) return true;
  }

  if ((leaf_version % 2) != 0) return false;  // Odd
  if ((leaf_version >= 0xc0) && (leaf_version <= 0xfe)) return true;
  return false;
}

ByteData TaprootUtil::CreateTapScriptControl(
    const SchnorrPubkey& internal_pubkey, const TapBranch& merkle_tree,
    SchnorrPubkey* witness_program, Script* locking_script) {
  bool parity = false;
  auto pubkey_data =
      merkle_tree.GetTweakedPubkey(internal_pubkey, &parity).GetByteData256();
  uint8_t top = merkle_tree.GetLeafVersion();
  if (top == 0) top = TaprootScriptTree::kTapScriptLeafVersion;
  if (parity) top |= 0x01;
  Serializer builder;
  builder.AddDirectByte(top);
  builder.AddDirectBytes(internal_pubkey.GetData());
  for (const auto& node : merkle_tree.GetNodeList()) {
    builder.AddDirectBytes(node);
  }
  if (witness_program != nullptr) {
    *witness_program = SchnorrPubkey(pubkey_data);
  }
  if (locking_script != nullptr) {
    *locking_script = ScriptUtil::CreateTaprootLockingScript(pubkey_data);
  }
  return builder.Output();
}

bool TaprootUtil::VerifyTaprootCommitment(
    bool has_parity, uint8_t tapleaf_bit,
    const SchnorrPubkey& target_taproot,  // witness program
    const SchnorrPubkey& internal_pubkey,
    const std::vector<ByteData256>& nodes, const Script& tapscript,
    ByteData256* tapleaf_hash) {
  if (nodes.size() > TaprootScriptTree::kTaprootControlMaxNodeCount) {
    warn(CFD_LOG_SOURCE, "control node maximum over. [{}]", nodes.size());
    return false;
  }

  // Compute the tapleaf hash.
  TaprootScriptTree tree(tapleaf_bit, tapscript);
  if (tapleaf_hash != nullptr) *tapleaf_hash = tree.GetTapLeafHash();

  // Compute the Merkle root from the leaf and the provided path.
  for (const auto& node : nodes) {
    tree.AddBranch(node);
  }
  // Compute the tweak from the Merkle root and the inner pubkey.
  auto hash = tree.GetTapTweak(internal_pubkey);
  // Verify that the output pubkey matches the tweaked inner pubkey, after correcting for parity. // NOLINT
  return target_taproot.IsTweaked(internal_pubkey, hash, has_parity);
}

void TaprootUtil::ParseTaprootSignData(
    const std::vector<ByteData>& witness_stack,
    SchnorrSignature* schnorr_signature, bool* has_parity,
    uint8_t* tapleaf_bit, SchnorrPubkey* internal_pubkey,
    std::vector<ByteData256>* nodes, Script* tapscript,
    std::vector<ByteData>* stack, ByteData* annex) {
  static constexpr size_t kControlMinimumSize =
      SchnorrPubkey::kSchnorrPubkeySize + 1;

  size_t size = witness_stack.size();
  if ((size >= 2) && (!witness_stack.back().IsEmpty()) &&
      (witness_stack.back().GetHeadData() == TaprootUtil::kAnnexTag)) {
    if (annex != nullptr) *annex = witness_stack.back();
    --size;
  }

  if (size == 0) {
    warn(CFD_LOG_SOURCE, "witness_stack is empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "witness_stack is empty.");
  } else if (size == 1) {
    if (schnorr_signature != nullptr) {
      *schnorr_signature = SchnorrSignature(witness_stack.at(0));
    }
  } else {
    Script script(witness_stack.at(size - 2));
    ByteData data = witness_stack.at(size - 1);
    if ((data.GetDataSize() < kControlMinimumSize) ||
        (((data.GetDataSize() - 1) % kByteData256Length) != 0)) {
      warn(CFD_LOG_SOURCE, "wrong taproot control size.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "wrong taproot control size.");
    }
    size_t max_node =
        (data.GetDataSize() - kControlMinimumSize) / kByteData256Length;
    if (max_node > TaprootScriptTree::kTaprootControlMaxNodeCount) {
      warn(
          CFD_LOG_SOURCE, "taproot control node maximum over. [{}]", max_node);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "taproot control node maximum over.");
    }

    Deserializer parser(data);
    uint8_t top = parser.ReadUint8();
    if (has_parity != nullptr) *has_parity = (top & 0x01);
    if (tapleaf_bit != nullptr) *tapleaf_bit = top & 0xfe;

    ByteData256 pubkey_bytes(parser.ReadBuffer(kByteData256Length));
    if (internal_pubkey != nullptr) {
      *internal_pubkey = SchnorrPubkey(pubkey_bytes);
    }
    if (nodes != nullptr) {
      for (size_t index = 0; index < max_node; ++index) {
        ByteData256 node(parser.ReadBuffer(kByteData256Length));
        nodes->emplace_back(node);
      }
    }

    if (tapscript != nullptr) *tapscript = script;
    if ((stack != nullptr) && (size > 2)) {
      for (size_t index = 0; index < size - 2; ++index) {
        stack->emplace_back(witness_stack.at(index));
      }
    }
  }
}

}  // namespace core
}  // namespace cfd
