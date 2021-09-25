// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_block.cpp
 *
 * @brief Classes related to block.
 *
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/merkleblock.cpp
 */
#include "cfdcore/cfdcore_block.h"

#include <string>
#include <vector>

#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_block_internal.h"  // NOLINT

namespace cfd {
namespace core {

using logger::warn;

// -----------------------------------------------------------------------------
// Internal file functions
// -----------------------------------------------------------------------------
/**
 * @brief calculate tree width
 * @param[in] transaction_count     transaction count
 * @param[in] height                height
 * @return tree width
 */
static uint64_t CalcTreeWidth(uint64_t transaction_count, uint64_t height) {
  uint64_t u64_1{1};
  return (transaction_count + (u64_1 << height) - 1) >> height;
}

/**
 * @brief Convert bits to bytes.
 * @param[in] bits      bits.
 * @return byte data
 */
static ByteData BitsToBytes(const std::vector<bool>& bits) {
  std::vector<uint8_t> ret((bits.size() + 7) / 8);
  for (size_t p = 0; p < bits.size(); p++) {
    ret[p / 8] |= bits[p] << (p % 8);
  }
  return ByteData(ret);
}

// -----------------------------------------------------------------------------
// Block
// -----------------------------------------------------------------------------
Block::Block() : data_() {
  // do nothing
}

Block::Block(const ByteData& data) : data_(data) {
  Deserializer dec(data);
  header_.version = dec.ReadUint32();
  header_.prev_block_hash = BlockHash(dec.ReadBuffer(32));
  header_.merkle_root_hash = BlockHash(dec.ReadBuffer(32));
  header_.time = dec.ReadUint32();
  header_.bits = dec.ReadUint32();
  header_.nonce = dec.ReadUint32();
  uint64_t tx_count = dec.ReadVariableInt();
  size_t read_size = data.GetDataSize() - dec.GetReadSize();
  auto txs = ByteData(dec.ReadBuffer(static_cast<uint32_t>(read_size)));
  for (uint64_t index = 0; index < tx_count; ++index) {
    Transaction tx(txs);
    auto tx_data = tx.GetData();
    uint32_t cur_size = static_cast<uint32_t>(tx_data.GetDataSize());
    uint32_t unread_size = static_cast<uint32_t>(txs.GetDataSize()) - cur_size;
    if (unread_size != 0) {
      auto arr = txs.SplitData(std::vector<uint32_t>{cur_size, unread_size});
      txs = arr[1];
    }
    txs_.emplace_back(tx_data);
    txids_.emplace_back(tx.GetTxid());
  }
}

Block::Block(const std::string& hex) : Block(ByteData(hex)) {}

Block::Block(const Block& object) {
  data_ = object.data_;
  header_ = object.header_;
  txs_ = object.txs_;
  txids_ = object.txids_;
}

Block& Block::operator=(const Block& object) {
  if (this != &object) {
    data_ = object.data_;
    header_ = object.header_;
    txs_ = object.txs_;
    txids_ = object.txids_;
  }
  return *this;
}

std::string Block::GetHex() const { return data_.GetHex(); }

ByteData Block::GetData() const { return data_; }

BlockHash Block::GetBlockHash() const {
  return BlockHash(HashUtil::Sha256D(SerializeBlockHeader()));
}

Txid Block::GetTxid(uint32_t index) const {
  if (static_cast<uint32_t>(txids_.size()) <= index) {
    throw CfdException(
        CfdError::kCfdOutOfRangeError,
        "The index is outside the scope of the txid list.");
  }
  return txids_[index];
}

std::vector<Txid> Block::GetTxids() const { return txids_; }

bool Block::ExistTxid(const Txid& txid) const {
  for (const auto& temp_txid : txids_) {
    if (txid.Equals(temp_txid)) return true;
  }
  return false;
}

Transaction Block::GetTransaction(const Txid& txid) const {
  for (size_t index = 0; index < txids_.size(); ++index) {
    if (txid.Equals(txids_[index])) {
      return Transaction(txs_[index]);
    }
  }
  throw CfdException(
      CfdError::kCfdIllegalArgumentError, "target txid not found.");
}

uint32_t Block::GetTransactionCount() const {
  return static_cast<uint32_t>(txids_.size());
}

BlockHeader Block::GetBlockHeader() const { return header_; }

ByteData Block::SerializeBlockHeader() const {
  Serializer obj;
  obj.AddDirectNumber(header_.version);
  obj.AddDirectBytes(header_.prev_block_hash.GetData());
  obj.AddDirectBytes(header_.merkle_root_hash.GetData());
  obj.AddDirectNumber(header_.time);
  obj.AddDirectNumber(header_.bits);
  obj.AddDirectNumber(header_.nonce);
  return obj.Output();
}

bool Block::IsValid() const { return !data_.IsEmpty(); }

ByteData Block::GetTxOutProof(const Txid& txid) const {
  return GetTxOutProof(std::vector<Txid>{txid});
}

ByteData Block::GetTxOutProof(const std::vector<Txid>& txids) const {
  MerkleBlock merkle_block(*this, txids);
  Serializer obj;
  obj.AddDirectBytes(SerializeBlockHeader());
  obj.AddDirectBytes(merkle_block.Serialize());
  return obj.Output();
}

// -----------------------------------------------------------------------------
// MerkleBlock
// -----------------------------------------------------------------------------
MerkleBlock::MerkleBlock(const Block& block, const std::vector<Txid>& txids) {
  std::vector<bool> target_indexes;
  auto txid_list = block.GetTxids();
  target_indexes.reserve(txid_list.size());
  for (const auto& txid : txid_list) {
    bool is_find = false;
    for (const auto& target_txid : txids) {
      if (target_txid.Equals(txid)) {
        is_find = true;
        break;
      }
    }
    target_indexes.push_back(is_find);
  }

  transaction_count = static_cast<uint64_t>(txid_list.size());
  bits_.clear();
  txids_.clear();

  uint64_t height = 0;
  while (CalcTreeWidth(transaction_count, height) > 1) ++height;

  TraverseAndBuild(height, 0, txid_list, target_indexes);
}

ByteData MerkleBlock::Serialize() const {
  Serializer obj;
  obj.AddDirectNumber(static_cast<uint32_t>(transaction_count));
  obj.AddVariableInt(txids_.size());
  for (const auto& txid : txids_) {
    obj.AddDirectBytes(txid.GetData());
  }
  auto bits = BitsToBytes(bits_);
  obj.AddVariableBuffer(bits);
  return obj.Output();
}

void MerkleBlock::TraverseAndBuild(
    uint64_t height, uint64_t pos, const std::vector<Txid>& txids,
    const std::vector<bool> matches) {
  bool has_parent_of_match = false;
  for (uint64_t index = pos << height;
       (index < ((pos + 1) << height)) && (index < transaction_count);
       ++index) {
    if (matches[index]) {
      has_parent_of_match = true;
      break;
    }
  }
  bits_.push_back(has_parent_of_match);
  if ((height == 0) || (!has_parent_of_match)) {
    // if at height 0, or nothing interesting below, store hash and stop
    txids_.push_back(CalculateHash(height, pos, txids));
  } else {
    TraverseAndBuild(height - 1, pos * 2, txids, matches);
    if ((pos * 2 + 1) < CalcTreeWidth(transaction_count, height - 1)) {
      TraverseAndBuild(height - 1, pos * 2 + 1, txids, matches);
    }
  }
}

Txid MerkleBlock::CalculateHash(
    uint64_t height, uint64_t pos, const std::vector<Txid>& txids) {
  if (height == 0) return txids[pos];

  Txid left = CalculateHash(height - 1, pos * 2, txids);
  Txid right;
  if ((pos * 2 + 1) < CalcTreeWidth(transaction_count, height - 1)) {
    right = CalculateHash(height - 1, pos * 2 + 1, txids);
  } else {
    right = left;
  }
  ByteData data = left.GetData().Concat(right.GetData());
  return Txid(HashUtil::Sha256D(data));
}

}  // namespace core
}  // namespace cfd
