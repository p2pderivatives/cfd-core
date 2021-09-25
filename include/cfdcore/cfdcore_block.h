// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_block.h
 *
 * @brief The block related class definition.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BLOCK_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BLOCK_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_transaction.h"

namespace cfd {
namespace core {

/**
 * @brief block header.
 */
struct BlockHeader {
  uint32_t version = 0;        //!< version
  BlockHash prev_block_hash;   //!< previous block hash
  BlockHash merkle_root_hash;  //!< merkle root hash
  uint32_t time = 0;           //!< time
  uint32_t bits = 0;           //!< bits
  uint32_t nonce = 0;          //!< nonce
};

/**
 * @brief block data class.
 */
class CFD_CORE_EXPORT Block {
 public:
  /**
   * @brief default constructor
   */
  Block();
  /**
   * @brief constructor
   * @param[in] hex     hex string
   */
  explicit Block(const std::string& hex);
  /**
   * @brief constructor
   * @param[in] data    byte data
   */
  explicit Block(const ByteData& data);
  /**
   * @brief destructor.
   */
  virtual ~Block() {
    // do nothing
  }
  /**
   * @brief copy constructor.
   * @param[in] object    object
   */
  Block(const Block& object);
  /**
   * @brief copy constructor.
   * @param[in] object    object
   * @return object
   */
  Block& operator=(const Block& object);
  /**
   * @brief Get a hex string.
   * @return hex string
   */
  std::string GetHex() const;
  /**
   * @brief Get a ByteData object.
   * @return ByteData object.
   */
  ByteData GetData() const;
  /**
   * @brief check valid data.
   * @retval true   valid.
   * @retval false  invalid.
   */
  bool IsValid() const;
  /**
   * @brief Get a BlockHash.
   * @return block hash.
   */
  BlockHash GetBlockHash() const;

  /**
   * @brief get txoutproof.
   * @param[in] txid      target txid
   * @return txoutproof.
   */
  ByteData GetTxOutProof(const Txid& txid) const;
  /**
   * @brief get txoutproof.
   * @param[in] txids     target txid list
   * @return txoutproof.
   */
  ByteData GetTxOutProof(const std::vector<Txid>& txids) const;

  /**
   * @brief get txid.
   * @param[in] index   tx index
   * @return txid.
   */
  Txid GetTxid(uint32_t index) const;
  /**
   * @brief get txid list.
   * @return txid list.
   */
  std::vector<Txid> GetTxids() const;
  /**
   * @brief exist txid.
   * @param[in] txid    txid
   * @retval true   exist
   * @retval false  not exist
   */
  bool ExistTxid(const Txid& txid) const;
  /**
   * @brief Get the transaction.
   * @param[in] txid    txid
   * @return transaction
   */
  Transaction GetTransaction(const Txid& txid) const;
  /**
   * @brief Get the transaction count.
   * @return transaction count
   */
  uint32_t GetTransactionCount() const;
  /**
   * @brief get block header.
   * @return block header.
   */
  BlockHeader GetBlockHeader() const;
  /**
   * @brief Serialize block header.
   * @return Serialized block header.
   */
  ByteData SerializeBlockHeader() const;

 private:
  ByteData data_;              ///< byte data
  BlockHeader header_;         ///< block header
  std::vector<ByteData> txs_;  ///< transaction data list
  std::vector<Txid> txids_;    ///< transaction id list
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_BLOCK_H_
