// Copyright 2021 CryptoGarage
/**
 * @file cfdcore_block_internal.h
 *
 * @brief The block related class definition.
 */
#ifndef CFD_CORE_SRC_CFDCORE_BLOCK_INTERNAL_H_
#define CFD_CORE_SRC_CFDCORE_BLOCK_INTERNAL_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_block.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_common.h"

namespace cfd {
namespace core {

/**
 * @brief Calc merkle block class.
 */
class CFD_CORE_EXPORT MerkleBlock {
 public:
  /**
   * @brief constructor.
   * @param[in] block   block object.
   * @param[in] txids   target txid list.
   */
  MerkleBlock(const Block& block, const std::vector<Txid>& txids);

  /**
   * @brief get serialize data.
   * @return serialized data.
   */
  ByteData Serialize() const;

 private:
  uint64_t transaction_count;  //!< total number of transactions
  std::vector<bool> bits_;     //!< node-is-parent-of-matched-txid bits
  std::vector<Txid> txids_;    //!< transaction id list

  /**
   * @brief Traverse and build.
   * @param[in] height      height
   * @param[in] pos         position
   * @param[in] txids       txid list
   * @param[in] matches     target match list
   */
  void TraverseAndBuild(
      uint64_t height, uint64_t pos, const std::vector<Txid>& txids,
      const std::vector<bool> matches);

  /**
   * @brief calculate hash.
   * @param[in] height      height
   * @param[in] pos         position
   * @param[in] txids       txid list
   * @return hash (txid)
   */
  Txid CalculateHash(
      uint64_t height, uint64_t pos, const std::vector<Txid>& txids);
};

}  // namespace core
}  // namespace cfd
#endif  // CFD_CORE_SRC_CFDCORE_BLOCK_INTERNAL_H_
