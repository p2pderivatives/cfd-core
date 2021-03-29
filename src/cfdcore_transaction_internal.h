// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_transaction_internal.h
 *
 * @brief transaction internal header.
 *
 */
#ifndef CFD_CORE_SRC_CFDCORE_TRANSACTION_INTERNAL_H_
#define CFD_CORE_SRC_CFDCORE_TRANSACTION_INTERNAL_H_
#ifdef __cplusplus

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

/**
 * @brief convert bitcoin transaction from wally tx.
 * @param[in] tx  wally tx
 * @param[in] force_exclude_witness  exclude witness force flag.
 * @return transaction byte data.
 */
extern ByteData ConvertBitcoinTxFromWally(
    const struct wally_tx *tx, bool force_exclude_witness);

}  // namespace core
}  // namespace cfd

#endif  // __cplusplus
#endif  // CFD_CORE_SRC_CFDCORE_TRANSACTION_INTERNAL_H_
