/* NOIR wallet — Ethereum transaction parsing + sighash (M7e).
 *
 * Anti-blind-signing core: fully parse the transaction, extract the fields,
 * derive chainId, and compute the EIP-155 / EIP-1559 signing hash. Any
 * malformation is a hard reject (caller maps -1 to SW_BAD_DATA 0x6A80) — there
 * is no "sign anyway" path.
 *
 * Supported in v0: legacy (type 0, pre-155 and EIP-155) and EIP-1559 (type 2).
 * EIP-2930 (type 1) is rejected.
 */

#ifndef ETH_TX_H
#define ETH_TX_H

#include <stdint.h>

#define ETH_TX_LEGACY   0
#define ETH_TX_EIP1559  2

#define ETH_TX_SIGHASH_LEN 32
#define ETH_TX_MAX_LEN     2048   /* v0 tx size cap (typical swap tx << 1 KB) */

/* A reference into the raw transaction buffer. */
typedef struct {
    const uint8_t *ptr;
    uint32_t       len;
} eth_field_t;

/* Parsed transaction (normalized view). Field pointers alias `raw`. */
typedef struct {
    uint8_t  type;          /* ETH_TX_LEGACY or ETH_TX_EIP1559 */
    uint64_t chain_id;      /* 0 = none (legacy pre-155) */
    uint8_t  is_creation;   /* 1 if `to` is empty (contract creation) */
    uint8_t  to[20];        /* 20-byte destination (zero if creation) */

    eth_field_t nonce, gas_price, gas_limit, to_field, value, data;
    eth_field_t max_priority_fee, max_fee;   /* EIP-1559 only */
    eth_field_t access_list;                 /* EIP-1559 only: full RLP list */
    eth_field_t v, r, s;
} eth_tx_t;

/* Fully parse raw transaction bytes. Returns 0 on success, -1 on any
 * structural error (bad RLP, wrong field count, bad to/chainId, trailing
 * bytes, unsupported type). */
int eth_tx_parse(const uint8_t *raw, uint32_t len, eth_tx_t *tx);

/* Compute the signing hash (keccak256) into sighash[32]. 0 = ok. */
int eth_tx_sighash(const eth_tx_t *tx, uint8_t sighash[ETH_TX_SIGHASH_LEN]);

#endif /* ETH_TX_H */
