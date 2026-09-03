/* NOIR wallet — APDU wallet handlers (see wallet_handlers.h). */

#include "wallet_handlers.h"
#include "wallet_state.h"
#include "apdu.h"          /* SW_* codes */
#include "memzero.h"
#include <string.h>

/* ---- pending approval state -------------------------------------- */
static wh_pending_t pending = WH_IDLE;
static eth_tx_t     p_tx;
static uint8_t      p_sighash[32];
static uint32_t     p_index;
static uint8_t      p_pub65[65];
static uint8_t      p_addr[20];

/* ---- SIGN_TX accumulation ----------------------------------------- */
static uint8_t  raw[ETH_TX_MAX_LEN];
static uint32_t raw_len;

void wh_reset(void) {
    pending = WH_IDLE;
    raw_len = 0;
    memzero(p_sighash, sizeof p_sighash);
    memzero(p_pub65, sizeof p_pub65);
    memzero(p_addr, sizeof p_addr);
    memzero(raw, sizeof raw);
}

/* lowercase hex (no terminator needed if the caller knows the length, but we
 * write it anyway). */
static void hexstr(const uint8_t *d, int n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[2 * i]     = h[d[i] >> 4];
        out[2 * i + 1] = h[d[i] & 0xF];
    }
    out[2 * n] = 0;
}

/* ---- derivation-path allowlist ------------------------------------ */

/* Parse a derivation path at the START of `d` as [count][count*4 BE bytes].
 * Enforces the v0 allowlist m/44'/60'/0'/0/index and returns the path length
 * (bytes consumed) on success, or -1. Trailing bytes after the path are
 * allowed (SIGN_TX carries the tx in the same first chunk). */
static int parse_path(const uint8_t *d, uint16_t n, uint32_t *index) {
    if (n < 1) return -1;
    uint8_t cnt = d[0];
    if (cnt == 0 || n < 1 + 4 * (uint16_t)cnt) return -1;   /* path must fit */
    if (cnt != 5) return -1;          /* m/44'/60'/0'/0/index */

    uint32_t c[5];
    for (int i = 0; i < 5; i++)
        c[i] = ((uint32_t)d[1 + 4*i] << 24) | ((uint32_t)d[2 + 4*i] << 16) |
               ((uint32_t)d[3 + 4*i] << 8)  |  (uint32_t)d[4 + 4*i];

    if (c[0] != 0x8000002Cu) return -1;   /* 44' */
    if (c[1] != 0x8000003Cu) return -1;   /* 60' */
    if (c[2] != 0x80000000u) return -1;   /* 0'  */
    if (c[3] != 0x00000000u) return -1;   /* 0   */
    *index = c[4];
    return 1 + 4 * (int)cnt;
}

/* ---- GET_PUBLIC_KEY ------------------------------------------------
 *
 * Response (matches ledger-app-eth set_result_get_publicKey):
 *   [pubkey_len=65][uncompressed pubkey 65][addr_len=40][addr 40 ASCII hex]
 *   = 107 bytes, lowercase, no "0x" prefix (the host adds "0x"). */

uint16_t wh_get_pubkey(uint8_t p1, uint8_t p2, const uint8_t *d, uint16_t n,
                       uint8_t *out, uint16_t *olen) {
    (void)p2;
    uint32_t index;
    int plen = parse_path(d, n, &index);
    if (plen < 0 || (uint16_t)plen != n) return SW_BAD_DATA;  /* exact only */

    uint8_t priv[32], pub65[65], addr[20];
    if (wallet_state_derive(index, priv, pub65, addr) != 0) {
        memzero(priv, sizeof priv);
        return SW_LOCKED;
    }
    memzero(priv, sizeof priv);

    if (p1 & 0x01) {                    /* confirm on device: defer */
        pending = WH_CONFIRM_ADDR;
        p_index = index;
        memcpy(p_pub65, pub65, 65);
        memcpy(p_addr, addr, 20);
        *olen = 0;
        return SW_OK;
    }

    out[0] = 65;
    memcpy(out + 1, pub65, 65);
    out[66] = 40;
    hexstr(addr, 20, (char *)(out + 67));
    *olen = 107;
    return SW_OK;
}

/* ---- SIGN_TX ------------------------------------------------------- */

uint16_t wh_sign_tx(uint8_t p1, uint8_t p2, const uint8_t *d, uint16_t n,
                    uint8_t *out, uint16_t *olen) {
    (void)p2; (void)out;
    *olen = 0;

    if (p1 == 0x00) {
        uint32_t index;
        int plen = parse_path(d, n, &index);
        if (plen < 0) return SW_BAD_DATA;
        p_index = index;
        uint16_t tx_len = (uint16_t)(n - plen);
        if (tx_len > ETH_TX_MAX_LEN) return SW_BAD_DATA;
        memcpy(raw, d + plen, tx_len);
        raw_len = tx_len;
    } else if (p1 == 0x80) {
        if ((uint64_t)raw_len + n > ETH_TX_MAX_LEN) { raw_len = 0; return SW_BAD_DATA; }
        memcpy(raw + raw_len, d, n);
        raw_len += n;
    } else {
        return SW_BAD_DATA;
    }

    /* Complete once the accumulated bytes parse as a whole transaction. */
    eth_tx_t tx;
    if (eth_tx_parse(raw, raw_len, &tx) == 0) {
        if (eth_tx_sighash(&tx, p_sighash) != 0) { raw_len = 0; return SW_BAD_DATA; }
        p_tx = tx;
        pending = WH_REVIEW_TX;
        return SW_OK;                   /* deferred: review -> approve/reject */
    }
    return SW_OK;                       /* incomplete: acknowledge, expect more */
}

/* ---- pending accessors --------------------------------------------- */

wh_pending_t wh_pending_kind(void)    { return pending; }
const eth_tx_t *wh_pending_tx(void)   { return (pending == WH_REVIEW_TX) ? &p_tx : NULL; }
uint32_t wh_pending_index(void)       { return p_index; }
void wh_pending_addr(uint8_t addr[20]) {
    if (pending == WH_CONFIRM_ADDR) memcpy(addr, p_addr, 20);
}

/* ---- v byte ---------------------------------------------------------
 *
 * The host reconstructs the full signature v from a single byte plus the
 * chainId it already knows (ledger-live getV/getParity):
 *   EIP-1559 / typed : parity (0x00 / 0x01)
 *   legacy EIP-155    : (chainId*2 + 35 + parity) & 0xFF   (low byte)
 *   legacy pre-155    : 27 + parity
 */
static uint8_t v_byte(const eth_tx_t *tx, uint8_t parity) {
    if (tx->type == ETH_TX_EIP1559) return parity;
    if (tx->chain_id == 0) return (uint8_t)(27 + parity);
    return (uint8_t)((2ull * tx->chain_id + 35ull + parity) & 0xFFull);
}

/* ---- approve / reject ---------------------------------------------- */

int wh_approve(uint8_t *resp, int cap) {
    if (pending == WH_CONFIRM_ADDR) {
        if (cap < 109) return 0;
        resp[0] = 65; memcpy(resp + 1, p_pub65, 65);
        resp[66] = 40; hexstr(p_addr, 20, (char *)(resp + 67));
        resp[107] = 0x90; resp[108] = 0x00;
        pending = WH_IDLE;
        return 109;
    }

    if (pending == WH_REVIEW_TX) {
        uint8_t sig[64], parity = 0;
        if (wallet_state_sign(p_index, p_sighash, sig, &parity) != 0) {
            pending = WH_IDLE;
            if (cap < 2) return 0;
            resp[0] = 0x6A; resp[1] = 0x80;   /* SW_BAD_DATA */
            return 2;
        }
        /* v(1) || r(32) || s(32) */
        resp[0] = v_byte(&p_tx, parity);
        memcpy(resp + 1, sig, 32);          /* r */
        memcpy(resp + 33, sig + 32, 32);    /* s */
        resp[65] = 0x90; resp[66] = 0x00;
        memzero(sig, sizeof sig);
        pending = WH_IDLE;
        return 67;
    }

    return 0;
}

int wh_reject(uint8_t *resp, int cap) {
    if (pending == WH_IDLE) return 0;
    if (cap < 2) return 0;
    resp[0] = 0x69; resp[1] = 0x85;   /* SW_REJECTED */
    pending = WH_IDLE;
    return 2;
}
