/* NOIR wallet — APDU wallet handlers (GET_PUBKEY + SIGN_TX), USB-free.
 *
 * Pure logic so it is host-testable: path allowlist, tx chunk accumulation,
 * sighash, deferred approval, and the Ledger response formats. hid_callbacks.c
 * registers these as APDU handlers and pumps the deferred responses; main.c
 * drives the review UI off wh_pending_*().
 *
 * Deferral: GET_PUBKEY with P1&0x01 (confirm) and a *complete* SIGN_TX both
 * return SW_OK but leave wh_pending_kind() != WH_IDLE, which the transport
 * layer detects (skip queueing) and the UI resolves via wh_approve() /
 * wh_reject().
 */

#ifndef WALLET_HANDLERS_H
#define WALLET_HANDLERS_H

#include <stdint.h>
#include <stdbool.h>
#include "eth_tx.h"

typedef enum {
    WH_IDLE = 0,
    WH_CONFIRM_ADDR,   /* GET_PUBKEY confirm-on-device in flight */
    WH_REVIEW_TX,      /* SIGN_TX parsed, awaiting review + hold-to-sign */
} wh_pending_t;

/* Reset accumulation + pending state (boot, lock, after approve/reject). */
void wh_reset(void);

/* GET_PUBLIC_KEY (INS 0x02). P1 bit0 = confirm on device (deferred). */
uint16_t wh_get_pubkey(uint8_t p1, uint8_t p2, const uint8_t *d, uint16_t n,
                       uint8_t *out, uint16_t *olen);

/* SIGN_TX (INS 0x04). P1 0x00 = first chunk (path + tx), 0x80 = continuation.
 * Acknowledges incomplete txs with SW_OK; defers a complete tx for review. */
uint16_t wh_sign_tx(uint8_t p1, uint8_t p2, const uint8_t *d, uint16_t n,
                    uint8_t *out, uint16_t *olen);

/* ---- pending approval (drives the review UI) --------------------- */
wh_pending_t     wh_pending_kind(void);
const eth_tx_t  *wh_pending_tx(void);    /* valid when WH_REVIEW_TX */
uint32_t         wh_pending_index(void); /* account index */
void             wh_pending_addr(uint8_t addr[20]); /* WH_CONFIRM_ADDR */

/* User decision: write the FULL response (data + 2-byte SW) to resp, return
 * its length (0 if nothing pending). approve() signs for WH_REVIEW_TX or
 * returns pubkey+addr for WH_CONFIRM_ADDR. reject() returns 0x6985. */
int wh_approve(uint8_t *resp, int cap);
int wh_reject(uint8_t *resp, int cap);

#endif /* WALLET_HANDLERS_H */
