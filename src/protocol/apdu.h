/* NOIR wallet — APDU dispatch (M7d).
 *
 * Sits above hid_frame.c: receives a reassembled APDU (CLA INS P1 P2 Lc data),
 * routes it to a registered handler, and formats the response as data + 2-byte
 * status word. Ledger Ethereum app instruction set:
 *
 *   CLA 0xE0
 *   INS 0x02 GET_PUBLIC_KEY      (P1 0x00 = no confirm, 0x01 = confirm on device)
 *   INS 0x04 SIGN_TX             (P1 0x00 first chunk, 0x80 continuation)
 *   INS 0x06 GET_APP_CONFIGURATION
 *   INS 0x08 SIGN_PERSONAL_MESSAGE
 *
 * Lock gate: while locked, every INS except GET_APP_CONFIGURATION is refused
 * with SW_LOCKED (0x6982), matching the boot-LOCKED invariant.
 */

#ifndef APDU_H
#define APDU_H

#include <stdint.h>
#include <stdbool.h>

#define APDU_CLA_ETH            0xE0
#define APDU_INS_GET_PUBKEY     0x02
#define APDU_INS_SIGN_TX        0x04
#define APDU_INS_GET_CONFIG     0x06
#define APDU_INS_SIGN_PERSONAL  0x08

/* Status words (Ledger convention). */
#define SW_OK            0x9000
#define SW_REJECTED      0x6985   /* user rejected on device */
#define SW_LOCKED        0x6982   /* app-level "security not satisfied" */
#define SW_DEVICE_LOCKED 0x5515   /* BOLOS "Locked device" (PIN not entered) —
                                     MetaMask maps THIS to LockedDeviceError and
                                     enters its unlock-retry loop. */
#define SW_BAD_DATA      0x6A80   /* bad APDU data / tx parse failure */
#define SW_WRONG_LENGTH  0x6700   /* Lc does not match data length */
#define SW_INS_BAD       0x6D00   /* unknown INS */
#define SW_CLA_BAD       0x6E00   /* unknown CLA */

#define APDU_MAX_RESP    255

/* Handler: given P1/P2 and the data field, write response data (without the
 * status word) to out[0..*out_len-1] and return the status word. */
typedef uint16_t (*apdu_handler_t)(
    uint8_t p1, uint8_t p2,
    const uint8_t *data, uint16_t data_len,
    uint8_t *out, uint16_t *out_len);

/* Reset routes and unlock. */
void apdu_reset(void);

/* Register a handler for an INS (replaces any previous). */
void apdu_register(uint8_t ins, apdu_handler_t h);

/* Set the lock gate. */
void apdu_set_locked(bool locked);

/* Dispatch a complete APDU -> full response (data + SW). Returns the response
 * length (>= 2), or 0 if resp_cap is too small (defensive; never with a
 * 255-byte buffer). */
int apdu_dispatch(const uint8_t *apdu, int apdu_len,
                  uint8_t *resp, int resp_cap);

#endif /* APDU_H */
