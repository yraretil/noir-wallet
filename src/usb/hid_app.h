/* NOIR wallet — HID application layer glue (USB <-> APDU).
 *
 * Ties the Ledger HID transport (64-byte reports) to the APDU dispatcher:
 * receive -> hid_frame reassembly -> apdu dispatch -> response -> chunked
 * frames -> interrupt-IN. Boot LOCKED: only GET_APP_CONFIGURATION is served
 * until the PIN/state machine (P3) unlocks the device.
 */

#ifndef HID_APP_H
#define HID_APP_H

/* Register APDU handlers + boot LOCKED. Call once after tusb_init(). */
void hid_app_init(void);

/* Pump queued outgoing response frames. Call from the main loop right after
 * tud_task(). */
void hid_app_task(void);

/* Flip the APDU lock gate (unlock on PIN verify, lock on unmount/idle). */
void hid_app_set_locked(bool locked);

/* Async approval: after a deferred GET_PUBKEY (confirm) or SIGN_TX (complete),
 * the response is queued only once the user acts on-device. main.c calls these
 * on the user's decision (approve = sign/return, reject = 0x6985). */
void hid_app_approve(void);
void hid_app_reject(void);

#endif /* HID_APP_H */
