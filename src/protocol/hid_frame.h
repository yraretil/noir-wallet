/* NOIR wallet — Ledger HID framing (M7c).
 *
 * The Ledger transport is raw 64-byte HID reports carrying APDUs split across
 * one or more frames. Wire format (from ledgerjs / the Solana remote-wallet
 * reference implementation):
 *
 *   report[0..2)  channel id, uint16 big-endian   = 0x0101
 *   report[2]     tag                             = 0x05 (APDU)
 *   report[3..5)  sequence number, uint16 BE       = 0, 1, 2, ... per message
 *   report[5..64) payload
 *
 * The FIRST frame (seq 0) prepends a 2-byte big-endian total APDU length to
 * its payload, so it carries 57 APDU bytes; each continuation frame carries 59.
 * Responses are framed identically (response data + 2-byte status word).
 *
 * This layer only reassembles/chunks bytes. APDU structure (CLA/INS/Lc) is
 * validated upstream in apdu.c.
 */

#ifndef HID_FRAME_H
#define HID_FRAME_H

#include <stdint.h>

#define HID_FRAME_SIZE       64
#define HID_FRAME_CHANNEL    0x0101
#define HID_FRAME_TAG_APDU   0x05
#define HID_FRAME_MAX_APDU   255   /* Ledger APDU max (1-byte Lc) */
#define HID_FRAME_MIN_APDU   4     /* CLA INS P1 P2 */

enum {
    HID_FRAME_NEED_MORE = 0,   /* frame consumed, message incomplete */
    HID_FRAME_DONE      = 1,   /* complete APDU in apdu_out[0..*len-1] */
    HID_FRAME_ERR       = -1,  /* framing error; state reset */
};

/* Reset reassembly state (call on USB unmount / new session). */
void hid_frame_rx_reset(void);

/* Feed one 64-byte interrupt-OUT report. Returns HID_FRAME_* (above). */
int hid_frame_rx(uint8_t const *report, int len,
                 uint8_t *apdu_out, int *apdu_len_out);

/* Chunk a response APDU (data + 2-byte SW, len <= 255) into 64-byte frames.
 * Fills frames[0..ret-1], returns the frame count, or 0 if len out of range. */
int hid_frame_tx(uint8_t const *response, int len,
                 uint8_t frames[][HID_FRAME_SIZE]);

#endif /* HID_FRAME_H */
