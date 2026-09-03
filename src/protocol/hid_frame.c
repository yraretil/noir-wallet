/* NOIR wallet — Ledger HID framing (M7c). See hid_frame.h for the wire format. */

#include "hid_frame.h"
#include <string.h>

/* ---- Receive-side reassembly state ------------------------------- */
static uint8_t rx_apdu[HID_FRAME_MAX_APDU];
static int     rx_total;   /* total APDU length from first frame; 0 = idle */
static int     rx_len;     /* bytes accumulated so far */
static int     rx_seq;     /* next expected sequence number */

void hid_frame_rx_reset(void) {
    rx_total = 0;
    rx_len = 0;
    rx_seq = 0;
}

int hid_frame_rx(uint8_t const *report, int len,
                 uint8_t *apdu_out, int *apdu_len_out) {
    if (len < 5) return HID_FRAME_ERR;   /* need channel+tag+seq */

    uint16_t channel = (uint16_t)((report[0] << 8) | report[1]);
    uint8_t  tag     = report[2];
    uint16_t seq     = (uint16_t)((report[3] << 8) | report[4]);

    /* Frames on other channels/tags are not ours; ignore without disturbing
     * any in-flight message. */
    if (channel != HID_FRAME_CHANNEL || tag != HID_FRAME_TAG_APDU)
        return HID_FRAME_NEED_MORE;

    if (seq == 0) {
        /* First frame of a (possibly new) message: read total length. */
        if (len < 7) return HID_FRAME_ERR;
        int total = (report[5] << 8) | report[6];
        if (total < HID_FRAME_MIN_APDU || total > HID_FRAME_MAX_APDU) {
            hid_frame_rx_reset();
            return HID_FRAME_ERR;
        }
        rx_total = total;
        rx_len   = 0;
        rx_seq   = 0;
    } else {
        /* Continuation frame: must be the one we expect next. */
        if (rx_total == 0 || (int)seq != rx_seq) {
            hid_frame_rx_reset();
            return HID_FRAME_ERR;
        }
    }

    /* Copy this frame's payload (first frame skips the 2-byte length field). */
    int hdr   = (seq == 0) ? 7 : 5;
    int avail = len - hdr;
    if (avail < 0) { hid_frame_rx_reset(); return HID_FRAME_ERR; }
    int want  = rx_total - rx_len;
    int c     = (avail < want) ? avail : want;
    memcpy(&rx_apdu[rx_len], &report[hdr], (size_t)c);
    rx_len += c;
    rx_seq  = (int)seq + 1;

    if (rx_len >= rx_total) {
        int n = rx_total;
        memcpy(apdu_out, rx_apdu, (size_t)n);
        *apdu_len_out = n;
        hid_frame_rx_reset();
        return HID_FRAME_DONE;
    }
    return HID_FRAME_NEED_MORE;
}

/* ---- Send-side chunking ------------------------------------------ */
int hid_frame_tx(uint8_t const *response, int len,
                 uint8_t frames[][HID_FRAME_SIZE]) {
    if (len < 1 || len > HID_FRAME_MAX_APDU) return 0;

    int nframes = 0;
    int offset  = 0;
    int seq     = 0;

    while (offset < len) {
        uint8_t *f = frames[nframes];
        memset(f, 0, HID_FRAME_SIZE);
        f[0] = (uint8_t)(HID_FRAME_CHANNEL >> 8);
        f[1] = (uint8_t)(HID_FRAME_CHANNEL & 0xFF);
        f[2] = HID_FRAME_TAG_APDU;
        f[3] = (uint8_t)(seq >> 8);
        f[4] = (uint8_t)(seq & 0xFF);

        int hdr = (seq == 0) ? 7 : 5;    /* first frame carries 2-byte length */
        if (seq == 0) {
            f[5] = (uint8_t)(len >> 8);
            f[6] = (uint8_t)(len & 0xFF);
        }

        int cap = HID_FRAME_SIZE - hdr;
        int c   = len - offset;
        if (c > cap) c = cap;
        memcpy(&f[hdr], response + offset, (size_t)c);

        offset  += c;
        seq++;
        nframes++;
    }
    return nframes;
}
