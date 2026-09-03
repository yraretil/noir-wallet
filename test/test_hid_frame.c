/* M7c host test — Ledger HID framing round-trips and error handling. */

#include <stdio.h>
#include <string.h>
#include "hid_frame.h"

static int failures = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS  %s\n", name); \
    else { printf("FAIL  %s\n", name); failures++; } \
} while (0)

/* Feed every frame through RX; return the final result, or -100 if a frame
 * completed the APDU before the last frame. */
static int feed_all(uint8_t frames[][HID_FRAME_SIZE], int nframes,
                    uint8_t *apdu, int *apdu_len) {
    int r = HID_FRAME_NEED_MORE;
    for (int i = 0; i < nframes; i++) {
        r = hid_frame_rx(frames[i], HID_FRAME_SIZE, apdu, apdu_len);
        if (r == HID_FRAME_ERR) return HID_FRAME_ERR;
        if (r == HID_FRAME_DONE)
            return (i == nframes - 1) ? HID_FRAME_DONE : -100;
    }
    return r;
}

/* Chunk then reassemble; assert DONE, exact length, exact bytes. */
static int roundtrip(const uint8_t *msg, int len, const char *name) {
    uint8_t frames[5][HID_FRAME_SIZE];
    int n = hid_frame_tx(msg, len, frames);
    if (n <= 0) { printf("FAIL  %s (tx returned %d)\n", name, n); failures++; return -1; }

    uint8_t out[HID_FRAME_MAX_APDU];
    int outlen = 0;
    int r = feed_all(frames, n, out, &outlen);
    if (r != HID_FRAME_DONE || outlen != len || memcmp(out, msg, len) != 0) {
        printf("FAIL  %s (r=%d outlen=%d)\n", name, r, outlen);
        failures++;
        return -1;
    }
    printf("PASS  %s (%d bytes, %d frames)\n", name, len, n);
    return 0;
}

int main(void) {
    uint8_t apdu[HID_FRAME_MAX_APDU];
    int alen = 0;

    /* 1. Single-frame: 5-byte GET_APP_CONFIGURATION (E0 06 00 00 00). */
    {
        uint8_t m[5] = {0xE0, 0x06, 0x00, 0x00, 0x00};
        roundtrip(m, 5, "single-frame 5B APDU");
    }

    /* 2. Multi-frame: 255-byte APDU (the max, signTransaction-ish). */
    {
        uint8_t m[HID_FRAME_MAX_APDU];
        m[0] = 0xE0; m[1] = 0x04; m[2] = 0x00; m[3] = 0x00; m[4] = 0xFA;
        for (int i = 5; i < 255; i++) m[i] = (uint8_t)i;
        roundtrip(m, 255, "multi-frame 255B APDU");
    }

    /* 3. Exact wire bytes of frame 0 (channel/tag/seq/length). */
    {
        uint8_t m[7] = {0xE0, 0x06, 0x00, 0x00, 0x00, 0xAB, 0xCD};
        uint8_t frames[1][HID_FRAME_SIZE];
        int n = hid_frame_tx(m, 7, frames);
        CHECK(n == 1, "tx 7B -> 1 frame");
        CHECK(frames[0][0] == 0x01 && frames[0][1] == 0x01, "channel 0x0101");
        CHECK(frames[0][2] == 0x05, "tag 0x05");
        CHECK(frames[0][3] == 0x00 && frames[0][4] == 0x00, "seq 0");
        CHECK(frames[0][5] == 0x00 && frames[0][6] == 0x07, "total length 0x0007");
        CHECK(memcmp(&frames[0][7], m, 7) == 0, "payload exact");
        CHECK(frames[0][14] == 0x00, "frame zero-padded");
    }

    /* 4. Continuation frame seq continuity (255B => seq 0..4). */
    {
        uint8_t m[HID_FRAME_MAX_APDU];
        for (int i = 0; i < 255; i++) m[i] = (uint8_t)(255 - i);
        uint8_t frames[5][HID_FRAME_SIZE];
        int n = hid_frame_tx(m, 255, frames);
        CHECK(n == 5, "255B -> 5 frames");
        int ok = 1;
        for (int i = 0; i < n; i++) {
            int seq = (frames[i][3] << 8) | frames[i][4];
            if (seq != i) ok = 0;
        }
        CHECK(ok, "sequence numbers 0..4");
    }

    /* 5. Out-of-order: frame 0 then frame 2 (skipping 1) -> ERR. */
    {
        uint8_t m[HID_FRAME_MAX_APDU];
        for (int i = 0; i < 255; i++) m[i] = (uint8_t)i;
        uint8_t frames[5][HID_FRAME_SIZE];
        hid_frame_tx(m, 255, frames);
        hid_frame_rx_reset();
        CHECK(hid_frame_rx(frames[0], 64, apdu, &alen) == HID_FRAME_NEED_MORE, "frame0 -> need more");
        CHECK(hid_frame_rx(frames[2], 64, apdu, &alen) == HID_FRAME_ERR, "skipped seq -> ERR");
    }

    /* 6. Wrong channel ignored without corrupting in-flight message. */
    {
        uint8_t m[HID_FRAME_MAX_APDU];
        for (int i = 0; i < 255; i++) m[i] = (uint8_t)i;
        uint8_t frames[5][HID_FRAME_SIZE];
        hid_frame_tx(m, 255, frames);
        hid_frame_rx_reset();
        CHECK(hid_frame_rx(frames[0], 64, apdu, &alen) == HID_FRAME_NEED_MORE, "frame0 -> need more");
        uint8_t bad[HID_FRAME_SIZE];
        memcpy(bad, frames[0], 64);
        bad[1] = 0x02;   /* channel 0x0102 */
        CHECK(hid_frame_rx(bad, 64, apdu, &alen) == HID_FRAME_NEED_MORE, "foreign channel ignored");
        /* real continuation frames 1..4 still accepted, completes intact */
        int r = HID_FRAME_NEED_MORE;
        for (int i = 1; i < 5; i++) r = hid_frame_rx(frames[i], 64, apdu, &alen);
        CHECK(r == HID_FRAME_DONE && alen == 255 && memcmp(apdu, m, 255) == 0,
              "message survives foreign frame");
    }

    /* 7. Oversized declared length -> ERR. */
    {
        uint8_t bad[HID_FRAME_SIZE];
        memset(bad, 0, 64);
        bad[0] = 0x01; bad[1] = 0x01; bad[2] = 0x05;
        bad[5] = 0x01; bad[6] = 0x00;   /* total = 256 */
        CHECK(hid_frame_rx(bad, 64, apdu, &alen) == HID_FRAME_ERR, "oversized length -> ERR");
    }

    /* 8. New seq-0 frame mid-message restarts cleanly. */
    {
        uint8_t m[HID_FRAME_MAX_APDU];
        for (int i = 0; i < 255; i++) m[i] = (uint8_t)i;
        uint8_t frames[5][HID_FRAME_SIZE];
        hid_frame_tx(m, 255, frames);
        hid_frame_rx_reset();
        hid_frame_rx(frames[0], 64, apdu, &alen);   /* start message */
        uint8_t m2[7] = {0xE0, 0x06, 0x00, 0x00, 0x00, 0xAA, 0xBB};
        uint8_t f2[1][HID_FRAME_SIZE];
        hid_frame_tx(m2, 7, f2);
        CHECK(hid_frame_rx(f2[0], 64, apdu, &alen) == HID_FRAME_DONE && alen == 7 && memcmp(apdu, m2, 7) == 0,
              "new seq-0 restarts message");
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
