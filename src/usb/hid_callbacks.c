/* NOIR wallet — TinyUSB HID callbacks + APDU glue (see hid_app.h).
 *
 * Receive path: host OUT reports (64-byte Ledger frames) are fed to
 * hid_frame_rx() until a complete APDU is reassembled, then dispatched via
 * apdu_dispatch(). Send path: the response is chunked by hid_frame_tx() into
 * frames and pumped out the interrupt-IN endpoint from hid_app_task().
 */

#include "tusb.h"
#include "usb_descriptors.h"
#include "hid_frame.h"
#include "apdu.h"
#include "hid_app.h"
#include "wallet_handlers.h"

/* ---- receive + send state --------------------------------------- */
static uint8_t rx_apdu[HID_FRAME_MAX_APDU];
static uint8_t resp[APDU_MAX_RESP];

static uint8_t tx_frames[5][HID_FRAME_SIZE];   /* max 5 frames per 255-B resp */
static int     tx_nframes;
static int     tx_idx;

static void queue_response(const uint8_t *r, int len) {
    tx_nframes = hid_frame_tx(r, len, tx_frames);
    tx_idx = 0;
}

/* ---- APDU handlers ---------------------------------------------- */

/* GET_APP_CONFIGURATION (0x06): honest v0 config. */
static uint16_t h_get_config(uint8_t p1, uint8_t p2,
                             const uint8_t *d, uint16_t n,
                             uint8_t *out, uint16_t *olen) {
    (void)p1; (void)p2; (void)d; (void)n;
    out[0] = 0x00;              /* arbitrary_data_enabled = 0 */
    out[1] = 0x01;              /* version 1.10.2 (matches getAppNameAndVersion) */
    out[2] = 0x0A;
    out[3] = 0x02;
    *olen = 4;
    return SW_OK;
}

/* ---- lifecycle --------------------------------------------------- */

void hid_app_init(void) {
    hid_frame_rx_reset();
    apdu_reset();
    wh_reset();
    apdu_register(APDU_INS_GET_CONFIG, h_get_config);
    apdu_register(APDU_INS_GET_PUBKEY, wh_get_pubkey);
    apdu_register(APDU_INS_SIGN_TX,    wh_sign_tx);
    /* sign-personal / EIP-712 stay unregistered: unknown INS -> 0x6D00. */
    apdu_set_locked(true);      /* boot LOCKED */

    tx_nframes = 0;
    tx_idx = 0;
}

void hid_app_task(void) {
    while (tx_idx < tx_nframes && tud_hid_n_ready(ITF_NUM_HID)) {
        if (!tud_hid_n_report(ITF_NUM_HID, 0, tx_frames[tx_idx], HID_FRAME_SIZE))
            break;
        tx_idx++;
    }
}

void hid_app_set_locked(bool locked) {
    apdu_set_locked(locked);
    if (locked) wh_reset();   /* drop any in-flight review/accumulation */
}

void hid_app_approve(void) {
    int rlen = wh_approve(resp, sizeof resp);
    if (rlen > 0) queue_response(resp, rlen);
}

void hid_app_reject(void) {
    int rlen = wh_reject(resp, sizeof resp);
    if (rlen > 0) queue_response(resp, rlen);
}

/* ---- TinyUSB HID callbacks -------------------------------------- */

/* Host requested a report via control transfer — not used by Ledger's transport. */
uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen) {
    (void)itf; (void)report_id; (void)report_type; (void)buffer; (void)reqlen;
    return 0;
}

/* Host -> device: one 64-byte frame on the interrupt OUT endpoint (0x01). */
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize) {
    (void)itf; (void)report_id;
    if (report_type != HID_REPORT_TYPE_OUTPUT) return;

    int alen = 0;
    int r = hid_frame_rx(buffer, (int)bufsize, rx_apdu, &alen);
    if (r == HID_FRAME_DONE) {
        int rlen = apdu_dispatch(rx_apdu, alen, resp, sizeof resp);
        /* A deferred approval (get-pubkey confirm / complete sign-tx) leaves
         * wh_pending_kind() != WH_IDLE: hold the response until the user acts,
         * then hid_app_approve()/reject() queue it. */
        if (wh_pending_kind() == WH_IDLE && rlen > 0)
            queue_response(resp, rlen);
    }
    /* HID_FRAME_NEED_MORE: accumulate. HID_FRAME_ERR: drop silently (host
     * times out and retries). */
}
