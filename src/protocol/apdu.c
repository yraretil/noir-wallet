/* NOIR wallet — APDU dispatch (M7d). See apdu.h for the protocol. */

#include "apdu.h"
#include <string.h>

#define APDU_MAX_ROUTES 8

typedef struct {
    uint8_t        ins;
    apdu_handler_t h;
} apdu_route_t;

static apdu_route_t routes[APDU_MAX_ROUTES];
static int          n_routes;
static bool         locked;

void apdu_reset(void) {
    n_routes = 0;
    locked   = false;
}

void apdu_register(uint8_t ins, apdu_handler_t h) {
    for (int i = 0; i < n_routes; i++) {
        if (routes[i].ins == ins) { routes[i].h = h; return; }
    }
    if (n_routes < APDU_MAX_ROUTES)
        routes[n_routes++] = (apdu_route_t){ .ins = ins, .h = h };
}

void apdu_set_locked(bool l) {
    locked = l;
}

static apdu_handler_t find_handler(uint8_t ins) {
    for (int i = 0; i < n_routes; i++)
        if (routes[i].ins == ins) return routes[i].h;
    return NULL;
}

/* Build [data...][sw_hi][sw_lo]. Returns total length, or 0 if cap too small. */
static int respond(uint8_t *resp, int cap,
                   const uint8_t *data, int data_len, uint16_t sw) {
    int total = data_len + 2;
    if (total > cap) return 0;
    if (data_len > 0) memcpy(resp, data, (size_t)data_len);
    resp[data_len]     = (uint8_t)(sw >> 8);
    resp[data_len + 1] = (uint8_t)(sw & 0xFF);
    return total;
}

/* BOLOS OS-level commands used by the MetaMask Ledger bridge to identify and
 * open the Ethereum app. Served regardless of the app lock gate (the real
 * device's OS answers these even while the PIN screen is shown). Returns the
 * response length, or -1 if `(cla, ins)` is not a BOLOS command. */
static int bolos_dispatch(uint8_t cla, uint8_t ins,
                          const uint8_t *data, uint16_t data_len,
                          uint8_t *resp, int resp_cap) {
    (void)data; (void)data_len;
    if (cla == 0xB0 && ins == 0x01) {          /* getAppNameAndVersion */
        static const uint8_t out[] = {
            0x01, 0x08,
            'E', 't', 'h', 'e', 'r', 'e', 'u', 'm',
            0x06,
            '1', '.', '1', '0', '.', '2',
        };
        return respond(resp, resp_cap, out, (int)sizeof out, SW_OK);
    }
    if (cla == 0xB0 && ins == 0xA7)            /* closeApps */
        return respond(resp, resp_cap, NULL, 0, SW_OK);
    if (cla == 0xE0 && ins == 0xD8)            /* openApp ("Ethereum") */
        return respond(resp, resp_cap, NULL, 0, SW_OK);
    return -1;
}

int apdu_dispatch(const uint8_t *apdu, int apdu_len,
                  uint8_t *resp, int resp_cap) {
    if (apdu_len < 4)
        return respond(resp, resp_cap, NULL, 0, SW_WRONG_LENGTH);

    uint8_t cla = apdu[0], ins = apdu[1], p1 = apdu[2], p2 = apdu[3];
    int lc       = (apdu_len >= 5) ? apdu[4] : 0;
    int data_len = (apdu_len >= 5) ? (apdu_len - 5) : 0;

    if (data_len != lc)
        return respond(resp, resp_cap, NULL, 0, SW_WRONG_LENGTH);

    /* BOLOS OS commands (app name / open / close) — served regardless of the
     * app lock, because MetaMask needs them before the device is unlocked. */
    int bolos = bolos_dispatch(cla, ins, &apdu[5], (uint16_t)lc, resp, resp_cap);
    if (bolos >= 0) return bolos;

    if (cla != APDU_CLA_ETH)
        return respond(resp, resp_cap, NULL, 0, SW_CLA_BAD);

    /* Lock gate: only GET_APP_CONFIGURATION is served while locked. Refuse
     * with 0x5515 (LockedDeviceError) so MetaMask prompts "unlock your device"
     * and retries instead of timing out. */
    if (locked && ins != APDU_INS_GET_CONFIG)
        return respond(resp, resp_cap, NULL, 0, SW_DEVICE_LOCKED);

    apdu_handler_t h = find_handler(ins);
    if (!h)
        return respond(resp, resp_cap, NULL, 0, SW_INS_BAD);

    static uint8_t  out[APDU_MAX_RESP];   /* static: 255 B on the stack is
                                             wasteful and risks overflow */
    uint16_t out_len = 0;
    uint16_t sw = h(p1, p2, &apdu[5], (uint16_t)lc, out, &out_len);
    return respond(resp, resp_cap, out, out_len, sw);
}
