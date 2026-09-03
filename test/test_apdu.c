/* M7d host test — APDU dispatch: routing, SW codes, lock gate, response format. */

#include <stdio.h>
#include <string.h>
#include "apdu.h"

static int failures = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS  %s\n", name); \
    else { printf("FAIL  %s\n", name); failures++; } \
} while (0)

/* ---- mock handlers + capture ------------------------------------ */
static uint8_t  cap_p1, cap_p2;
static uint8_t  cap_data[256];
static uint16_t cap_data_len;
static int      cap_called;

static uint16_t mock_get_config(uint8_t p1, uint8_t p2,
                                const uint8_t *d, uint16_t n,
                                uint8_t *out, uint16_t *olen) {
    (void)p1; (void)p2; (void)d; (void)n;
    /* Ledger get-config: arbitrary_data(1) version(3) */
    out[0] = 0x00;              /* arbitrary_data_enabled = 0 */
    out[1] = 0x00; out[2] = 0x01; out[3] = 0x00;   /* version 0.1.0 */
    *olen = 4;
    return SW_OK;
}

static uint16_t mock_echo(uint8_t p1, uint8_t p2,
                          const uint8_t *d, uint16_t n,
                          uint8_t *out, uint16_t *olen) {
    cap_p1 = p1; cap_p2 = p2;
    cap_data_len = n;
    memcpy(cap_data, d, n);
    memcpy(out, d, n);
    *olen = n;
    cap_called++;
    return SW_OK;
}

static uint16_t mock_reject(uint8_t p1, uint8_t p2,
                            const uint8_t *d, uint16_t n,
                            uint8_t *out, uint16_t *olen) {
    (void)p1; (void)p2; (void)d; (void)n; (void)out;
    *olen = 0;
    return SW_REJECTED;
}

static uint16_t resp_sw(const uint8_t *resp, int len) {
    return (uint16_t)((resp[len - 2] << 8) | resp[len - 1]);
}

int main(void) {
    uint8_t resp[APDU_MAX_RESP];
    int r;

    apdu_reset();

    /* 1. GET_CONFIG routes and returns data + 9000. */
    apdu_register(APDU_INS_GET_CONFIG, mock_get_config);
    {
        uint8_t apdu[5] = {0xE0, 0x06, 0x00, 0x00, 0x00};
        r = apdu_dispatch(apdu, 5, resp, sizeof resp);
        CHECK(r == 6 && resp_sw(resp, r) == SW_OK, "get-config -> data+9000");
        CHECK(resp[0] == 0x00 && resp[1] == 0x00 && resp[2] == 0x01 && resp[3] == 0x00,
              "get-config payload (0x00 00 01 00)");
    }

    /* 2. Handler receives P1/P2/data intact. */
    apdu_register(APDU_INS_GET_PUBKEY, mock_echo);
    {
        uint8_t apdu[9] = {0xE0, 0x02, 0x01, 0x00, 0x04, 0x2C, 0x00, 0x00, 0x80};
        cap_called = 0;
        r = apdu_dispatch(apdu, 9, resp, sizeof resp);
        CHECK(cap_called == 1 && cap_p1 == 0x01 && cap_p2 == 0x00 && cap_data_len == 4,
              "handler sees P1/P2/data");
        CHECK(memcmp(cap_data, &apdu[5], 4) == 0 && memcmp(resp, &apdu[5], 4) == 0,
              "handler data round-trips");
        CHECK(resp_sw(resp, r) == SW_OK, "echo -> 9000");
    }

    /* 3. Bad CLA -> 6E00. */
    {
        uint8_t apdu[5] = {0xE1, 0x06, 0x00, 0x00, 0x00};
        r = apdu_dispatch(apdu, 5, resp, sizeof resp);
        CHECK(resp_sw(resp, r) == SW_CLA_BAD, "bad CLA -> 6E00");
    }

    /* 4. Unregistered INS -> 6D00. */
    {
        uint8_t apdu[5] = {0xE0, 0x0C, 0x00, 0x00, 0x00};   /* EIP-712, unregistered in v0 */
        r = apdu_dispatch(apdu, 5, resp, sizeof resp);
        CHECK(resp_sw(resp, r) == SW_INS_BAD, "unregistered INS -> 6D00");
    }

    /* 5. Lc mismatch -> 6700. */
    {
        uint8_t apdu[7] = {0xE0, 0x02, 0x00, 0x00, 0x10, 0xAA, 0xBB};  /* Lc=16 but 2 data bytes */
        r = apdu_dispatch(apdu, 7, resp, sizeof resp);
        CHECK(resp_sw(resp, r) == SW_WRONG_LENGTH, "Lc mismatch -> 6700");
    }

    /* 6. Case-1 APDU (4 bytes, no Lc) routes with empty data. */
    {
        uint8_t apdu[4] = {0xE0, 0x06, 0x00, 0x00};
        r = apdu_dispatch(apdu, 4, resp, sizeof resp);
        CHECK(r == 6 && resp_sw(resp, r) == SW_OK, "4-byte APDU -> get-config OK");
    }

    /* 7. Lock gate: non-config refused with 5515, get-config still served. */
    apdu_set_locked(true);
    {
        uint8_t pk[9] = {0xE0, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
        r = apdu_dispatch(pk, 9, resp, sizeof resp);
        CHECK(resp_sw(resp, r) == SW_DEVICE_LOCKED, "locked get-pubkey -> 5515");

        uint8_t cfg[5] = {0xE0, 0x06, 0x00, 0x00, 0x00};
        r = apdu_dispatch(cfg, 5, resp, sizeof resp);
        CHECK(resp_sw(resp, r) == SW_OK, "locked get-config -> still 9000");
    }
    apdu_set_locked(false);

    /* 7b. BOLOS OS commands (MetaMask bridge). */
    {
        uint8_t apdu[5] = {0xB0, 0x01, 0x00, 0x00, 0x00};   /* getAppNameAndVersion */
        r = apdu_dispatch(apdu, 5, resp, sizeof resp);
        CHECK(r == 19 && resp_sw(resp, r) == SW_OK, "bolos getAppNameAndVersion -> 9000");
        CHECK(resp[0] == 0x01 && resp[1] == 0x08 &&
              memcmp(resp + 2, "Ethereum", 8) == 0, "app name = Ethereum");
        CHECK(resp[10] == 0x06 && memcmp(resp + 11, "1.10.2", 6) == 0,
              "version = 1.10.2");

        uint8_t open_[13] = {0xE0, 0xD8, 0x00, 0x00, 0x08,
                             'E','t','h','e','r','e','u','m'};   /* openApp */
        r = apdu_dispatch(open_, 13, resp, sizeof resp);
        CHECK(r == 2 && resp_sw(resp, r) == SW_OK, "bolos openApp -> 9000");

        uint8_t close_[5] = {0xB0, 0xA7, 0x00, 0x00, 0x00};   /* closeApps */
        r = apdu_dispatch(close_, 5, resp, sizeof resp);
        CHECK(r == 2 && resp_sw(resp, r) == SW_OK, "bolos closeApps -> 9000");
    }

    /* 7c. BOLOS commands served even while locked. */
    apdu_set_locked(true);
    {
        uint8_t apdu[5] = {0xB0, 0x01, 0x00, 0x00, 0x00};
        r = apdu_dispatch(apdu, 5, resp, sizeof resp);
        CHECK(resp_sw(resp, r) == SW_OK, "bolos served while locked");
    }
    apdu_set_locked(false);

    /* 8. Error SW from handler propagates (reject -> 6985). */
    apdu_register(APDU_INS_SIGN_PERSONAL, mock_reject);
    {
        uint8_t apdu[6] = {0xE0, 0x08, 0x00, 0x00, 0x01, 0x42};
        r = apdu_dispatch(apdu, 6, resp, sizeof resp);
        CHECK(r == 2 && resp_sw(resp, r) == SW_REJECTED, "handler reject -> 6985 (SW only)");
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
