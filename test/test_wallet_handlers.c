/* Host tests for the wallet APDU handlers (GET_PUBKEY + SIGN_TX).
 *
 * Verifies the exact Ledger wire formats against the real ledger-app-eth /
 * ledger-live behaviour:
 *   - GET_PUBKEY  -> [65][pubkey][40][40-hex address] = 107 bytes
 *   - SIGN_TX     -> v(1) || r(32) || s(32) = 65 bytes; v is the parity byte
 *                    (typed), (chainId*2+35+parity)&0xFF (legacy EIP-155), or
 *                    27+parity (pre-155).
 * Signatures are verified with ecdsa_verify_digest against the derived pubkey.
 */

#include <stdio.h>
#include <string.h>
#include "wallet_handlers.h"
#include "wallet_state.h"
#include "wallet.h"
#include "eth_tx.h"
#include "apdu.h"
#include "ecdsa.h"
#include "secp256k1.h"

static int failures = 0;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } \
} while (0)

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *s, uint8_t *out, int max) {
    int n = 0;
    for (int i = 0; s[i] && s[i + 1]; i += 2) {
        if (n >= max) return -1;
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* m/44'/60'/0'/0/index path as APDU data. Returns length. */
static int path_data(uint32_t index, uint8_t *b) {
    b[0] = 5;
    uint32_t c[5] = {0x8000002Cu, 0x8000003Cu, 0x80000000u, 0u, index};
    for (int i = 0; i < 5; i++) {
        b[1 + 4*i] = (uint8_t)(c[i] >> 24);
        b[2 + 4*i] = (uint8_t)(c[i] >> 16);
        b[3 + 4*i] = (uint8_t)(c[i] >> 8);
        b[4 + 4*i] = (uint8_t)c[i];
    }
    return 21;
}

/* Feed a raw tx through wh_sign_tx (path first, then two chunks), assert it
 * lands in REVIEW. Returns the sighash via eth_tx_sighash. */
static void feed_tx(const uint8_t *raw, int rawlen, uint8_t *sighash) {
    uint8_t first[256], path[21];
    path_data(0, path);
    memcpy(first, path, 21);
    int split = rawlen / 2;
    if (split > 230) split = 230;
    memcpy(first + 21, raw, split);

    uint8_t out[120]; uint16_t olen = 0;
    CHECK(wh_sign_tx(0x00, 0x00, first, 21 + split, out, &olen) == SW_OK);
    CHECK(wh_pending_kind() == WH_IDLE);          /* incomplete after first chunk */
    CHECK(wh_sign_tx(0x80, 0x00, raw + split, rawlen - split, out, &olen) == SW_OK);
    CHECK(wh_pending_kind() == WH_REVIEW_TX);
    const eth_tx_t *tx = wh_pending_tx();
    CHECK(tx != NULL);
    CHECK(eth_tx_sighash(tx, sighash) == 0);
}

int main(void) {
    uint8_t seed[64];
    for (int i = 0; i < 64; i++) seed[i] = (uint8_t)i;
    wallet_state_set_seed(seed);

    uint8_t priv[32], pub65[65], addr[20];
    CHECK(wallet_derive_eth(seed, 0, priv, pub65, addr) == 0);

    uint8_t path[21], out[128], resp[256];
    uint16_t olen = 0;
    path_data(0, path);

    /* --- GET_PUBKEY immediate --- */
    CHECK(wh_get_pubkey(0x00, 0x00, path, 21, out, &olen) == SW_OK);
    CHECK(olen == 107);
    CHECK(out[0] == 65 && out[66] == 40);
    CHECK(memcmp(out + 1, pub65, 65) == 0);
    {
        char hex[41];
        for (int i = 0; i < 20; i++) sprintf(hex + 2*i, "%02x", addr[i]);
        CHECK(memcmp(out + 67, hex, 40) == 0);   /* lowercase, no "0x" */
    }

    /* --- GET_PUBKEY confirm -> defer -> approve --- */
    CHECK(wh_get_pubkey(0x01, 0x00, path, 21, out, &olen) == SW_OK);
    CHECK(wh_pending_kind() == WH_CONFIRM_ADDR);
    {
        uint8_t a2[20];
        wh_pending_addr(a2);
        CHECK(memcmp(a2, addr, 20) == 0);
    }
    CHECK(wh_approve(resp, sizeof resp) == 109);
    CHECK(resp[0] == 65 && resp[66] == 40);
    CHECK(resp[107] == 0x90 && resp[108] == 0x00);
    CHECK(wh_pending_kind() == WH_IDLE);

    /* --- GET_PUBKEY confirm -> reject --- */
    CHECK(wh_get_pubkey(0x01, 0x00, path, 21, out, &olen) == SW_OK);
    CHECK(wh_reject(resp, sizeof resp) == 2);
    CHECK(resp[0] == 0x69 && resp[1] == 0x85);

    /* --- GET_PUBKEY bad path --- */
    {
        uint8_t bad[22]; path_data(0, bad);
        bad[0] = 4;                              /* wrong component count */
        CHECK(wh_get_pubkey(0x00, 0x00, bad, 17, out, &olen) == SW_BAD_DATA);
        uint8_t badpath[21]; path_data(0, badpath);
        badpath[1] = 0x00;                       /* 44' -> 0x0000002c */
        CHECK(wh_get_pubkey(0x00, 0x00, badpath, 21, out, &olen) == SW_BAD_DATA);
    }

    /* --- GET_PUBKEY while locked --- */
    wallet_state_clear();
    CHECK(wh_get_pubkey(0x00, 0x00, path, 21, out, &olen) == SW_LOCKED);
    wallet_state_set_seed(seed);

    /* --- SIGN_TX EIP-155 (chainId 1) --- */
    {
        uint8_t raw[128];
        int n = hex_decode("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080258080", raw, sizeof raw);
        CHECK(n > 0);
        uint8_t sighash[32];
        feed_tx(raw, n, sighash);
        const eth_tx_t *tx = wh_pending_tx();
        CHECK(tx->type == ETH_TX_LEGACY);
        CHECK(tx->chain_id == 1);
        uint8_t sh[32];
        hex_decode("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53", sh, 32);
        CHECK(memcmp(sighash, sh, 32) == 0);

        CHECK(wh_approve(resp, sizeof resp) == 67);
        CHECK(resp[65] == 0x90 && resp[66] == 0x00);
        CHECK(resp[0] == 37 || resp[0] == 38);   /* 2*1+35+parity */
        uint8_t sig[64];
        memcpy(sig, resp + 1, 64);
        CHECK(ecdsa_verify_digest(&secp256k1, pub65, sig, sighash) == 0);
    }

    /* --- SIGN_TX EIP-1559 (v = parity) --- */
    {
        uint8_t raw[128];
        int n = hex_decode("02ea0180843b9aca0084773594008252089435353535353535353535353535353535353535358080c0808080", raw, sizeof raw);
        uint8_t sighash[32];
        feed_tx(raw, n, sighash);
        CHECK(wh_pending_tx()->type == ETH_TX_EIP1559);
        uint8_t sh[32];
        hex_decode("dbb471776a525993bfa890461f09a8e4861f1f9a3408424ad15d2e1f3a873781", sh, 32);
        CHECK(memcmp(sighash, sh, 32) == 0);
        CHECK(wh_approve(resp, sizeof resp) == 67);
        CHECK(resp[0] == 0x00 || resp[0] == 0x01);
        uint8_t sig[64];
        memcpy(sig, resp + 1, 64);
        CHECK(ecdsa_verify_digest(&secp256k1, pub65, sig, sighash) == 0);
    }

    /* --- SIGN_TX legacy pre-155 (v = 27/28) --- */
    {
        uint8_t raw[128];
        int n = hex_decode("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000801b8080", raw, sizeof raw);
        uint8_t sighash[32];
        feed_tx(raw, n, sighash);
        CHECK(wh_pending_tx()->chain_id == 0);
        uint8_t sh[32];
        hex_decode("f9e36c28c8cb35adba138005c02ab7aa7fbcd891f3139cb2eeed052a51cd2713", sh, 32);
        CHECK(memcmp(sighash, sh, 32) == 0);
        CHECK(wh_approve(resp, sizeof resp) == 67);
        CHECK(resp[0] == 27 || resp[0] == 28);
        uint8_t sig[64];
        memcpy(sig, resp + 1, 64);
        CHECK(ecdsa_verify_digest(&secp256k1, pub65, sig, sighash) == 0);
    }

    /* --- SIGN_TX legacy large chainId (31337, Sepolia-class) --- */
    {
        uint8_t raw[128];
        int n = hex_decode("e18001825208943535353535353535353535353535353535353535808082f4f58080", raw, sizeof raw);
        uint8_t sighash[32];
        feed_tx(raw, n, sighash);
        CHECK(wh_pending_tx()->chain_id == 31337);
        CHECK(wh_approve(resp, sizeof resp) == 67);
        CHECK(resp[0] == 245 || resp[0] == 246); /* (2*31337+35+parity)&0xff */
        uint8_t sig[64];
        memcpy(sig, resp + 1, 64);
        CHECK(ecdsa_verify_digest(&secp256k1, pub65, sig, sighash) == 0);
    }

    /* --- SIGN_TX reject --- */
    {
        uint8_t raw[128];
        int n = hex_decode("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080258080", raw, sizeof raw);
        uint8_t sighash[32];
        feed_tx(raw, n, sighash);
        CHECK(wh_reject(resp, sizeof resp) == 2);
        CHECK(resp[0] == 0x69 && resp[1] == 0x85);
        CHECK(wh_pending_kind() == WH_IDLE);
    }

    if (failures == 0) {
        printf("wallet_handlers_test: ALL PASS\n");
        return 0;
    }
    printf("wallet_handlers_test: %d FAILURE(S)\n", failures);
    return 1;
}
