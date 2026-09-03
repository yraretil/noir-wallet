/* M7e host test — tx parsing, chainId derivation, and sighash vs reference
 * vectors (EIP-155 example + independently generated legacy/EIP-1559). */

#include <stdio.h>
#include <string.h>
#include "eth_tx.h"

static int failures = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS  %s\n", name); \
    else { printf("FAIL  %s\n", name); failures++; } \
} while (0)

static int from_hex(const char *s, uint8_t *out) {
    size_t len = strlen(s) / 2;
    for (size_t i = 0; i < len; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)len;
}

static void hexdump(const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", d[i]);
}

/* Parse + sighash, compare to expected. */
static int check_sighash(const char *raw_hex, const char *expect_hex, const char *name) {
    uint8_t raw[ETH_TX_MAX_LEN];
    int rawlen = from_hex(raw_hex, raw);
    eth_tx_t tx;
    if (eth_tx_parse(raw, (uint32_t)rawlen, &tx) != 0) {
        printf("FAIL  %s (parse)\n", name); failures++; return -1;
    }
    uint8_t sh[ETH_TX_SIGHASH_LEN];
    if (eth_tx_sighash(&tx, sh) != 0) {
        printf("FAIL  %s (sighash)\n", name); failures++; return -1;
    }
    uint8_t expect[32];
    from_hex(expect_hex, expect);
    if (memcmp(sh, expect, 32) != 0) {
        printf("FAIL  %s (got ", name); hexdump(sh, 32); printf(")\n");
        failures++; return -1;
    }
    printf("PASS  %s\n", name);
    return 0;
}

int main(void) {
    uint8_t raw[ETH_TX_MAX_LEN];
    eth_tx_t tx;

    /* ---- Valid transactions ---- */

    /* EIP-155 (v=37 => chainId 1), from the EIP-155 spec example. */
    check_sighash("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080258080",
                  "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53",
                  "EIP-155 sighash (chainId 1)");

    /* Legacy pre-155 (v=27 => no chainId). */
    check_sighash("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000801b8080",
                  "f9e36c28c8cb35adba138005c02ab7aa7fbcd891f3139cb2eeed052a51cd2713",
                  "legacy pre-155 sighash (chainId 0)");

    /* EIP-1559 (type 2). */
    check_sighash("02ea0180843b9aca0084773594008252089435353535353535353535353535353535353535358080c0808080",
                  "dbb471776a525993bfa890461f09a8e4861f1f9a3408424ad15d2e1f3a873781",
                  "EIP-1559 sighash");

    /* Fully-signed EIP-155 (v=37, r/s present) — same sighash, ignores r/s. */
    check_sighash("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
                  "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53",
                  "signed EIP-155 -> same sighash");

    /* ---- Field extraction ---- */
    {
        int n = from_hex("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080258080", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == 0, "parse for field check");
        CHECK(tx.type == ETH_TX_LEGACY, "type = legacy");
        CHECK(tx.chain_id == 1, "chainId = 1");
        CHECK(tx.is_creation == 0, "not contract creation");
        uint8_t to[20]; from_hex("3535353535353535353535353535353535353535", to);
        CHECK(memcmp(tx.to, to, 20) == 0, "to == 0x3535..35");
        CHECK(tx.value.len == 8 && tx.value.ptr[0] == 0x0d, "value field (10^18)");
    }

    /* Contract creation (empty to). */
    {
        int n = from_hex("cf80843b9aca00825208808080258080", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == 0, "parse creation tx");
        CHECK(tx.is_creation == 1 && tx.to_field.len == 0, "creation flagged, empty to");
    }

    /* EIP-1559 field extraction: chainId from field 0. */
    {
        int n = from_hex("02ea0180843b9aca0084773594008252089435353535353535353535353535353535353535358080c0808080", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == 0, "parse 1559");
        CHECK(tx.type == ETH_TX_EIP1559 && tx.chain_id == 1, "1559 type + chainId 1");
        CHECK(tx.max_priority_fee.len == 4 && tx.max_fee.len == 4, "1559 fee fields");
    }

    /* ---- Malformed -> hard reject ---- */
    CHECK(eth_tx_parse(raw, 0, &tx) == -1, "empty input -> reject");
    {
        int n = from_hex("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000802580", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == -1, "truncated RLP -> reject");
    }
    {
        int n = from_hex("01c0", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == -1, "EIP-2930 (type 1) -> reject");
    }
    {
        int n = from_hex("eb098504a817c8008252089335353535353535353535353535353535353535880de0b6b3a764000080258080", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == -1, "to != 20 bytes -> reject");
    }
    {
        int n = from_hex("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025808000", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == -1, "trailing byte -> reject");
    }
    {
        int n = from_hex("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000801d8080", raw);
        CHECK(eth_tx_parse(raw, (uint32_t)n, &tx) == -1, "invalid v=29 -> reject");
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
