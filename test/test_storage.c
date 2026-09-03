/* P3 host test — PIN storage: provision, verify, fail counter, wipe. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"

/* trezor-crypto consteq() fault hook — never fires in a normal run. */
void tc_fault_handler(const char *msg) {
    fprintf(stderr, "tc_fault_handler: %s\n", msg);
    abort();
}

static int failures = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS  %s\n", name); \
    else { printf("FAIL  %s\n", name); failures++; } \
} while (0)

int main(void) {
    uint8_t salt[STORAGE_SALT_LEN];
    for (int i = 0; i < STORAGE_SALT_LEN; i++) salt[i] = (uint8_t)(i + 1);

    CHECK(!storage_provisioned(), "starts unprovisioned");

    CHECK(storage_set_pin(salt, "1234") == 0, "set pin");
    CHECK(storage_provisioned(), "provisioned after set");

    CHECK(storage_check_pin("1234") == 1, "correct pin matches");
    CHECK(storage_fail_count() == 0, "fail count 0 after match");

    CHECK(storage_check_pin("9999") == 0, "wrong pin mismatches");
    CHECK(storage_fail_count() == 1, "fail count incremented");

    CHECK(storage_check_pin("1234") == 1, "correct pin still works after fail");
    CHECK(storage_fail_count() == 0, "fail count reset on success");

    /* 9 wrong, then the 10th wipes. */
    int wiped = 0;
    for (int i = 0; i < 9; i++) storage_check_pin("0000");
    wiped = (storage_check_pin("0000") == -1);
    CHECK(wiped, "10th wrong entry wipes");
    CHECK(!storage_provisioned(), "unprovisioned after wipe");

    CHECK(storage_set_pin(salt, "5678") == 0, "re-provision after wipe");
    CHECK(storage_check_pin("5678") == 1, "new pin verifies");

    /* Different salt -> different verifier for the same pin. */
    uint8_t salt2[STORAGE_SALT_LEN];
    memset(salt2, 0xAA, STORAGE_SALT_LEN);
    CHECK(storage_set_pin(salt2, "1234") == 0, "re-set with different salt");
    CHECK(storage_check_pin("1234") == 1, "pin valid across salt change");
    CHECK(storage_check_pin("4321") == 0, "different pin still wrong");

    storage_wipe();
    CHECK(!storage_provisioned(), "explicit wipe -> unprovisioned");

    /* ---- Seed record ---- */
    uint8_t entropy[STORAGE_ENTROPY_LEN];
    for (int i = 0; i < STORAGE_ENTROPY_LEN; i++) entropy[i] = (uint8_t)(0x40 + i);

    CHECK(!storage_seed_exists(), "seed absent initially");
    CHECK(storage_seed_set(entropy) == 0, "seed set");
    CHECK(storage_seed_exists(), "seed present after set");

    uint8_t readback[STORAGE_ENTROPY_LEN];
    CHECK(storage_seed_get(readback) == 0 &&
          memcmp(readback, entropy, STORAGE_ENTROPY_LEN) == 0,
          "seed round-trips");

    /* Critical: PIN fail-count update must NOT touch the seed (separate sectors). */
    CHECK(storage_set_pin(salt, "1234") == 0, "re-provision pin alongside seed");
    CHECK(storage_check_pin("0000") == 0, "wrong pin");
    CHECK(storage_check_pin("0000") == 0, "wrong pin again");
    CHECK(storage_seed_exists(), "seed survives PIN fail-count rewrites");
    CHECK(storage_seed_get(readback) == 0 &&
          memcmp(readback, entropy, STORAGE_ENTROPY_LEN) == 0,
          "seed bytes intact after PIN rewrites");

    storage_seed_wipe();
    CHECK(!storage_seed_exists(), "seed wipe -> absent");
    CHECK(storage_provisioned(), "seed wipe leaves PIN intact");

    /* 10-fail wipe must destroy BOTH pin and seed. */
    uint8_t e2[STORAGE_ENTROPY_LEN];
    memset(e2, 0x5A, STORAGE_ENTROPY_LEN);
    storage_seed_set(e2);
    storage_set_pin(salt, "1234");
    for (int i = 0; i < 10; i++) storage_check_pin("0000");
    CHECK(!storage_provisioned() && !storage_seed_exists(),
          "10 wrong wipes PIN and seed together");

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
