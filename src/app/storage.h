/* NOIR wallet — persistent PIN + seed storage (P3). See storage.c for the format.
 *
 * Two records in separate flash sectors (F401CC 256 KB flash; firmware sits in
 * sectors 0-3, so 4 and 5 are free):
 *   - PIN record  @ sector 5 (0x08020000): salted PBKDF2 verifier + fail counter
 *   - seed record @ sector 4 (0x08010000): 32-byte entropy (24-word mnemonic)
 *
 * They MUST be in separate sectors: every PIN fail-count update erases its
 * whole sector, which would destroy the seed if they shared one.
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stdbool.h>

#define STORAGE_SALT_LEN      16
#define STORAGE_VERIFIER_LEN  32
#define STORAGE_MAX_FAILS     10
#define STORAGE_PBKDF2_ITERS  10000
#define STORAGE_ENTROPY_LEN   32

/* ---- PIN ---- */

/* 1 if a valid PIN verifier is stored. */
bool storage_provisioned(void);

/* Store a verifier for `pin` (salt = 16 random bytes). 0 = ok. */
int storage_set_pin(const uint8_t salt[STORAGE_SALT_LEN], const char *pin);

/* Verify `pin`. 1 = match (fail counter reset), 0 = mismatch (counter++),
 * -1 = wiped (max fails reached, back to unprovisioned). */
int storage_check_pin(const char *pin);

/* Current fail count (0 if unprovisioned). */
int storage_fail_count(void);

/* Erase the PIN record (back to unprovisioned). */
void storage_wipe(void);

/* ---- Seed ---- */

/* 1 if a valid seed is stored. */
bool storage_seed_exists(void);

/* Store the 32-byte entropy. 0 = ok. */
int storage_seed_set(const uint8_t entropy[STORAGE_ENTROPY_LEN]);

/* Read the 32-byte entropy. 0 = ok, -1 = no valid seed. */
int storage_seed_get(uint8_t entropy[STORAGE_ENTROPY_LEN]);

/* Erase the seed record. */
void storage_seed_wipe(void);

#endif /* STORAGE_H */
