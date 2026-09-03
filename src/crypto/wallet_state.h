/* NOIR wallet — unlocked key-material cache (shared between UI and APDU).
 *
 * Holds the 64-byte BIP-39 seed in RAM only while the device is unlocked, so
 * the APDU handlers (get-pubkey / sign-tx) can derive keys on demand for any
 * account index without the UI and the transport layer owning the secret
 * separately. lock -> wallet_state_clear() zeroes it (memzero, not memset).
 */

#ifndef WALLET_STATE_H
#define WALLET_STATE_H

#include <stdint.h>
#include <stdbool.h>

/* Cache the seed (unlocks). */
void wallet_state_set_seed(const uint8_t seed[64]);

/* Seed pointer, or NULL when locked. Do not modify. */
const uint8_t *wallet_state_seed(void);

/* Zero the seed (locks). */
void wallet_state_clear(void);

bool wallet_state_is_unlocked(void);

/* Derive m/44'/60'/0'/0/index on demand. 0 = ok, -1 if locked or derivation
 * failed. */
int wallet_state_derive(uint32_t index, uint8_t priv[32], uint8_t pub65[65],
                        uint8_t addr[20]);

/* Sign hash32 with the derived key for `index`. 0 = ok, -1 if locked or the
 * signing failed. recid (0/1) is the Ethereum recovery-id parity. */
int wallet_state_sign(uint32_t index, const uint8_t hash32[32],
                      uint8_t sig[64], uint8_t *recid);

#endif /* WALLET_STATE_H */
