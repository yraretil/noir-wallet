/* NOIR wallet — unlocked key-material cache (see wallet_state.h). */

#include "wallet_state.h"
#include "wallet.h"
#include "memzero.h"
#include <string.h>

static uint8_t g_seed[64];
static bool    g_unlocked;

void wallet_state_set_seed(const uint8_t seed[64]) {
    memcpy(g_seed, seed, 64);
    g_unlocked = true;
}

const uint8_t *wallet_state_seed(void) {
    return g_unlocked ? g_seed : NULL;
}

void wallet_state_clear(void) {
    memzero(g_seed, sizeof g_seed);
    g_unlocked = false;
}

bool wallet_state_is_unlocked(void) {
    return g_unlocked;
}

int wallet_state_derive(uint32_t index, uint8_t priv[32], uint8_t pub65[65],
                        uint8_t addr[20]) {
    if (!g_unlocked) return -1;
    return wallet_derive_eth(g_seed, index, priv, pub65, addr);
}

int wallet_state_sign(uint32_t index, const uint8_t hash32[32],
                      uint8_t sig[64], uint8_t *recid) {
    if (!g_unlocked) return -1;
    uint8_t priv[32], pub65[65], addr[20];
    if (wallet_derive_eth(g_seed, index, priv, pub65, addr) != 0) return -1;
    int r = wallet_sign(priv, hash32, sig, recid);
    memzero(priv, sizeof priv);
    memzero(pub65, sizeof pub65);
    memzero(addr, sizeof addr);
    return r;
}
