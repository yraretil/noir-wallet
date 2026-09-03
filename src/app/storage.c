/* NOIR wallet — persistent PIN + seed storage (P3). See storage.h.
 *
 * Record layouts (word-aligned):
 *   PIN  (64 B): magic(4) version(4) salt(16) verifier(32) fail_count(4) crc32(4)
 *   seed (44 B): magic(4) version(4) entropy(32) crc32(4)
 *
 * Flash backend swappable via STORAGE_TEST (RAM mock for host tests). The
 * core logic above flash_read/flash_erase/flash_program is pure and testable.
 */

#include "storage.h"
#include "pbkdf2.h"
#include "consteq.h"
#include <string.h>
#include <stddef.h>

/* Sector 5 = PIN, sector 4 = seed (firmware occupies sectors 0-3). */
#define PIN_ADDR    0x08020000UL
#define SEED_ADDR   0x08010000UL

#define PIN_MAGIC   0x4E4F4952UL   /* "NOIR" */
#define PIN_VERSION 1
#define SEED_MAGIC  0x53454544UL   /* "SEED" */
#define SEED_VERSION 1

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t  salt[STORAGE_SALT_LEN];
    uint8_t  verifier[STORAGE_VERIFIER_LEN];
    uint32_t fail_count;
    uint32_t crc32;
} pin_record_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t  entropy[STORAGE_ENTROPY_LEN];
    uint32_t crc32;
} seed_record_t;

/* ---- CRC-32 (IEEE 802.3, bit-by-bit — no 1 KB table) ------------ */
static uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c ^= data[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return c ^ 0xFFFFFFFFu;
}

/* ---- Flash backend ---------------------------------------------- */
#ifdef STORAGE_TEST
/* RAM mocks keyed by address (erase -> 0xFF, then program). */
#define PIN_SECTOR   5
#define SEED_SECTOR  4
static uint8_t mock_pin[sizeof(pin_record_t)];
static uint8_t mock_seed[sizeof(seed_record_t)];

static void flash_read(uint32_t addr, void *buf, size_t len) {
    const uint8_t *src = (addr == SEED_ADDR) ? mock_seed : mock_pin;
    memcpy(buf, src, len);
}
static void flash_erase(uint32_t addr, size_t len) {
    uint8_t *d = (addr == SEED_ADDR) ? mock_seed : mock_pin;
    memset(d, 0xFF, len);
}
static void flash_program(uint32_t addr, const void *buf, size_t len) {
    uint8_t *d = (addr == SEED_ADDR) ? mock_seed : mock_pin;
    memcpy(d, buf, len);
}

#else
#include "stm32f4xx_hal.h"

#define PIN_SECTOR   FLASH_SECTOR_5
#define SEED_SECTOR  FLASH_SECTOR_4

static uint32_t sector_of(uint32_t addr) {
    return (addr == SEED_ADDR) ? SEED_SECTOR : PIN_SECTOR;
}
static void flash_read(uint32_t addr, void *buf, size_t len) {
    memcpy(buf, (const void *)addr, len);
}
static void flash_erase(uint32_t addr, size_t len) {
    (void)len;
    HAL_FLASH_Unlock();
    __disable_irq();
    FLASH_EraseInitTypeDef e = {0};
    e.TypeErase = FLASH_TYPEERASE_SECTORS;
    e.Sector = sector_of(addr);
    e.NbSectors = 1;
    e.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    uint32_t err = 0;
    HAL_FLASHEx_Erase(&e, &err);
    __enable_irq();
    HAL_FLASH_Lock();
}
static void flash_program(uint32_t addr, const void *buf, size_t len) {
    HAL_FLASH_Unlock();
    __disable_irq();
    const uint32_t *w = (const uint32_t *)buf;
    for (size_t i = 0; i < len / 4; i++)
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, addr + i * 4, w[i]);
    __enable_irq();
    HAL_FLASH_Lock();
}
#endif

/* Erase sector + program a record. */
static void flash_write(uint32_t addr, const void *rec, size_t len) {
    flash_erase(addr, len);
    flash_program(addr, rec, len);
}

/* ---- PIN core ---------------------------------------------------- */

static uint32_t pin_crc(const pin_record_t *r) {
    return crc32((const uint8_t *)r, offsetof(pin_record_t, crc32));
}

static void compute_verifier(const uint8_t salt[STORAGE_SALT_LEN],
                             const char *pin, uint8_t out[STORAGE_VERIFIER_LEN]) {
    pbkdf2_hmac_sha256((const uint8_t *)pin, strlen(pin),
                       salt, STORAGE_SALT_LEN,
                       STORAGE_PBKDF2_ITERS, out, STORAGE_VERIFIER_LEN);
}

bool storage_provisioned(void) {
    pin_record_t rec;
    flash_read(PIN_ADDR, &rec, sizeof rec);
    return rec.magic == PIN_MAGIC && rec.version == PIN_VERSION &&
           rec.crc32 == pin_crc(&rec);
}

int storage_set_pin(const uint8_t salt[STORAGE_SALT_LEN], const char *pin) {
    pin_record_t rec;
    memset(&rec, 0, sizeof rec);
    rec.magic = PIN_MAGIC;
    rec.version = PIN_VERSION;
    memcpy(rec.salt, salt, STORAGE_SALT_LEN);
    compute_verifier(salt, pin, rec.verifier);
    rec.fail_count = 0;
    rec.crc32 = pin_crc(&rec);
    flash_write(PIN_ADDR, &rec, sizeof rec);
    return 0;
}

int storage_check_pin(const char *pin) {
    pin_record_t rec;
    flash_read(PIN_ADDR, &rec, sizeof rec);
    if (rec.magic != PIN_MAGIC || rec.version != PIN_VERSION)
        return 0;

    uint8_t verifier[STORAGE_VERIFIER_LEN];
    compute_verifier(rec.salt, pin, verifier);

    if (consteq(verifier, rec.verifier, STORAGE_VERIFIER_LEN)) {
        if (rec.fail_count != 0) {
            rec.fail_count = 0;
            rec.crc32 = pin_crc(&rec);
            flash_write(PIN_ADDR, &rec, sizeof rec);
        }
        return 1;
    }

    rec.fail_count++;
    if (rec.fail_count >= STORAGE_MAX_FAILS) {
        /* Wipe everything: back to unprovisioned (PIN + seed both gone). */
        flash_erase(PIN_ADDR, sizeof rec);
        flash_erase(SEED_ADDR, sizeof(seed_record_t));
        return -1;
    }
    rec.crc32 = pin_crc(&rec);
    flash_write(PIN_ADDR, &rec, sizeof rec);
    return 0;
}

int storage_fail_count(void) {
    pin_record_t rec;
    flash_read(PIN_ADDR, &rec, sizeof rec);
    return (rec.magic == PIN_MAGIC) ? (int)rec.fail_count : 0;
}

void storage_wipe(void) {
    /* Full reset: destroy PIN verifier AND seed. */
    flash_erase(PIN_ADDR, sizeof(pin_record_t));
    flash_erase(SEED_ADDR, sizeof(seed_record_t));
}

/* ---- Seed core --------------------------------------------------- */

static uint32_t seed_crc(const seed_record_t *r) {
    return crc32((const uint8_t *)r, offsetof(seed_record_t, crc32));
}

bool storage_seed_exists(void) {
    seed_record_t rec;
    flash_read(SEED_ADDR, &rec, sizeof rec);
    return rec.magic == SEED_MAGIC && rec.version == SEED_VERSION &&
           rec.crc32 == seed_crc(&rec);
}

int storage_seed_set(const uint8_t entropy[STORAGE_ENTROPY_LEN]) {
    seed_record_t rec;
    memset(&rec, 0, sizeof rec);
    rec.magic = SEED_MAGIC;
    rec.version = SEED_VERSION;
    memcpy(rec.entropy, entropy, STORAGE_ENTROPY_LEN);
    rec.crc32 = seed_crc(&rec);
    flash_write(SEED_ADDR, &rec, sizeof rec);
    return 0;
}

int storage_seed_get(uint8_t entropy[STORAGE_ENTROPY_LEN]) {
    seed_record_t rec;
    flash_read(SEED_ADDR, &rec, sizeof rec);
    if (rec.magic != SEED_MAGIC || rec.version != SEED_VERSION ||
        rec.crc32 != seed_crc(&rec))
        return -1;
    memcpy(entropy, rec.entropy, STORAGE_ENTROPY_LEN);
    return 0;
}

void storage_seed_wipe(void) {
    flash_erase(SEED_ADDR, sizeof(seed_record_t));
}
