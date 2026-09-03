/* NOIR wallet — v0 firmware (demo-ready).
 *
 * Boot flow:
 *   fresh (no seed)  -> SET PIN -> GENERATE (24 words) -> BACKUP -> READY -> HOME
 *   provisioned      -> ENTER PIN -> HOME
 * HOME menu: Receive (address) / Lock. Signing arrives later via MetaMask APDUs
 * (get-pubkey / sign-tx), which will drive the review screens.
 *
 * The seed is stored in flash (storage.c) and derived into RAM only while
 * unlocked; lock_wallet() wipes the cached key material.
 */

#include "stm32f4xx_hal.h"
#include "ssd1306_min.h"
#include "gpio_map.h"
#include "buttons.h"
#include "screens.h"
#include "pin.h"
#include "storage.h"
#include "atecc.h"
#include "wallet.h"
#include "usb_setup.h"
#include "hid_app.h"
#include "wallet_state.h"
#include "wallet_handlers.h"
#include "eth_tx.h"
#include "tusb.h"
#include <string.h>
#include <stdio.h>

#define ATECC_ADDR7 0x60

I2C_HandleTypeDef hi2c1;

void SysTick_Handler(void) { HAL_IncTick(); }

void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
    RCC_OscInitStruct.HSEState = RCC_HSE_ON;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
    RCC_OscInitStruct.PLL.PLLM = 25;
    RCC_OscInitStruct.PLL.PLLN = 336;          /* VCO = 25/25 * 336 = 336 MHz */
    RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4; /* SYSCLK = 84 MHz */
    RCC_OscInitStruct.PLL.PLLQ = 7;            /* USB OTG FS = 336/7 = 48 MHz */
    HAL_RCC_OscConfig(&RCC_OscInitStruct);
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                                |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
    HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2);
}

static void MX_GPIO_Init(void) {
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
    GPIO_InitTypeDef g = {0};
    g.Mode = GPIO_MODE_INPUT;
    g.Pull = GPIO_PULLUP;
    g.Speed = GPIO_SPEED_FREQ_LOW;
    for (int i = 0; i < BTN_COUNT; i++) {
        g.Pin = BTN_MAP[i].pin;
        HAL_GPIO_Init(BTN_MAP[i].port, &g);
    }
    g.Pin = GPIO_PIN_13;
    g.Mode = GPIO_MODE_OUTPUT_PP;
    g.Pull = GPIO_NOPULL;
    g.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOC, &g);
    HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13, GPIO_PIN_SET);
}

void MX_I2C1_Init(void) {
    __HAL_RCC_I2C1_CLK_ENABLE();
    GPIO_InitTypeDef g = {0};
    g.Pin = GPIO_PIN_6 | GPIO_PIN_7;
    g.Mode = GPIO_MODE_AF_OD;
    g.Pull = GPIO_PULLUP;
    g.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    g.Alternate = GPIO_AF4_I2C1;
    HAL_GPIO_Init(GPIOB, &g);
    hi2c1.Instance = I2C1;
    hi2c1.Init.ClockSpeed = 100000;
    hi2c1.Init.DutyCycle = I2C_DUTYCYCLE_2;
    hi2c1.Init.OwnAddress1 = 0;
    hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
    hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
    HAL_I2C_Init(&hi2c1);
}

/* ---- app state -------------------------------------------------- */

typedef enum {
    ST_SPLASH,
    ST_PIN,
    ST_PIN_FAIL,
    ST_PIN_WIPED,
    ST_BACKUP,
    ST_READY,
    ST_HOME,
    ST_RECEIVE,
    ST_CONFIRM_ADDR,   /* GET_PUBKEY confirm-on-device */
    ST_REVIEW,         /* SIGN_TX review + hold-to-sign */
    ST_ERROR,
} state_t;

static state_t state;
static int     page;              /* backup page (0-5) / home menu cursor (0-1) */

static char     mnemonic[256];
static char    *words[24];
static int      n_words;

/* Cached wallet key material — valid only while unlocked. */
static uint8_t  wseed[64];
static uint8_t  wpriv[32];
static uint8_t  wpub65[65];
static uint8_t  waddr[20];

/* PIN flow */
typedef enum { PIN_MODE_ENTER, PIN_MODE_SET1, PIN_MODE_SET2 } pin_mode_t;
static pin_mode_t pin_mode;
static char        first_pin[PIN_MAX_LEN + 1];

/* ---- helpers ---------------------------------------------------- */

static void hexstr(const uint8_t *d, int n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[2 * i]     = h[d[i] >> 4];
        out[2 * i + 1] = h[d[i] & 0xF];
    }
    out[2 * n] = 0;
}

/* Short address form: 0x1234...cdef. */
static void short_addr(char *out) {
    char hex[41];
    hexstr(waddr, 20, hex);
    out[0] = '0'; out[1] = 'x';
    memcpy(out + 2, hex, 4);
    out[6] = '.'; out[7] = '.'; out[8] = '.';
    memcpy(out + 9, hex + 36, 4);
    out[13] = 0;
}

/* Short form of an arbitrary 20-byte address (for the tx review screen). */
static void short_addr_of(const uint8_t *a, char *out) {
    char hex[41];
    hexstr(a, 20, hex);
    out[0] = '0'; out[1] = 'x';
    memcpy(out + 2, hex, 4);
    out[6] = '.'; out[7] = '.'; out[8] = '.';
    memcpy(out + 9, hex + 36, 4);
    out[13] = 0;
}

/* Big-endian bytes -> minimal decimal string ("0" for zero). */
static void be_dec(const uint8_t *be, uint32_t len, char *out) {
    const uint8_t *p = be;
    uint32_t n = len;
    while (n > 1 && *p == 0) { p++; n--; }
    if (n == 1 && *p == 0) { out[0] = '0'; out[1] = 0; return; }
    uint8_t tmp[32];
    memcpy(tmp, p, n);
    char rev[80];
    int k = 0;
    while (n > 0) {
        uint32_t rem = 0, nz = 0;
        for (uint32_t i = 0; i < n; i++) {
            uint32_t cur = (rem << 8) | tmp[i];
            uint32_t q = cur / 10;
            rem = cur % 10;
            tmp[i] = (uint8_t)q;
            if (q) nz = i + 1;
        }
        rev[k++] = (char)('0' + rem);
        n = nz;
    }
    for (int i = 0; i < k; i++) out[i] = rev[k - 1 - i];
    out[k] = 0;
}

/* uint64 -> decimal string (avoids %llu, unsupported by nano printf). */
static void u64_dec(uint64_t v, char *out) {
    if (v == 0) { out[0] = '0'; out[1] = 0; return; }
    char rev[24];
    int k = 0;
    while (v) { rev[k++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = 0; i < k; i++) out[i] = rev[k - 1 - i];
    out[k] = 0;
}

/* wei -> "X.YYY ETH" (or "0 ETH"), fraction trimmed to <= 6 digits. */
static void fmt_eth(const eth_field_t *value, char *out) {
    int zero = 1;
    for (uint32_t i = 0; i < value->len; i++)
        if (value->ptr[i]) { zero = 0; break; }
    if (zero) { strcpy(out, "0 ETH"); return; }

    char dec[80];
    be_dec(value->ptr, value->len, dec);
    int L = (int)strlen(dec);
    char ip[64], frac[24];
    if (L <= 18) {
        strcpy(ip, "0");
        int pad = 18 - L, fp = 0;
        while (pad--) frac[fp++] = '0';
        for (int i = 0; i < L; i++) frac[fp++] = dec[i];
        frac[fp] = 0;
    } else {
        int il = L - 18;
        memcpy(ip, dec, il); ip[il] = 0;
        int fp = 0;
        for (int i = il; i < L; i++) frac[fp++] = dec[i];
        frac[fp] = 0;
    }
    int fl = (int)strlen(frac);
    while (fl > 0 && frac[fl - 1] == '0') fl--;
    if (fl > 6) fl = 6;
    if (fl == 0) snprintf(out, 24, "%s ETH", ip);
    else { frac[fl] = 0; snprintf(out, 24, "%s.%s ETH", ip, frac); }
}

/* Split the space-separated mnemonic in place into `words`. MUST be called
 * only AFTER wallet_seed_from_mnemonic() (which needs the intact string). */
static int split_words(char *mn) {
    int n = 0;
    char *p = mn;
    while (*p && n < 24) {
        words[n++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = 0;
    }
    return n;
}

static void enable_cycle_counter(void) {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

/* Mix in MCU entropy (cycle counter + tick, LCG churn) on top of the ATECC
 * TRNG. Demo-grade until the ATECC config is locked; see ATECC-NOTES.md. */
static void mix_entropy(uint8_t *buf, int len) {
    uint32_t v = DWT->CYCCNT ^ (HAL_GetTick() << 16);
    for (int i = 0; i < len; i++) {
        v = v * 1664525u + 1013904223u;
        v ^= DWT->CYCCNT ^ HAL_GetTick();
        buf[i] ^= (uint8_t)(v >> 24);
    }
}

/* 16 random bytes for the PIN verifier salt. */
static int get_salt(uint8_t salt[STORAGE_SALT_LEN]) {
    uint8_t rnd[32];
    if (atecc_random(&hi2c1, ATECC_ADDR7, rnd) != 0) return -1;
    memcpy(salt, rnd, STORAGE_SALT_LEN);
    mix_entropy(salt, STORAGE_SALT_LEN);
    memset(rnd, 0, sizeof rnd);
    return 0;
}

/* ---- wallet key lifecycle --------------------------------------- */

/* Generate 32-byte entropy, store the seed, and derive the account keys. */
static int provision(void) {
    uint8_t entropy[STORAGE_ENTROPY_LEN];
    uint8_t rnd[32];

    if (atecc_random(&hi2c1, ATECC_ADDR7, rnd) != 0) return -1;
    memcpy(entropy, rnd, STORAGE_ENTROPY_LEN);
    mix_entropy(entropy, STORAGE_ENTROPY_LEN);

    if (storage_seed_set(entropy) != 0) return -1;   /* ~1s flash write */

    if (wallet_mnemonic_from_entropy(entropy, STORAGE_ENTROPY_LEN, mnemonic) != 0) return -1;
    wallet_seed_from_mnemonic(mnemonic, "", wseed);
    if (wallet_derive_eth(wseed, 0, wpriv, wpub65, waddr) != 0) return -1;
    wallet_state_set_seed(wseed);
    n_words = split_words(mnemonic);
    if (n_words != 24) return -1;

    memset(rnd, 0, sizeof rnd);
    memset(entropy, 0, sizeof entropy);
    return 0;
}

/* Derive the cached keys from the stored seed (called on unlock). */
static int unlock_wallet(void) {
    uint8_t entropy[STORAGE_ENTROPY_LEN];
    if (storage_seed_get(entropy) != 0) return -1;
    if (wallet_mnemonic_from_entropy(entropy, STORAGE_ENTROPY_LEN, mnemonic) != 0) return -1;
    wallet_seed_from_mnemonic(mnemonic, "", wseed);
    if (wallet_derive_eth(wseed, 0, wpriv, wpub65, waddr) != 0) return -1;
    wallet_state_set_seed(wseed);
    memset(entropy, 0, sizeof entropy);
    return 0;
}

static void lock_wallet(void) {
    memset(wseed, 0, sizeof wseed);
    memset(wpriv, 0, sizeof wpriv);
    memset(wpub65, 0, sizeof wpub65);
    memset(waddr, 0, sizeof waddr);
    wallet_state_clear();
}

/* ---- render ----------------------------------------------------- */

static void render_splash(void) {
    ui_clear();
    ui_text_center(6, "NOIR", 2);
    ui_text_center(28, "WALLET", 1);
    if (storage_seed_exists()) {
        ui_text_center(40, "LEFT to unlock", 1);
        ui_hint("UNLOCK", "");
    } else {
        ui_text_center(40, "LEFT to set up", 1);
        ui_hint("SET UP", "");
    }
    ui_render();
}

static void render_pin(void) {
    const char *t = (pin_mode == PIN_MODE_ENTER) ? "ENTER PIN"
                  : (pin_mode == PIN_MODE_SET1) ? "SET PIN"
                  : "CONFIRM PIN";
    pin_render(t);
}

static void render_pin_fail(void) {
    char msg[24];
    ui_clear();
    ui_title("WRONG PIN");
    snprintf(msg, sizeof msg, "%d/%d tries left",
             STORAGE_MAX_FAILS - storage_fail_count(), STORAGE_MAX_FAILS);
    ui_text_center(28, msg, 1);
    ui_hint("", "OK");
    ui_render();
}

static void render_pin_wiped(void) {
    ui_clear();
    ui_title("WIPED");
    ui_text_center(24, "too many tries", 1);
    ui_text_center(34, "device reset", 1);
    ui_hint("", "OK");
    ui_render();
}

static void render_generating(void) {
    ui_clear();
    ui_title("GENERATING");
    ui_text_center(24, "24-word seed", 1);
    ui_text_center(34, "storing...", 1);
    ui_render();
}

static void render_backup(void) {
    char t[20];
    snprintf(t, sizeof t, "WORDS %d-%d/24", page * 4 + 1, page * 4 + 4);
    ui_clear();
    ui_title(t);
    for (int i = 0; i < 4; i++) {
        int idx = page * 4 + i;
        char line[20];
        snprintf(line, sizeof line, "%2d. %s", idx + 1, words[idx]);
        ui_text(4, 14 + i * 10, line, 1);
    }
    ui_hint("UP DN", "OK DONE");
    ui_render();
}

static void render_ready(void) {
    char sa[14];
    short_addr(sa);
    ui_clear();
    ui_title("WALLET READY");
    ui_text_center(24, sa, 2);
    ui_hint("", "OK");
    ui_render();
}

static void render_home(void) {
    char sa[14];
    short_addr(sa);
    ui_clear();
    ui_title("NOIR");
    ui_text_center(14, sa, 1);
    ui_text(6, 30, (page == 0) ? "> Receive" : "  Receive", 1);
    ui_text(6, 42, (page == 1) ? "> Lock"    : "  Lock",    1);
    ui_hint("UP DN", "OK SEL");
    ui_render();
}

static void render_receive(void) {
    char hex[41];
    hexstr(waddr, 20, hex);
    char l1[22] = "0x";
    memcpy(l1 + 2, hex, 18); l1[20] = 0;
    char l2[21]; memcpy(l2, hex + 18, 20); l2[20] = 0;
    char l3[3];  memcpy(l3, hex + 38, 2);  l3[2] = 0;
    ui_clear();
    ui_title("RECEIVE");
    ui_text(4, 16, l1, 1);
    ui_text(4, 26, l2, 1);
    ui_text(4, 36, l3, 1);
    ui_hint("BACK", "");
    ui_render();
}

static void render_confirm_addr(void) {
    uint8_t addr[20];
    wh_pending_addr(addr);
    char hex[41];
    hexstr(addr, 20, hex);
    char l1[22] = "0x";
    memcpy(l1 + 2, hex, 18); l1[20] = 0;
    char l2[21]; memcpy(l2, hex + 18, 20); l2[20] = 0;
    char l3[3];  memcpy(l3, hex + 38, 2);  l3[2] = 0;
    ui_clear();
    ui_title("CONFIRM ADDR");
    ui_text(4, 16, l1, 1);
    ui_text(4, 26, l2, 1);
    ui_text(4, 36, l3, 1);
    ui_hint("REJECT", "OK");
    ui_render();
}

static void render_review(void) {
    const eth_tx_t *tx = wh_pending_tx();
    if (!tx) return;
    ui_clear();
    if (page == 0) {
        ui_title("REVIEW 1/2");
        char cid[24];
        if (tx->chain_id == 0) strcpy(cid, "none");
        else u64_dec(tx->chain_id, cid);
        char line[24];
        snprintf(line, sizeof line, "chain %s", cid);
        ui_text(4, 14, line, 1);
        ui_text(4, 24, (tx->type == ETH_TX_EIP1559) ? "type EIP-1559" : "type legacy", 1);
        if (tx->is_creation) {
            ui_text(4, 34, "to  (create)", 1);
        } else {
            char sa[14];
            short_addr_of(tx->to, sa);
            char tl[24];
            snprintf(tl, sizeof tl, "to  %s", sa);
            ui_text(4, 34, tl, 1);
        }
    } else {
        ui_title("VALUE 2/2");
        char ve[24];
        fmt_eth(&tx->value, ve);
        ui_text_center(26, ve, 2);
    }
    ui_hint("REJECT", "HOLD OK");
    ui_render();
}

static void render_error(void) {
    ui_clear();
    ui_title("ERROR");
    ui_text_center(24, "something failed", 1);
    ui_hint("", "OK RETRY");
    ui_render();
}

static void render(void) {
    switch (state) {
    case ST_SPLASH:    render_splash();    break;
    case ST_PIN:       render_pin();       break;
    case ST_PIN_FAIL:  render_pin_fail();  break;
    case ST_PIN_WIPED: render_pin_wiped(); break;
    case ST_BACKUP:    render_backup();    break;
    case ST_READY:     render_ready();     break;
    case ST_HOME:      render_home();      break;
    case ST_RECEIVE:   render_receive();   break;
    case ST_CONFIRM_ADDR: render_confirm_addr(); break;
    case ST_REVIEW:    render_review();    break;
    case ST_ERROR:     render_error();     break;
    }
}

/* ---- main ------------------------------------------------------- */

/* Boot progress marker: shows which init step was reached. If the device
 * hangs, this tells us where; a hard fault instead overwrites it with the
 * HardFault handler's PC dump. */
static void boot_mark(const char *s) {
    SSD1306_Clear();
    SSD1306_DrawString(2, 1, "BOOT", 1);
    SSD1306_DrawString(2, 14, s, 1);
    SSD1306_UpdateScreen(&hi2c1);
}

int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_I2C1_Init();
    SSD1306_Init(&hi2c1);
    boot_mark("1 oled");
    buttons_init();
    boot_mark("2 btn");

    enable_cycle_counter();
    atecc_selftest(&hi2c1, ATECC_ADDR7);   /* condition the TRNG (best effort) */
    boot_mark("3 atecc");
    usb_init();                            /* OTG FS + TinyUSB HID */
    boot_mark("4 usb");

    state = ST_SPLASH;
    page = 0;
    render();

    while (1) {
        tud_task();          /* TinyUSB device stack */
        hid_app_task();      /* pump queued APDU response frames */

        /* A deferred APDU approval (get-pubkey confirm / sign-tx review)
         * drives the on-device review UI. */
        if (wh_pending_kind() != WH_IDLE &&
            state != ST_REVIEW && state != ST_CONFIRM_ADDR) {
            state = (wh_pending_kind() == WH_REVIEW_TX) ? ST_REVIEW
                                                        : ST_CONFIRM_ADDR;
            page = 0;
            render();
        }

        btn_evt_t ev;
        if (buttons_poll(&ev)) {
            if (ev.ev == BTN_LONG_PRESS) {
                if (state == ST_REVIEW && ev.id == BTN_CENTER) {
                    hid_app_approve();       /* hold-to-sign */
                    state = ST_HOME;
                    page = 0;
                    render();
                }
                continue;
            }
            if (ev.ev != BTN_PRESS) continue;

            int changed = 0;
            switch (state) {
            case ST_SPLASH:
                if (ev.id == BTN_LEFT) {
                    pin_mode = storage_seed_exists() ? PIN_MODE_ENTER : PIN_MODE_SET1;
                    pin_reset();
                    state = ST_PIN;
                    changed = 1;
                }
                break;
            case ST_PIN:
                if (ev.id == BTN_RIGHT) {      /* cancel */
                    state = ST_SPLASH;
                    changed = 1;
                } else {
                    if (pin_event(&ev)) changed = 1;
                    if (pin_confirmed()) {
                        char digits[PIN_MAX_LEN + 1];
                        pin_digits(digits);
                        if (pin_mode == PIN_MODE_ENTER) {
                            int r = storage_check_pin(digits);
                            if (r == 1) {
                                if (unlock_wallet() == 0) {
                                    hid_app_set_locked(false);
                                    page = 0;
                                    state = ST_HOME;
                                } else {
                                    state = ST_ERROR;
                                }
                            } else if (r == -1) {
                                state = ST_PIN_WIPED;
                            } else {
                                state = ST_PIN_FAIL;
                            }
                        } else if (pin_mode == PIN_MODE_SET1) {
                            strcpy(first_pin, digits);
                            pin_mode = PIN_MODE_SET2;
                            pin_reset();
                        } else {  /* SET2: confirm */
                            if (strcmp(digits, first_pin) == 0) {
                                uint8_t salt[STORAGE_SALT_LEN];
                                if (get_salt(salt) == 0 &&
                                    storage_set_pin(salt, digits) == 0) {
                                    render_generating();
                                    if (provision() != 0) state = ST_ERROR;
                                    else {
                                        hid_app_set_locked(false);
                                        page = 0;
                                        state = ST_BACKUP;
                                    }
                                } else {
                                    state = ST_ERROR;
                                }
                            } else {
                                pin_mode = PIN_MODE_SET1;   /* restart set */
                                pin_reset();
                                state = ST_PIN_FAIL;
                            }
                        }
                        changed = 1;
                    }
                }
                break;
            case ST_PIN_FAIL:
                pin_reset();
                state = ST_PIN;
                changed = 1;
                break;
            case ST_PIN_WIPED:
                state = ST_SPLASH;
                changed = 1;
                break;
            case ST_BACKUP:
                if (ev.id == BTN_UP && page > 0)       { page--; changed = 1; }
                else if (ev.id == BTN_DOWN && page < 5) { page++; changed = 1; }
                else if (ev.id == BTN_CENTER) { state = ST_READY; changed = 1; }
                break;
            case ST_READY:
                if (ev.id == BTN_CENTER) { page = 0; state = ST_HOME; changed = 1; }
                break;
            case ST_HOME:
                if (ev.id == BTN_UP && page > 0)       { page--; changed = 1; }
                else if (ev.id == BTN_DOWN && page < 1) { page++; changed = 1; }
                else if (ev.id == BTN_CENTER) {
                    if (page == 0) {
                        state = ST_RECEIVE;
                    } else {                /* Lock */
                        lock_wallet();
                        hid_app_set_locked(true);
                        state = ST_SPLASH;
                    }
                    changed = 1;
                }
                break;
            case ST_RECEIVE:
                if (ev.id == BTN_LEFT) { state = ST_HOME; changed = 1; }
                break;
            case ST_CONFIRM_ADDR:
                if (ev.id == BTN_CENTER) {
                    hid_app_approve();
                    state = ST_HOME; page = 0; changed = 1;
                } else if (ev.id == BTN_LEFT) {
                    hid_app_reject();
                    state = ST_HOME; page = 0; changed = 1;
                }
                break;
            case ST_REVIEW:
                if (ev.id == BTN_UP && page > 0)       { page--; changed = 1; }
                else if (ev.id == BTN_DOWN && page < 1) { page++; changed = 1; }
                else if (ev.id == BTN_LEFT) {
                    hid_app_reject();
                    state = ST_HOME; page = 0; changed = 1;
                }
                break;
            case ST_ERROR:
                if (ev.id == BTN_CENTER) { state = ST_SPLASH; changed = 1; }
                break;
            }
            if (changed) render();
        }
        HAL_Delay(10);
    }
}
