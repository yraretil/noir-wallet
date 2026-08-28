/* NOIR wallet — ATECC diagnostic v3. Root-cause the serial=zeros and the
 * deterministic TRNG. Screens (OK next, LEFT prev):
 *   0 BUS SCAN, 1 WAKE TOKEN, 2 REVISION, 3 SERIAL, 4 RANDOM A/B, 5 CONFIG.
 * Each shows a raw return code + hex bytes. */

#include "stm32f4xx_hal.h"
#include "ssd1306_min.h"
#include "gpio_map.h"
#include "buttons.h"
#include "screens.h"
#include "atecc.h"
#include <string.h>
#include <stdio.h>

#define ADDR 0x60

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
    RCC_OscInitStruct.PLL.PLLN = 168;
    RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
    RCC_OscInitStruct.PLL.PLLQ = 4;
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

static char hexdig(uint8_t n) { return "0123456789abcdef"[n & 0xF]; }

/* ---- results (declared before the probe functions) ---- */
static uint8_t  scanbuf[8]; static int nscan;
static uint8_t  wk[4];      static int wk_ret;
static uint8_t  rev[4];     static int rev_ret;
static uint8_t  ser[9];     static int ser_ret;
static uint8_t  rnda[32], rndb[32]; static int rnda_ret, rndb_ret;
static uint8_t  cfg[32];    static int cfg_ret;

static int scan(uint8_t *found, int max) {
    int n = 0;
    for (int a = 0x02; a < 0x7E && n < max; a++) {
        if (HAL_I2C_IsDeviceReady(&hi2c1, (uint16_t)(a << 1), 1, 50) == HAL_OK)
            found[n++] = (uint8_t)a;
    }
    return n;
}

static int raw_wake(uint8_t out[4]) {
    uint16_t dev = (uint16_t)(ADDR << 1);
    uint8_t zero = 0x00;
    atecc_wake(&hi2c1);
    if (HAL_I2C_Master_Transmit(&hi2c1, dev, &zero, 1, 50) != HAL_OK) return -1;
    if (HAL_I2C_Master_Receive(&hi2c1, dev, out, 4, 50) != HAL_OK) return -2;
    return 0;
}

/* Raw Read command (0x02): config zone, block 0, 32 bytes. */
static int raw_read_config(uint8_t out[32]) {
    uint8_t cmd[7];
    cmd[0] = 7;
    cmd[1] = 0x02;   /* Read */
    cmd[2] = 0x80;   /* zone=config(0) | 32-byte read flag(0x80) */
    cmd[3] = 0x00;   /* block lo */
    cmd[4] = 0x00;   /* block hi */
    uint16_t crc = atecc_crc16(0, cmd, 5);
    cmd[5] = (uint8_t)(crc & 0xFF);
    cmd[6] = (uint8_t)(crc >> 8);
    uint8_t tx[8] = {0x03, cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5], cmd[6]};
    uint16_t dev = (uint16_t)(ADDR << 1);
    atecc_wake(&hi2c1);
    if (HAL_I2C_Master_Transmit(&hi2c1, dev, tx, 8, 100) != HAL_OK) return -1;
    HAL_Delay(2);
    uint8_t count, buf[40];
    if (HAL_I2C_Master_Receive(&hi2c1, dev, &count, 1, 100) != HAL_OK) return -2;
    if (HAL_I2C_Master_Receive(&hi2c1, dev, buf, count - 1, 100) != HAL_OK) return -3;
    uint8_t verify[40];
    verify[0] = count;
    memcpy(&verify[1], buf, (uint32_t)(count - 3));
    uint16_t rxcrc = (uint16_t)buf[count - 3] | ((uint16_t)buf[count - 2] << 8);
    if (atecc_crc16(0, verify, (uint32_t)1 + (count - 3)) != rxcrc) return -4;
    int n = count - 3;
    if (n > 32) n = 32;
    memcpy(out, buf, n);
    return 0;
}

static int screen = 0;
#define N_SCREEN 6

static void hex_line(int y, const uint8_t *d, int n, int spaced) {
    char line[64];
    int p = 0;
    for (int i = 0; i < n && p < 60; i++) {
        line[p++] = hexdig(d[i] >> 4);
        line[p++] = hexdig(d[i] & 0xF);
        if (spaced) line[p++] = ' ';
    }
    line[p] = 0;
    ui_text(2, y, line, 1);
}

static void show_ret(int y, int ret) {
    char s[20];
    snprintf(s, sizeof s, "ret=%d", ret);
    ui_text(2, y, s, 1);
}

static void render_screen(void) {
    char s[40];
    ui_clear();
    switch (screen) {
    case 0:
        ui_title("BUS SCAN");
        if (nscan == 0) ui_text(2, 16, "(none)", 1);
        else hex_line(16, scanbuf, nscan, 1);
        break;
    case 1:
        ui_title("WAKE TOKEN");
        show_ret(14, wk_ret);
        hex_line(26, wk, 4, 0);
        break;
    case 2:
        ui_title("REVISION (want 00006003)");
        show_ret(14, rev_ret);
        hex_line(26, rev, 4, 0);
        break;
    case 3:
        ui_title("SERIAL");
        show_ret(14, ser_ret);
        if (ser_ret == 0) hex_line(26, ser, 9, 0);
        else ui_text(2, 26, "(failed)", 1);
        break;
    case 4:
        ui_title("RANDOM A / B");
        snprintf(s, sizeof s, "A=%d B=%d", rnda_ret, rndb_ret);
        ui_text(2, 13, s, 1);
        hex_line(22, rnda, 5, 0);
        hex_line(32, rndb, 5, 0);
        ui_text(2, 43, (memcmp(rnda, rndb, 32) == 0) ? "SAME" : "DIFF", 1);
        break;
    case 5:
        ui_title("CONFIG[0:15]");
        show_ret(14, cfg_ret);
        if (cfg_ret == 0) { hex_line(24, cfg, 8, 0); hex_line(34, cfg + 8, 8, 0); }
        else ui_text(2, 26, "(failed)", 1);
        break;
    }
    ui_hint("OK NEXT", "L PREV");
    ui_render();
}

int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_I2C1_Init();
    SSD1306_Init(&hi2c1);
    buttons_init();

    nscan   = scan(scanbuf, 8);
    wk_ret  = raw_wake(wk);
    rev_ret = atecc_read_revision(&hi2c1, ADDR, rev);
    ser_ret = atecc_read_serial(&hi2c1, ADDR, ser);
    rnda_ret = atecc_random(&hi2c1, ADDR, rnda);
    rndb_ret = atecc_random(&hi2c1, ADDR, rndb);
    cfg_ret = raw_read_config(cfg);

    render_screen();

    while (1) {
        btn_evt_t ev;
        if (buttons_poll(&ev) && ev.ev == BTN_PRESS) {
            if (ev.id == BTN_CENTER && screen < N_SCREEN - 1) { screen++; render_screen(); }
            else if (ev.id == BTN_LEFT && screen > 0)         { screen--; render_screen(); }
        }
        HAL_Delay(10);
    }
}
