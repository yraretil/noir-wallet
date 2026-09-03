/* NOIR wallet — HardFault diagnostics.
 *
 * Overrides the weak HardFault_Handler from the startup file (which is just an
 * infinite loop) so a crash reports WHERE it happened instead of leaving a
 * jumbled screen. Displays the faulting PC, the stacked LR, and CFSR on the
 * OLED and blinks the LED. hardfault_dump() never returns.
 *
 * Usage: flash, reproduce, read the hex off the screen, then resolve the PC
 * with `arm-none-eabi-addr2line -e .pio/build/blackpill_f401cc/firmware.elf <pc>`.
 */

#include "stm32f4xx_hal.h"
#include "ssd1306_min.h"
#include "gpio_map.h"

static void hex32(uint32_t v, char out[9]) {
    static const char h[] = "0123456789ABCDEF";
    for (int i = 0; i < 8; i++) out[i] = h[(v >> (28 - 4 * i)) & 0xF];
    out[8] = 0;
}

static void line(int y, const char *label, uint32_t v) {
    char hex[9];
    hex32(v, hex);
    char buf[32];
    int p = 0;
    for (const char *s = label; *s; s++) buf[p++] = *s;
    buf[p] = 0;
    SSD1306_DrawString(2, y, buf, 1);
    SSD1306_DrawString(2 + 6 * (int)p, y, hex, 1);
}

void hardfault_dump(uint32_t *sp) {
    uint32_t pc   = sp[6];       /* stacked PC where the fault occurred */
    uint32_t lr   = sp[5];       /* stacked LR */
    uint32_t cfsr = SCB->CFSR;
    uint32_t hfsr = SCB->HFSR;

    SSD1306_Clear();
    SSD1306_DrawString(2, 1, "HARD FAULT", 1);
    line(14, "pc:   ", pc);
    line(24, "lr:   ", lr);
    line(34, "cfsr: ", cfsr);
    line(44, "hfsr: ", hfsr);
    SSD1306_UpdateScreen(&hi2c1);

    for (;;) {
        HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_13);
        for (volatile uint32_t i = 0; i < 400000; i++) { }
    }
}

/* Determine which stack was active and pass its frame to the C dumper. */
__attribute__((naked)) void HardFault_Handler(void) {
    __asm volatile(
        "tst lr, #4\n\t"
        "ite eq\n\t"
        "mrseq r0, msp\n\t"
        "mrsne r0, psp\n\t"
        "b hardfault_dump\n\t"
    );
}
