/* NOIR wallet — USB OTG FS bring-up for STM32F401 (DWC2 core).
 *
 * The 48 MHz USB clock comes from PLLQ=7 (VCO 336 MHz / 7) set in
 * SystemClock_Config(). This file only enables the peripheral clock, muxes
 * PA11 (DM) / PA12 (DP) to AF10, and starts TinyUSB. All F401-specific USB
 * code lives here so a board swap touches only this file.
 */

#include "stm32f4xx_hal.h"
#include "tusb.h"
#include "usb_setup.h"
#include "hid_app.h"

/* Route the OTG FS interrupt to TinyUSB's DWC2 handler (rhport 0 = OTG_FS).
 * Also count interrupts so the splash can show whether the host is talking. */
volatile uint32_t usb_irq_count = 0;

void OTG_FS_IRQHandler(void) {
    usb_irq_count++;
    tud_int_handler(0);
}

void usb_init(void) {
    GPIO_InitTypeDef g = {0};

    __HAL_RCC_GPIOA_CLK_ENABLE();

    /* PA11 = USB_DM, PA12 = USB_DP */
    g.Pin       = GPIO_PIN_11 | GPIO_PIN_12;
    g.Mode      = GPIO_MODE_AF_PP;
    g.Pull      = GPIO_NOPULL;
    g.Speed     = GPIO_SPEED_FREQ_HIGH;
    g.Alternate = GPIO_AF10_OTG_FS;
    HAL_GPIO_Init(GPIOA, &g);

    __HAL_RCC_USB_OTG_FS_CLK_ENABLE();

    tusb_init();

    /* Two STM32F4 bring-up fixes TinyUSB 0.17 doesn't do for the FS PHY:
     * 1. PWRDWN (GCCFG bit 16) — "Activate the USB Transceiver". The HAL's
     *    USB_CoreInit sets this AFTER the core soft reset; TinyUSB sets it
     *    BEFORE (in dwc2_phy_init) so reset_core() wipes it and the FS
     *    transceiver stays off -> D+ never pulls up (observed as pw0/irq0).
     * 2. NOVBUSSENS (bit 21) — the BlackPill doesn't route VBUS to PA9, so
     *    override VBUS sensing (device assumes VBUS always present). */
    USB_OTG_FS->GCCFG |= USB_OTG_GCCFG_PWRDWN | USB_OTG_GCCFG_NOVBUSSENS;

    /* Clear ALL PHY power/clock gating (matches the HAL's `PCGCCTL = 0` in
     * USB_DevInit). TinyUSB only clears STOPCLK/GATECLK after the core reset;
     * PHYSUSP (bit 4) survives and keeps the PHY suspended so D+ never drives
     * high — observed as all-connect-bits-ok but zero interrupts. */
    *(volatile uint32_t *)(USB_OTG_FS_PERIPH_BASE + USB_OTG_PCGCCTL_BASE) = 0;

    /* Register APDU handlers and boot LOCKED. */
    hid_app_init();
}
