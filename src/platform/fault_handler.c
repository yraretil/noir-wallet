/* NOIR wallet — trezor-crypto fault handler.
 *
 * consteq() (constant-time compare) calls tc_fault_handler() if its loop
 * completion check fails — a sign of fault injection / memory corruption. A
 * wallet must not continue after its constant-time guarantees are violated:
 * halt the device.
 */

#include "fault_handler.h"
#include "stm32f4xx_hal.h"

void tc_fault_handler(const char *msg) {
    (void)msg;
    __disable_irq();
    while (1) { }
}
