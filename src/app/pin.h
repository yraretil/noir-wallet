/* NOIR wallet — PIN entry wheel (P3).
 *
 * A 12-position wheel: digits 0-9, then backspace ("<"), then confirm ("OK").
 * UP/DOWN rotate, CENTER selects, LEFT is a backspace shortcut, RIGHT cancels
 * (handled by the caller's state machine). 4-8 digits, confirmed on "OK".
 *
 * Logic here is pure (no display) so it's unit-testable; pin_render() draws
 * the wheel using the ui_* helpers.
 */

#ifndef PIN_H
#define PIN_H

#include "buttons.h"

#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 8

void pin_reset(void);

/* Feed a button event. Returns 1 if the display should redraw. */
int pin_event(btn_evt_t *e);

/* Draw the wheel + progress dots (title set by the caller's mode). */
void pin_render(const char *title);

/* Result accessors. */
int  pin_confirmed(void);     /* 1 once a valid-length PIN was confirmed */
int  pin_len(void);           /* digits entered so far */
void pin_digits(char *out);   /* digit string, out >= PIN_MAX_LEN+1 */

#endif /* PIN_H */
