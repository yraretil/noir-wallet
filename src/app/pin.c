/* NOIR wallet — PIN entry wheel (P3). See pin.h. */

#include "pin.h"
#include "gpio_map.h"   /* btn_id_t (BTN_UP/BTN_DOWN/...) */
#include "screens.h"

#define WHEEL_COUNT 12   /* 0..9, backspace (10), confirm (11) */

static int digits[PIN_MAX_LEN];
static int len;
static int pos;          /* wheel position (0..9, 10=backspace, 11=confirm) */
static int confirmed;

void pin_reset(void) {
    len = 0;
    pos = 0;
    confirmed = 0;
}

static const char *wheel_symbol(int p, char *buf) {
    if (p <= 9) { buf[0] = (char)('0' + p); buf[1] = 0; return buf; }
    if (p == 10) return "<";     /* backspace */
    return "OK";                 /* confirm */
}

int pin_event(btn_evt_t *e) {
    if (e->ev != BTN_PRESS) return 0;

    switch (e->id) {
    case BTN_UP:
        pos = (pos + WHEEL_COUNT - 1) % WHEEL_COUNT;
        return 1;
    case BTN_DOWN:
        pos = (pos + 1) % WHEEL_COUNT;
        return 1;
    case BTN_LEFT:                    /* backspace shortcut */
        if (len > 0) len--;
        return 1;
    case BTN_CENTER:
        if (pos <= 9) {
            if (len < PIN_MAX_LEN) digits[len++] = pos;
        } else if (pos == 10) {       /* wheel backspace */
            if (len > 0) len--;
        } else {                      /* wheel confirm */
            if (len >= PIN_MIN_LEN) confirmed = 1;
        }
        return 1;
    default:
        return 0;                     /* RIGHT handled by the caller (cancel) */
    }
}

int pin_confirmed(void) { return confirmed; }
int pin_len(void)        { return len; }

void pin_digits(char *out) {
    for (int i = 0; i < len; i++) out[i] = (char)('0' + digits[i]);
    out[len] = 0;
}

void pin_render(const char *title) {
    char sym[3];
    char dots[PIN_MAX_LEN + 1];

    ui_clear();
    ui_title(title);

    /* Big current wheel symbol (scale 3 = ~24px tall). */
    ui_text_center(17, wheel_symbol(pos, sym), 3);

    /* Progress: '*' entered, '_' remaining. */
    for (int i = 0; i < PIN_MAX_LEN; i++) dots[i] = (i < len) ? '*' : '_';
    dots[PIN_MAX_LEN] = 0;
    ui_text_center(45, dots, 1);

    ui_hint("UP DN", "SEL");
    ui_render();
}
