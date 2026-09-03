/* NOIR wallet — Ethereum transaction parsing + sighash (M7e). See eth_tx.h. */

#include "eth_tx.h"
#include <string.h>      /* before sha3.h: provides size_t */
#include "sha3.h"        /* keccak_256 (trezor-crypto) */

/* ---- RLP --------------------------------------------------------- */

typedef struct {
    int            is_list;
    const uint8_t *ptr;   /* string: content; list: full encoding */
    uint32_t       len;
} rlp_item_t;

#define RLP_ERR (-1)

/* Decode the single RLP item at buf[0..avail). Returns bytes consumed (>=1),
 * or RLP_ERR on malformed input. */
static int rlp_decode(const uint8_t *buf, int avail, rlp_item_t *it) {
    if (avail < 1) return RLP_ERR;
    uint8_t b = buf[0];

    if (b < 0x80) {                       /* single byte 0x00..0x7f */
        it->is_list = 0; it->ptr = buf; it->len = 1; return 1;
    }
    if (b <= 0xb7) {                      /* short string 0..55 bytes */
        int l = b - 0x80;
        if (avail < 1 + l) return RLP_ERR;
        it->is_list = 0; it->ptr = buf + 1; it->len = (uint32_t)l; return 1 + l;
    }
    if (b <= 0xbf) {                      /* long string >55 bytes */
        int ll = b - 0xb7;
        if (avail < 1 + ll) return RLP_ERR;
        uint32_t l = 0;
        for (int i = 0; i < ll; i++) l = (l << 8) | buf[1 + i];
        if (avail < 1 + ll + (int)l) return RLP_ERR;
        it->is_list = 0; it->ptr = buf + 1 + ll; it->len = l; return 1 + ll + (int)l;
    }
    if (b <= 0xf7) {                      /* short list 0..55 bytes payload */
        int l = b - 0xc0;
        if (avail < 1 + l) return RLP_ERR;
        it->is_list = 1; it->ptr = buf; it->len = (uint32_t)(1 + l); return 1 + l;
    }
    /* long list >55 bytes payload */
    int ll = b - 0xf7;
    if (avail < 1 + ll) return RLP_ERR;
    uint32_t l = 0;
    for (int i = 0; i < ll; i++) l = (l << 8) | buf[1 + i];
    if (avail < 1 + ll + (int)l) return RLP_ERR;
    it->is_list = 1; it->ptr = buf; it->len = (uint32_t)(1 + ll + (int)l); return 1 + ll + (int)l;
}

/* Length of a list's header (1 or 1+len_of_len). */
static int rlp_list_hdr(uint8_t b) {
    return (b <= 0xf7) ? 1 : 1 + (b - 0xf7);
}

/* ---- RLP encoders (canonical) ----------------------------------- */

/* Encode a byte string. Returns bytes written. */
static int rlp_put_str(uint8_t *out, const uint8_t *s, uint32_t len) {
    if (len == 1 && s[0] < 0x80) { out[0] = s[0]; return 1; }
    if (len <= 55) {
        out[0] = (uint8_t)(0x80 + len);
        if (len) memcpy(out + 1, s, len);
        return 1 + (int)len;
    }
    uint32_t t = len; int ll = 0;
    while (t) { ll++; t >>= 8; }
    out[0] = (uint8_t)(0xb7 + ll);
    for (int i = 0; i < ll; i++) out[1 + i] = (uint8_t)(len >> (8 * (ll - 1 - i)));
    memcpy(out + 1 + ll, s, len);
    return 1 + ll + (int)len;
}

/* Encode a minimal big-endian integer given as a (possibly zero-padded) byte
 * string. Leading zeros stripped; zero -> empty string (0x80). */
static int rlp_put_int(uint8_t *out, const uint8_t *be, uint32_t len) {
    const uint8_t *p = be;
    while (len > 0 && *p == 0) { p++; len--; }
    return rlp_put_str(out, p, len);
}

/* Encode a list header for a payload of `payload_len` bytes. */
static int rlp_put_list_hdr(uint8_t *out, int payload_len) {
    if (payload_len <= 55) { out[0] = (uint8_t)(0xc0 + payload_len); return 1; }
    uint32_t t = (uint32_t)payload_len; int ll = 0;
    while (t) { ll++; t >>= 8; }
    out[0] = (uint8_t)(0xf7 + ll);
    for (int i = 0; i < ll; i++) out[1 + i] = (uint8_t)(payload_len >> (8 * (ll - 1 - i)));
    return 1 + ll;
}

/* uint64 -> minimal big-endian bytes. Returns length (0 for value 0). */
static int u64_to_be(uint64_t v, uint8_t out[8]) {
    if (v == 0) return 0;
    uint8_t tmp[8]; int n = 0;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

/* Big-endian field -> uint64. Returns 0 on success, -1 if > 8 bytes. */
static int field_to_u64(const eth_field_t *f, uint64_t *out) {
    if (f->len > 8) return -1;
    uint64_t v = 0;
    for (uint32_t i = 0; i < f->len; i++) v = (v << 8) | f->ptr[i];
    *out = v;
    return 0;
}

/* ---- Parsing ----------------------------------------------------- */

#define MAX_TX_FIELDS 12

int eth_tx_parse(const uint8_t *raw, uint32_t len, eth_tx_t *tx) {
    if (len == 0 || len > ETH_TX_MAX_LEN) return -1;
    memset(tx, 0, sizeof *tx);

    const uint8_t *body = raw;
    uint32_t body_len = len;
    uint8_t type;

    if (raw[0] == 0x02) {
        type = ETH_TX_EIP1559;
        body++; body_len--;
    } else if (raw[0] == 0x01) {
        return -1;   /* EIP-2930 access-list tx, unsupported in v0 */
    } else if (raw[0] >= 0xc0) {
        type = ETH_TX_LEGACY;
    } else {
        return -1;   /* not a list / not a supported envelope */
    }

    /* Outer list must consume the whole buffer (no trailing bytes). */
    rlp_item_t outer;
    int consumed = rlp_decode(body, (int)body_len, &outer);
    if (consumed < 0 || !outer.is_list || consumed != (int)body_len) return -1;

    /* Walk the outer list's items. */
    const uint8_t *pc = outer.ptr + rlp_list_hdr(outer.ptr[0]);
    int remaining = (int)outer.len - rlp_list_hdr(outer.ptr[0]);

    rlp_item_t f[MAX_TX_FIELDS];
    int n = 0;
    while (remaining > 0) {
        if (n >= MAX_TX_FIELDS) return -1;
        int c = rlp_decode(pc, remaining, &f[n]);
        if (c < 0) return -1;
        pc += c;
        remaining -= c;
        n++;
    }

    int expect = (type == ETH_TX_LEGACY) ? 9 : 12;
    if (n != expect) return -1;

    tx->type = type;

    if (type == ETH_TX_LEGACY) {
        tx->nonce     = (eth_field_t){ f[0].ptr, f[0].len };
        tx->gas_price = (eth_field_t){ f[1].ptr, f[1].len };
        tx->gas_limit = (eth_field_t){ f[2].ptr, f[2].len };
        tx->to_field  = (eth_field_t){ f[3].ptr, f[3].len };
        tx->value     = (eth_field_t){ f[4].ptr, f[4].len };
        tx->data      = (eth_field_t){ f[5].ptr, f[5].len };
        tx->v         = (eth_field_t){ f[6].ptr, f[6].len };
        tx->r         = (eth_field_t){ f[7].ptr, f[7].len };
        tx->s         = (eth_field_t){ f[8].ptr, f[8].len };

        /* chainId from v: empty/27/28 = pre-155; >=35 = EIP-155. */
        uint64_t v = 0;
        if (f[6].len > 0) {
            if (field_to_u64(&tx->v, &v) != 0) return -1;
        }
        if (v == 0 || v == 27 || v == 28) {
            tx->chain_id = 0;
        } else if (v >= 35) {
            tx->chain_id = (v - 35) / 2;
        } else {
            return -1;   /* invalid v for legacy */
        }
    } else { /* EIP-1559 */
        if (field_to_u64(&(eth_field_t){ f[0].ptr, f[0].len }, &tx->chain_id) != 0)
            return -1;
        tx->nonce            = (eth_field_t){ f[1].ptr, f[1].len };
        tx->max_priority_fee = (eth_field_t){ f[2].ptr, f[2].len };
        tx->max_fee          = (eth_field_t){ f[3].ptr, f[3].len };
        tx->gas_limit        = (eth_field_t){ f[4].ptr, f[4].len };
        tx->to_field         = (eth_field_t){ f[5].ptr, f[5].len };
        tx->value            = (eth_field_t){ f[6].ptr, f[6].len };
        tx->data             = (eth_field_t){ f[7].ptr, f[7].len };
        if (!f[8].is_list) return -1;            /* accessList must be a list */
        tx->access_list      = (eth_field_t){ f[8].ptr, f[8].len };
        tx->v                = (eth_field_t){ f[9].ptr, f[9].len };
        tx->r                = (eth_field_t){ f[10].ptr, f[10].len };
        tx->s                = (eth_field_t){ f[11].ptr, f[11].len };
    }

    /* Normalize `to` (empty = creation; else exactly 20 bytes). */
    if (tx->to_field.len == 0) {
        tx->is_creation = 1;
    } else {
        if (tx->to_field.len != 20) return -1;
        memcpy(tx->to, tx->to_field.ptr, 20);
    }

    return 0;
}

/* ---- Sighash ----------------------------------------------------- */

static uint8_t sighash_buf[ETH_TX_MAX_LEN + 16];
static uint8_t items[ETH_TX_MAX_LEN + 16];   /* static: too big for MCU stack */

int eth_tx_sighash(const eth_tx_t *tx, uint8_t sighash[ETH_TX_SIGHASH_LEN]) {
    int items_len = 0;

    if (tx->type == ETH_TX_LEGACY) {
        items_len += rlp_put_int(items + items_len, tx->nonce.ptr, tx->nonce.len);
        items_len += rlp_put_int(items + items_len, tx->gas_price.ptr, tx->gas_price.len);
        items_len += rlp_put_int(items + items_len, tx->gas_limit.ptr, tx->gas_limit.len);
        items_len += rlp_put_str(items + items_len, tx->to_field.ptr, tx->to_field.len);
        items_len += rlp_put_int(items + items_len, tx->value.ptr, tx->value.len);
        items_len += rlp_put_str(items + items_len, tx->data.ptr, tx->data.len);
        if (tx->chain_id != 0) {   /* EIP-155: append chainId, 0, 0 */
            uint8_t cid[8];
            int cl = u64_to_be(tx->chain_id, cid);
            items_len += rlp_put_int(items + items_len, cid, (uint32_t)cl);
            items_len += rlp_put_str(items + items_len, NULL, 0);
            items_len += rlp_put_str(items + items_len, NULL, 0);
        }
        int hdr = rlp_put_list_hdr(sighash_buf, items_len);
        memcpy(sighash_buf + hdr, items, (size_t)items_len);
        keccak_256(sighash_buf, (size_t)(hdr + items_len), sighash);
        return 0;
    }

    if (tx->type == ETH_TX_EIP1559) {
        uint8_t cid[8];
        int cl = u64_to_be(tx->chain_id, cid);
        items_len += rlp_put_int(items + items_len, cid, (uint32_t)cl);
        items_len += rlp_put_int(items + items_len, tx->nonce.ptr, tx->nonce.len);
        items_len += rlp_put_int(items + items_len, tx->max_priority_fee.ptr, tx->max_priority_fee.len);
        items_len += rlp_put_int(items + items_len, tx->max_fee.ptr, tx->max_fee.len);
        items_len += rlp_put_int(items + items_len, tx->gas_limit.ptr, tx->gas_limit.len);
        items_len += rlp_put_str(items + items_len, tx->to_field.ptr, tx->to_field.len);
        items_len += rlp_put_int(items + items_len, tx->value.ptr, tx->value.len);
        items_len += rlp_put_str(items + items_len, tx->data.ptr, tx->data.len);
        /* accessList re-embedded verbatim (already a canonical RLP list) */
        memcpy(items + items_len, tx->access_list.ptr, tx->access_list.len);
        items_len += (int)tx->access_list.len;

        int hdr = rlp_put_list_hdr(sighash_buf + 1, items_len);
        sighash_buf[0] = 0x02;
        memcpy(sighash_buf + 1 + hdr, items, (size_t)items_len);
        keccak_256(sighash_buf, (size_t)(1 + hdr + items_len), sighash);
        return 0;
    }

    return -1;
}
