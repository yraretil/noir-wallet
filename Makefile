CC      = gcc
CFLAGS  = -O2 -std=gnu99 -Wall -Wno-unused-function \
          -Ilib/trezor-crypto -Isrc/crypto -Isrc/protocol -Isrc/app \
          -DUSE_BIP32_25519_CURVES=0 -DUSE_NEM=0 -DUSE_CARDANO=0 \
          -DUSE_INSECURE_PRNG=1 \
          -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--gc-sections

TC = lib/trezor-crypto
# aes/ and ed25519-donna/ are NOT compiled: they're only used by NEM and
# 25519-curve code paths, both compiled out. Their headers are still needed
# (bip32.h includes them unconditionally), which is why the files exist.
TC_SRCS = $(TC)/bignum.c $(TC)/ecdsa.c $(TC)/curves.c $(TC)/secp256k1.c \
          $(TC)/nist256p1.c $(TC)/hmac.c $(TC)/bip32.c $(TC)/bip39.c \
          $(TC)/bip39_english.c $(TC)/pbkdf2.c $(TC)/base58.c $(TC)/sha2.c \
          $(TC)/sha3.c $(TC)/hasher.c $(TC)/memzero.c $(TC)/rfc6979.c \
          $(TC)/hmac_drbg.c \
          $(TC)/der.c $(TC)/consteq.c $(TC)/buffer.c $(TC)/rand.c $(TC)/rand_insecure.c

host_test: test/test_wallet.c src/crypto/wallet.c $(TC_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

frame_test: test/test_hid_frame.c src/protocol/hid_frame.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

apdu_test: test/test_apdu.c src/protocol/apdu.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

eth_tx_test: test/test_eth_tx.c src/protocol/eth_tx.c $(TC_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

storage_test: test/test_storage.c src/app/storage.c $(TC_SRCS)
	$(CC) $(CFLAGS) -DSTORAGE_TEST $^ -o $@ $(LDFLAGS)

wallet_handlers_test: test/test_wallet_handlers.c src/app/wallet_handlers.c src/crypto/wallet_state.c src/crypto/wallet.c src/protocol/eth_tx.c $(TC_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: host_test frame_test apdu_test eth_tx_test storage_test wallet_handlers_test
	./host_test
	./frame_test
	./apdu_test
	./eth_tx_test
	./storage_test
	./wallet_handlers_test

.PHONY: clean test
clean:
	rm -f host_test frame_test apdu_test eth_tx_test storage_test wallet_handlers_test
