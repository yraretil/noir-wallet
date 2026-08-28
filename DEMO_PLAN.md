# NOIR Wallet — Monad Demo Build Plan (v0, bare minimum)

Goal: plug device into a laptop, connect to MetaMask on Monad testnet, show the
address, send + receive native MON. Presented at the Monad hackathon as a
"we exist" demo.

Hardware: WeAct STM32F401CCU6 + ATECC608B + SSD1306 128x64 + 5 buttons.
Buttons: LEFT=PA7, RIGHT=PB0, UP=PA6, DOWN=PB10, CENTER=PB1 (active-low).
OLED + ATECC608B share I2C1 on PB6/PB7. ATECC = entropy source (TRNG) for demo.

## Steps (do one at a time, keep the user in the loop)
- [ ] 0. ATECC probe — verify secure element answers on the shared bus (wake + Info -> revision).
- [ ] 1. Platform: flash config storage (last sector: magic + CRC + passcode hash + seed entropy + provisioned flag) + reset (erase sector).
- [ ] 2. Buttons library: debounce + press/release/long-press events.
- [ ] 3. OLED UI framework: screen/title/hint bar, menu, arrows, pagination.
- [ ] 4. ATECC driver (refactor probe): wake / serial / Random (entropy).
- [ ] 5. Crypto core HOST-TESTED FIRST: vendor trezor-crypto; bip39 (12 words) + bip32 + secp256k1 + keccak; derive m/44'/60'/0'/0/N, address, sign.
- [ ] 6. Setup wizard + state machine: UNPROVISIONED / LOCKED / READY; passcode (button sequence) set + unlock; seed gen from ATECC TRNG -> 12 words on OLED.
- [ ] 7. USB: TinyUSB + Ledger Nano S Plus VID/PID + HID framing + APDU (get-config 0x06, get-address 0x02, sign-msg 0x08, sign-tx 0x04).
- [ ] 8. MetaMask e2e on Monad testnet: connect -> confirm address on device -> receive MON -> sign tx (review + hold OK).

## Demo flow (booth script)
reset -> set passcode (button sequence) -> generate 12 words (ATECC TRNG) -> wallet ready
-> connect MetaMask -> confirm address on OLED -> receive MON -> send MON (review + sign).

## Security reality (say it, don't fake it)
Demo shortcut: seed entropy stored in FLASH (not yet AES-wrapped in ATECC); passcode
lockout is software (not the ATECC monotonic counter); no secure boot. ATECC provides
certified TRNG only, for now. Never load a real seed or real funds on this build.
