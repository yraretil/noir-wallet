# Iron Keys — Build Plan

> How we actually build the hardware wallet described in `book/` (the "Iron Keys" technical reference).
> The book is our spec. This plan turns chapters into milestones, milestones into exit criteria, and defines the repo layout, toolchain, and decision points.

**Status:** Planning only — nothing has been set up yet.
**Current state:** `hardware-wallet/` contains only `book/` (LaTeX source + compiled PDF). No firmware, no host code, no toolchain install.

---

## 1. Goal

Build a working, reproducible hardware wallet from scratch:

- **Hardware:** Raspberry Pi Pico (RP2040) + Microchip ATECC608B secure element + SSD1306 OLED + 2 buttons. Total BOM < $15.
- **Firmware:** Bare-metal C on the Pico SDK. USB HID device, I2C to the secure element and display, on-device BIP-39/32/44 derivation, secp256k1 signing, PIN + lockout.
- **Host:** A browser dApp and a MetaMask Snap speaking to the device over WebHID.
- **MVP Definition of Done (E2E):** plug in the device → a browser page shows the derived Ethereum address → we send test ETH on a local Anvil node → the device screen asks for confirmation → we press the button → the signed transaction is broadcast and lands on-chain.

**Hard truth, stated up front:** RP2040 has no secure boot and no anti-glitch protection, and trezor-crypto is software crypto on a $4 MCU. This is an *educational-grade* wallet. It must **never hold real funds**. We design it to the standard of a production wallet anyway — that's the point of the project.

---

## 2. Design Recap (from the book — this is locked)

```
  [ PC / Browser ]
       |  WebHID (USB)
  [ RP2040 ]          Main MCU: USB, UI, parsing, BIP-32/39, secp256k1 signing
       |  I2C (SDA/SCL + pull-ups)
  [ ATECC608B ]       Secure element: TRNG, secure seed storage, P-256, counters
```

### Division of responsibility

| Task | Where |
|---|---|
| USB enumeration / HID framing | RP2040 (TinyUSB) |
| OLED UI, buttons, PIN entry | RP2040 |
| Tx parsing (RLP, EIP-155/1559, EIP-712) | RP2040 |
| BIP-39 mnemonic generation/display | RP2040 |
| BIP-32/44 key derivation | RP2040 (RAM only, never flash) |
| secp256k1 ECDSA signing | RP2040 (software, trezor-crypto) |
| True randomness | ATECC608B TRNG (**primary source**) |
| Encrypted seed-at-rest | ATECC608B data zone (AES-128) |
| P-256 ECDSA / ECDH / AES-128 / monotonic counters | ATECC608B |
| PIN brute-force lockout | ATECC608B monotonic counter |

### The secp256k1 problem (the one real architectural wrinkle)
ATECC608B only does P-256 (NIST curve); Ethereum/Bitcoin use secp256k1 (Koblitz). Solution the book locks in:

1. ATECC TRNG produces the entropy.
2. RP2040 derives the BIP-39 mnemonic + 64-byte seed from that entropy.
3. All HD derivation and signing happens in RP2040 RAM with trezor-crypto.
4. The seed is stored **encrypted** (AES-128) inside the ATECC data zone.
5. On boot, RP2040 requests the decrypted seed over an authenticated session.

Net effect: the seed never exists unencrypted in RP2040 flash.

---

## 3. Decisions to lock BEFORE building

These shape the repo and toolchain. Recommend values marked ★; each is cheap to change early, expensive late.

| # | Decision | Options | Recommendation & reasoning |
|---|---|---|---|
| D1 | MCU / board | RP2040 (Pico) vs RP2350 (Pico 2) | ★ **RP2040 first.** The book is written for it and the SDK path is well-trodden. Keep crypto isolated behind a HAL so an RP2350 port (signed boot, ch13.6) is a later milestone, not a rewrite. |
| D2 | Host integration path | (a) Ledger-APDU emulation (VID/PID + APDUs, works in MetaMask today) · (b) Custom protocol + **MetaMask Snap** · (c) Custom protocol + custom WebHID dApp | ★ **(b) Snap + (c) dApp.** (a) is seductive (zero MetaMask changes) but means impersonating a Ledger product — legal/IP murk and it drags in Ledger's exact APDU edge cases. Build (c) first as our test harness, then wrap the same protocol in a Snap. Revisit (a) only as an explicit stretch goal. |
| D3 | Protocol framing | Ledger-style HID framing vs custom | ★ **Custom minimal framing** (magic + seq + len + CRC) over 64-byte raw HID reports, mirroring the book's ch11 but without Ledger baggage. Same APDU-style command table internally (CLA/INS/P1/P2), so a future Ledger-compat layer is mostly a translator. |
| D4 | RTOS vs bare-metal | FreeRTOS vs bare-metal state machine | ★ **Bare-metal** (book ch7.4). One I2C bus, one USB stack, a tiny state machine — an RTOS adds nothing but complexity and nondeterminism. |
| D5 | Project name / product identity | — | ★ Keep **Iron Keys** from the book. Gives us a clean VID/PID namespace story later (custom USB VID is ~$5k from USB-IF; for now use the Pico SDK's default or a reserved experimental range and make VID configurable). |

---

## 4. Bill of Materials

| Item | Part | Qty | ~Cost |
|---|---|---|---|
| MCU board | Raspberry Pi Pico (RP2040) | 1 | $4 |
| Secure element | ATECC608B-MAHDA-S breakout (or DM320118 dev kit) | 1 | $3 |
| Display | SSD1306 OLED 128×64, I2C | 1 | $2 |
| Input | Tactile buttons | 2 | $0.50 |
| Passives | 2× 4.7kΩ pull-ups (I2C), decoupling caps | set | $1 |
| Debug | Picoprobe (2nd Pico as SWD debugger) | 1 (optional) | $4 |
| Debug | UART-USB bridge (CP2102/CH340) | 1 | $2 |
| Tools | Breadboard, jumpers, logic analyzer (or saleae clone) | — | $10 |

**Buy note:** an ATECC608B breakout that exposes SDA/SCL/3V3/GND is fine for prototyping. SparkFun sells a qwiic one that's breadboard-friendly.

---

## 5. Repository Layout (to be created in the setup phase)

```
hardware-wallet/
├── PLAN.md                ← this file
├── book/                  ← existing Iron Keys reference (the spec)
├── firmware/              ← Pico SDK C project (this is the real product)
│   ├── CMakeLists.txt
│   ├── pico_sdk_import.cmake        (vendored or fetched)
│   ├── src/
│   │   ├── main.c                   ← state machine: BOOT → LOCKED → IDLE → SIGN
│   │   ├── usb/                     ← TinyUSB HID: descriptors, get/set_report
│   │   ├── proto/                   ← framing + APDU-style command table
│   │   ├── crypto/                  ← secp256k1, BIP-32/39, keccak, RLP (trezor-crypto)
│   │   ├── secure/                  ← ATECC HAL + commands (wake, random, aes, counters)
│   │   ├── ui/                      ← SSD1306 driver, fonts, confirm screens, PIN pad
│   │   └── board/                   ← pin map, i2c init, button debounce
│   ├── lib/
│   │   ├── cryptoauthlib/           ← Microchip's library (only the needed subset)
│   │   └── trezor-crypto/           ← LGPL; review license before any distribution
│   ├── provisioning/                ← one-time factory setup firmware (separate binary)
│   └── tests/                       ← host-side unit tests (APDU parser, framing, crypto)
├── host/
│   ├── dapp/                        ← plain WebHID + ethers.js page (our test harness)
│   └── snap/                        ← MetaMask Snap wrapping the same protocol
├── scripts/                         ← flash.sh, test.sh, provisioning helpers
└── docs/                            ← wiring (appendix A), troubleshooting, BOM
```

`firmware/provisioning` as a **separate binary** is deliberate: the provisioning step that writes slot configs and locks the ATECC is one-shot and must not ship in the main firmware.

---

## 6. Phases & Milestones

Each phase ends with **exit criteria** — concrete, observable outcomes. We don't start the next phase until the current one is verifiable. Book chapter references tell us what to read for each phase.

### M0 — Toolchain & scaffolding  *(book ch1)*
- Install: ARM GNU toolchain (`arm-none-eabi-gcc` — **not installed yet**, verified today), Pico SDK, CMake+Ninja (already present), OpenOCD, picocom/minicom.
- Fetch/vendor `cryptoauthlib` and `trezor-crypto` as submodules or vendored copies.
- Create the repo skeleton above; `firmware/` builds a blink binary and flashes over UF2.
- **Exit:** `firmware` builds with zero warnings; LED blinks on real hardware; `git` history clean and committed per milestone.

### M1 — Hardware bring-up  *(book ch2, ch3, app A)*
- Breadboard per appendix A: I2C0 (GPIO 4/5) → ATECC @ 0x60, I2C1 (GPIO 6/7) → OLED @ 0x3C, buttons on GPIO 14/15, UART debug on GPIO 0/1.
- Programs: I2C scanner (finds both devices) → ATECC wake/info/serial-number/random → OLED "hello" + scrolling text → debounced button echo.
- **Exit:** scanner prints `0x60` and `0x3C`; `atecc_info` returns a valid serial; a logic-analyzer capture shows clean START/ACK/STOP with correct pull-up timing; OLED renders text; button presses print over UART.

### M2 — Crypto core on the HOST first (de-risking)  *(book ch4, ch5, app D)*
Everything crypto is validated on the PC before it touches firmware:
- Compile trezor-crypto on host. BIP-39 mnemonic from given entropy; BIP-32/44 derivation; address computation.
- **Verify against official test vectors** (appendix D): BIP-39 vectors, BIP-32 vectors, `m/44'/60'/0'/0/0` address check.
- secp256k1 sign/verify round-trip; RFC6979 deterministic nonce; EIP-155 `v` handling.
- **Exit:** a host test binary passes the full test-vector suite (this becomes `firmware/tests` + CI later).

### M3 — ATECC provisioning & seed vault  *(book ch3.5–3.6, ch8)*
- Write the RP2040 CryptoAuthLib HAL (i2c init/send/receive, bit-banged 80µs wake — the timing is the fiddly bit).
- Provisioning firmware: configure slot 0 (encrypted seed blob) + slot 1 (P-256 sign-only), **lock config zone**, genkey slot 1, derive/store AES key material, lock data zone.
- Main firmware: entropy from ATECC TRNG → generate + display 24-word mnemonic on OLED (paginated) → require re-entry confirmation → derive seed → AES-encrypt → write blob to slot 0.
- Boot-restore path: authenticated session → read + decrypt seed → zero RAM copies.
- **Exit:** provisioning binary runs once and locks the chip (re-running it fails cleanly); reboot restores the same seed and address as at creation; power-cycling never loses state; logic analyzer shows valid wake pulses.

### M4 — On-device wallet crypto  *(book ch9)*
- Port the M2 host crypto into the firmware CMake build (same sources, different toolchain).
- On-device: derive the Ethereum address; sign a fixed digest; compare against host-computed signature.
- PIN entry + lockout using the ATECC monotonic counter (N failures → wipe data zone).
- **Exit:** device-derived address matches host for the same seed; firmware signature verifies; lockout wipes after N attempts and survives reboot.

### M5 — USB HID & wire protocol  *(book ch10, ch11)*
- TinyUSB: raw 64-byte HID report device, `tud_hid_get/set_report` callbacks.
- Framing (D3) + APDU-style command table: `GET_PUBLIC_KEY`, `SIGN_TX`, `GET_APP_INFO`, `SIGN_TYPED_DATA` (later).
- Host-side conformance test: a small Python/Node script sends framed commands over HID (`hidapi`) and asserts responses.
- **Exit:** `GET_PUBLIC_KEY` round-trips over real USB; malformed frames get a clean error APDU, not a hang; fuzz a few hundred random frames with no crash.

### M6 — Browser integration  *(book ch12)*
- WebHID dApp (ch12.5): request device (VID/PID filter), get address, build + sign a tx, broadcast via ethers.js against a local **Anvil** node.
- MetaMask Snap (ch12.4): wraps the same protocol; `snap_getBip32Entropy` not used — our Snap talks to the device directly via WebHID.
- On-device confirm screen: show `to`, `value`, `chainId`; button confirms; second button rejects.
- **Exit:** the **MVP Definition of Done from §1** passes end-to-end through both the dApp and the Snap.

### M7 — Security hardening  *(book ch13, ch14)*
- Signed firmware images (Ed25519) + anti-rollback counter; bootloader hash check workaround for RP2040.
- Zeroization audit (every key buffer wiped with volatile memset); constant-time review of the secp256k1 path.
- Threat-model pass per ch13 (remote, physical, supply chain, evil maid) — document mitigations and accepted risks.
- **Exit:** a written threat model with per-attack status (mitigated / accepted / out-of-scope); firmware updates require a valid signature and cannot roll back.

### M8 — E2E validation, docs & CI  *(book ch15, appendices)*
- Full integration test script: flash → provision → dApp address → Anvil tx → on-chain receipt (ch15).
- Host unit tests + firmware build wired into CI (host tests run everywhere; firmware build via a pico-sdk container).
- Final docs: wiring diagram, troubleshooting table (ch15.4), BOM, and a "safety" README section stating **never use with real funds**.
- **Exit:** `scripts/test.sh` passes green from a clean checkout on a fresh machine.

### Stretch goals (after M8)
- **RP2350 port** (secure boot, ch13.6) via the crypto HAL boundary.
- Ledger-APDU compatibility layer (D2-a) as an experiment, clearly documented as non-commercial.
- Bitcoin (P2WPKH, BIP-143 sighash) and EIP-712 typed-data signing.
- Custom PCB (KiCad) + 3D-printed case with epoxy-potting demo for ch13.4.

---

## 7. Testing strategy (three layers)

1. **Host unit tests (fast, CI)** — trezor-crypto against official vectors; APDU parser and framing fuzz; RLP encode/decode against known hashes. Runs in milliseconds on the PC, so it's our primary correctness net.
2. **Hardware-in-the-loop (every milestone)** — a Python/Node harness drives the device over HID/UART and asserts protocol behavior. Milestone exits depend on it.
3. **E2E (M6/M8)** — real browser + Anvil + real device, the only test that proves the actual product.

---

## 8. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| ATECC608B I2C/wake timing quirks | Bring-up stalls | Bit-banged wake, logic analyzer early (M1), CryptoAuthLib HAL isolated in `secure/` |
| secp256k1 timing/constant-time on Cortex-M0+ | Side-channel exposure | trezor-crypto's hardened code, keys RAM-only + zeroized, never on real funds |
| RP2040 has no secure boot / no glitch protection | Physical attacker wins | Accepted for an educational device; documented in threat model; RP2350 stretch |
| MetaMask Snap API churn | Host integration breakage | Protocol isolated in one module; dApp is the canary that doesn't depend on Snap |
| WebHID unavailable in some browsers | Host integration breakage | dApp + Snap both supported; UART-based harness as last resort |
| Licenses (trezor-crypto LGPL-3.0, cryptoauthlib) | Distribution constraint | Fine for a personal/educational project; flag before any commercial release |
| Custom USB VID cost (~$5k) | — | Use Pico SDK default / experimental range; VID configurable at build time |

---

## 9. First session (what "set it up" means next)

When we start, in order:
1. **M0:** install `arm-none-eabi-gcc` + Pico SDK; vendor the two libs; scaffold the `firmware/` + `host/` tree.
2. Confirm D1–D5 with you (30 seconds each).
3. First green build: blink on the Pico, I2C scanner finding the ATECC and OLED on the breadboard.
4. Commit M0/M1 as the first milestone.

Everything else follows M0–M8 in order. Milestones are small enough that we can always stop, rebuild, and re-verify.
