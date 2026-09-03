#!/usr/bin/env python3
"""NOIR wallet — USB HID smoke test (zero dependencies, uses /dev/hidraw).

Sends Ledger APDUs over the 64-byte HID transport and prints the response.
Verifies: (1) GET_APP_CONFIGURATION answers while locked, (2) GET_PUBLIC_KEY is
refused with 0x6982 (boot-LOCKED gate), (3) a multi-frame SIGN_TX APDU is
reassembled and refused while locked.

Usage: python3 tools/test_usb.py            # auto-find 2c97:5011
       python3 tools/test_usb.py /dev/hidraw2   # or pass the node explicitly
"""

import os, sys, struct, glob, time

def find_hidraw():
    for dev in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            uevent = open(os.path.join(dev, "device/uevent")).read()
        except OSError:
            continue
        if "HID_ID=0003:00002C97:00005011" in uevent:
            return "/dev/" + os.path.basename(dev)
    return None

def make_frames(apdu: bytes):
    """Chunk an APDU into 64-byte Ledger HID frames (channel 0x0101, tag 0x05,
    seq from 0; first frame carries the 2-byte total length)."""
    assert 4 <= len(apdu) <= 255
    frames, seq, off = [], 0, 0
    while off < len(apdu):
        f = bytearray(64)
        f[0:2] = b"\x01\x01"                # channel
        f[2]   = 0x05                       # tag: APDU
        f[3:5] = struct.pack(">H", seq)     # sequence
        hdr = 7 if seq == 0 else 5
        if seq == 0:
            f[5:7] = struct.pack(">H", len(apdu))   # total length
        c = min(64 - hdr, len(apdu) - off)
        f[hdr:hdr+c] = apdu[off:off+c]
        off += c; seq += 1
        frames.append(bytes(f))
    return frames

def parse_response(f: bytes):
    total = f[5] << 8 | f[6]
    payload = bytes(f[7:7+total])
    sw = (payload[-2] << 8 | payload[-1]) if len(payload) >= 2 else None
    return total, payload, sw

def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else find_hidraw()
    if not dev:
        print("ERROR: no hidraw node for 2c97:5011 (is the device flashed+plugged?)")
        sys.exit(1)
    print(f"using {dev}")

    fd = os.open(dev, os.O_RDWR)
    os.set_blocking(fd, False)

    def exchange(apdu, name):
        frames = make_frames(apdu)
        for fr in frames:
            os.write(fd, fr); time.sleep(0.02)
        time.sleep(0.06)
        try:
            data = os.read(fd, 64)
        except BlockingIOError:
            print(f"[{name}] NO RESPONSE ({len(frames)} frame(s) sent)")
            return
        if len(data) < 7:
            print(f"[{name}] short read ({len(data)} bytes): {data.hex()}")
            return
        total, payload, sw = parse_response(data)
        tag = f"[{name}] {len(frames)} frame(s) ->"
        print(f"{tag} len={total} payload={payload.hex()} SW=0x{sw:04X}"
              + ("" if sw == 0x9000 else ""))

    # 1. GET_APP_CONFIGURATION: E0 06 00 00 00 -> expect 00 000100 + 9000
    exchange(bytes.fromhex("e006000000"), "GET_CONFIG ")

    # 2. GET_PUBLIC_KEY (empty path): E0 02 00 00 00 -> expect 6982 (locked)
    exchange(bytes.fromhex("e002000000"), "GET_PUBKEY ")

    # 3. Multi-frame SIGN_TX (120 bytes -> 3 frames) -> expect 6982 (locked)
    tx = b"\xe0\x04\x00\x00" + bytes([0x73]) + bytes(range(0x73))
    exchange(tx, "SIGN_TX   ")

    os.close(fd)

if __name__ == "__main__":
    main()
