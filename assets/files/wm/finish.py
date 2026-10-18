#!/usr/bin/env python3
"""Finisher: given the 16-byte RC4 seed (hex), decrypt loader's WMPK payload,
verify CRC32 against the header field, and dump stage2.bin.

Usage: python3 finish.py <seed_hex_32chars> [loader]
Everything else (device, ioctl numbers, struct layout, RC4, CRC32, exec) is
already established statically; only the kernel-module-derived seed is missing.
"""
import struct, sys, zlib

seed_hex = sys.argv[1] if len(sys.argv) > 1 else "00" * 16
seed = bytes.fromhex(seed_hex)
assert len(seed) == 16, "seed must be 16 bytes"
ld = open(sys.argv[2] if len(sys.argv) > 2 else "loader", "rb").read()
DB = 0x3080                      # .data: vaddr 0x4080 -> file 0x3080
hdr = ld[DB + 0x20: DB + 0x38]   # vaddr 0x40a0
assert hdr[:4] == b"WMPK"
ln = struct.unpack("<I", hdr[12:16])[0]
expect = struct.unpack("<I", hdr[16:20])[0]
payload = ld[DB + 0x38: DB + 0x38 + ln]

def rc4(key, msg):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(len(msg))
    for idx in range(len(msg)):
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff; S[i], S[j] = S[j], S[i]
        out[idx] = msg[idx] ^ S[(S[i] + S[j]) & 0xff]
    return bytes(out)

dec = rc4(seed, payload)
crc = zlib.crc32(dec)
print("seed=%s len=%#x expect_crc=%#x got_crc=%#x match=%s" % (seed.hex(), ln, expect, crc, crc == expect))
print("first32:", dec[:32].hex())
if crc == expect:
    open("stage2.bin", "wb").write(dec)
    print("wrote stage2.bin -> disassemble it (objdump -D -b binary -m i386:x86-64)")
