#!/usr/bin/env python3
"""Run decrypted stage2 ELF under Unicorn with syscall stubs; capture its write() output."""
import struct
from unicorn import *
from unicorn.x86_const import *

BIN = open("stage2.bin", "rb").read()
BASE, STACK, ARG = 0x400000, 0x800000, 0x900000
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(BASE, 0x4000)
mu.mem_write(BASE, BIN)
mu.mem_map(STACK, 0x10000)
mu.mem_map(ARG, 0x1000)

seed = bytes.fromhex("36f7a811d99d2fff7e65fa283a3780f0")
blob = bytes.fromhex("80766664c4aa93a736c8451d4afaa26ab87669")
nonce = struct.pack("<Q", 0x66d82e9bc451a73f)
# struct: magic 'TCMW'(4) + fd(4) + nonce(8) + seed(16)
mu.mem_write(ARG, b"TCMW" + struct.pack("<I", 3) + nonce + seed)
mu.reg_write(UC_X86_REG_RDI, ARG)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x8000)

out = []
def hook_code(mu, addr, size, _):
    if mu.mem_read(addr, 1) == b"\x0f" and mu.mem_read(addr+1, 1) == b"\x05":  # syscall
        nr = mu.reg_read(UC_X86_REG_RAX)
        a1, a2, a3 = (mu.reg_read(r) for r in (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX))
        if nr == 101:            # ptrace
            mu.reg_write(UC_X86_REG_RAX, 0)
        elif nr == 16:           # ioctl
            if a2 == 0xC0445703:                     # BLOB -> 68-byte wm_blob
                mu.mem_write(a3, struct.pack("<I", len(blob)) + blob.ljust(0x40, b"\x00"))
                mu.reg_write(UC_X86_REG_RAX, 0)
            elif a2 == 0x40205702:                   # VERIFY -> accept
                print("TAG_SENT:", bytes(mu.mem_read(a3, 16)).hex())
                mu.reg_write(UC_X86_REG_RAX, 0)
            else:
                mu.reg_write(UC_X86_REG_RAX, 0)
        elif nr == 1:            # write
            out.append(bytes(mu.mem_read(a2, a3)))
            mu.reg_write(UC_X86_REG_RAX, a3)
        elif nr in (60, 231):    # exit
            mu.emu_stop()
        else:
            mu.reg_write(UC_X86_REG_RAX, 0)
        mu.reg_write(UC_X86_REG_RIP, addr + size)

mu.hook_add(UC_HOOK_CODE, hook_code)
try:
    mu.emu_start(BASE + 0x24b, 0, count=200000)
except UcError as e:
    print("UC error:", e, "rip=%#x" % (mu.reg_read(UC_X86_REG_RIP) - BASE))
print("rax(return):", hex(mu.reg_read(UC_X86_REG_RAX)))
print("captured output:", b"".join(out))
