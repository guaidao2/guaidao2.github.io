#!/usr/bin/env python3
"""Apply relocations to wm_kmod.ko, run SEED then wm_do_verify, check the tag stage2 sent."""
import struct
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *

ef = ELFFile(open("wm_kmod.ko", "rb")     # 指向未 strip 的模块)
bases = {}
cur = 0x100000
for i, sec in enumerate(ef.iter_sections()):
    if sec.name in (".text", ".rodata", ".data", ".bss", ".init.text", ".exit.text") or sec.name.startswith((".rodata", ".data.")):
        bases[i] = cur; cur += 0x20000
symtab = ef.get_section_by_name(".symtab")
def sym_addr(s):
    idx = s["st_shndx"]
    return bases[idx] + s["st_value"] if isinstance(idx, int) and idx in bases else 0
img = {}
for i, b in bases.items():
    sec = ef.get_section(i)
    img[b] = bytearray(sec.data()) if sec["sh_type"] != "SHT_NOBITS" else bytearray(sec["sh_size"])
for sec in ef.iter_sections():
    if sec["sh_type"] not in ("SHT_RELA", "SHT_REL") or sec["sh_info"] not in bases:
        continue
    tb = bases[sec["sh_info"]]; buf = img[tb]
    for rel in sec.iter_relocations():
        off = rel["r_offset"]; info = rel["r_info"]
        add = rel["r_addend"] if sec["sh_type"] == "SHT_RELA" else 0
        S = sym_addr(symtab.get_symbol(info >> 32)) if (info >> 32) else 0
        P = tb + off; t = info & 0xffffffff; val = S + add
        if t == 1: buf[off:off+8] = struct.pack("<Q", val & (2**64-1))
        elif t in (2, 4): buf[off:off+4] = struct.pack("<I", (val - P) & 0xffffffff)
        elif t in (10, 11): buf[off:off+4] = struct.pack("<I", val & 0xffffffff)
        elif t == 24: buf[off:off+8] = struct.pack("<Q", (val - P) & (2**64-1))
TEXT = bases[ef.get_section_index(".text")]

mu = Uc(UC_ARCH_X86, UC_MODE_64)
for b, d in img.items():
    mu.mem_map(b, (len(d) + 0xfff) & ~0xfff); mu.mem_write(b, bytes(d))
STACK, UBUF = 0x6000000, 0x5000000
mu.mem_map(STACK, 0x40000); mu.mem_map(UBUF, 0x2000)
nonce = struct.pack("<Q", 0x66d82e9bc451a73f)

st = {"buf": None}
def hook(mu, addr, size, _):
    if addr == TEXT + 0x427:
        dst = mu.reg_read(UC_X86_REG_RDI)
        st["buf"] = dst
        mu.mem_write(dst, bytes(mu.mem_read(mu.reg_read(UC_X86_REG_RSI), mu.reg_read(UC_X86_REG_RDX))))
        mu.reg_write(UC_X86_REG_RAX, 0); mu.reg_write(UC_X86_REG_RIP, addr + size)
    elif addr == TEXT + 0x5a5:
        mu.reg_write(UC_X86_REG_RAX, 0); mu.emu_stop()
mu.hook_add(UC_HOOK_CODE, hook)

# 1) SEED
mu.mem_write(UBUF, nonce + b"\x00" * 16)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x20000); mu.reg_write(UC_X86_REG_RBX, UBUF)
try: mu.emu_start(TEXT + 0x3ff, TEXT + 0x700, count=300000)
except UcError as e: print("seed run err:", e)
seed = bytes(mu.mem_read(st["buf"] + 8, 16)) if st["buf"] else b""
print("module SEED:", seed.hex())

# 2) VERIFY with the tag stage2 sent
tag = bytes.fromhex("47cae5ef87d1222bbc2a01418e3045a4")
mu.mem_write(UBUF + 0x100, tag + b"\x00" * 16)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x20000)
mu.reg_write(UC_X86_REG_RDI, UBUF + 0x100)
try:
    mu.emu_start(TEXT + 0x160, TEXT + 0x2d0, count=300000)
    print("wm_do_verify ret =", mu.reg_read(UC_X86_REG_RAX))
except UcError as e:
    print("verify err:", e, "rip=%#x" % (mu.reg_read(UC_X86_REG_RIP) - TEXT))
