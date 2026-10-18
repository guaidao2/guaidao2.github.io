#!/usr/bin/env python3
"""Apply RELA relocations of the unstripped wm_kmod.ko and emulate the SEED ioctl path.
Layout: each section gets its own base; symbol values are section-relative."""
import struct, sys
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *

KO = "wm_kmod.ko"          # 指向未 strip 的模块
ef = ELFFile(open(KO, "rb"))

# assign bases
bases = {}
cur = 0x100000
for i, sec in enumerate(ef.iter_sections()):
    if sec.name in (".text", ".rodata", ".data", ".bss", ".init.text", ".exit.text") or sec.name.startswith((".rodata", ".data.")):
        bases[i] = cur
        cur += 0x20000
print("bases:", {ef.get_section(i).name: hex(b) for i, b in bases.items()})

# symbol address resolver
symtab = ef.get_section_by_name(".symtab")
def sym_addr(sym):
    shndx = sym["st_shndx"]
    if isinstance(shndx, int) and shndx in bases:
        return bases[shndx] + sym["st_value"]
    return 0

# image bytes
img = {}
for i, base in bases.items():
    sec = ef.get_section(i)
    data = bytearray(sec.data()) if sec["sh_type"] != "SHT_NOBITS" else bytearray(sec["sh_size"])
    img[base] = data

def sec_base_of_file_offset(shndx):
    return bases.get(shndx)

# apply relocations
applied = 0
for sec in ef.iter_sections():
    if sec["sh_type"] not in ("SHT_RELA", "SHT_REL"):
        continue
    target_idx = sec["sh_info"]
    if target_idx not in bases:
        continue
    tbase = bases[target_idx]
    buf = img[tbase]
    for rel in sec.iter_relocations():
        off = rel["r_offset"]; info = rel["r_info"]; addend = rel["r_addend"] if sec["sh_type"] == "SHT_RELA" else 0
        symidx = info >> 32; rtype = info & 0xffffffff
        S = sym_addr(symtab.get_symbol(symidx)) if symidx else 0
        P = tbase + off
        val = S + addend
        if rtype == 1:      # R_X86_64_64
            buf[off:off+8] = struct.pack("<Q", val & 0xffffffffffffffff)
        elif rtype in (2, 4):   # PC32 / PLT32
            buf[off:off+4] = struct.pack("<i", (val - P) & 0xffffffff if (val - P) >= 0 else (val - P))
            buf[off:off+4] = struct.pack("<I", (val - P) & 0xffffffff)
        elif rtype in (10, 11):  # 32 / 32S
            buf[off:off+4] = struct.pack("<I", val & 0xffffffff)
        elif rtype == 24:   # PC64
            buf[off:off+8] = struct.pack("<Q", (val - P) & 0xffffffffffffffff)
        else:
            pass
        applied += 1
print("relocations applied:", applied)

TEXT = bases[ef.get_section_index(".text")]
print("text base:", hex(TEXT))

mu = Uc(UC_ARCH_X86, UC_MODE_64)
for base, data in img.items():
    size = (len(data) + 0xfff) & ~0xfff
    mu.mem_map(base, max(size, 0x1000))
    mu.mem_write(base, bytes(data))
STACK = 0x6000000; UBUF = 0x5000000
mu.mem_map(STACK, 0x40000)
mu.mem_map(UBUF, 0x1000)

nonce = struct.pack("<Q", 0x66d82e9bc451a73f)
mu.mem_write(UBUF, nonce + b"\x00" * 16)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x20000)
mu.reg_write(UC_X86_REG_RBX, UBUF)

CALL_FROM, CALL_TO = TEXT + 0x427, TEXT + 0x5a5
state = {"buf": None}

def hook(mu, addr, size, _):
    if addr == CALL_FROM:
        dst = mu.reg_read(UC_X86_REG_RDI); src = mu.reg_read(UC_X86_REG_RSI); n = mu.reg_read(UC_X86_REG_RDX)
        state["buf"] = dst
        mu.mem_write(dst, bytes(mu.mem_read(src, n)))
        mu.reg_write(UC_X86_REG_RAX, 0); mu.reg_write(UC_X86_REG_RIP, addr + size)
    elif addr == CALL_TO:
        mu.reg_write(UC_X86_REG_RAX, 0); mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook)
try:
    mu.emu_start(TEXT + 0x3ff, TEXT + 0x700, count=500000)
except UcError as e:
    print("UC error:", e, "rip=%#x" % mu.reg_read(UC_X86_REG_RIP))

if state["buf"]:
    out = bytes(mu.mem_read(state["buf"], 0x18))
    print("resp:", out.hex())
    print("SEED:", out[8:].hex())
else:
    print("no buffer")
