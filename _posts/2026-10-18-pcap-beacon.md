---
layout: post
title: 流量取证：把 flag 藏进 1×1 像素请求的分片里
summary: 98 个包的抓包，页面和资源都正常，数据通道只有 pixel.gif 的 d= 参数。
tags: 取证 pcap 流量分析
date: 2026-10-18 09:40:00 +0800
---

## 1. 概况

`traffic.pcapng`：98 个包，全部为明文 HTTP（capinfos 显示链路类型为 "No link-layer encapsulation"）。

共 6 条 HTTP 请求：

| frame | 请求 | 备注 |
|-------|------|------|
| 5 | `GET /` | 首页 |
| 19 | `GET /style.css` | 样式 |
| 33 | `GET /script.js` | 脚本 |
| 47 | `GET /pixel.gif?d=U1lDe1JfVV9BXw%3D%3D&s=00` | 分片 0 |
| 61 | `GET /pixel.gif?d=RjBSM05TMUM1&s=01` | 分片 1 |
| 75 | `GET /pixel.gif?d=X01BU1RFUj99&s=02` | 分片 2 |
| 89 | `GET /pixel.gif?r=noop` | 诱饵（无 `d/s`） |

首页 HTML 内部还有 `<img src="/pixel.gif?r=warmup">`，同样只是诱饵。

## 2. 解码

三个 `d=` 参数是 base64 分片，`s=` 是序号：

```
U1lDe1JfVV9BXw==  ->  SYC{R_U_A_
RjBSM05TMUM1      ->  F0R3NS1C5
X01BU1RFUj99      ->  _MASTER?}
```

按 `s` 排序拼接：

```
SYC{R_U_A_F0R3NS1C5_MASTER?}
```

## 3. 关于末尾的 `?`

不是解码错误：

- 三段长度分别为 16 / 12 / 12，均为 4 的倍数，可独立解码且拼接后语义连贯（"R U A FORENSICS MASTER?"）
- `base64(b"_MASTER}") == "X01BU1RFUn0="`，与实际抓到的 `X01BU1RFUj99` 不同；`X01BU1RFUj99` 解出的是 `_MASTER?}`（多一个 `0x3F`）

## 4. 排除项

- 页面 / CSS / JS 内容正常（HTML 只有 "Just a normal page."，JS 只有 `console.log("page loaded")`）
- 无自定义 HTTP 头（仅标准头）
- `pixel.gif` 响应体固定 7 字节 `GIF89a;`
- 全部 `tcp.len > 0` 的字节都能被 HTTP 解析消费，无隧道或额外载荷

因此数据通道只有 `d=` 参数这一处。

## 5. 脚本

```python
#!/usr/bin/env python3
"""traffic.pcapng solver: reassemble the flag from base64 pixel-beacon fragments.

Each data-bearing request looks like
  GET /pixel.gif?d=<base64>&s=<HH>&r=<random>
so: pull every http.request.full_uri, keep those with d= and s=, URL-decode d,
base64-decode it, sort by s, concatenate.
"""
import base64, re, subprocess, sys, urllib.parse

pcap = sys.argv[1] if len(sys.argv) > 1 else "traffic.pcapng"
out = subprocess.run(["tshark", "-r", pcap, "-Y", "http.request",
                      "-T", "fields", "-e", "frame.number",
                      "-e", "http.request.full_uri"],
                     capture_output=True, text=True).stdout

frags = {}
for line in out.splitlines():
    if not line.strip():
        continue
    num, _, uri = line.partition("\t")
    m = re.search(r"[?&]d=([^&]+)", uri)
    s = re.search(r"[?&]s=(\d+)", uri)
    if not (m and s):
        continue
    b = base64.b64decode(urllib.parse.unquote(m.group(1)))
    frags[s.group(1)] = b
    print("frame %-4s s=%s  %r" % (num, s.group(1), b))

flag = b"".join(frags[k] for k in sorted(frags))
print("FLAG:", flag.decode())
```

运行：

```bash
python3 pcap_solve.py traffic.pcapng
```

输出：

```
frame 47   s=00  b'SYC{R_U_A_'
frame 61   s=01  b'F0R3NS1C5'
frame 75   s=02  b'_MASTER?}'
FLAG: SYC{R_U_A_F0R3NS1C5_MASTER?}
```

脚本下载：[`pcap_solve.py`](/assets/files/pcap/pcap_solve.py)。

## 6. 检测/防护角度

- 出站请求中出现 `?d=<base64>&s=<序号>` 这类"碎片 + 序号"组合，属于典型的分片外带特征
- 1×1 像素请求携带非必要的长参数，可作为检测规则
- 该样本的页面与资源均正常，说明单看页面内容不足以发现问题
