---
layout: tool
title: crackweb
tagline: 流量驱动的 Web DAST。把浏览器挂到代理上正常访问，它对经过的流量做测试。
platforms: [Windows amd64, Linux amd64]
license: MIT
status: 活跃维护
repo_url: https://github.com/guaidao2/crackweb
release_url: https://github.com/guaidao2/crackweb
---

<p class="lead">用 Go 写的动态应用安全测试工具，形态参考 xray：把浏览器（或任意 HTTP 客户端）的代理指向它，正常访问目标，经过代理的每个请求都会被分析；只要请求里带参数，它就会主动发起变异重放去测。单一静态二进制，无运行时依赖。</p>

<p class="credit mono dim">guaidao2 &amp; coolmoon · 变异引擎与核心算法由 coolmoon 主导</p>

## 三种用法

```bash
# 一、边浏览边扫描（主用法）：起代理，浏览器指过来，装上它导出的 CA，然后正常用这个应用
crackweb proxy --listen 127.0.0.1:7777 --export-ca ~/crackweb-ca.crt

# 二、交给爬虫去走：对不方便手动点击的目标驱动同一套引擎
crackweb crawl -u https://example.com --engine hybrid -o report.html

# 三、只测一个请求
crackweb scan -u "https://example.com/api/items?category=books" -o report.html
crackweb scan -r request.txt                  # 扫从 Burp 保存下来的报文
crackweb scan -u https://example.com/login --forms   # 并提交该页面声明的表单
```

`--forms` 补的是单 URL 扫描本来测不到的情况——真正的参数不在 URL 里。加上它之后，crackweb 会提交页面自己声明的内容：HTML 表单，以及页面脚本自发发起的请求（搜索带 JSON 体、上传带 multipart 体），各自提交到自己的地址、带自己的请求体和编码。登录页、搜索框、上传控件因此不必爬整个站点就能测。页面只以 PUT / PATCH / DELETE 发起的调用仍然排除。

## 子命令

| 子命令 | 用途 |
|---|---|
| `proxy` | 起中间代理：浏览器挂上来正常访问，它对经过的流量做测试 |
| `crawl` | 爬取目标，并扫描爬到的每个请求 |
| `scan` | 扫描单个目标，或其它工具保存下来的原始 HTTP 请求 |
| `oob` | 起带外交互服务器（DNS 与 HTTP 回调） |
| `ca` | 创建、查看并导出用于 HTTPS 拦截的 CA 证书 |
| `local` | 对已有的物件做离线分析：JWT、hash，不发送任何流量 |

## 工作原理

```
                    ┌──── 流量来源 ────┐
  浏览器 →[代理]────▶  代理流量        │
                    │  爬虫发现        ├──▶ httpmsg.Request ──▶ 扫描队列
  原始报文文件 ─────▶  手工导入        │
                    └──────────────────┘
                              │
  第 0 层  被动分析   不额外发包   安全头、Cookie、CORS、信息泄露
  第 1 层  重放变异   注入 payload  SQLi、XSS、SSRF、RCE、SSTI、LFI …
  第 2 层  模板匹配   nuclei 兼容   复用公开模板库
                              │
                              ▼
                结果 → HTML / JSON / SARIF / Markdown
```

**统一报文模型**：代理抓到的流量、爬虫发现的请求、从 Burp 粘进来的请求、扫描器变异构造的请求，都是同一个 `httpmsg.Request`。请求头以保序、保留原始大小写的列表存储而不是 map，所以一份报文被改过一处之后可以原样写回，其余部分与抓到的内容逐字节一致。这是"代理、爬虫、扫描器合成一个工具"的前提。

**第 1 层是核心**：取出浏览器真正发过的每个请求，提取参数，针对性重放变异请求，再用一套归一化 + 相似度引擎判断"到底变了没有"——时间戳、CSRF token 这类动态噪声会被抹平，页面里只有内嵌时钟在变时不会被当成变化，没起作用的 payload 不会被报出来。

因为覆盖面跟着**真实流量**走而不是跟着爬虫走，扫描一开始就有产出，能覆盖用户能到达的一切（包括登录之后的页面），也不会把请求浪费在没有参数的地方。

## 带外检测

盲 SSRF、盲命令注入、存储型 XSS 在响应里不留痕迹。它自带 DNS 与 HTTP 回调监听，把**回调本身**当作证据：

```bash
crackweb proxy --listen 127.0.0.1:7777 --oob-http 0.0.0.0:8081 --oob-dns 0.0.0.0:5353
crackweb oob --domain oob.example.com      # 也可独立部署在目标能回连的主机上
```

## 离线分析

`local` 只对物件本身做运算，不发任何请求——不存在锁账号或污染日志的问题。

```bash
crackweb local jwt "<token>"                          # 解码，并用内置密钥列表尝试
crackweb local jwt "<token>" -w words.txt              # 同时试自己的字典
crackweb local jwt "<token>" -s "<密钥>" --forge \
    --claim role=admin --claim is_admin=true           # 用密钥签出自己的 token
crackweb local hash 5f4dcc3b5aa765d61d8327deb882cf99   # 识别并用字典尝试
```

候选来自内置列表、你的字典，以及 token 自身的声明——`iss: "NeuraTech-OA"` 能推出 `NeuraTech2024`，这是通用字典不会收录的。能还原签名的密钥会被报出，并说明持有它的人可以为任意身份伪造 token。带盐或刻意变慢的哈希（bcrypt、argon2、scrypt、PBKDF2）只报身份、不做尝试。

## 语言

默认输出英文，中文是显式选择：

```bash
crackweb --lang zh --help
CRACKWEB_LANG=zh crackweb --help
```

报告同样如此，`--lang zh` 跑出来的就是中文报告。

## 能力边界

- **强在"有没有"**：读侧注入、JWT 与被动面的识别很稳，报出的条目带可复现的请求与判定依据。
- **不负责"怎么打"**：利用与打通是另一类工具的事。拿它的"没报"当"没洞"是误用。
- **写侧默认不覆盖**：默认不发 PUT / DELETE，越权写与写侧注入要看手工。
- **报出之后仍要复核**：同一处缺陷可能出现在多个参数上，其中一部分只是回显而非执行。
- 站点带 `charset=gb2312/gbk` 时注入面必须走宽字节；`-r` 要喂**正常态**报文，喂成功态会让基线被自身响应污染；目标按 UA 白名单时先加 `--random-ua`，否则会以"没有洞"收场。

`crackweb scan --list-checks` 列出全部检测项。
