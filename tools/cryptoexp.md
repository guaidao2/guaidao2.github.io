---
layout: tool
title: cryptoexp
tagline: 密码学 Python 库：零依赖原语 + 一层分析管线，另附命令行与工作台。
platforms: [Python 3.9+, 跨平台]
license: MIT
status: 预发布 0.1.0aN，0.2.0 转正式
repo_url: https://github.com/guaidao2/cryptoexp
---

<p class="lead">面向 CTF、安全评估与研究的密码学库：核心只用标准库，AES、LLL、Coppersmith、SHA-1/2 长度扩展、ChaCha20、MT19937 都是自己实现的；上面再叠一层分析管线——提取参数、列出攻击假设、生成可运行的工作台。26000 行纯 Python，248 个用例全绿。</p>

<p class="credit mono dim">coolmoon &amp; guaidao2 · 整合与设计：guaidao2，实现：coolmoon · 原名 cryptokit（该名 2022 年已被无关项目占用）</p>

## 库优先

`import cryptoexp as cx`，全部原语从包根取到：

```python
import cryptoexp as cx

cx.long_to_bytes(0x4142)                 # b'AB'
cx.b64d('ZmxhZ3thfQ==')                  # b'flag{a}'
cx.algebra.gcd(24, 36)                   # 12
cx.lll([[1, 1, 1], [1, 0, 1], [0, 1, 1]])          # 纯 Python 格基约减
cx.known_high_bits_factor(n, p_high, 160)          # Coppersmith
cx.wiener_attack(e, n, c)                          # 私钥过小
cx.ecb_byte_at_a_time(cx.make_ecb_oracle(key, secret))
cx.padding_oracle_attack(valid, iv + ct)
cx.clone_from_outputs(outputs)                     # 克隆 MT19937 状态
cx.discrete_log(g, h, p)['x']                      # BSGS → Pohlig-Hellman
cx.dsa_nonce_reuse(p, q, g, y, r, s1, s2, h1, h2)  # 随机数重用还原私钥
cx.length_extension(h1, len(data), b"&admin=1", secret_len=len(secret))
cx.berlekamp_massey(bits)                          # 从输出比特恢复 LFSR 抽头
cx.java_random_predict(outputs, 4)                 # java.util.Random 状态恢复
```

零依赖是刻意的：没有包索引的内网机器上同样能跑。`gmpy2`、`sympy`、`pycryptodome`、`z3` 只是可选加速，缺失不影响正确性。

## 命令行

```bash
python3 cryptoexp_cli.py analyze challenges/rsa_wiener.txt
python3 cryptoexp_cli.py analyze challenges/xor_repeating.txt --solve --run
python3 cryptoexp_cli.py hypotheses challenges/rsa_high_bits.txt   # 攻击面 + 缺口
python3 cryptoexp_cli.py lab "把整段题面粘在这里"                    # 工作台脚手架
python3 cryptoexp_cli.py list                                      # 分析器 + 模板 + API 地图
```

## 为什么它不是模板库

“固定漏洞类 → 固定利用链”在 pwn 上成立，是因为类别有限。密码学相反：要读构造、找结构性弱点，最后一步常常得自己写。所以它是分层的：

| 层 | 作用 | 位置 |
|---|---|---|
| 原语 | 可复用的积木 | `src/cryptoexp/utils/*` |
| 分析 | 提取参数、判定攻击面、尝试攻击 | `src/cryptoexp/core/analysis/*` |
| 假设引擎 | 27 条显式假设，带 `needs` 与缺口：哪条适用、为什么不适用、**缺哪一块信息** | `src/cryptoexp/hypothesis.py` |
| 工作台 | 可运行脚手架：参数内联、假设与缺口写成注释、留出接口 | `src/cryptoexp/lab.py` |
| 解题模板 | 常见家族快路径，生成独立可运行脚本 | `src/cryptoexp/core/solve.py` |
| 验证 | `confirmed` / `candidate` / `not_reproduced` 三态 | `src/cryptoexp/core/verify.py` |

模板只是便利，不是答案。

## 覆盖范围

- **数论与模运算**：gcd/egcd/CRT、模逆、Miller-Rabin、Pollard rho、连分数、Wiener、Fermat、BSGS、Tonelli-Shanks；Legendre/Jacobi/Kronecker、totient/Carmichael、原根、非互素 CRT、光滑性、`binomial_mod`。
- **多项式与代数**：polymod、结式、Rabin 不可约判定、GF(p) 线性代数（RREF/零空间/求解）、GF(2) 与 LFSR、Berlekamp-Massey 恢复抽头、CRC 计算与**伪造**、未知域原像。
- **格**：纯 Python LLL、单变量 Coppersmith、已知高位分解、低密度子集和（LLL）与中间相遇；双变量 Coppersmith、线性化格、共用 d 的 SDAP 格（实验性，边界见下）。
- **编码与古典**：hex/base64/base32/base58/base85、解码链搜索、单字节与重复密钥 XOR、凯撒/仿射/维吉尼亚/摩斯/栅栏（带打分）、Playfair、Hill、Bacon、ADFGVX、自动密钥、base62/base91。
- **分组与流**：纯 Python AES-128/192/256 的 ECB/CBC、PKCS#7、CBC 字节翻转、仅凭密文识别 ECB；RC4、ChaCha20（RFC 8439）、AES-CTR、密钥流重用与 crib dragging。
- **哈希与 PRNG**：SHA-1/SHA-256 长度扩展与可续跑的 `HashState`；MT19937 克隆/预测/爆破种子、Java `Random` 恢复、glibc `rand` 状态恢复、xorshift、截断 LCG。
- **RSA 与签名**：小指数、广播、共模、共享素因子、Wiener、Fermat、Pollard、dp/phi 泄露、已知高位、Franklin-Reiter、带填充 Håstad、已知部分明文、奇偶/LSB oracle；ECDSA/DSA 随机数重用、e=3 签名伪造、PKCS#1 v1.5。
- **Oracle 攻击**：分组大小与模式识别、未知前缀对齐、ECB 逐字节恢复、CBC padding oracle。

## 不止 CTF

同一批原语也回答真实工作中的问题：

- `batch_gcd(moduli)` — 一批公钥里有没有共享素因子（乘积树，支持上千把）
- `audit_rsa_key(n, e, extra_moduli=[...])` — 带等级的弱密钥审计
- `detect_weak_prng(outputs)` — 识别 LCG / glibc `rand` / xorshift / Java `Random` / MT19937，且只在恢复结果能重放观测值时才下结论
- `parse_jwt` / `parse_der_signature` / `parse_ssh_public_key` / `key_fingerprint_sha256`
- `find_flags(data, prefixes=[...])` — 内存镜像、配置、日志里的标记串
- `crc_forge_append(...)`、`crc_solve_unknown(...)`

## 设计纪律

- **黑板**：`analyze_all` 只物化一次上下文，分析器消费它而不重复解析；单个分析器失败降级为警告，不中断整轮。
- **双注册表**：`register_analyzer` 与 `register_solver`，未知键自动渲染，加分析器不改展示层。
- **未知是一等状态**：假设声明它需要什么，引擎报告**缺口**而不是沉默。
- **有界工作**：昂贵步骤有显式预算，用尽会上报。
- **验证优先于启发式**：开发中发现的每个 bug 都变成回归测试——搜索类目标函数不得含 flag 加分（否则爬山会伪造 flag）、Coppersmith 拒绝 `p = n` 这种平凡分解、生成的脚本必须真的跑到 flag。

## 边界（如实说明）

- `glibc_rand_recover` 需要约 96 个以上连续输出；更少时枚举所有一致解，只有后续输出也一致才返回状态，否则返回 `None`——它从不猜。
- `lcg_recover_truncated` **不是**格基实现；可见高位不足以唯一确定参数时返回 `None`，而不是编一段序列。
- 次数 > 1 的 Coppersmith 在纯 Python 下只在很小维度可行；双变量 Coppersmith 实测是每个未知量几个 bit、`n` 到约 384 位，512 位会被预检直接拒绝。
- 线性化格上限约 12 个格坐标；变量只以乘积形式出现时解不了，那属于双变量 Coppersmith。
- 共用私钥 d：512 位模数下 m=3 约 2^128 位、m=4 约 2^150；m=2 相比连分数无增益。
- ADFGX/ADFGVX 已知方阵时读序 k≤8 可穷举；方阵未知时只在词级证据过阈值才给答案，否则把最好的往返结果作为假设给出。
- 玩具曲线以外的 ECC、Boneh-Durfee、完整 Bleichenbacher：报缺口，不假装能做。
- 离散对数只有 BSGS / Pohlig-Hellman，群阶含大素因子时如实报告不可行。
- 纯 Python 分数 LLL 在维度 ~8 以内比较舒服。
- CRC 原像只在 `8 * unknown_len <= width` 时能唯一确定未知域，否则返回一个 `unique: False` 的解。
- Playfair / Hill / 列移位 / Bacon 天生有损，“往返”指 `decrypt(encrypt(x)) == prepared(x)`。
- 不做网络 IO、不扫描；oracle 类攻击需要你提供回调（针对目标写十行适配层即可）。
- 暂无 Web 界面：这是一个库加一个命令行工具。

## 测试

**248 个用例全绿**。涵盖官方向量（FIPS-197 AES、RFC 8439 ChaCha20、CRC-32/16、SHA-1/256）、代数与格恒等式、针对本地 oracle 的攻击、验签与随机数重用、19 道端到端靶场（生成的脚本必须真的跑到 flag）、以及两轮独立审计发现缺陷的回归测试。

## 署名

coolmoon & guaidao2。整合与设计由 guaidao2 负责，代码实现全部由 coolmoon 完成。
