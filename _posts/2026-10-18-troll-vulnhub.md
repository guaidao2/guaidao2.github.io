---
layout: post
title: VulnHub troll：一个「地址」其实是目录名
summary: 从 robots.txt 走到 SSH，再靠一个 777 的 cron 脚本拿到 root。中间最值钱的一步，是把 ELF 输出里的地址当成路径去试。
tags: 打靶 提权 cron
date: 2026-10-18 08:40:00 +0800
---

VulnHub 上的 `troll`，Ubuntu 14.04，i686。名字起得挺准 —— 一路上全是"看着像 A，其实是 B"的坑。

## 入口

扫出来 7 个端口：21 FTP、22 SSH、25 SMTP、80 HTTP、110 POP3、143 IMAP，外加一个 NetBIOS。FTP 有一组弱口令。

`robots.txt` 给了 `Disallow: /secret`，进去是个空目录 —— 诱饵。

真正的线索在 FTP 里的 `lol.pcap`。打开一看，是**上一次渗透的抓包**：有人在 Kali 上 dumpcap 录的，流量里出现过一个目录名 `sup3rs3cr3tdirlol`。

访问 `/sup3rs3cr3tdirlol/`，目录索引里躺着一个 `roflmao` —— 32 位 x86 的 ELF，7 KB。跑一下：

```
Find address 0x0856BF to proceed
```

看着像要往内存里找一个地址。我顺手把它当路径试了：

```
http://troll/0x0856BF/
```

404。回来看了一眼输出 —— `0x0856BF` 是大写。路径名区分大小写，小写当然 404：它本来就是个目录名。

`/0x0856BF/` 下面两个目录：`good_luck/` 和 `this_folder_contains_the_password/`。

第一个里是 `which_one_lol.txt`，10 个候选用户名；第二个里是 `Pass.txt`。`Pass.txt` 的**内容**是 `Good_job_:)` —— 看着像有人在夸你。目录名说的是"这个文件夹里装的东西就是密码"，而**文件内容只是干扰，文件名才是密码**。

于是用户名 × 密码逐个试 SSH。这里要注意 sshd 有限流：连续失败六七次之后就开始 `i/o timeout`，所以必须串行、加间隔。最后 `overflow:Pass.txt` 进去了。

## 提权

进来是 `uid=1002(overflow)`，`sudo -l` 没权限，SUID 只有系统标准件。

`/etc/passwd` 里有一处很怪：

```
hackman::0:0:root:/root:/bin/bash
```

出现了 8 次。手动加一行就够拿到 root 了，为什么会重复八次？

`/var/log/cronlog` 里有答案：

```
*/2 * * * * cleaner.py
```

每两分钟以 root 跑一个 `cleaner.py`，相对名。顺着找「root 拥有、但我可写」的文件，`/lib/log/cleaner.py` 是 `root:root` 但权限 **777**。

读它的内容：

```python
# 每 2 分钟
把 hackman 行追加到 /etc/passwd
chmod 777 /root
rm -r /tmp/*
```

所以 `/etc/passwd` 里那 8 行、以及 `/root` 为什么是 **777**，都是这个脚本干的 —— 作者刻意留了一条"直接读 flag"的路。

到这里其实已经能读 `/root/proof.txt` 了。但我还是想把提权做实：把 `cleaner.py` 换成"原功能 + 复制一份 SUID bash"，等 cron 以 root 执行，就得到 `/lib/log/rootbash`。

```
/lib/log/rootbash -p -c 'id'
# euid=0(root)
```

## 这台上学到的

- **ELF 里的 "Find address 0x…" 可能是个目录名**，不一定指内存地址。hex 的大小写也要穷举 —— 大小写敏感的文件系统上，一个字母就决定 404 还是通。
- **目录索引（autoindex）常是提示链的载体**：`/secret/`（诱饵）、`/sup3rs3cr3tdirlol/`、`/0x0856BF/` 全开着，一路读下来像看故事。
- **pcap 可以是"上一次渗透的记录"**：直接泄漏下一环的名字。抓到别人的抓包，先别急着看协议，先看里面出现过哪些字符串。
- **"文件夹里的内容是密码"⇒ 文件名才是密码**，文件内容（`Good_job_:)`）是专门用来骗人的。
- **cron 里写相对命令名 ≠ 就能 PATH 劫持**：这台 `/etc/environment` 的 PATH 只有系统目录且不可写，往 `/tmp`、`/var/tmp` 投 `cleaner.py` 都不生效。真正能下手的，是那个"root 拥有但我可写"的具体文件。
- **`atime` 不能当证据**：机器挂载了 `noatime/relatime`，`roflmao` 我明明跑过，atime 还停在 2014。
- **限流是设计的一部分**：这台作者在 sshd 前面做了失败计数，约 6 次就开始超时。所以端口扫描照样扫得到 22 端口（TCP 握手成功就是开），但凭据尝试必须慢下来 —— 把"被打烦了的服务"当成"没这个服务"，是很容易犯的错。
