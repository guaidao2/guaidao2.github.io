---
layout: post
title: php2shell：从 8.5.11 到 8.5.12，补丁里那句 "avoid state corruption" 是什么
summary: 晚上十点补丁落地，官方只写了一句话。把两个版本的源码拆开对比、再自己编个 ASAN 靶场打几轮，能看清它修的不是某个检查，而是"出错之后谁负责收拾现场"。附三个崩溃现场、最小七请求配方，以及我一开始想错、后来被打掉的四个判断。
tags: 漏洞分析 PHP CVE
date: 2026-10-21 22:45:00 +0800
---

今天晚上十点，PHP 发了紧急补丁：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35，修 CVE-2026-109618 和 CVE-2026-109619，外面叫它 php2shell。

官方 changelog 写得很省，Core 那一行就一句：`Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state corruption via bailout)`。公告对两个 CVE 也只有一句话——109618 是 "RCE via OOM corruption"，109619 是 "RCE via stale global state"。

我把两个版本的源码拆开对了一遍，又自己编了个带 ASAN 的靶场打了几轮。下面写的是这个过程。

## 一、我做了什么

物料是官方的 `php-8.5.11.tar.gz` 和 `php-8.5.12.tar.gz`，校验过哈希，diff 只看 `Zend/`、`main/`、`ext/session/` 三块。

靶场从源码自己编：`--disable-all --enable-cli --enable-cgi --enable-session --enable-debug` 加 ASAN，装在独立前缀下，系统那份 PHP 没动。另外单独编了一份关掉调试开关的版本，`-O2 -g` 加 ASAN——这一份用来排除"只在断言下成立"。

跑法用 `php -S`，常驻 worker。原因很实际：这次要看的都是跨请求留下的东西，一次性 CGI 看不到。

有个细节先记下来：为了让 ASAN 看见 malloc 层，我关掉过 Zend 自己的内存管理器（`USE_ZEND_ALLOC=0`），这时候 `memory_limit` 就不起作用了——6MB 的请求在 8M 限制下正常返回。所以后来所有 OOM 实验都放回 Zend MM 模式做。

## 二、根因：一次 longjmp，后面没人收拾

PHP 分配内存失败时走这条链：

```
分配失败 → zend_mm_safe_error() → zend_error_noreturn(E_ERROR, "Allowed memory size ... exhausted")
        → zend_error_zstr_at() → zend_bailout()
```

`zend_bailout()` 是 longjmp。意思是：从当前位置直接跳走，跳点之后的 C 代码一行都不执行。

平时这没关系。请求结束了，进程还在，下一个请求从干净状态开始。但当它跳在下面这几处，就会把半成品留在进程内存里：解释器还没初始化完（`init_executor()` 之前）、请求作用域还没建立（模块 RINIT 之前）、某个内部函数只构造了一半（反序列化、JSON 解析解到一半）。

后面的事就好理解了：留下的东西被当成有效数据用。官方把两种情况分开编了号——一种是半成品容器被复用（109618，OOM corruption），一种是跨请求残留的全局量被读到（109619，stale global state）。

8.5.12 的改法不是补一个检查。它把"任意点 longjmp"整个换掉了：出错先记账、分配允许失败、在检查点统一处理、启动前先把脏东西清掉。

## 三、为什么"请求启动期"最容易出事

8.5.11 的请求启动顺序是这样的：

```
php_output_activate();
zend_interned_strings_activate();   // 字符串驻留表，这里可能 OOM，且早于 init_executor
zend_activate();                    // 执行器状态在这之后才重置
sapi_activate();                    // 读 POST 数据，multipart / 上传进度回调在这里
php_hash_environment();             // 装配 $_POST
zend_activate_modules();            // 模块 RINIT，会话全局量在这里才初始化
```

按这个顺序看，有三处很要命。

第一，解释器初始化之前就有会失败的分配。字符串驻留表激活时要分配内存，失败就走报错；而报错的时候要读"当前请求的错误处理闭包"——读到的是上一个请求留下的那个。`Zend/zend.c:1583` 会真的去调用它。可那个闭包对象在上个请求结束时就销毁了。

第二，读 POST 数据早于模块 RINIT。所以上传进度回调跑起来的时候，会话相关的全局量全是上一请求的残留，本该在 RINIT 做的初始化还没发生。

第三，这个阶段一旦 bailout，模块 RINIT 就跑不到了，对应的清理也被跳过（看 `PG(modules_activated)`）。会话全局量和进度结构不会被清，要么泄漏，要么留脏。

## 四、补丁到底改了什么

**分配器。** 这一处加了近千行，是主体。新增 `EG(delayed_oom)`，四个状态：无、待处理、处理中、已处理；分配失败先记账，到检查点由 `zend_handle_delayed_oom()` 统一处理。新增一族可失败分配——`femalloc`、`fecalloc`、`ferealloc` 这些，失败返回 NULL 而不是跳走。字符串驻留表的扩容也改成可失败可上报，正好对上前面那个窗口。另外加了内存硬限制的百分比接口，让"解析期 OOM"走正常 fatal，而不是 hard limit 的 longjmp。

**执行器。** 请求结束时，现在会清掉上一请求留下的这些东西：

```c
ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
if (EG(errors)) { zend_array_destroy(EG(errors)); EG(errors) = NULL; }
EG(exception) = NULL;
EG(user_error_handler) = NULL;
```

补丁注释写得很直白：这些量可能在 `init_executor()` 之前就被用到。另一处是调用入口——`zend_call_function()` 之类先看一眼有没有待处理的 OOM，有就干净地失败返回。这样"调用到一半 OOM"不会在参数已经压栈、调用帧已经分配的状态下跳走。

**会话模块。** 四处改动：multipart 开始事件里提前初始化会话全局量（注释是"要在 RINIT 之前跑，所以得在这儿清"）；新增"正在处理上传进度"的标志，这期间不加载类、不调 `__wakeup` / `__unserialize`，对象一律当"不完整类"原样写回；会话初始化失败就中止，以前失败了还会继续往下走；结束事件把 `$_SESSION` 从全局符号表摘掉。

**解析路径。** `rfc1867.c`、`SAPI.c`、`php_variables.c` 里的分配改成可失败、可上报，别在解析中途跳。

值得一提的是补丁自带的那批测试，名字几乎就是缺陷目录：`oom_unserialize_001..016`、`oom_SplFixedArray___unserialize`、`oom_SplObjectStorage___unserialize`、`oom_array_fill_*`、`oom_range_*`、`oom_str_repeat`、`oom_json_decode_*`、`oom_interrupt_unfinished_call_frame`、`oom_request_parsing`，还有 `rfc1867_no_user_code`（上传进度解码不许执行用户代码）和 `rfc1867_incomplete_class_reserved_props`。光看名字就知道这个面有多宽。

## 五、两个 CVE 各自是什么

**109618**：OOM 落在内部函数中途，跳走时已经建了一半的对象、哈希表、引用还挂在返回槽、调用帧、全局变量或者 `$_SESSION` 上。后面的代码把它们当正常数据释放、复用，就是 UAF 或者类型混淆。

**109619**：上一请求注册了错误处理闭包，请求结束时闭包对象被销毁，但全局指针没清；下一请求在解释器初始化之前 OOM，报错路径读到这个悬空指针，然后调用它。修法是在请求结束时把这些全局量全部置空。

## 六、崩溃的三个现场

真正打出来的崩溃有三个，各有各的形态。

**第一个，解码上下文被释放后又被读。** 崩在 `var_unserializer.c:168`，`var_hash = (*var_hashx)->last_dtor` 这一句。把栈上的指针展开，它指向的内容是一串小整数（`0x8140, 0xa, 0x15, 0xe` 这样），不是反序列化上下文该有的字段——说明这块结构已经被释放，还被别的分配复用了。取出来的指针是 `0x15`，下一句解引用就死了。这是解码器自己状态的 use-after-free，不是随机栈垃圾。

**第二个，函数指针是空的却还被调用。** debug 版崩在一句断言上，`ZEND_ASSERT(PS(serializer))`。release 版里这句被编译掉，直接就是 `PS(serializer)->decode(...)`。原因在业务逻辑里：这个字段只在会话 RINIT 里赋值，而上传进度那条路径只在"会话状态是 none"的时候才走初始化；前一次启动期 bailout 把状态留在了 active，于是这次跳过初始化直接进解码，字段还是空的。

这里得收一句：这个字段只会被赋成静态的 handler 地址，不由请求数据或堆内容决定。所以第二个现场的现实影响是空指针解引用型的 DoS，不能据此说控制流劫持。它的价值是证明"bailout 之后的残留全局量确实能一路走到间接调用"——和 109619 那个悬空闭包是同一类，只是这个字段不可控。

**第三个，换个 handler 照样崩。** 把会话记录改成 `php_serialize` 的格式，崩溃点变成 `var_push`（`var_unserializer.c:133`）。说明这不是某个 handler 的私有 bug，而是解码上下文在所有 handler 上共享的状态回滚缺失。

## 七、七个请求打崩一个 worker

配方是这样：对同一个 `PHPSESSID` 依次写入六种会致命失败的畸形序列化结构，每次写完发一个 multipart 请求；之后不再碰记录，只用同一个 ID 继续请求。

```
C:8:"stdClass":4:{AAAA}
O:13:"SplFixedArray":1:{i:0;N;}
C:13:"SplFixedArray":6:{i:0;N;}
O:16:"SplObjectStorage":1:{i:0;N;}
a:1:{i:0;R:1;}
O:7:"Closure":0:{}       ← 之后重复
```

8.5.11 到第七个请求，进程死了，三次全中。栈整条都在 `php_request_startup` 里，脚本一行都没编译：

```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000015
    #0 tmp_var                      var_unserializer.c:168
    #2 ps_srlzr_decode_php          session.c:1123
    #3 php_session_decode           session.c:1150
    #4 php_session_initialize       session.c:514
    #5 php_session_rfc1867_update   session.c:3405
    #6 php_session_rfc1867_callback session.c:3330
    ...
    php_request_startup
```

关掉调试开关的 release 版同样复现，段错误地址换成 `0x63`，栈基本一样，只是那一行在 release 下是真正的函数指针调用。所以这不是"只在断言里成立"的东西，生产上就是一条真的 SEGV。

带 50 毫秒间隔的版本八次全中；把间隔去掉，阈值附近会抖。所以脚本里保留了这个间隔。

8.5.12 上同一套配方跑四十轮，全部正常返回，一条 ASAN 记录都没有。

## 八、我一开始猜错的四件事

这部分是打完才明白过来的。我一开始有四个判断，全错了。

我一开始以为纯 pre-auth 就能打崩，不需要写记录的能力。于是拿"上传进度 + 6MB 尾字段"连着做了二十五轮解析期 OOM。结果 worker 一直活着，零泄漏，零 ASAN 记录。结论：解析期 bailout 的清理是完整的，要崩必须经过解码那一步的致命失败。

接着我以为一个请求就够。做了十七种形状——引用越界、给非可序列化类、对象计数不符、无效类名、转义、自引用——每种开一个全新 worker 单发。全部返回 200，有些只留下启动期的致命错误。结论：要累积，有阈值。

然后我想换个思路，每次用新的会话 ID 试试。十三个请求，每个独立 ID 加独立恶意记录。全部存活。结论：残留是会话级的，同一条记录得被反复解码，跟 worker 本身没关系。

最后我以为崩溃是完全确定的。去掉 50 毫秒间隔、改请求头形状之后，七到八个请求之间会出现偶发存活。结论：对堆布局和时序敏感。

所以准确的说法不是"发一个未认证请求就能打崩任何 8.5.11"。准确的说法是：**在能反复投喂同一条恶意会话记录的前提下，第七到第八个请求能把 worker 打崩。**

顺便记一句日志现象，它当时差点把我带偏：解析期 OOM 之后，日志里会同时出现"会话已销毁"和"会话写入失败"，还有"头部已发送，cookie 无法再发"，同一次请求里内存管理器报了十一处没释放。这些看着很像"已经烂掉了"，但第一件事做完就说明，光到这一步并不足以打崩 worker。

## 九、后来补做的四个实验

一是 `session.upload_progress.cleanup=1`（默认值）。之前我关掉它方便观察，有人会问是不是靠关它才成立。用默认值重跑，第七八个请求照样崩。不依赖。

二是 `session.use_strict_mode=1`。也崩。但这里要说清楚：靶场直接给了我写会话记录的能力，等于绕过了 strict_mode 的"ID 必须已存在"那道门槛。所以**不能**拿这个结果说该配置无效——它挡的是"攻击者自己挑一个 ID"，跟能不能写记录是两件事。

三是换 `php_serialize` handler。照样崩，就是前面第三个现场。

四是 `request_parse_body()`。8.5 有个 API 允许应用在 `enable_post_data_reading=0` 的情况下自己解析 body，PUT/PATCH 常见。写了个调用它的页面：8.5.11 是调用前看不到会话、调用后攻击者的键出现在会话里，还落了一个 340 字节的会话文件；8.5.12 是调用前后都看不到。

这条值得单独说一句：**它把会话被隐式初始化这件事，从请求启动期挪到了任意一个用户代码点。** 用这个 API 的应用，攻击者可以在一次请求内完成注入并立刻消费，不需要应用写 `session_start()`，也不经过 `$_POST` 装配。原来"必须跨请求累积"的限制，在这条路径上会松一档。

## 十、为什么"一个请求通杀"不成立

社区里那个 php2shell PoC 仓库我也看了源码。它列的三条"已验证"链里，两条是旧技术：上传进度配文件包含，2018 年前后就很流行，前提是站点自己有 `include`，这次补丁也没修它；两个目录序列化处理器不一致导致对象注入，是 PHP bug #71101，2014 年就有公开分析。只有第三条 `var_destroy` 重入 UAF 挨着本次修的东西。

所以它 README 里"从 5.4 到 8.5 全部 pre-auth RCE、可靠性 100%"说得太满。实际算下来：前两条要站点自己有洞，第三条要能反复写同一条会话记录。

另外它的靶场起的是特权容器，还把 9000 端口映射到外面；镜像用浮动 tag，现在拉下来就是修好的 8.2.35，反而复现不出来。

## 十一、加固与复测

升级到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35。8.1 及更早是 EOL，官方不会再修。

配置上还能再收一层，但这是收窄入口，不是修根因：

```ini
session.upload_progress.enabled = 0     ; 业务不用就关
session.use_strict_mode = 1             ; 别让攻击者自己挑会话 ID
session.save_path = <独立目录，最小权限>
```

这句"收窄入口"不是客套。`use_strict_mode=1` 在没有写记录能力的环境里能挡住攻击者自选 ID，在靶场那种直接给写权限的环境里挡不住——两件事别混。

开发侧两条：别把请求数据直接塞进 `$_SESSION`，它既是 payload 来源也是信息泄漏来源；用 `request_parse_body()` 解析 body 的应用，回头看一眼解析完之后对会话做了什么。

复测三点：新版本上跑注入脚本，应当什么都读不到；跑崩溃配方，不应出现进程退出或 ASAN 记录；上传进度相关请求，在错误日志里不该再有 `PHP Request Startup` 前缀的会话告警。

## 最后

这次修的不是"少了一个检查"，是"出错的时候怎么收拾现场"。

这类 bug 很难靠读代码发现，因为每一步看着都对：分配失败就报错，报错就退出，很合理。不合理的是退出方式——longjmp 一走，后面没人收拾。

剩下的活是从崩溃走到利用，那需要把那个垃圾指针换成受控值，再配堆布局。一件事一件事来，不急着下结论。
