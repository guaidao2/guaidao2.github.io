---
layout: tool
title: vuln4all
tagline: 模块化 Web 漏洞靶场。丢一个 module.py 进去，就多一道题。
platforms: [Python 3.9+, 跨平台]
license: 见仓库
status: 22 类 / 46 题
---

<p class="lead">一个可以自己长出题目的靶场。在 <code>modules/&lt;分类&gt;/&lt;名字&gt;/</code> 放一个 <code>module.py</code>，重启，首页清单里就多一道题 —— 不碰核心、不登记表、不改别人的文件。目前 22 个类别、46 道题。</p>

<p class="credit mono dim">guaidao2 · 打完之后的记录在 <a href="{{ '/blog/vuln4all-teaching/' | relative_url }}">这篇</a></p>

## 跑起来

```bash
python3 main.py                 # 默认只绑 127.0.0.1:8800
python3 main.py --lan           # 开放到局域网（多人一起打）
python3 main.py --port 9000
```

启动后会把本机与局域网两种地址都打出来，局域网那个可以直接发人。

## 命令

```bash
python3 main.py list                       # 列出所有题目
python3 main.py list --category sqli       # 只看某一类
python3 main.py check                      # 每道题的通关进度
python3 main.py check --json               # 机器可读
python3 main.py reset sqli/login_bypass    # 把一道题恢复出厂
python3 main.py reset --all
python3 main.py doctor                     # 体检：模块合不合规、能不能跑
python3 main.py new xss/dom_based          # 生成一道新题的骨架
```

`doctor` 有错误时返回非零退出码，可以直接挂到 CI 上 —— 新增模块在合并前就会因为契约问题被拦下。

## 加一道题

```
modules/
  sqli/
    login_bypass/
      module.py
```

`module.py` 声明这一题的元信息（分类、难度、CWE、挂载点）、页面路由、重置逻辑，以及判定通关的条件。`new` 会生成一份可运行的骨架，照着填就能起来。

## 每道题自带的东西

- **重置按钮**：把这一题的数据恢复出厂，不影响别的题。
- **提示 / 答案**：两个折叠区，卡住的时候先看提示。
- **objective**：通关条件写在模块里，`check --json` 输出布尔值。页面文案可以随便写，那两个布尔才是权威 —— 只看一个很容易把"满足了一半"当成打穿。

`/__vuln4all/status` 是体检页，能看到模块契约、挂载点冲突、硬编码路径这类问题。

## 覆盖的类别

业务逻辑 · 命令注入 · CORS · CSRF · 反序列化 · DoS · Flask Session · Host 头 · 越权 · 信息泄露 · JWT · 开放重定向 · 路径穿越 · 竞态条件 · SQL 注入 · SSRF · SSTI · 文件上传 · XSS · XXE

## 设计取向

- **模块化优先**：加题不改核心。这样才能按"一个知识点一道题"来铺，而不是凑数量。
- **可判定的通关**：objective 是程序判的，不靠页面说了什么。
- **可教学**：提示与答案分层，初学者卡住不至于出不来；`doctor` 保证模块质量不随时间腐坏。
- **单进程**：题目数据共享，多人同时打请各自拿一份副本 —— 这是刻意的简单，不是缺陷。

## 注意

这些漏洞是真的，默认只绑 `127.0.0.1`；要开放到局域网用 `--lan`，它会在启动时明确告诉你"别人能连进来了"。别带到公网、别拿真实数据跑。
