# js-pulse

> 从前端 JavaScript 里挖出 API 端点、密钥、Bug Bounty 金矿。纯静态分析，零依赖。

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)

---


**它能从 JS bundle 里挖出来的东西：**

- API 端点（REST、GraphQL、WebSocket），还带 HTTP 方法
- 密钥和 API key（AWS、Stripe、Slack、GitHub、`alg: none` 的 JWT……）
- 内部基础设施（私有 IP、内部域名、你不知道的子域）
- 漏洞面——容易 SSRF 的参数名、硬编码的 SQL、`eval()` 调用、藏起来的 admin 路径
- 任何看起来「不该出现在公开 JS 文件里」的东西



---

## 安装

单文件 Python，零依赖。

```bash
git clone https://github.com/yourname/js-pulse.git
cd js-pulse
chmod +x js_pulse.py
./js_pulse.py --help
```

或者就一个文件：

```bash
wget https://raw.githubusercontent.com/yourname/js-pulse/main/js_pulse.py
chmod +x js_pulse.py
```

Python 3.8+
---

## 快速开始

指个 URL 给你出一份报告：

```bash
./js_pulse.py scan https://目标.com --format markdown -o report.md
```

或者你已经把 JS 拉下来了，直接喂文件：

```bash
./js_pulse.py analyze app.bundle.js -o findings.json
```

想直接分析某个 JS URL？一样，那个 URL 形式 HTML 页面和直接的 .js 链接都吃。

几个常用的参数：

```bash
# 只看高置信度的发现
./js_pulse.py scan https://目标.com --min-score 60

# 管道友好的 text 输出（一行一个发现，grep/awk 神器）
./js_pulse.py scan https://目标.com --format text

# 把原始 JS bundle 一起存下来（留档用）
./js_pulse.py scan https://目标.com --save-js ./bundles/

# 跳过爬虫——只分析你给的 URL
./js_pulse.py analyze https://目标.com/app.js https://目标.com/vendor.js
```

---

## 输出长啥样

```text
$ ./js_pulse.py scan https://example.com

[i] Fetching https://example.com ... (1.2 KB)
[i] Found 3 <script> tags
[i] Downloading 2 external scripts ...
    [+] /static/js/main.chunk.js   (142 KB)
    [+] /static/js/vendor.chunk.js (387 KB)
[i] Analyzing 2 bundles (529 KB total) ...

═══════════════════════════════════════════════════════════════
 js-pulse findings — example.com
═══════════════════════════════════════════════════════════════

[HIGH] AWS Access Key (AKIA...)
  ├─ file:    main.chunk.js
  ├─ match:   AKIA[0-9A-Z]{16} in line 4291
  └─ context: const AWS_KEY = "AKIA...";  // legacy, see ops

[HIGH] 内部 API 端点，可能存在越权
  ├─ file:    main.chunk.js
  ├─ match:   /api/v1/internal/users/{id}
  └─ context: api.get(`/api/v1/internal/users/${uid}`)

[MED]  生产环境还有 debug 代码
  ├─ file:    vendor.chunk.js
  └─ match:   console.log("DEBUG: cart state =", state)

[MED]  WebSocket 端点（潜在的实时攻击面）
  ├─ file:    main.chunk.js
  └─ match:   wss://realtime.example.com/socket

[LOW]  JS 源码里的邮箱地址
  ├─ file:    main.chunk.js
  └─ match:   support@example.com

═══════════════════════════════════════════════════════════════
 Summary: 2 high · 3 medium · 4 low · 7 informational
═══════════════════════════════════════════════════════════════
```

`--format json` 输出结构化，方便接其他工具（schema 看 README 末尾）。

---

## 命令

| 命令 | 干啥 |
|------|------|
| `scan <url>` | 抓页面，发现它的 JS，爬下来全分析一遍 |
| `analyze <files...>` | 跳过爬虫——分析你已有的 JS（本地路径或 URL） |
| `patterns` | 列出所有检测规则（调权重的时候用） |
| `version` | 打印版本号退出 |

全局参数：`--format`, `--min-score`, `--save-js`, `--no-color`, `--verbose`。

---

## 工作原理（简化版）

1. **爬** —— 给个 URL，抓 HTML，提取每个 `<script src=...>`（也吃内联脚本）
2. **抓** —— 下载每个外部脚本。也支持 sourcemap（`--sourcemaps` 开启时）
3. **提** —— 对每个 bundle 跑一堆正则 + 启发式提取器：
   - URL 类（路径、完整 URL、模板路径）
   - URL 旁边的 HTTP 方法名（粗略关联，不保证 100% 准）
   - 已知密钥格式（前缀、base64 解出来是 JSON 的、JWT 等）
   - 可疑调用（`eval`、`Function`、`document.write`、`innerHTML =`）
   - 硬编码的邮箱、IP（带私有 IP 段识别）、看起来内部的域名
4. **打分** —— 每个发现 0-100 分。看起来是真的密钥就高分。看起来是注释里的 `example.com` 就低分
5. **报告** —— 输出 text/JSON/CSV/Markdown

完整架构在 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。不深，但实诚。

---

## 检测规则

跑 `./js_pulse.py patterns` 看实时列表。最新统计，`js-pulse` 能识别：

- **20+ 种密钥格式** —— AWS、Stripe（live + restricted）、GitHub PAT、Slack、Google API、JWT、SendGrid、Mailgun、Twilio、npm、Discord、Telegram bot 等等
- **8+ 种端点形态** —— REST 路径、GraphQL query、WebSocket URL、RPC 风格方法名、静态资源路径（默认会过滤）
- **6+ 种漏洞面信号** —— 容易 SSRF 的参数名、硬编码 SQL 片段、危险 sink、仅内网域名、debug 残留
- **PII 提取器** —— 邮箱、电话、内网 IP、私有域名

想加自己的规则？看 [docs/ADD_PATTERN.md](docs/ADD_PATTERN.md)。规则格式故意做得简单——就是 Python 正则加元数据，不搞 DSL。

---

## 凭啥不直接用 LinkFinder / getjs / subjs？

| | js-pulse | LinkFinder | getjs | subjs |
|---|---|---|---|---|
| 端点提取 | ✅ | ✅（只 URL） | ❌ | ❌ |
| HTTP 方法关联 | ✅（启发式） | ❌ | ❌ | ❌ |
| 密钥扫描 | ✅（20+ 格式） | ❌ | ❌ | ❌ |
| 漏洞面信号 | ✅ | ❌ | ❌ | ❌ |
| 内部基础设施提取 | ✅ | ❌ | ❌ | ❌ |
| 零依赖单文件 | ✅ | ❌（Python 2） | ❌（Go） | ❌（Go） |
| 管道友好输出 | ✅ | 一般 | ❌ | ❌ |

LinkFinder 是最接近的替代品。多年没维护了，只做 URL 提取。我喜欢它点子，就是不喜欢它现在的状态。

---


## 路线图

按我打算做的顺序排：

- [ ] 基于 AST 的端点提取（现在正则能覆盖 ~85%，剩下是动态构造）
- [ ] 内置 sourcemap 感知的反混淆（Webpack/Burble/Vite 之类的 bundle）
- [ ] 置信度加权的误报抑制（跟踪历史上经常误报的 pattern）
- [ ] Webhook 友好的输出（按需把发现推送到 Slack/Discord）
- [ ] 自定义检测器的插件系统


---

## 贡献

两种贡献方式，按我感激程度排：

1. **PR 一个新的检测规则。** 这贡献性价比最高。每个 bug bounty hunter 笔记应用里都有一条规则别人用得上。
2. **Issue 报一个误报。** 附上 JS 片段（脱敏）和为啥是误报。我根据这些调权重。

枯燥的细节看 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 免责声明
请忽用于未经允许的渗透测试


