# cline-api-worker (vvxw 版) — 已修复版

基于 https://github.com/vvxw/Cline-api-worker 的 Cloudflare Worker 中转，
让任意 OpenAI 兼容客户端（Hermes / 第三方 AI 代理软件）能用上 `api.cline.bot`
的免费模型（如 `z-ai/glm-5.3-flash`）。

## 本分支的修复

### 1. 剥离 `max_tokens`（关键）
上游 `api.cline.bot` 对免费模型有风控：请求体**只要带 `max_tokens` 字段**
就返回 `500 {"error":"empty response content"}`，与请求头、代理、key 都无关。

Hermes GUI 的"测延迟"固定发 `max_tokens:1`，所以必然失败。

修复：`stripMaxTokens()` 在转发前删掉该字段，上游即正常返回 200。
实测非流式 / 流式均正常。

### 2. Cline 官方客户端指纹头
上游会校验请求是否来自 Cline 产品面，缺失时报
`403 only available via Cline product surfaces`。

修复：`clineFingerprintHeaders()` 附加官方头（逆向自
https://github.com/cline/cline `sdk/packages/llms/src/providers`）：

```
User-Agent: Cline/3.0.47
HTTP-Referer: https://cline.bot
X-Title: Cline
X-IS-MULTIROOT: false
X-CLIENT-TYPE: cline-sdk
X-CLIENT-VERSION: 3.0.47
X-PLATFORM: terminal
X-PLATFORM-VERSION: 3.0.47
X-CORE-VERSION: 0.0.66
X-Task-ID: <动态 UUID>
```

### 3. 清空 CONFIG 直配区占位符
原版 `CONFIG.ACCESS_TOKEN` 有非空假占位符，会覆盖环境变量导致全部 401。

## 部署

```bash
cd vvxw-worker
npx wrangler secret put CLINE_API_KEYS    # 上游 key，逗号分隔
npx wrangler secret put ACCESS_TOKEN      # 保护本 worker 自身的 token
npx wrangler deploy
```

环境变量：

- `CLINE_API_KEYS` — 上游 Cline API Key（必填）
- `ACCESS_TOKEN` — 保护本 Worker（可选）
- `SOCKS5_PROXIES` — 代理列表（可选；CF Workers 机房段常被代理方拒绝，直连可用时留空）
- `REQUIRE_SOCKS5` — 设为 `0` 允许直连
