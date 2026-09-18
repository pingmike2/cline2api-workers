/**
 * Cline API 调度器 (Cloudflare Workers)
 * ============================================================
 * 功能:
 *  - OpenAI 兼容透传: POST /v1/chat/completions -> https://api.cline.bot/api/v1/chat/completions
 *    (客户端路径 /v1/* 自动映射为上游 /api/v1/*, 旧路径 /api/v1/* 仍兼容)
 *  - 支持配置 单个 / 多个 上游 API Key, 每次请求随机选择
 *  - Key 与 SOCKS5 一一固定绑定: 第 N 个 Key 永远走第 N 个 SOCKS5 代理
 *    (代理数量少于 Key 时按索引取模; 只配 1 个代理则全部 Key 共用)
 *  - 所有上游流量强制经过 SOCKS5 (TLS 在隧道内建立, 证书按目标域名校验)
 *  - 请求失败(网络错误 / 401 / 403 / 429 / 5xx)自动换 Key 重试, 最大重试 3 次
 *  - 支持 stream: true (SSE 流式透传, 支持 chunked 解码)
 *  - 可选 ACCESS_TOKEN 保护本 Worker 自身
 *
 * 快捷配置: 可直接在本文件下方 "CONFIG 直接配置区" 填写 Key/代理等,
 *   非空值优先于环境变量; 留空则回退到环境变量 (两种方式可混用)
 *
 * 环境变量 (wrangler.toml [vars] 或 wrangler secret put):
 *  - CLINE_API_KEYS   上游 Key, 逗号/换行分隔, 例如 "sk_aaa,sk_bbb" (必填)
 *  - SOCKS5_PROXIES   SOCKS5 代理列表, 与 Key 按位置一一对应绑定, 例如
 *                     "socks5://user:pass@1.2.3.4:1080,socks5://5.6.7.8:1080"
 *  - UPSTREAM_BASE    上游地址, 默认 https://api.cline.bot
 *  - ACCESS_TOKEN     可选, 保护本 Worker: 客户端需携带 Authorization: Bearer <token> 或 X-Api-Key
 *  - MAX_RETRIES      失败后最大重试次数(换 Key), 默认 3 (总尝试 = 重试 + 1)
 *  - REQUIRE_SOCKS5   默认 "1" (强制 SOCKS5)。api.cline.bot 由 Cloudflare 托管, Workers
 *                     直连其 IP 会被拒绝, 因此必须走代理; 设为 "0" 才允许直连
 *  - ALLOW_DIRECT_FALLBACK 默认 "1": SOCKS5 请求失败时自动改用 Worker 直连 fetch 重试
 *  - SOCKS_TIMEOUT_MS SOCKS5 连接/握手超时, 默认 10000
 *  - HEAD_TIMEOUT_MS  上游响应头超时, 默认 30000
 *
 * 使用示例:
 *   curl https://<your-worker>.workers.dev/v1/chat/completions \
 *     -H "Content-Type: application/json" \
 *     -d '{"model":"z-ai/glm-4.6","messages":[{"role":"user","content":"hello"}]}'
 * ============================================================
 */

import { connect } from 'cloudflare:sockets';
// ============================================================
const CONFIG = {
  // 上游 API Key, 逗号分隔, 可多个: "sk_aaa,sk_bbb"
  CLINE_API_KEYS: '',

  // SOCKS5 代理, 逗号分隔, 可多个, 与 Key 按位置一一绑定:
  // "socks5://user:pass@1.2.3.4:1080,socks5://5.6.7.8:1080"
  SOCKS5_PROXIES: '',

  // 保护本 Worker 的访问令牌 (客户端需带 Authorization: Bearer <token>), 留空则不启用
  ACCESS_TOKEN: '',

  // 失败后最大重试次数 (换 Key), 留空用默认 3; 填 0 表示不重试
  MAX_RETRIES: '',

  // 上游地址, 留空用默认 https://api.cline.bot
  UPSTREAM_BASE: '',

  // SOCKS5 请求失败时自动回退为 Worker 直连 fetch (1=启用, 0=禁用)
  // SOCKS5 仍是主路径; 仅当隧道/请求失败 (代理被限速/拦截等) 时才触发, 保证服务可用
  ALLOW_DIRECT_FALLBACK: '1',

  // 首字节超时 (秒): 上游已返回响应头但迟迟不吐第一个数据块时, 主动掐断并换 Key 重试。
  // 免费通道偶发"收下请求却不吐字"的假死, 不设此项客户端会空等到自己的 stale 阈值 (如 180s)。
  // 填 0 表示关闭该探测。
  FIRST_BYTE_TIMEOUT: '',
};

const DEFAULT_UPSTREAM = 'https://api.cline.bot';

let socksTimeoutMs = 10_000;
let headTimeoutMs = 30_000;
let firstByteTimeoutMs = 45_000;

const RETRYABLE_STATUS = new Set([401, 403, 407, 408, 429, 500, 502, 503, 504, 521, 522, 523, 524, 525, 526, 527]);

// 逐跳头部: 不应透传给客户端
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

const SOCKS_REP_MESSAGES = {
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// 上游 api.cline.bot 风控: 免费模型 (z-ai/glm-5.3-flash 等) 的请求体只要带
// max_tokens 字段就返回 500 "empty response content"。这里剥离该字段再转发。
// max_tokens 不影响模型生成本质, 只影响客户端显示; 剥离后上游正常返回。
function stripMaxTokens(body) {
  if (!body) return body;
  try {
    const obj = JSON.parse(body);
    if (obj && typeof obj === 'object' && 'max_tokens' in obj) {
      delete obj.max_tokens;
      return JSON.stringify(obj);
    }
    return body;
  } catch {
    return body;
  }
}
// ============================================================
// 首字节探测: 上游已返回响应头但迟迟不吐第一个数据块时主动掐断。
// 免费通道 (cline-free / z-ai 等) 偶发"收下请求却不吐字"的假死: 响应头秒回 200,
// 但 body 几分钟没有一个字节, 客户端只能空等到自己的 stale 阈值 (Hermes 默认 180s)。
// 这里把等待压到 FIRST_BYTE_TIMEOUT, 超时即掐断连接, 交给上层换 Key 重试。
// 只提前取出第一个 chunk, 再用新流把它接回剩余数据, 不改变响应内容。
// ============================================================
async function probeFirstByte(result, timeoutMs) {
  if (!result || !result.body || !timeoutMs || timeoutMs <= 0) return result;
  if (result.status === 204 || result.status === 304) return result;

  const reader = result.body.getReader();
  let timer = null;
  let first;
  try {
    first = await Promise.race([
      reader.read(),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`上游 ${Math.round(timeoutMs / 1000)}s 内未返回首字节 (first-byte timeout)`)),
          timeoutMs,
        );
      }),
    ]);
  } catch (err) {
    if (timer) clearTimeout(timer);
    try { await reader.cancel(); } catch { /* ignore */ }
    throw err;
  }
  if (timer) clearTimeout(timer);

  const stream = new ReadableStream({
    start(controller) {
      if (first.done) { controller.close(); return; }
      if (first.value) controller.enqueue(first.value);
      (async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            controller.enqueue(value);
          }
          controller.close();
        } catch (err) {
          try { controller.error(err); } catch { /* ignore */ }
        }
      })();
    },
    cancel(reason) {
      try { reader.cancel(reason); } catch { /* ignore */ }
    },
  });

  return { ...result, body: stream };
}
// ============================================================
// 入口
// ============================================================

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      console.error('unhandled error:', err);
      return jsonResponse({ success: false, error: { message: `内部错误: ${errMsg(err)}` } }, 500);
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);

  // 配置合并: CONFIG 直接配置区非空值优先, 否则回退环境变量
  const value = (name) => {
    const direct = CONFIG[name];
    if (direct != null && String(direct).trim() !== '') return String(direct).trim();
    const fromEnv = env ? env[name] : undefined;
    return fromEnv != null ? String(fromEnv).trim() : '';
  };

  // 运行时超时配置
  socksTimeoutMs = intWithDefault(env.SOCKS_TIMEOUT_MS, 10_000);
  headTimeoutMs = intWithDefault(env.HEAD_TIMEOUT_MS, 30_000);
  firstByteTimeoutMs = intWithDefault(value('FIRST_BYTE_TIMEOUT') || env.FIRST_BYTE_TIMEOUT, 45) * 1000;

  if (request.method === 'OPTIONS') return corsPreflight();

  const keys = getConfigKeys(value);
  const proxies = getConfigProxies(value);
  const upstreamBase = sanitizeUpstream(value('UPSTREAM_BASE') || DEFAULT_UPSTREAM);
  const requireSocks = String(env.REQUIRE_SOCKS5 ?? '1').trim() !== '0'; // 默认强制 SOCKS5
  const allowDirectFallback = String(value('ALLOW_DIRECT_FALLBACK') || '1').trim() !== '0';
  const token = value('ACCESS_TOKEN') || String(env.API_TOKEN || '').trim();

  // 状态页: 公开访问 (仅暴露数量与开关状态, 不含密钥), 不做令牌校验
  if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/health' || url.pathname === '/status')) {
    return jsonResponse({
      success: true,
      service: 'cline-api-dispatcher',
      upstream: upstreamBase,
      api_keys: keys.length,
      socks5_proxies: proxies.length,
      binding: 'index-locked (key[i] -> proxy[i % proxies.length])',
      mode: proxies.length ? 'socks5' : (requireSocks ? 'blocked (REQUIRE_SOCKS5=1 但未配置代理)' : 'direct'),
      require_socks5: requireSocks,
      auth_enabled: Boolean(token),
      max_retries: intWithDefault(value('MAX_RETRIES') || env.MAX_RETRIES || env.MAX_ATTEMPTS, 3),
      first_byte_timeout_ms: firstByteTimeoutMs,
      usage: 'POST /v1/chat/completions (OpenAI 兼容, 透传上游)',
    });
  }

  // 模型列表: GET /v1/models (也兼容 /api/v1/models)
  // 上游 https://api.cline.bot/api/v1/models 是公开端点 (无需认证),
  // 先尝试无认证请求; 失败 (401/403) 再用随机 Key 带认证重试一次
  const isModelsRequest = request.method === 'GET'
    && (url.pathname === '/v1/models' || url.pathname === '/api/v1/models');
  if (isModelsRequest) {
    return handleModelsRequest({ keys, proxies, requireSocks, allowDirectFallback, search: url.search });
  }

  // 代理诊断: GET /debug/proxy 逐个测试所有 SOCKS5 代理,
  // 报告每个代理失败在哪个阶段 (TCP / 认证 / CONNECT / TLS), 便于定位问题
  if (request.method === 'GET' && url.pathname === '/debug/proxy') {
    return handleProxyDebug({ keys, proxies });
  }

  // 保护本 Worker: 状态页与模型列表之外的所有请求都需要令牌
  if (token) {
    const provided = extractAccessToken(request);
    if (provided !== token) {
      return jsonResponse({
        success: false,
        error: {
          message: 'Unauthorized: 无效的访问令牌。请在请求头携带 Authorization: Bearer <ACCESS_TOKEN> 或 X-Api-Key; 若不需要保护, 可将 CONFIG 中的 ACCESS_TOKEN 留空。',
        },
      }, 401);
    }
  }

  if (!keys.length) {
    return jsonResponse({ success: false, error: { message: '未配置上游 API Key: 请设置环境变量 CLINE_API_KEYS' } }, 500);
  }
  if (!proxies.length && requireSocks) {
    return jsonResponse({
      success: false,
      error: {
        message: '未配置 SOCKS5 代理。api.cline.bot 由 Cloudflare 托管, Workers 直连其 IP 会被拒绝, 必须通过 SOCKS5 代理访问。请设置 SOCKS5_PROXIES, 或显式设置 REQUIRE_SOCKS5=0 允许直连。',
      },
    }, 500);
  }

  const method = request.method;
  let bodyText = null;
  if (method !== 'GET' && method !== 'HEAD') {
    bodyText = await request.text();
    bodyText = stripMaxTokens(bodyText);
  }

  // 路径映射: /v1/* -> 上游 /api/v1/*; 其他路径原样透传
  // (/v1/chat/completions 和 /api/v1/chat/completions 均可用)
  let pathname = url.pathname || '/';
  if (pathname === '/v1' || pathname.startsWith('/v1/')) {
    pathname = '/api' + pathname;
  }
  const targetUrl = upstreamBase + pathname + url.search;

  // 失败重试: 每次失败换一个 Key(其固定绑定的代理也随之切换), 最大重试 MAX_RETRIES 次
  // 注意: MAX_RETRIES=0 表示不重试 (总尝试 1 次); intWithDefault 会把 0 当默认值, 需先特判
  const rawRetries = value('MAX_RETRIES') || env.MAX_RETRIES || env.MAX_ATTEMPTS || '';
  const maxRetries = String(rawRetries).trim() === '0'
    ? 0
    : Math.max(0, Math.min(intWithDefault(rawRetries, 3), keys.length - 1));
  const totalAttempts = Math.min(maxRetries + 1, keys.length);

  // 随机起始 Key: 每次请求随机选中一个 Key; 重试时按 (start + i) % n 换下一个 Key
  const start = Math.floor(Math.random() * keys.length);

  let lastStatus = null;
  let lastError = null;
  let lastTried = [];

  for (let attempt = 0; attempt < totalAttempts; attempt++) {
    const keyIndex = (start + attempt) % keys.length;
    const key = keys[keyIndex];
    // Key 固定绑定代理: 第 keyIndex 个 Key 永远走第 keyIndex % proxies.length 个代理
    const proxy = proxies.length ? proxies[keyIndex % proxies.length] : null;
    const viaProxy = Boolean(proxy);
    const isLast = attempt === totalAttempts - 1;
    lastTried.push(`key#${keyIndex}${proxy ? '@' + proxy.hostname : ''}`);

    try {
      let result = viaProxy
        ? await requestViaSocks5({ targetUrl, method, bodyText, key, proxy, request })
        : await requestDirect({ targetUrl, method, bodyText, key, request });

      // SOCKS5 路径抛错或返回异常状态时, 可选回退为直连 fetch (Worker -> 上游, 不经代理)
      let fallbackUsed = false;
      if (viaProxy && allowDirectFallback) {
        if (RETRYABLE_STATUS.has(result.status) || result.status === 404) {
          console.error(`attempt ${attempt + 1}: socks5 ${proxy.hostname} 返回 ${result.status}, 尝试直连回退`);
          try { await result.body?.cancel(); } catch { /* ignore */ }
          result = await requestDirect({ targetUrl, method, bodyText, key, request });
          fallbackUsed = true;
        }
      }

      // 可重试状态且还有机会 -> 换下一个 Key 再试
      if (!isLast && RETRYABLE_STATUS.has(result.status)) {
        lastStatus = result.status;
        console.error(`attempt ${attempt + 1}/${totalAttempts}: key #${keyIndex} 上游返回 ${result.status}, 换 Key 重试`);
        try { await result.body?.cancel(); } catch { /* ignore */ }
        continue;
      }

      // 首字节超时: 响应头已回但上游迟迟不吐数据 -> 掐断换 Key, 别让客户端空等
      try {
        result = await probeFirstByte(result, firstByteTimeoutMs);
      } catch (fbErr) {
        lastError = fbErr;
        lastStatus = result.status;
        console.error(`attempt ${attempt + 1}/${totalAttempts}: key #${keyIndex} ${errMsg(fbErr)}, ${isLast ? '已是最后一次尝试' : '换 Key 重试'}`);
        if (!isLast) continue;
        return jsonResponse({
          success: false,
          error: {
            message: `${errMsg(fbErr)} (key #${keyIndex})`,
            tried: lastTried,
            last_status: lastStatus,
          },
        }, 504);
      }

      console.log(`dispatch ok: key #${keyIndex}, ${fallbackUsed ? 'direct-fallback' : (viaProxy ? 'socks5 ' + proxy.hostname : 'direct')}, status ${result.status}`);
      return buildOutgoingResponse(result, { keyIndex, viaProxy: fallbackUsed ? false : viaProxy, attempt, proxy: fallbackUsed ? null : proxy, fallback: fallbackUsed });
    } catch (err) {
      lastError = err;
      console.error(`attempt ${attempt + 1}/${totalAttempts} failed (key #${keyIndex}${proxy ? ', proxy ' + proxy.hostname + ':' + proxy.port : ''}):`, errMsg(err));
      // SOCKS5 链路异常 (TLS 失败/超时等) -> 直连回退
      if (viaProxy && allowDirectFallback) {
        try {
          const result = await requestDirect({ targetUrl, method, bodyText, key, request });
          if (!isLast && RETRYABLE_STATUS.has(result.status)) {
            lastStatus = result.status;
            try { await result.body?.cancel(); } catch { /* ignore */ }
            continue;
          }
          console.log(`dispatch ok (direct-fallback after error): key #${keyIndex}, status ${result.status}`);
          return buildOutgoingResponse(result, { keyIndex, viaProxy: false, attempt, proxy: null, fallback: true });
        } catch (fbErr) {
          console.error(`direct fallback also failed (key #${keyIndex}):`, errMsg(fbErr));
        }
      }
    }
  }

  return jsonResponse({
    success: false,
    error: {
      message: lastError
        ? `上游请求失败: ${errMsg(lastError)}`
        : `上游返回不可用状态码: ${lastStatus}`,
      tried: lastTried,
      max_retries: maxRetries,
      last_status: lastStatus,
    },
  }, 502);
}

// ============================================================
// 模型列表: GET /v1/models
// ============================================================

async function handleModelsRequest({ keys, proxies, requireSocks, allowDirectFallback, search }) {
  const target = 'https://api.cline.bot/api/v1/models' + (search || '');
  const start = keys.length ? Math.floor(Math.random() * keys.length) : 0;
  // 尝试序列: 先无认证 (公开端点), 再依次带 Key 认证 (最多取 2 个 Key)
  const tries = [{ key: null }];
  for (let i = 0; i < Math.min(2, keys.length); i++) {
    tries.push({ key: keys[(start + i) % keys.length] });
  }

  let lastError = null;
  let lastStatus = null;

  for (const { key } of tries) {
    const keyIndex = key ? keys.indexOf(key) : -1;
    const proxy = proxies.length ? proxies[Math.max(keyIndex, 0) % proxies.length] : null;
    const label = key == null ? 'no-auth' : `key#${keyIndex}`;
    try {
      if (proxy) {
        let result;
        try {
          result = await requestViaSocks5({ targetUrl: target, method: 'GET', bodyText: null, key, proxy, request: null });
        } catch (socksErr) {
          if (!allowDirectFallback) throw socksErr;
          console.error(`models socks5 failed (${label}, ${proxy.hostname}): ${errMsg(socksErr)}, 尝试直连回退`);
          result = await requestDirect({ targetUrl: target, method: 'GET', bodyText: null, key, request: null });
        }
        // 401/403 时换下一个策略再试; 其余状态 (包括 200) 直接透传
        if (result.status === 401 || result.status === 403) {
          lastStatus = result.status;
          try { await result.body?.cancel(); } catch { /* ignore */ }
          continue;
        }
        return buildOutgoingResponse(result, { keyIndex: Math.max(keyIndex, 0), viaProxy: true, attempt: 0, proxy });
      }
      // 无代理直连 (仅 REQUIRE_SOCKS5=0 时)
      if (requireSocks) {
        return jsonResponse({
          success: false,
          error: { message: '未配置 SOCKS5 代理, 无法访问上游获取模型列表。请设置 SOCKS5_PROXIES, 或显式设置 REQUIRE_SOCKS5=0 允许直连。' },
        }, 500);
      }
      const result = await requestDirect({ targetUrl: target, method: 'GET', bodyText: null, key, request: null });
      if (result.status === 401 || result.status === 403) {
        lastStatus = result.status;
        try { await result.body?.cancel(); } catch { /* ignore */ }
        continue;
      }
      return buildOutgoingResponse(result, { keyIndex: Math.max(keyIndex, 0), viaProxy: false, attempt: 0, proxy: null });
    } catch (err) {
      lastError = err;
      console.error(`models fetch failed (${label}${proxy ? ', proxy ' + proxy.hostname : ''}):`, errMsg(err));
    }
  }

  return jsonResponse({
    success: false,
    error: {
      message: lastError ? `获取模型列表失败: ${errMsg(lastError)}` : `获取模型列表失败, 上游返回 ${lastStatus}`,
      last_status: lastStatus,
    },
  }, 502);
}

// ============================================================
// 上游请求: SOCKS5 隧道路径
// ============================================================

async function requestViaSocks5({ targetUrl, method, bodyText, key, proxy, request }) {
  const target = new URL(targetUrl);
  if (target.protocol !== 'https:') {
    throw new Error('SOCKS5 模式仅支持 https 上游');
  }
  const hostname = target.hostname;
  const port = target.port ? parseInt(target.port, 10) : 443;

  const tlsSocket = await socks5Tunnel(proxy, hostname, port);
  try {
    const headers = buildUpstreamHeaders(request, key);
    return await sendHttpRequest(tlsSocket, {
      method,
      path: (target.pathname || '/') + target.search,
      host: target.host,
      headers,
      body: bodyText,
    });
  } catch (err) {
    try { tlsSocket.close(); } catch { /* ignore */ }
    throw err;
  }
}

// Cline 官方客户端指纹头 (逆向自 github.com/cline/cline sdk/packages/llms/src/providers)
// 上游 api.cline.bot 靠这些头判定"是否 Cline 客户端", 缺失/不全会被 403/500 拒绝:
//   "only available via Cline product surfaces" / "empty response content"
// 必须包含动态 X-Task-ID (会话 ID) — 固定值会被风控
function clineFingerprintHeaders(taskId) {
  return {
    'User-Agent': 'Cline/3.0.47',
    'HTTP-Referer': 'https://cline.bot',
    'X-Title': 'Cline',
    'X-IS-MULTIROOT': 'false',
    'X-CLIENT-TYPE': 'cline-sdk',
    'X-CLIENT-VERSION': '3.0.47',
    'X-PLATFORM': 'terminal',
    'X-PLATFORM-VERSION': '3.0.47',
    'X-CORE-VERSION': '0.0.66',
    'X-Task-ID': taskId,
  };
}

function newTaskId() {
  // 尽力生成 UUID 格式会话 ID; crypto.randomUUID 在 Workers 可用
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

async function requestDirect({ targetUrl, method, bodyText, key, request }) {
  const incoming = request && request.headers;
  const headers = new Headers();
  if (key) headers.set('Authorization', `Bearer ${key}`);
  headers.set('Accept', (incoming && incoming.get('accept')) || 'application/json');
  // 官方 Cline 客户端指纹头 (必须, 否则上游 403/500)
  const fp = clineFingerprintHeaders(newTaskId());
  for (const [k, v] of Object.entries(fp)) headers.set(k, v);
  if (bodyText != null && incoming && incoming.get('content-type')) {
    headers.set('Content-Type', incoming.get('content-type'));
  }
  const response = await fetch(targetUrl, { method, headers, body: bodyText });
  // 统一成与 socket 路径相同的结构
  const outHeaders = new Headers(response.headers);
  return { status: response.status, statusText: response.statusText, headers: outHeaders, body: response.body };
}

function buildUpstreamHeaders(request, key) {
  const incoming = request && request.headers;
  const headers = {
    'Accept': (incoming && incoming.get('accept')) || 'application/json',
    'Accept-Encoding': 'identity', // 避免上游 gzip, 省去解压
    ...clineFingerprintHeaders(newTaskId()),
  };
  if (key) headers['Authorization'] = `Bearer ${key}`; // key 为空时不发送 (公开端点), 避免发出 "Bearer null"
  const contentType = incoming && incoming.get('content-type');
  if (contentType) headers['Content-Type'] = contentType;
  return headers;
}

/**
 * 在已建立的 TLS socket 上发送 HTTP/1.1 请求并解析响应
 * 返回 { status, statusText, headers, body }
 */
async function sendHttpRequest(socket, { method, path, host, headers, body }) {
  const headLines = [`${method} ${path || '/'} HTTP/1.1`, `Host: ${host}`];
  for (const [k, v] of Object.entries(headers)) headLines.push(`${k}: ${v}`);

  let bodyBytes = null;
  if (body != null && method !== 'GET' && method !== 'HEAD') {
    bodyBytes = typeof body === 'string' ? encoder.encode(body) : body;
    headLines.push(`Content-Length: ${String(bodyBytes.byteLength)}`);
  }
  headLines.push('Connection: close');
  const headText = headLines.join('\r\n') + '\r\n\r\n';

  const writer = socket.writable.getWriter();
  await writer.write(encoder.encode(headText));
  if (bodyBytes) await writer.write(bodyBytes);
  writer.releaseLock();

  // 读取响应头 (直到 \r\n\r\n)
  const reader = socket.readable.getReader();
  let buf = new Uint8Array(0);
  let headEnd = -1;
  for (;;) {
    headEnd = findDoubleCrlf(buf);
    if (headEnd !== -1) break;
    const res = await withTimeout(
      reader.read(),
      headTimeoutMs,
      '读取上游响应头超时',
      () => { try { socket.close(); } catch { /* ignore */ } },
    );
    if (res.done) throw new Error('上游在返回完整响应头之前关闭了连接');
    if (res.value && res.value.byteLength) buf = concat(buf, res.value);
    if (buf.byteLength > 256 * 1024) throw new Error('上游响应头过大');
  }

  const headBytes = buf.slice(0, headEnd + 4);
  let rest = buf.slice(headEnd + 4);

  const { status, statusText, headers: respHeaders } = parseResponseHead(headBytes);
  if (status >= 100 && status < 200) {
    throw new Error(`收到非预期的临时响应状态码 ${status}`);
  }

  const isChunked = /(^|,)\s*chunked\s*(,|$)/i.test(respHeaders['transfer-encoding'] || '');
  const contentLength = respHeaders['content-length'] != null
    ? Number.parseInt(respHeaders['content-length'], 10)
    : null;
  const noBodyStatus = status === 204 || status === 304;

  let outBody = null;
  if (noBodyStatus) {
    try { socket.close(); } catch { /* ignore */ }
  } else {
    // 响应体流: 首包剩余字节 + 后续 socket 数据
    const base = new ReadableStream({
      start(controller) {
        if (rest && rest.byteLength) controller.enqueue(rest);
        rest = null;
      },
      async pull(controller) {
        const res = await reader.read();
        if (res.done) { controller.close(); return; }
        if (res.value && res.value.byteLength) controller.enqueue(res.value);
      },
      cancel() { try { socket.close(); } catch { /* ignore */ } },
    });

    if (isChunked) {
      outBody = base.pipeThrough(createChunkedDecoder());
    } else if (contentLength != null && Number.isFinite(contentLength) && contentLength >= 0) {
      outBody = base.pipeThrough(createFixedLengthDecoder(contentLength));
    } else {
      outBody = base; // 读到 EOF 为止
    }
  }

  // 过滤逐跳头部; chunked 已解包, 不再透传 content-length
  const outHeaders = new Headers();
  for (const [k, v] of Object.entries(respHeaders)) {
    if (HOP_BY_HOP.has(k)) continue;
    if (k === 'content-length') continue;
    outHeaders.set(k, v);
  }

  return { status, statusText, headers: outHeaders, body: outBody };
}

function parseResponseHead(headBytes) {
  const text = decoder.decode(headBytes);
  const lines = text.split('\r\n');
  const m = /^HTTP\/1\.[01]\s+(\d{3})(?:\s+(.*))?$/.exec(lines[0]);
  if (!m) throw new Error(`无法解析上游响应状态行: ${lines[0]}`);
  const status = parseInt(m[1], 10);
  const statusText = m[2] || '';
  const headers = {};
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const ci = line.indexOf(':');
    if (ci === -1) continue;
    const k = line.slice(0, ci).trim().toLowerCase();
    const v = line.slice(ci + 1).trim();
    headers[k] = headers[k] ? `${headers[k]}, ${v}` : v;
  }
  return { status, statusText, headers };
}

// ============================================================
// 代理诊断: 逐个测试 SOCKS5 代理并报告失败阶段
// ============================================================

async function handleProxyDebug({ keys, proxies }) {
  const results = [];
  for (let i = 0; i < proxies.length; i++) {
    const proxy = proxies[i];
    const step = await testProxy(proxy);
    results.push({
      index: i,
      proxy: `${proxy.hostname}:${proxy.port}`,
      auth: Boolean(proxy.username || proxy.password),
      ok: step.step === 'done',
      step: step.step,        // 成功到达的阶段: tcp / auth / connect / tls / done
      error: step.error || null,
      ms: step.ms,
    });
  }
  return jsonResponse({
    success: true,
    note: 'step 字段表示成功到达的阶段: tcp(连上代理) -> auth(认证通过) -> connect(隧道建立) -> tls(TLS握手成功) -> http(真实HTTP请求完成) -> done(全链路通); 失败会停在对应阶段并给出 error',
    target: `${DEFAULT_UPSTREAM} :443 (GET /api/v1/models 端到端验证)`,
    total: proxies.length,
    results,
  });
}

/** 对单个代理做完整链路测试, 返回 { step, error, ms } */
async function testProxy(proxy) {
  const t0 = Date.now();
  let socket = null;
  try {
    socket = connect(
      { hostname: proxy.hostname, port: proxy.port },
      { secureTransport: 'starttls' },
    );
    await withTimeout(socket.opened, socksTimeoutMs, 'TCP 连接代理超时', () => { try { socket.close(); } catch { /* ignore */ } });
  } catch (err) {
    return { step: 'tcp', error: errMsg(err), ms: Date.now() - t0 };
  }

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const socks = new SocksReader(reader, socket, socksTimeoutMs);

  try {
    // 方法协商 + 认证
    const supportsAuth = Boolean(proxy.username || proxy.password);
    const methods = supportsAuth ? [0x00, 0x02] : [0x00];
    await writer.write(new Uint8Array([0x05, methods.length, ...methods]));
    const chosen = await socks.readExact(2, '方法协商');
    if (chosen[0] !== 0x05) throw Object.assign(new Error(`代理返回未知协议版本 0x${chosen[0].toString(16)} (该端口可能不是 SOCKS5, 而是 HTTP 代理或其他服务)`), { step: 'auth' });
    if (chosen[1] === 0xff) throw Object.assign(new Error('代理不接受客户端提供的认证方式'), { step: 'auth' });
    if (chosen[1] === 0x02) {
      if (!proxy.username || proxy.password == null) throw Object.assign(new Error('代理要求用户名/密码认证, 但未提供'), { step: 'auth' });
      const user = encoder.encode(proxy.username);
      const pass = encoder.encode(proxy.password);
      const authReq = new Uint8Array(3 + user.byteLength + pass.byteLength);
      authReq[0] = 0x01;
      authReq[1] = user.byteLength;
      authReq.set(user, 2);
      authReq[2 + user.byteLength] = pass.byteLength;
      authReq.set(pass, 3 + user.byteLength);
      await writer.write(authReq);
      const auth = await socks.readExact(2, '用户名/密码认证');
      if (auth[0] !== 0x01 || auth[1] !== 0x00) throw Object.assign(new Error('用户名/密码认证失败 (账号或密码错误)'), { step: 'auth' });
    } else if (chosen[1] !== 0x00) {
      throw Object.assign(new Error(`不支持的认证方式 0x${chosen[1].toString(16)}`), { step: 'auth' });
    }

    // CONNECT 到 api.cline.bot:443
    const hostBytes = encoder.encode('api.cline.bot');
    const req = new Uint8Array(7 + hostBytes.byteLength);
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
    req[4] = hostBytes.byteLength;
    req.set(hostBytes, 5);
    req[5 + hostBytes.byteLength] = 0x01; req[6 + hostBytes.byteLength] = 0xbb; // 443
    await writer.write(req);

    const replyHead = await socks.readExact(4, 'CONNECT 响应');
    if (replyHead[0] !== 0x05) throw Object.assign(new Error('CONNECT 响应版本错误'), { step: 'connect' });
    const rep = replyHead[1];
    if (rep !== 0x00) {
      throw Object.assign(new Error(`CONNECT 失败 (0x${rep.toString(16).padStart(2, '0')} ${SOCKS_REP_MESSAGES[rep] || '未知错误'})`), { step: 'connect' });
    }
    const atyp = replyHead[3];
    if (atyp === 0x01) await socks.readExact(6, 'CONNECT 响应地址');
    else if (atyp === 0x04) await socks.readExact(18, 'CONNECT 响应地址');
    else if (atyp === 0x03) {
      const lenByte = await socks.readExact(1, 'CONNECT 响应域名长度');
      await socks.readExact(lenByte[0] + 2, 'CONNECT 响应域名');
    }
  } catch (err) {
    return { step: err.step || 'connect', error: errMsg(err), ms: Date.now() - t0 };
  } finally {
    try { writer.releaseLock(); } catch { /* ignore */ }
    try { reader.releaseLock(); } catch { /* ignore */ }
  }

  // TLS 握手 (证书按 api.cline.bot 校验)
  let tlsSocket;
  try {
    tlsSocket = socket.startTls({ expectedServerHostname: 'api.cline.bot' });
    await withTimeout(tlsSocket.opened, socksTimeoutMs, 'TLS 握手超时', () => { try { tlsSocket.close(); } catch { /* ignore */ } });
  } catch (err) {
    return { step: 'tls', error: errMsg(err), ms: Date.now() - t0 };
  }

  // 端到端验证: 在隧道内发一个真实 HTTP 请求 (GET /api/v1/models),
  // TLS 握手成功但真实请求失败 => 代理对流量限速/拦截或上游风控该出口
  try {
    const result = await sendHttpRequest(tlsSocket, {
      method: 'GET',
      path: '/api/v1/models',
      host: 'api.cline.bot',
      headers: { 'Accept': 'application/json', 'User-Agent': 'cline-api-dispatcher/1.0 (+debug)', 'Accept-Encoding': 'identity' },
      body: null,
    });
    try { await result.body?.cancel(); } catch { /* ignore */ }
    if (result.status >= 200 && result.status < 500) {
      // 4xx 也算链路通 (说明 HTTP 层正常, 只是该端点要求权限等)
      return { step: 'done', error: null, ms: Date.now() - t0, http_status: result.status };
    }
    return { step: 'http', error: `TLS 握手成功但真实请求返回 ${result.status}`, ms: Date.now() - t0, http_status: result.status };
  } catch (err) {
    return { step: 'http', error: `TLS 握手成功但真实请求失败: ${errMsg(err)}`, ms: Date.now() - t0 };
  }
}

// ============================================================
// SOCKS5 客户端 (RFC 1928 / RFC 1929) + TLS 升级
// ============================================================

class SocksReader {
  constructor(reader, socket, timeoutMs) {
    this.reader = reader;
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.buffer = new Uint8Array(0);
  }

  async readExact(n, label) {
    while (this.buffer.byteLength < n) {
      const res = await withTimeout(
        this.reader.read(),
        this.timeoutMs,
        `SOCKS5 握手超时: ${label}`,
        () => { try { this.socket.close(); } catch { /* ignore */ } },
      );
      if (res.done) throw new Error(`SOCKS5: ${label} 时连接被关闭`);
      if (res.value && res.value.byteLength) this.buffer = concat(this.buffer, res.value);
    }
    const out = this.buffer.slice(0, n);
    this.buffer = this.buffer.slice(n);
    return out;
  }
}

/**
 * 通过 SOCKS5 代理建立到 targetHost:targetPort 的隧道, 并升级为 TLS
 * 返回可用的 TLS Socket (readable/writable)
 */
async function socks5Tunnel(proxy, targetHost, targetPort) {
  let socket;
  try {
    socket = connect(
      { hostname: proxy.hostname, port: proxy.port },
      { secureTransport: 'starttls' }, // 先明文, 之后 startTls 升级
    );
  } catch (err) {
    throw new Error(`无法创建到 SOCKS5 代理的连接 ${proxy.hostname}:${proxy.port}: ${errMsg(err)}`);
  }

  // 1) TCP 连接代理
  try {
    await withTimeout(
      socket.opened,
      socksTimeoutMs,
      `连接 SOCKS5 代理超时: ${proxy.hostname}:${proxy.port}`,
      () => { try { socket.close(); } catch { /* ignore */ } },
    );
  } catch (err) {
    try { socket.close(); } catch { /* ignore */ }
    throw new Error(`连接 SOCKS5 代理失败 ${proxy.hostname}:${proxy.port}: ${errMsg(err)}`);
  }

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const socks = new SocksReader(reader, socket, socksTimeoutMs);

  try {
    // 2) 方法协商: 有账号密码则提供 0x00(无认证) + 0x02(用户名/密码)
    const supportsAuth = Boolean(proxy.username || proxy.password);
    const methods = supportsAuth ? [0x00, 0x02] : [0x00];
    await writer.write(new Uint8Array([0x05, methods.length, ...methods]));
    const chosen = await socks.readExact(2, '方法协商');
    if (chosen[0] !== 0x05) throw new Error(`SOCKS5: 代理返回未知协议版本 0x${chosen[0].toString(16)}`);
    if (chosen[1] === 0xff) throw new Error('SOCKS5: 代理不接受客户端提供的认证方式');
    if (chosen[1] === 0x02) {
      if (!proxy.username || proxy.password == null) {
        throw new Error('SOCKS5: 代理要求用户名/密码认证, 但 SOCKS5 地址中未提供');
      }
      const user = encoder.encode(proxy.username);
      const pass = encoder.encode(proxy.password);
      if (user.byteLength > 255 || pass.byteLength > 255) {
        throw new Error('SOCKS5: 用户名或密码过长 (RFC1929 限制 255 字节)');
      }
      const authReq = new Uint8Array(3 + user.byteLength + pass.byteLength);
      authReq[0] = 0x01;
      authReq[1] = user.byteLength;
      authReq.set(user, 2);
      authReq[2 + user.byteLength] = pass.byteLength;
      authReq.set(pass, 3 + user.byteLength);
      await writer.write(authReq);
      const auth = await socks.readExact(2, '用户名/密码认证');
      if (auth[0] !== 0x01 || auth[1] !== 0x00) throw new Error('SOCKS5: 用户名/密码认证失败');
    } else if (chosen[1] !== 0x00) {
      throw new Error(`SOCKS5: 不支持的认证方式 0x${chosen[1].toString(16)}`);
    }

    // 3) CONNECT: ATYP=3 (域名), 即 socks5h 语义 —— 由代理解析目标 DNS
    const hostBytes = encoder.encode(targetHost);
    if (hostBytes.byteLength > 255) throw new Error('SOCKS5: 目标主机名过长');
    const req = new Uint8Array(7 + hostBytes.byteLength);
    req[0] = 0x05; // VER
    req[1] = 0x01; // CMD: CONNECT
    req[2] = 0x00; // RSV
    req[3] = 0x03; // ATYP: domain
    req[4] = hostBytes.byteLength;
    req.set(hostBytes, 5);
    req[5 + hostBytes.byteLength] = (targetPort >> 8) & 0xff;
    req[6 + hostBytes.byteLength] = targetPort & 0xff;
    await writer.write(req);

    // 4) CONNECT 响应: VER REP RSV ATYP ADDR PORT
    const replyHead = await socks.readExact(4, 'CONNECT 响应');
    if (replyHead[0] !== 0x05) throw new Error('SOCKS5: CONNECT 响应版本错误');
    const rep = replyHead[1];
    if (rep !== 0x00) {
      throw new Error(`SOCKS5: CONNECT 失败 (0x${rep.toString(16).padStart(2, '0')} ${SOCKS_REP_MESSAGES[rep] || '未知错误'})`);
    }
    const atyp = replyHead[3];
    if (atyp === 0x01) {
      await socks.readExact(6, 'CONNECT 响应地址'); // IPv4 + port
    } else if (atyp === 0x04) {
      await socks.readExact(18, 'CONNECT 响应地址'); // IPv6 + port
    } else if (atyp === 0x03) {
      const lenByte = await socks.readExact(1, 'CONNECT 响应域名长度');
      await socks.readExact(lenByte[0] + 2, 'CONNECT 响应域名');
    } else {
      throw new Error(`SOCKS5: 未知地址类型 0x${atyp.toString(16)}`);
    }
    // 此时不会有额外数据: TLS ServerHello 只会在我们发出 ClientHello 之后到达
  } catch (err) {
    try { socket.close(); } catch { /* ignore */ }
    throw err instanceof Error ? err : new Error(String(err));
  } finally {
    try { writer.releaseLock(); } catch { /* ignore */ }
    try { reader.releaseLock(); } catch { /* ignore */ }
  }

  // 5) 升级 TLS: 证书/SNI 按目标主机名校验
  let tlsSocket;
  try {
    tlsSocket = socket.startTls({ expectedServerHostname: targetHost });
  } catch (err) {
    try { socket.close(); } catch { /* ignore */ }
    const msg = errMsg(err);
    if (msg.includes('expectedServerHostname')) {
      throw new Error('当前运行时不支持 startTls({ expectedServerHostname }), 无法对隧道目标校验 TLS 证书');
    }
    throw err instanceof Error ? err : new Error(msg);
  }

  try {
    await withTimeout(
      tlsSocket.opened,
      socksTimeoutMs,
      `TLS 握手超时 (${targetHost})`,
      () => { try { tlsSocket.close(); } catch { /* ignore */ } },
    );
  } catch (err) {
    try { tlsSocket.close(); } catch { /* ignore */ }
    throw new Error(`TLS 握手失败 (${targetHost}): ${errMsg(err)}`);
  }

  return tlsSocket;
}

// ============================================================
// 流工具: chunked 解码 / 定长截断
// ============================================================

function createChunkedDecoder() {
  let buffer = new Uint8Array(0);
  let state = 'size'; // size | data | crlf | trailer | done
  let remaining = 0;

  return new TransformStream({
    transform(chunk, controller) {
      if (state === 'done') return;
      let data = chunk;
      while (data.byteLength > 0) {
        if (state === 'size') {
          const idx = findCrlf(data);
          if (idx === -1) { buffer = concat(buffer, data); return; }
          const lineBytes = concat(buffer, data.slice(0, idx));
          buffer = new Uint8Array(0);
          const size = Number.parseInt(decoder.decode(lineBytes).split(';')[0].trim(), 16);
          if (Number.isNaN(size) || size < 0) throw new Error('chunked: 非法的 chunk 大小');
          data = data.slice(idx + 2);
          if (size === 0) {
            state = 'trailer';
          } else {
            remaining = size;
            state = 'data';
          }
        } else if (state === 'data') {
          const take = Math.min(remaining, data.byteLength);
          if (take > 0) controller.enqueue(data.slice(0, take));
          remaining -= take;
          data = data.slice(take);
          if (remaining === 0) state = 'crlf';
        } else if (state === 'crlf') {
          if (buffer.byteLength + data.byteLength < 2) { buffer = concat(buffer, data); return; }
          const combined = concat(buffer, data);
          buffer = new Uint8Array(0);
          data = combined.slice(2);
          state = 'size';
        } else if (state === 'trailer') {
          const idx = findCrlf(data);
          if (idx === -1) { buffer = concat(buffer, data); return; }
          const lineBytes = concat(buffer, data.slice(0, idx));
          buffer = new Uint8Array(0);
          data = data.slice(idx + 2);
          if (lineBytes.byteLength === 0) {
            state = 'done';
            controller.close();
            return;
          }
          // 忽略 trailer 行, 继续等待结束空行
        }
      }
    },
    flush(controller) {
      if (state !== 'done') {
        try { controller.close(); } catch { /* ignore */ }
      }
    },
  });
}

function createFixedLengthDecoder(total) {
  let remaining = total;
  return new TransformStream({
    transform(chunk, controller) {
      if (remaining <= 0) return;
      const take = Math.min(remaining, chunk.byteLength);
      remaining -= take;
      if (take > 0) controller.enqueue(chunk.slice(0, take));
      if (remaining === 0) controller.close();
    },
    flush(controller) {
      if (remaining > 0) {
        try { controller.close(); } catch { /* ignore */ } // 上游提前断开, 尽力而为
      }
    },
  });
}

// ============================================================
// 通用工具
// ============================================================

function buildOutgoingResponse(result, { keyIndex, viaProxy, attempt, proxy, fallback }) {
  const headers = result.headers instanceof Headers ? result.headers : new Headers();
  addCors(headers);
  headers.set('X-Dispatch-Key-Index', String(keyIndex));
  headers.set('X-Dispatch-Mode', fallback ? 'direct-fallback' : (viaProxy ? 'socks5' : 'direct'));
  if (proxy && !fallback) headers.set('X-Dispatch-Proxy', `${proxy.hostname}:${proxy.port}`);
  headers.set('X-Dispatch-Attempt', String(attempt + 1));
  const noBody = result.status === 204 || result.status === 304;
  return new Response(noBody ? null : result.body, {
    status: result.status,
    statusText: result.statusText || undefined,
    headers,
  });
}

function getConfigKeys(value) {
  const raw = value('CLINE_API_KEYS') || value('CLINE_API_KEY') || value('UPSTREAM_API_KEYS') || '';
  return parseList(raw);
}

function getConfigProxies(value) {
  const raw = value('SOCKS5_PROXIES') || value('SOCKS5_PROXY') || '';
  const out = [];
  for (const item of parseList(raw)) {
    try {
      out.push(parseProxyUrl(item));
    } catch (err) {
      console.warn(`忽略无效的 SOCKS5 配置: ${item} (${errMsg(err)})`);
    }
  }
  return out;
}

function parseList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((s) => String(s).trim()).filter(Boolean);
  return String(value).split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
}

function parseProxyUrl(str) {
  let s = String(str).trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'socks5://' + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error(`无效的 SOCKS5 地址: ${str}`);
  }
  const scheme = u.protocol.replace(':', '').toLowerCase();
  if (scheme !== 'socks5' && scheme !== 'socks5h' && scheme !== 'socks') {
    throw new Error(`仅支持 socks5 代理: ${str}`);
  }
  const port = u.port ? parseInt(u.port, 10) : 1080;
  if (!u.hostname || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`无效的 SOCKS5 主机/端口: ${str}`);
  }
  return {
    hostname: u.hostname,
    port,
    username: safeDecode(u.username),
    password: safeDecode(u.password),
    raw: str,
  };
}

function safeDecode(v) {
  if (!v) return '';
  try { return decodeURIComponent(v); } catch { return v; }
}

function sanitizeUpstream(v) {
  return String(v || '').trim().replace(/\/+$/, '');
}

function extractAccessToken(request) {
  const auth = request.headers.get('authorization') || '';
  if (auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  return request.headers.get('x-api-key')
    || request.headers.get('x-access-token')
    || request.headers.get('x-auth-token')
    || '';
}

function intWithDefault(v, dflt) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : dflt;
}

function concat(a, b) {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

function findCrlf(bytes) {
  for (let i = 0; i + 1 < bytes.byteLength; i++) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) return i;
  }
  return -1;
}

function findDoubleCrlf(bytes) {
  for (let i = 0; i + 3 < bytes.byteLength; i++) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a && bytes[i + 2] === 0x0d && bytes[i + 3] === 0x0a) return i;
  }
  return -1;
}

function withTimeout(promise, ms, message, onTimeout) {
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      if (onTimeout) { try { onTimeout(); } catch { /* ignore */ } }
      reject(new Error(message));
    }, ms);
  });
  // 超时获胜后, 原 promise 稍后可能 reject, 挂一个空 catch 避免未处理 rejection
  promise.catch(() => { /* ignore */ });
  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function errMsg(err) {
  return (err && err.message) ? String(err.message) : String(err);
}

// ============================================================
// 响应辅助
// ============================================================

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Max-Age': '86400',
};

function addCors(headers) {
  for (const [k, v] of Object.entries(CORS_HEADERS)) headers.set(k, v);
  headers.set('Access-Control-Expose-Headers', 'X-Dispatch-Key-Index, X-Dispatch-Mode, X-Dispatch-Proxy, X-Dispatch-Attempt');
  return headers;
}

function corsPreflight() {
  return new Response(null, { status: 204, headers: addCors(new Headers()) });
}

function jsonResponse(obj, status = 200) {
  const headers = new Headers({ 'content-type': 'application/json; charset=utf-8' });
  addCors(headers);
  return new Response(JSON.stringify(obj, null, 2), { status, headers });
}
