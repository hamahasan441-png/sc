/**
 * Unified API client for the ATOMIC dashboard.
 *
 * Responsibilities (all in one place instead of scattered across 70+
 * ad-hoc fetch() calls in the legacy template):
 *   - Unwrap the `{status, data}` envelope; throw on `status === "error"`.
 *   - Attach the CSRF token (double-submit cookie) on unsafe methods,
 *     bootstrapping it from /api/csrf-token on first use.
 *   - Attach an optional `X-API-Key` from localStorage.
 *   - Cancel in-flight requests via AbortController (views pass a signal
 *     so navigating away aborts stale loads instead of racing the DOM).
 *   - De-duplicate identical concurrent GETs and serve a short TTL cache
 *     so tab switches don't re-hammer the backend.
 */

const CSRF_COOKIE = "csrf_token";
const CSRF_HEADER = "X-CSRF-Token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const API_KEY_STORAGE = "atomic_api_key";
const ACCESS_TOKEN_STORAGE = "atomic_access_token";
const REFRESH_TOKEN_STORAGE = "atomic_refresh_token";

/** @type {Map<string, {expires:number, data:any}>} */
const _cache = new Map();
/** @type {Map<string, Promise<any>>} */
const _inflight = new Map();

function readCookie(name) {
  const prefix = name + "=";
  for (const part of (document.cookie || "").split(";")) {
    const c = part.replace(/^\s+/, "");
    if (c.startsWith(prefix)) return decodeURIComponent(c.slice(prefix.length));
  }
  return "";
}

let _csrfPrimed = null;
async function ensureCsrf() {
  if (readCookie(CSRF_COOKIE)) return;
  if (!_csrfPrimed) {
    _csrfPrimed = fetch("/api/csrf-token", { credentials: "same-origin" })
      .catch(() => {})
      .finally(() => {
        _csrfPrimed = null;
      });
  }
  await _csrfPrimed;
}

export function setApiKey(key) {
  if (key) localStorage.setItem(API_KEY_STORAGE, key);
  else localStorage.removeItem(API_KEY_STORAGE);
}

export function getApiKey() {
  return localStorage.getItem(API_KEY_STORAGE) || "";
}

export function setAuthTokens(data = {}) {
  if (data.access_token) localStorage.setItem(ACCESS_TOKEN_STORAGE, data.access_token);
  if (data.refresh_token) localStorage.setItem(REFRESH_TOKEN_STORAGE, data.refresh_token);
}

export function clearAuthTokens() {
  localStorage.removeItem(ACCESS_TOKEN_STORAGE);
  localStorage.removeItem(REFRESH_TOKEN_STORAGE);
  _cache.clear();
}

export function getAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_STORAGE) || "";
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_STORAGE) || "";
}

let _refreshing = null;
async function refreshAccessToken() {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;
  if (_refreshing) return _refreshing;
  _refreshing = (async () => {
    await ensureCsrf();
    const headers = { "Content-Type": "application/json" };
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) headers[CSRF_HEADER] = csrf;
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
      headers,
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    const payload = await res.json().catch(() => null);
    if (!res.ok || !payload || payload.status !== "success") {
      clearAuthTokens();
      return false;
    }
    setAuthTokens(payload.data || {});
    return true;
  })().finally(() => { _refreshing = null; });
  return _refreshing;
}

/**
 * Core request. Returns the unwrapped `data` payload.
 * @param {string} path
 * @param {{method?:string, body?:any, signal?:AbortSignal, cache?:boolean, ttl?:number, raw?:boolean}} [opts]
 */
export async function request(path, opts = {}) {
  const method = (opts.method || "GET").toUpperCase();
  const useCache = opts.cache && method === "GET";
  const cacheKey = method + " " + path;

  if (useCache) {
    const hit = _cache.get(cacheKey);
    if (hit && hit.expires > Date.now()) return hit.data;
    const pending = _inflight.get(cacheKey);
    if (pending) return pending;
  }

  const run = (async () => {
    const headers = {};
    const init = { method, credentials: "same-origin", headers };

    if (opts.signal) init.signal = opts.signal;

    const apiKey = getApiKey();
    if (apiKey) headers["X-API-Key"] = apiKey;
    const accessToken = getAccessToken();
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body);
    }

    if (!SAFE_METHODS.has(method)) {
      await ensureCsrf();
      const token = readCookie(CSRF_COOKIE);
      if (token) headers[CSRF_HEADER] = token;
    }

    let res = await fetch(path, init);

    if (
      res.status === 401 &&
      !opts._authRetried &&
      !path.startsWith("/api/auth/login") &&
      !path.startsWith("/api/auth/setup") &&
      !path.startsWith("/api/auth/refresh") &&
      await refreshAccessToken()
    ) {
      headers.Authorization = `Bearer ${getAccessToken()}`;
      res = await fetch(path, init);
    }

    if (opts.raw) return res;

    let payload = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      payload = await res.json().catch(() => null);
    }

    if (!res.ok) {
      const msg = (payload && payload.data) || `HTTP ${res.status}`;
      const err = new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
      err.status = res.status;
      throw err;
    }

    if (payload && typeof payload === "object" && "status" in payload) {
      if (payload.status === "error") {
        const err = new Error(typeof payload.data === "string" ? payload.data : "Request failed");
        err.status = res.status;
        throw err;
      }
      return payload.data;
    }
    return payload;
  })();

  if (useCache) {
    _inflight.set(cacheKey, run);
    try {
      const data = await run;
      _cache.set(cacheKey, { expires: Date.now() + (opts.ttl || 3000), data });
      return data;
    } finally {
      _inflight.delete(cacheKey);
    }
  }
  return run;
}

/** Invalidate cached GETs whose key contains `fragment` (or all when omitted). */
export function invalidate(fragment) {
  if (!fragment) return _cache.clear();
  for (const key of _cache.keys()) if (key.includes(fragment)) _cache.delete(key);
}

export const api = {
  get: (path, opts) => request(path, { ...opts, method: "GET" }),
  post: (path, body, opts) => request(path, { ...opts, method: "POST", body }),
  put: (path, body, opts) => request(path, { ...opts, method: "PUT", body }),
  del: (path, opts) => request(path, { ...opts, method: "DELETE" }),
  invalidate,
  setApiKey,
  getApiKey,
  setAuthTokens,
  clearAuthTokens,
  getAccessToken,
  getRefreshToken,
};
