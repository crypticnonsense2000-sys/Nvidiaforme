const express = require('express');
const axios = require('axios');
const { Agent: HttpsAgent } = require('https');
const { URL } = require('url');
const dns = require('dns');
const { pipeline } = require('stream');
const { promisify } = require('util');

const streamPipeline = promisify(pipeline);

const app = express();
const PORT = parseInt(process.env.PORT) || 3000;

app.disable('x-powered-by');
app.disable('etag');

// ==========================================
// DNS CACHE
// ==========================================
class SecureDnsCache {
  constructor(maxSize = 100, ttlMs = 300000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttl = ttlMs;
  }
  
  _normalize(hostname) {
    return hostname.toLowerCase().trim();
  }

  get(hostname) {
    const key = this._normalize(hostname);
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    if (Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(key);
      return null;
    }
    
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry;
  }
  
  set(hostname, address, family) {
    const key = this._normalize(hostname);
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    this.cache.delete(key);
    this.cache.set(key, { address, family, timestamp: Date.now() });
  }
}

const dnsCache = new SecureDnsCache();

function customDnsLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  
  if (options && options.all) {
    return dns.lookup(hostname, options, callback);
  }

  const cached = dnsCache.get(hostname);
  if (cached) {
    return process.nextTick(() => callback(null, cached.address, cached.family));
  }
  
  dns.lookup(hostname, options, (err, address, family) => {
    if (!err && address) {
      dnsCache.set(hostname, address, family);
    }
    callback(err, address, family);
  });
}

// ==========================================
// CONFIGURATION
// ==========================================
// Default to Airforce API - you can override in Render dashboard if needed
const UPSTREAM_PROXY_URL = process.env.UPSTREAM_PROXY_URL || 'https://api.airforce/v1';
const UPSTREAM_API_KEY = process.env.UPSTREAM_API_KEY; // Optional fallback

if (!UPSTREAM_PROXY_URL) {
  console.error('FATAL: UPSTREAM_PROXY_URL not configured');
  process.exit(1);
}

try {
  const upstreamUrl = new URL(UPSTREAM_PROXY_URL);
  if (upstreamUrl.protocol !== 'https:') {
    console.warn('WARNING: Upstream URL should use HTTPS for security');
  }
} catch (e) {
  console.error('FATAL: Invalid UPSTREAM_PROXY_URL');
  process.exit(1);
}

const ENABLE_LOGGING = process.env.ENABLE_LOGGING !== 'false';
const STRIP_QUERY_PARAMS = process.env.STRIP_QUERY_PARAMS === 'true';

const METADATA_PATTERNS = [
  /^user[-_]?id$/i, /^session[-_]?id$/i, /^device[-_]?id$/i,
  /^client[-_]?id$/i, /^customer[-_]?id$/i, /^account[-_]?id$/i,
  /^tracking[-_]?id$/i, /^analytics[-_]?id$/i, /^request[-_]?id$/i,
  /^correlation[-_]?id$/i, /^trace[-_]?id$/i, /^span[-_]?id$/i,
  /^fingerprint$/i, /^ip[-_]?address$/i, /^client[-_]?ip$/i,
  /^remote[-_]?ip$/i, /^user[-_]?agent$/i, /^referer$/i,
  /^referrer$/i, /^utm_/i, /^x[-_]/i, /^_[a-z]{1,4}$/i
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
];

const ACCEPT_LANGUAGES = [
  'en-US,en;q=0.9',
  'en-GB,en;q=0.9',
  'en-US,en;q=0.9,es;q=0.8',
];

const httpsAgent = new HttpsAgent({ 
  rejectUnauthorized: true,
  keepAlive: true,
  maxSockets: 50,
  maxFreeSockets: 10,
  timeout: 60000,
  keepAliveMsecs: 1000,
  lookup: customDnsLookup
});

// ==========================================
// MIDDLEWARE
// ==========================================

// CORS for JanitorAI browser client
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json({ limit: '1mb', strict: true }));

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }
  next(err);
});

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

function sanitizePath(path) {
  return path.replace(/[^\w\-\/\.]/g, '').replace(/\.{2,}/g, '');
}

function sanitizeRequestBody(body, depth = 0) {
  const MAX_DEPTH = 10;
  
  if (!body || typeof body !== 'object') return body;
  
  if (depth > MAX_DEPTH) return {};
  
  if (Array.isArray(body)) {
    return body.map(item => sanitizeRequestBody(item, depth + 1));
  }
  
  const cleaned = {};
  for (const [key, value] of Object.entries(body)) {
    const isMetadata = METADATA_PATTERNS.some(pattern => pattern.test(key));
    if (!isMetadata) {
      cleaned[key] = sanitizeRequestBody(value, depth + 1);
    }
  }
  return cleaned;
}

function getRandomUserAgent() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

function getRandomAcceptLanguage() {
  return ACCEPT_LANGUAGES[Math.floor(Math.random() * ACCEPT_LANGUAGES.length)];
}

function logRequest(method, status, note = '') {
  if (!ENABLE_LOGGING) return;
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${method} ${status} ${note}`);
}

// ==========================================
// MAIN PROXY ENDPOINT
// ==========================================
app.all('/v1/*', async (req, res) => {
  if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const abortController = new AbortController();
  req.on('close', () => abortController.abort());

  try {
    const rawPath = req.path.substring(3);
    const safePath = sanitizePath(rawPath);
    
    if (!safePath) {
      return res.status(400).json({ error: 'Invalid path' });
    }
    
    const baseUrl = UPSTREAM_PROXY_URL.replace(/\/+$/, '');
    const fullUrl = `${baseUrl}/${safePath}`;
    
    let targetUrl;
    try {
      targetUrl = new URL(fullUrl);
      if (targetUrl.protocol !== 'https:' && targetUrl.protocol !== 'http:') {
        throw new Error('Invalid protocol');
      }
    } catch (e) {
      return res.status(400).json({ error: 'Invalid target URL' });
    }

    const body = sanitizeRequestBody(req.body);

    const headers = {
      'content-type': 'application/json',
      'user-agent': getRandomUserAgent(),
      'accept': 'application/json, text/plain, */*',
      'accept-language': getRandomAcceptLanguage(),
      'accept-encoding': 'gzip, deflate, br',
      'cache-control': 'no-cache',
      'pragma': 'no-cache',
    };
    
    // KEY CHANGE: Forward API key from JanitorAI (client), or use env fallback
    // JanitorAI sends: Authorization: Bearer sk-...
    if (req.headers.authorization) {
      headers['authorization'] = req.headers.authorization;
      logRequest(req.method, 200, 'Using client API key');
    } else if (req.headers['x-api-key']) {
      headers['authorization'] = `Bearer ${req.headers['x-api-key']}`;
      logRequest(req.method, 200, 'Using client X-Api-Key');
    } else if (UPSTREAM_API_KEY) {
      headers['authorization'] = `Bearer ${UPSTREAM_API_KEY}`;
      logRequest(req.method, 200, 'Using env API key');
    }

    const config = {
      method: req.method.toLowerCase(),
      url: targetUrl.toString(),
      headers: headers,
      data: body,
      params: STRIP_QUERY_PARAMS ? {} : req.query,
      responseType: 'stream',
      validateStatus: () => true,
      timeout: 300000,
      maxRedirects: 5,
      signal: abortController.signal,
      decompress: true,
      httpsAgent: httpsAgent,
    };

    logRequest(req.method, 200, 'FWD');

    const upstreamRes = await axios(config);

    const SAFE_RESPONSE_HEADERS = [
      'content-type',
      'transfer-encoding',
      'content-encoding'
    ];
    
    SAFE_RESPONSE_HEADERS.forEach(header => {
      const val = upstreamRes.headers[header];
      if (val) res.setHeader(header, val);
    });

    res.status(upstreamRes.status);

    await streamPipeline(upstreamRes.data, res);
    
    logRequest(req.method, upstreamRes.status, 'OK');

  } catch (error) {
    if (res.headersSent) return;
    
    if (error.code === 'ERR_STREAM_PREMATURE_CLOSE') return;

    let status = 500;
    let message = 'Internal error';
    let type = 'proxy_error';
    
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT' || error.code === 'ERR_CANCELED') {
      status = 504;
      message = 'Gateway timeout';
      type = 'timeout_error';
    } else if (error.response) {
      status = error.response.status || 500;
      message = 'Upstream error';
      type = 'upstream_error';
    } else if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
      status = 502;
      message = 'Bad gateway';
      type = 'dns_error';
    } else if (error.code === 'ECONNREFUSED') {
      status = 503;
      message = 'Service unavailable';
      type = 'connection_error';
    }

    logRequest(req.method, status, `ERR: ${error.code || type}`);
    res.status(status).json({ error: { message, type } });
  }
});

// ==========================================
// UTILITY ENDPOINTS
// ==========================================

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '6.0.0-janitor', upstream: UPSTREAM_PROXY_URL });
});

app.get('/stats', (req, res) => {
  if (process.env.ENABLE_STATS !== 'true') {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json({ 
    uptime: Math.floor(process.uptime()),
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    cacheSize: dnsCache.cache.size,
    status: 'running'
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  logRequest('ERR', 500, err.message);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// ==========================================
// PROCESS MANAGEMENT
// ==========================================

let server;

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  if (server) {
    server.close(() => process.exit(1));
  } else {
    process.exit(1);
  }
});

server = app.listen(PORT, () => {
  console.log(`JanitorAI Proxy running on port ${PORT}`);
  console.log(`Upstream: ${UPSTREAM_PROXY_URL}`);
  console.log(`Mode: ${UPSTREAM_API_KEY ? 'Env Key + Client Key' : 'Client Key Only'}`);
  console.log(`Features: Logging=${ENABLE_LOGGING}, StripQuery=${STRIP_QUERY_PARAMS}`);
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

function gracefulShutdown(signal) {
  console.log(`Received ${signal}, shutting down gracefully...`);
  
  server.close(() => {
    console.log('HTTP server closed');
    httpsAgent.destroy();
    console.log('HTTPS agent destroyed');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('Forced shutdown after 30s timeout');
    process.exit(1);
  }, 30000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));