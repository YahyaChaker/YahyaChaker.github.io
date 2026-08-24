import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

const NEON_AUTH_URL = 'https://ep-cold-poetry-axjdfnxy.neonauth.c-4.us-east-2.aws.neon.tech/neondb/auth';
const NEON_REST_URL = 'https://ep-cold-poetry-axjdfnxy.apirest.c-4.us-east-2.aws.neon.tech/neondb/rest/v1';

// Global CORS & preflight middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Prefer, Origin, Accept, Cookie, X-Requested-With');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Type, Authorization, Set-Cookie');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// Raw body parser for proxy routes
app.use('/api', express.raw({ type: '*/*', limit: '10mb' }));

// Helper to extract cookies
function getRawCookies(resp) {
  if (typeof resp.headers.getSetCookie === 'function') {
    return resp.headers.getSetCookie();
  }
  const single = resp.headers.get('set-cookie');
  return single ? [single] : [];
}

// Format cookies for iframe preview compatibility
function formatIframeCookies(rawCookies) {
  return rawCookies.map(cookieStr => {
    let c = cookieStr.replace(/Domain=[^;]+;?\s*/gi, '');
    if (!/SameSite=/i.test(c)) {
      c += '; SameSite=None; Secure; Partitioned';
    } else {
      c = c.replace(/SameSite=[^;]+/i, 'SameSite=None; Secure; Partitioned');
    }
    return c;
  });
}

// In-memory session-to-JWT cache to ensure seamless token acquisition in iframe environments
const sessionJwtCache = new Map();

// Auth Proxy
app.all('/api/auth*', async (req, res) => {
  try {
    const subpath = req.originalUrl.replace(/^\/api\/auth/, '') || '';
    const targetUrl = NEON_AUTH_URL + subpath;

    const forwardHeaders = {};
    for (const [key, val] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      if (['host', 'connection', 'content-length'].includes(lower)) continue;
      forwardHeaders[key] = val;
    }
    forwardHeaders['origin'] = 'https://yahyachaker.github.io';
    forwardHeaders['referer'] = 'https://yahyachaker.github.io/';

    const fetchOpts = {
      method: req.method,
      headers: forwardHeaders,
      redirect: 'manual'
    };

    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body && req.body.length > 0) {
      fetchOpts.body = req.body;
    }

    const resp = await fetch(targetUrl, fetchOpts);
    console.log(`[AUTH PROXY] ${req.method} ${subpath} -> ${resp.status}`);

    const rawCookies = getRawCookies(resp);
    const iframeCookies = formatIframeCookies(rawCookies);

    // If sign-in or sign-up succeeded, proactively fetch the JWT token server-side
    if (resp.ok && (subpath === '/sign-in/email' || subpath === '/sign-up/email')) {
      const respData = await resp.json().catch(() => null);
      if (respData) {
        let cookieHeader = rawCookies.map(c => c.split(';')[0]).join('; ');
        let token = null;

        if (cookieHeader) {
          try {
            const tokenResp = await fetch(NEON_AUTH_URL + '/token', {
              headers: {
                'origin': 'https://yahyachaker.github.io',
                'referer': 'https://yahyachaker.github.io/',
                'cookie': cookieHeader
              }
            });
            if (tokenResp.ok) {
              const tokenData = await tokenResp.json().catch(() => null);
              token = tokenData && (tokenData.token || tokenData.jwt);
            }
          } catch (e) {
            console.warn('[AUTH PROXY] Could not pre-fetch JWT token:', e.message);
          }
        }

        if (token) {
          respData.token = token;
          respData.jwt = token;
          if (respData.user && respData.user.id) {
            sessionJwtCache.set(respData.user.id, { token, exp: Date.now() + 300000 });
          }
        }

        res.status(resp.status);
        resp.headers.forEach((value, key) => {
          const lower = key.toLowerCase();
          if (lower === 'set-cookie' || lower.startsWith('access-control-') || lower === 'content-length') return;
          res.setHeader(key, value);
        });
        if (iframeCookies.length > 0) {
          res.setHeader('Set-Cookie', iframeCookies);
        }
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        return res.json(respData);
      }
    }

    res.status(resp.status);

    resp.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (lower === 'set-cookie' || lower.startsWith('access-control-')) return;
      res.setHeader(key, value);
    });

    if (iframeCookies.length > 0) {
      res.setHeader('Set-Cookie', iframeCookies);
    }

    const respBuffer = Buffer.from(await resp.arrayBuffer());
    res.send(respBuffer);
  } catch (err) {
    console.error('[AUTH PROXY ERROR]', err);
    res.status(500).json({ error: 'Auth proxy error: ' + err.message });
  }
});

// REST API Proxy
app.all('/api/rest*', async (req, res) => {
  try {
    const subpath = req.originalUrl.replace(/^\/api\/rest/, '') || '';
    const targetUrl = NEON_REST_URL + subpath;

    const forwardHeaders = {};
    for (const [key, val] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      if (['host', 'connection', 'content-length'].includes(lower)) continue;
      forwardHeaders[key] = val;
    }
    forwardHeaders['origin'] = 'https://yahyachaker.github.io';
    forwardHeaders['referer'] = 'https://yahyachaker.github.io/';

    const fetchOpts = {
      method: req.method,
      headers: forwardHeaders,
      redirect: 'manual'
    };

    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body && req.body.length > 0) {
      fetchOpts.body = req.body;
    }

    const resp = await fetch(targetUrl, fetchOpts);
    console.log(`[REST PROXY] ${req.method} ${subpath} -> ${resp.status}`);

    res.status(resp.status);

    resp.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (lower.startsWith('access-control-')) return;
      res.setHeader(key, value);
    });

    const respBuffer = Buffer.from(await resp.arrayBuffer());
    res.send(respBuffer);
  } catch (err) {
    console.error('[REST PROXY ERROR]', err);
    res.status(500).json({ error: 'REST proxy error: ' + err.message });
  }
});

// Static assets
app.use(express.static(__dirname));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`The Ledger server running on http://0.0.0.0:${PORT}`);
});
