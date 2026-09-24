import { browserGateSource } from './browser.js';
import { browserSource } from '../vendor/fpscanner-browser.js';
import { cleanTalkPasses, ipSecurityPasses, udgerPasses, fingerprintPasses } from './policy.js';

const PREFIX = '/__checkout_security/';
const TTL = 60000;
const API_TIMEOUT = 12000;
const MAX_BODY = 65536;
const encoder = new TextEncoder();

function response(body, type = 'application/json', status = 200) {
  return new Response(body, { status, headers: {
    'Content-Type': type + ';charset=UTF-8',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'no-referrer'
  } });
}

function deny(config) {
  return new Response(null, { status: 303, headers: {
    'Location': config.fallbackUrl,
    'Cache-Control': 'no-cache, no-store'
  } });
}

function base64(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unbase64(value) {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

async function signingKey(config) {
  if (![config.cleantalkKey, config.ipgeolocationKey, config.udgerKey].every(key => typeof key === 'string' && key.trim())) throw new Error('Configuration');
  const material = encoder.encode(JSON.stringify(['checkout-security-v1', config.cleantalkKey, config.ipgeolocationKey, config.udgerKey]));
  return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', material), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function sign(value, config) {
  const payload = base64(encoder.encode(JSON.stringify(value)));
  const signature = await crypto.subtle.sign('HMAC', await signingKey(config), encoder.encode(payload));
  return payload + '.' + base64(new Uint8Array(signature));
}

async function verify(token, config) {
  if (typeof token !== 'string' || token.length > 16000) throw new Error('Token');
  const parts = token.split('.');
  if (parts.length !== 2 || !await crypto.subtle.verify('HMAC', await signingKey(config), unbase64(parts[1]), encoder.encode(parts[0]))) throw new Error('Signature');
  const value = JSON.parse(new TextDecoder().decode(unbase64(parts[0])));
  if (!Number.isFinite(value.expires) || value.expires <= Date.now() || value.expires > Date.now() + TTL) throw new Error('Expired');
  return value;
}

async function readJson(request) {
  if (!request.headers.get('content-type')?.startsWith('application/json')) throw new Error('Content type');
  if (Number(request.headers.get('content-length')) > MAX_BODY || !request.body) throw new Error('Size');
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY) throw new Error('Size');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel();
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function checkProviders(request, config, ip) {
  const cleanTalk = new URL('https://api.cleantalk.org/');
  cleanTalk.search = new URLSearchParams({ method_name: 'spam_check', auth_key: config.cleantalkKey, ip });
  const ipSecurity = new URL('https://api.ipgeolocation.io/v3/security');
  ipSecurity.search = new URLSearchParams({ apiKey: config.ipgeolocationKey, ip });
  const headers = [...request.headers].filter(([name]) => name === 'user-agent' || name.startsWith('sec-ch-ua'))
    .map(([name, value]) => `${name}: ${value}`).join('\r\n');
  const udger = new URL('https://api.udger.com/v4/parse');
  udger.search = new URLSearchParams({ accesskey: config.udgerKey, headers, ip });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT);
  try {
    await Promise.all([
      [cleanTalk, cleanTalkPasses], [ipSecurity, ipSecurityPasses], [udger, udgerPasses]
    ].map(async ([url, passes]) => {
      const result = await fetch(url, { signal: controller.signal, redirect: 'manual', headers: { Accept: 'application/json' } });
      if (!result.ok || !passes(await result.json(), ip)) throw new Error('Provider');
    }));
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}


function loadingPage(challenge, config) {
  const safe = value => JSON.stringify(value).replace(/</g, '\\u003c');
  const fallback = config.fallbackUrl.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="robots" content="noindex, nofollow"><meta name="color-scheme" content="light only"><title>Loading</title><style>html,body{margin:0;min-height:100%;background:#fff}body{min-height:100vh;display:grid;place-items:center}.spinner{width:42px;height:42px;border:4px solid #eee;border-top-color:#666;border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}</style><noscript><meta http-equiv="refresh" content="0;url=' + fallback + '"></noscript></head><body><div class="spinner" role="status" aria-label="Loading"></div><script>(' + browserGateSource + ')(' + safe(challenge) + ',' + safe(config.fallbackUrl) + ',' + safe(PREFIX) + ');</script></body></html>';
}

export async function protectCheckout(request, config, checkoutHandler) {
  const url = new URL(request.url);
  if (url.pathname === '/robots.txt') return checkoutHandler(request);
  const country = request.cf?.country;
  if (typeof country !== 'string' || !/^[A-Z]{2}$/.test(country) || !Array.isArray(config.allowedCountries) || !config.allowedCountries.includes(country)) return deny(config);
  if (url.pathname === PREFIX + 'fpscanner.js' && request.method === 'GET') return response(browserSource, 'application/javascript');
  try {
    const ip = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    if (!ip || !userAgent || request.url.length > 8000) throw new Error('Identity');
    if (!url.pathname.startsWith(PREFIX)) {
      if (request.method !== 'GET' || url.protocol !== 'https:') throw new Error('Method');
      const challenge = await sign({ kind: 'challenge', url: request.url, ip, userAgent,
        nonce: crypto.randomUUID(), expires: Date.now() + TTL }, config);
      return response(loadingPage(challenge, config), 'text/html');
    }
    if (request.method !== 'POST' || request.headers.get('Origin') !== url.origin) throw new Error('Origin');
    const body = await readJson(request);
    const challenge = await verify(body.challenge, config);
    if (challenge.kind !== 'challenge' || challenge.ip !== ip || challenge.userAgent !== userAgent || new URL(challenge.url).origin !== url.origin) throw new Error('Binding');
    const stage = url.pathname.slice(PREFIX.length);
    if (stage === 'apis' || stage === 'scan') {
      if (stage === 'apis') await checkProviders(request, config, ip);
      if (stage === 'scan' && !fingerprintPasses(body.fingerprint, userAgent)) throw new Error('Fingerprint');
      const proof = await sign({ kind: stage, challenge: body.challenge, expires: challenge.expires }, config);
      return response(JSON.stringify({ proof }));
    }
    if (stage === 'complete') {
      const [apiProof, scanProof] = await Promise.all([verify(body.apiProof, config), verify(body.scanProof, config)]);
      if (apiProof.kind !== 'apis' || scanProof.kind !== 'scan' || apiProof.challenge !== body.challenge || scanProof.challenge !== body.challenge) throw new Error('Proof');
      return checkoutHandler(new Request(challenge.url, { method: 'GET', headers: request.headers }));
    }
    throw new Error('Route');
  } catch {
    return deny(config);
  }
}
