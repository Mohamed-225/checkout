import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { protectCheckout } from '../security/gate.js';
import { cleanTalkPasses, ipSecurityPasses, udgerPasses, fingerprintPasses, SECURITY_FLAGS } from '../security/policy.js';
import { detectionRules } from '../vendor/fpscanner-rules.js';
import { browserSource } from '../vendor/fpscanner-browser.js';
import checkoutWorker from '../index.js';

const ip = '203.0.113.17';
const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
const origin = 'https://checkout.example';
const config = { allowedCountries: ['GB', 'FR', 'MA', 'US'], cleantalkKey: 'test-clean', ipgeolocationKey: 'test-ip', udgerKey: 'test-udger', fallbackUrl: 'https://lovbook.net' };
const prefix = '/__checkout_security/';
const baseHeaders = { 'CF-Connecting-IP': ip, 'User-Agent': ua };
const makeRequest = (url = origin + '/?id=encrypted', init = {}) => {
  const { cf = { country: 'GB' }, ...options } = init;
  return Object.assign(new Request(url, { ...options, headers: { ...baseHeaders, ...options.headers } }), { cf });
};
const clean = () => ({ data: { [ip]: { appears: 0, in_security: 0, in_antispam: 0 } } });
const security = () => ({ ip, security: Object.fromEntries(SECURITY_FLAGS.map(key => [key, false])) });
const udger = () => ({ user_agent: { ua_class_code: 'browser' }, ip_address: { ip, ip_classification_code: 'unrecognized' } });

function fingerprint() {
  return {
    fastBotDetectionDetails: Object.fromEntries(detectionRules.map(([key]) => [key, { detected: false, severity: 'high' }])),
    signals: {
      automation: { webdriver: false, webdriverWritable: false, selenium: false, cdp: false, playwright: false },
      device: { cpuCount: 8, memory: 8, platform: 'Win32', screenResolution: { width: 1920, height: 1080, availableWidth: 1920, availableHeight: 1040, innerWidth: 1200, innerHeight: 900 } },
      browser: { userAgent: ua, features: { chrome: true }, etsl: 33, highEntropyValues: { platform: 'Windows' } },
      graphics: { webGL: { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel)' }, webgpu: { vendor: 'intel' } },
      locale: { internationalization: { timezone: 'Europe/Paris' }, languages: { language: 'en-US', languages: ['en-US', 'en'] } },
      contexts: {
        iframe: { webdriver: false, userAgent: ua, platform: 'Win32' },
        webWorker: { webdriver: 'NA', userAgent: ua, platform: 'Win32', vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel)' }
      }
    }
  };
}

async function start(handler = () => { throw new Error('Premature checkout'); }, url) {
  const result = await protectCheckout(makeRequest(url), config, handler);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('location'), null);
  const html = await result.text();
  const challenge = html.match(/\)\("([A-Za-z0-9_.-]+)",/)[1];
  return { html, challenge };
}

function post(stage, body, handler = () => { throw new Error('Premature checkout'); }, headers = {}) {
  return protectCheckout(makeRequest(origin + prefix + stage, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) }), config, handler);
}

function providerFetch(overrides = {}) {
  return async (input, options) => {
    if (options) assert.equal(options.redirect, 'manual');
    const url = new URL(input);
    assert.equal(url.searchParams.get('ip'), ip);
    if (url.hostname === 'api.cleantalk.org') {
      assert.equal(url.searchParams.get('method_name'), 'spam_check');
      return Response.json(overrides.clean ?? clean());
    }
    if (url.hostname === 'api.ipgeolocation.io') {
      assert.equal(url.pathname, '/v3/security');
      return Response.json(overrides.security ?? security());
    }
    assert.equal(url.hostname, 'api.udger.com');
    assert.equal(url.pathname, '/v4/parse');
    assert.match(url.searchParams.get('headers'), /user-agent: Mozilla/);
    return Response.json(overrides.udger ?? udger());
  };
}

test('allowed countries reach the loading screen and the country list is configurable', async () => {
  const handler = () => assert.fail('Premature checkout');
  for (const country of config.allowedCountries) {
    const result = await protectCheckout(makeRequest(undefined, { cf: { country } }), config, handler);
    assert.equal(result.status, 200, country);
    assert.match(await result.text(), /class="spinner"/);
  }
  const changed = { ...config, allowedCountries: ['DE'] };
  assert.equal((await protectCheckout(makeRequest(undefined, { cf: { country: 'DE' } }), changed, handler)).status, 200);
  assert.equal((await protectCheckout(makeRequest(), changed, handler)).status, 303);
});

test('country denial precedes loading, scanner assets, API calls and checkout on every protected route', async t => {
  let fetches = 0;
  t.mock.method(globalThis, 'fetch', () => { fetches++; throw new Error('Unexpected external request'); });
  const { challenge } = await start();
  const countries = ['DE', 'XX', 'T1', '', 'gb', ' GB ', null, undefined, 42];
  for (const cf of [null, {}, ...countries.map(country => ({ country }))]) {
    for (const path of ['/?id=encrypted', prefix + 'fpscanner.js', prefix + 'apis', prefix + 'scan', prefix + 'complete']) {
      const isPost = /\/(apis|scan|complete)$/.test(path);
      const request = makeRequest(origin + path, {
        cf, method: isPost ? 'POST' : 'GET',
        headers: { Origin: origin, 'CF-IPCountry': 'US', 'Content-Type': 'application/json' },
        ...(isPost ? { body: JSON.stringify({ challenge, fingerprint: fingerprint() }) } : {})
      });
      const result = await protectCheckout(request, config, () => assert.fail('Premature checkout'));
      assert.equal(result.status, 303);
      assert.equal(result.headers.get('location'), config.fallbackUrl);
      assert.equal(await result.text(), '');
    }
  }
  assert.equal(fetches, 0);
});

test('missing or empty country configuration denies access and entry point applies its configured list', async () => {
  for (const allowedCountries of [undefined, null, [], 'GB']) {
    const result = await protectCheckout(makeRequest(), { ...config, allowedCountries }, () => assert.fail('Premature checkout'));
    assert.equal(result.status, 303);
  }
  for (const country of config.allowedCountries) {
    const asset = await checkoutWorker.fetch(makeRequest(origin + prefix + 'fpscanner.js', { cf: { country } }));
    assert.equal(asset.status, 200);
  }
  const denied = await checkoutWorker.fetch(makeRequest(origin + prefix + 'fpscanner.js', { cf: { country: 'DE' } }));
  assert.equal(denied.status, 303);
  const robots = await checkoutWorker.fetch(makeRequest(origin + '/robots.txt', { cf: null }));
  assert.equal(robots.status, 200);
});

test('CleanTalk rejects every blacklist flag and incomplete/error responses', () => {
  assert.equal(cleanTalkPasses(clean(), ip), true);
  assert.equal(cleanTalkPasses({ data: { [ip]: { appears: 0 } } }, ip), true);
  assert.equal(cleanTalkPasses({ data: { [ip]: { in_security: '0', in_antispam: '0' } } }, ip), true);
  for (const key of ['appears', 'in_security', 'in_antispam']) {
    for (const value of [1, '1', true, false, null, 'false']) {
      const result = clean();
      result.data[ip][key] = value;
      assert.equal(cleanTalkPasses(result, ip), false);
    }
  }
  for (const result of [{}, { data: 'In progress' }, { data: { [ip]: {} } }, { error_no: 10, ...clean() }, { data: { [ip]: { error: 'Database error', appears: 0 } } }]) assert.equal(cleanTalkPasses(result, ip), false);
});

test('all eleven IP security flags must be literal false', () => {
  assert.equal(ipSecurityPasses(security(), ip), true);
  for (const key of SECURITY_FLAGS) for (const value of [true, null, undefined, 0, 'false']) {
    const result = security();
    result.security[key] = value;
    assert.equal(ipSecurityPasses(result, ip), false, key);
  }
  assert.equal(ipSecurityPasses(security(), '203.0.113.18'), false);
});

test('Udger uses exact case-sensitive v4 nested codes', () => {
  for (const code of ['browser', 'mobile_browser']) {
    const result = udger();
    result.user_agent.ua_class_code = code;
    assert.equal(udgerPasses(result, ip), true);
  }
  for (const code of ['Browser', 'Mobile_browser', 'mobile browser', 'crawler', undefined]) {
    const result = udger();
    result.user_agent.ua_class_code = code;
    assert.equal(udgerPasses(result, ip), false);
  }
  for (const code of ['Unrecognized', 'proxy', undefined]) {
    const result = udger();
    result.ip_address.ip_classification_code = code;
    assert.equal(udgerPasses(result, ip), false);
  }
});

test('all 21 client results are required and server recomputes every detector', () => {
  assert.equal(detectionRules.length, 21);
  assert.equal(fingerprintPasses(fingerprint(), ua), true);
  for (const [key] of detectionRules) for (const value of [undefined, { detected: true }, { detected: 'false' }]) {
    const fp = fingerprint();
    fp.fastBotDetectionDetails[key] = value;
    assert.equal(fingerprintPasses(fp, ua), false, key);
  }
  const mutations = [
    s => { s.device.screenResolution.width = 800; s.device.screenResolution.height = 600; },
    ...['webdriver', 'webdriverWritable', 'selenium', 'cdp', 'playwright'].map(key => s => { s.automation[key] = true; }),
    s => { s.device.memory = 64; }, s => { s.device.cpuCount = 128; }, s => { s.browser.features.chrome = false; },
    s => { s.contexts.iframe.webdriver = true; }, s => { s.contexts.webWorker.webdriver = true; },
    s => { s.contexts.webWorker.renderer = 'Other'; }, s => { s.contexts.iframe.platform = 'Linux'; },
    s => { s.contexts.webWorker.platform = 'Linux'; }, s => { s.graphics.webGL.renderer = 'SwiftShader'; },
    s => { s.locale.internationalization.timezone = 'UTC'; }, s => { s.locale.languages.languages = ['fr']; },
    s => { s.browser.etsl = 37; }, s => { s.contexts.iframe.userAgent = 'headless bot'; },
    s => { s.graphics.webgpu.vendor = 'apple'; }, s => { s.browser.highEntropyValues.platform = 'Mac'; }
  ];
  assert.equal(mutations.length, 21);
  for (const mutate of mutations) {
    const fp = fingerprint();
    mutate(fp.signals);
    assert.equal(fingerprintPasses(fp, ua), false);
  }
});

test('missing, malformed, skipped and failed signals cannot pass as OK', () => {
  for (const value of [undefined, null, 'ERROR', 'INIT', 'SKIPPED', {}]) {
    const fp = fingerprint();
    fp.signals.contexts.webWorker = value;
    assert.equal(fingerprintPasses(fp, ua), false);
    const other = fingerprint();
    other.signals.automation.cdp = value;
    assert.equal(fingerprintPasses(other, ua), false);
  }
  const fp = fingerprint();
  fp.signals.device.memory = 'NA';
  fp.signals.graphics.webgpu.vendor = 'NA';
  fp.signals.browser.highEntropyValues.platform = 'NA';
  assert.equal(fingerprintPasses(fp, ua), true);
});

test('initial 200 is only a white spinner with no checkout page, URL or secrets', async () => {
  const { html } = await start();
  assert.match(html, /background:#fff/);
  assert.match(html, /class="spinner"/);
  for (const text of ['Continue now', 'redirectDelay', 'checkout.stripe.com', ...Object.values(config).filter(value => typeof value === 'string' && value.startsWith('test-'))]) assert.equal(html.includes(text), false);
});

test('providers start in parallel and checkout is released only after both signed proofs', async t => {
  const { challenge } = await start();
  const pending = [];
  const calls = [];
  t.mock.method(globalThis, 'fetch', input => {
    calls.push(new URL(input).hostname);
    return new Promise(resolve => pending.push(() => providerFetch()(input).then(resolve)));
  });
  const apiTask = post('apis', { challenge });
  for (let i = 0; i < 100 && calls.length < 3; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.length, 3);
  const scan = await post('scan', { challenge, fingerprint: fingerprint() });
  assert.equal(scan.status, 200);
  const scanProof = (await scan.json()).proof;
  assert.equal((await post('complete', { challenge, scanProof })).status, 303);
  pending.forEach(resolve => resolve());
  const apis = await apiTask;
  assert.equal(apis.status, 200);
  const apiProof = (await apis.json()).proof;
  let checkoutCalls = 0;
  const result = await post('complete', { challenge, apiProof, scanProof }, request => {
    checkoutCalls++;
    assert.equal(request.url, origin + '/?id=encrypted');
    assert.equal(request.method, 'GET');
    return new Response('Original checkout HTML', { status: 200 });
  });
  assert.equal(checkoutCalls, 1);
  assert.equal(result.status, 200);
  assert.equal(await result.text(), 'Original checkout HTML');
});

test('provider errors and positive responses deny without checkout', async t => {
  const { challenge } = await start();
  for (const fetcher of [
    providerFetch({ clean: { data: { [ip]: { appears: 1 } } } }),
    providerFetch({ security: { ip, security: {} } }),
    providerFetch({ udger: { error: 403 } }),
    async () => new Response('{}', { status: 429 }),
    async () => new Response(null, { status: 302, headers: { Location: 'https://other.example' } }),
    async () => new Response('not json'),
    async () => { throw new Error('Network failure'); }
  ]) {
    const mock = t.mock.method(globalThis, 'fetch', fetcher);
    const result = await post('apis', { challenge });
    assert.equal(result.status, 303);
    assert.equal(result.headers.get('location'), config.fallbackUrl);
    mock.mock.restore();
  }
});

test('provider timeout aborts pending lookups and returns the homepage fallback', async t => {
  const { challenge } = await start();
  let expire;
  let started = 0;
  t.mock.method(globalThis, 'setTimeout', (callback, delay) => {
    assert.equal(delay, 12000);
    expire = callback;
    return 1;
  });
  t.mock.method(globalThis, 'clearTimeout', () => {});
  t.mock.method(globalThis, 'fetch', (input, options) => {
    started++;
    return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('Aborted'))));
  });
  const result = post('apis', { challenge });
  for (let i = 0; i < 100 && started < 3; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(started, 3);
  expire();
  assert.equal((await result).status, 303);
});

test('forged, expired, cross-IP, cross-UA, cross-origin and cross-payment proofs fail', async t => {
  t.mock.method(globalThis, 'fetch', providerFetch());
  const { challenge } = await start();
  const { proof: apiProof } = await (await post('apis', { challenge })).json();
  const { proof: scanProof } = await (await post('scan', { challenge, fingerprint: fingerprint() })).json();
  const body = { challenge, apiProof, scanProof };
  for (const headers of [{ 'CF-Connecting-IP': '203.0.113.18' }, { 'User-Agent': 'Other browser' }, { Origin: 'https://evil.example' }, { Origin: '' }]) assert.equal((await post('complete', body, undefined, headers)).status, 303);
  const other = await start(undefined, origin + '/?id=other');
  assert.equal((await post('complete', { ...body, challenge: other.challenge })).status, 303);
  assert.equal((await post('complete', { ...body, apiProof: scanProof })).status, 303);
  assert.equal((await post('complete', { ...body, challenge: 'forged.token' })).status, 303);
  assert.equal((await post('complete', { ...body, apiProof: apiProof.slice(0, -8) + 'aaaaaaaa' })).status, 303);
  const now = Date.now();
  t.mock.method(Date, 'now', () => now + 61000);
  assert.equal((await post('complete', body)).status, 303);
});

test('missing configuration, malformed bodies, direct entry and alternate methods fail closed', async () => {
  assert.equal((await protectCheckout(makeRequest(), { ...config, udgerKey: '' }, () => {})).status, 303);
  for (const stage of ['apis', 'scan', 'complete', 'unknown']) {
    assert.equal((await protectCheckout(makeRequest(origin + prefix + stage), config, () => {})).status, 303);
  }
  assert.equal((await post('scan', { payload: 'x'.repeat(70000) })).status, 303);
  assert.equal((await protectCheckout(makeRequest(origin + '/', { method: 'POST' }), config, () => {})).status, 303);
  assert.equal((await protectCheckout(makeRequest(origin + '/', { headers: { 'CF-Connecting-IP': '' } }), config, () => {})).status, 303);
});

test('browser starts APIs and script loading together, then submits signals and only installs approved HTML', async () => {
  const { html } = await start();
  const code = html.match(/<script>([\s\S]*)<\/script>/)[1];
  const calls = [];
  let load;
  let timer;
  const writes = [];
  const doc = { head: { appendChild(script) { calls.push('load-script'); load = script.onload; } }, createElement() { return {}; }, open() { writes.push('open'); }, write(value) { writes.push(value); }, close() { writes.push('close'); } };
  const context = { document: doc, AbortController, console,
    setTimeout(callback) { timer = callback; return 1; }, clearTimeout() {},
    window: { location: { replace(url) { calls.push(url); } }, addEventListener() {}, CheckoutFPScanner: { default: class { async collectFingerprint(options) { assert.equal(options.encrypt, false); calls.push('collect'); return fingerprint(); } } } },
    async fetch(path, options) {
      calls.push(path);
      assert.equal(writes.length, 0);
      const body = JSON.parse(options.body);
      if (path.endsWith('scan')) assert.ok(body.fingerprint.signals);
      if (path.endsWith('complete')) {
        assert.equal(body.apiProof, 'api-proof');
        assert.equal(body.scanProof, 'scan-proof');
        return new Response('approved HTML');
      }
      return Response.json({ proof: path.endsWith('apis') ? 'api-proof' : 'scan-proof' });
    }
  };
  vm.runInNewContext(code, context);
  assert.deepEqual(calls, [prefix + 'apis', 'load-script']);
  assert.equal(writes.length, 0);
  load();
  for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(writes, ['open', 'approved HTML', 'close']);
  assert.equal(typeof timer, 'function');
});

test('browser redirects immediately on API failure without waiting for scanner', async () => {
  const { html } = await start();
  const code = html.match(/<script>([\s\S]*)<\/script>/)[1];
  let destination;
  let written = false;
  vm.runInNewContext(code, {
    AbortController, setTimeout() { return 1; }, clearTimeout() {},
    document: { head: { appendChild() {} }, createElement() { return {}; }, open() { written = true; } },
    window: { location: { replace(url) { destination = url; } }, addEventListener() {} },
    async fetch() { return new Response(null, { status: 303 }); }
  });
  for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(destination, config.fallbackUrl);
  assert.equal(written, false);
});

test('browser loading timeout and script failure both deny without installing checkout', async () => {
  const { html } = await start();
  const code = html.match(/<script>([\s\S]*)<\/script>/)[1];
  for (const reason of ['timeout', 'script']) {
    let expire;
    let rejectScript;
    let destination;
    vm.runInNewContext(code, {
      AbortController,
      setTimeout(callback, delay) { assert.equal(delay, 25000); expire = callback; return 1; },
      clearTimeout() {},
      document: { head: { appendChild(script) { rejectScript = script.onerror; } }, createElement() { return {}; }, open() { assert.fail('Checkout must not load'); } },
      window: { location: { replace(url) { destination = url; } }, addEventListener() {} },
      fetch() { return new Promise(() => {}); }
    });
    if (reason === 'timeout') expire();
    else rejectScript(new Error('Script failed'));
    for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve));
    assert.equal(destination, config.fallbackUrl);
  }
});

test('original redirect template, handler, crypto and robots remain byte-for-byte unchanged', async () => {
  const current = await readFile(new URL('../index.js', import.meta.url), 'utf8');
  const section = text => text.slice(text.indexOf('const REDIRECT_PAGE_TEMPLATE'), text.indexOf('export default {'));
  const hash = text => createHash('sha256').update(text).digest('hex');
  assert.equal(hash(section(current)), 'e7db8ed4624b26b8584e64d34840ab7065e7690ac766b4a36c64a3161e6cbda2');
  assert.equal(hash(current.slice(current.indexOf('async function handleRequest'))), 'd8578d83813027f987cea41ddd47c71e53223b9eaf82800dd5409459d7d96a0b');
  assert.match(current, /var redirectDelay = 300000/);
});

test('vendored FPScanner loads and worker includes an actual webdriver collector', () => {
  const context = {};
  vm.runInNewContext(browserSource, context);
  assert.equal(typeof context.CheckoutFPScanner.default, 'function');
  assert.match(browserSource, /fingerprintWorker.webdriver/);
});

test('ES module default fetch export handles requests and retains the security gate', async () => {
  assert.equal(typeof checkoutWorker.fetch, 'function');
  const robots = await checkoutWorker.fetch(makeRequest(origin + '/robots.txt'));
  assert.equal(robots.status, 200);
  assert.match(await robots.text(), /User-agent: Stripe/);
  const asset = await checkoutWorker.fetch(makeRequest(origin + prefix + 'fpscanner.js'));
  assert.equal(asset.status, 200);
  assert.equal(await asset.text(), browserSource);
  const denied = await checkoutWorker.fetch(makeRequest(origin + prefix + 'complete'));
  assert.equal(denied.status, 303);
  assert.equal(denied.headers.get('location'), config.fallbackUrl);
});
