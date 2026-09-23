export const browserGateSource = String.raw`function browserGate(challenge, fallbackUrl, prefix) {
  const controller = new AbortController();
  const timer = setTimeout(fail, 25000);
  let failed = false;
  function fail() {
    if (failed) return;
    failed = true;
    clearTimeout(timer);
    controller.abort();
    window.location.replace(fallbackUrl);
  }
  async function post(path, data) {
    const result = await fetch(prefix + path, {
      method: 'POST', credentials: 'same-origin', redirect: 'manual', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' }, signal: controller.signal,
      body: JSON.stringify({ challenge, ...data })
    });
    if (result.status !== 200) throw new Error('Denied');
    return result;
  }
  const apis = post('apis', {}).then(result => result.json());
  const scanner = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = prefix + 'fpscanner.js';
    script.onload = resolve;
    script.onerror = reject;
    document.head.appendChild(script);
  }).then(async () => {
    const fingerprint = await new window.CheckoutFPScanner.default().collectFingerprint({ encrypt: false });
    const result = await post('scan', { fingerprint });
    return result.json();
  });
  Promise.all([apis, scanner]).then(async ([apiResult, scanResult]) => {
    const result = await post('complete', { apiProof: apiResult.proof, scanProof: scanResult.proof });
    const html = await result.text();
    if (failed) return;
    clearTimeout(timer);
    document.open();
    document.write(html);
    document.close();
  }).catch(fail);
  window.addEventListener('pageshow', event => { if (event.persisted) window.location.reload(); });
}`;
