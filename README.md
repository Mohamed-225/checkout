# Checkout

The Cloudflare Worker first returns HTTP 200 with a white loading screen. The browser starts the three server-side API lookups and loads the self-hosted FPScanner bundle concurrently. A separate request sends the collected signals to the Worker, which validates the signal schema and reruns all 21 FPScanner detection rules. Only after both checks pass does the Worker invoke the existing checkout handler and return its original HTML with HTTP 200. The browser installs that HTML and its existing script runs unchanged.

The original redirect template, five-minute delay (`300000`), manual link, AES-GCM decryption, fallback URL and robots response are unchanged. No checkout HTML, decrypted payment URL, manual payment link, payment iframe or payment resource is sent before approval.

The Worker entry point uses an ES module default export with a `fetch(request)` handler, so it supports Cloudflare's Versions Upload API as well as normal deployments. It does not register a Service Worker `fetch` event listener.

## Configuration

Fill these server-only constants at the top of `index.js` before deployment:

```js
const CLEANTALK_API_KEY = '';
const IPGEOLOCATION_API_KEY = '';
const UDGER_API_KEY = '';
```

Use a CleanTalk Blacklist API key with `spam_check`, an IPGeolocation subscription exposing all eleven security flags, and an Udger Cloud Parser v4 access key. The keys are used only by the Worker and are never embedded in the browser bundle or HTML. Keep filled-in keys out of public commits. No new Cloudflare bindings or database are required. Keep this Worker on HTTPS behind Cloudflare, which supplies the visitor IP through `CF-Connecting-IP`.

Missing keys, provider errors, non-2xx responses, malformed/missing required results, invalid browser signals and timeouts deny access. Server API requests time out after 12 seconds; the loading screen times out after 25 seconds. Failure uses the existing homepage destination and HTTP 303 on the Worker; the loading screen immediately uses `window.location.replace` for that destination without waiting for the other checks.

## Provider contracts

| Provider | Endpoint | Pass condition |
| --- | --- | --- |
| CleanTalk | `https://api.cleantalk.org/?method_name=spam_check` | No `1` in `appears`, `in_security` or `in_antispam`; reject malformed flag values and error records. A documented minimal `{ "appears": 0 }` is accepted. If `appears` is absent, both other flags must explicitly be zero. |
| IPGeolocation | `https://api.ipgeolocation.io/v3/security` | Each of the eleven requested `security.is_*` flags is the boolean `false`. |
| Udger | `https://api.udger.com/v4/parse` | `user_agent.ua_class_code` equals `browser` or `mobile_browser`, and `ip_address.ip_classification_code` equals `unrecognized`, with exact case. |

IPGeolocation and Udger must also return the IP that was requested. Only the request's User-Agent and `Sec-CH-UA*` headers are sent to Udger; cookies, authorization headers and checkout identifiers are excluded.

Udger was tested through its official live v4 PHP example before implementation, on 2026-09-24 UTC. The page displayed a request to `/v4/parse` and the actual response. Tests used the public IP `1.1.1.1`:

| Submitted User-Agent | Returned `ua_class_code` | Returned `ip_classification_code` |
| --- | --- | --- |
| Windows Chrome 140 | `browser` | `unrecognized` |
| iPhone Safari 18 | `mobile_browser` | `unrecognized` |

The display labels were `Browser`, `Mobile browser`, and `Unrecognized`; they are not the codes used in comparisons. This verifies Udger's live response contract, not the user's subscription credentials. Live authenticated CleanTalk and IPGeolocation tests still require the user's keys.

References: [Udger live v4 example](https://udger.com/api_try/apiv4.php), [Udger v4 reference](https://udger.com/support/documentation/?doc=84), [CleanTalk spam_check](https://cleantalk.org/help/api-spam-check), [IPGeolocation IP Security](https://ipgeolocation.io/documentation/ip-security-api.html).

## FPScanner

The vendored client and server rules are built from [FPScanner](https://github.com/antoinevastel/fpscanner) revision `4255cfd8a23fef5ea714147518d8c6ae1e5426d3` (package version 1.0.8). The browser sends raw signals over HTTPS with `encrypt: false`; no client-side API secret or XOR encryption is relied on for authorization. Each client detection must be present with `detected === false`, and its server recomputation must also return `false`, corresponding to the demo's `OK` state. The summary flag and severity never override an individual failure.

| Requested check | FPScanner rule |
| --- | --- |
| Headless screen resolution | `headlessChromeScreenResolution` |
| navigator.webdriver | `hasWebdriver` |
| webdriver writable | `hasWebdriverWritable` |
| Selenium property | `hasSeleniumProperty` |
| CDP markers | `hasCDP` |
| Playwright markers | `hasPlaywright` |
| Impossible device memory | `hasImpossibleDeviceMemory` |
| High CPU count | `hasHighCPUCount` |
| Missing chrome object | `hasMissingChromeObject` |
| Webdriver in iframe | `hasWebdriverIframe` |
| Webdriver in worker | `hasWebdriverWorker` |
| WebGL mismatch in worker | `hasMismatchWebGLInWorker` |
| Platform mismatch in iframe | `hasMismatchPlatformIframe` |
| Platform mismatch in worker | `hasMismatchPlatformWorker` |
| Swiftshader renderer | `hasSwiftshaderRenderer` |
| UTC timezone | `hasUTCTimezone` |
| Language mismatch | `hasMismatchLanguages` |
| Inconsistent ETSL | `hasInconsistentEtsl` |
| Bot user agent | `hasBotUserAgent` |
| GPU mismatch | `hasGPUMismatch` |
| Platform mismatch | `hasPlatformMismatch` |

Collection failures (`ERROR`, `INIT`, `SKIPPED`) in required inputs are rejected. Legitimately unsupported features represented by FPScanner's `NA` sentinel retain the library's semantics, such as device memory outside Chromium and `webdriver` being absent from WorkerNavigator. Missing properties are not accepted in place of explicit unsupported values.

Two collector fixes are applied reproducibly during bundling: the upstream worker collector omitted `webdriver` despite having a detection rule, so it now collects it explicitly; a null WebGPU adapter now yields `NA` instead of leaving uninitialized `INIT` values. Detection rules are unmodified. The MIT license is retained in `vendor/FPScanner-LICENSE.txt`; generated code contains no added comments. No CDN or package fetch is needed at runtime.

## Validation and rebuilding

Run `npm test` with Node.js 22.12+ or 24. Tests cover every required check, schema failures, parallel execution, invalid/expired/tampered proofs, request binding, provider failures, loading-page behavior, and byte-level preservation of the original redirect code.

Vendored files are committed and ready for Wrangler to bundle. To rebuild them, run `npm ci` followed by `npm run build:fpscanner`; this fetches the exact upstream revision and uses pinned esbuild. Validate the Worker bundle with `npx wrangler deploy --dry-run`.

The test suite uses synthetic browser signals and mocked provider responses. It does not claim live API credential validation or certification across all real browsers.

## Security scope

HMAC-SHA-256 proofs are bound to a short-lived challenge, the visitor IP, User-Agent and exact original payment URL. API and scanner proofs are separate and cannot substitute for one another. Their signing key is derived from the three server-only API keys, independently of the pre-existing payment-link encryption key. Cross-origin POSTs and oversized bodies are rejected, and responses are not cached.

Proofs expire after 60 seconds; this stateless implementation does not provide single-use replay tracking within that window. Browser signals remain client-controlled: server recomputation rejects contradictory or missing submissions, but cannot make a malicious browser's invented signals trustworthy. This gate protects access through this Worker; it cannot revoke a Stripe URL already known to someone. The requested strict rules also reject real users who trigger a heuristic, including UTC timezone and SwiftShader.
