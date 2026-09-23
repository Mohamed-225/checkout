import { detectionRules } from '../vendor/fpscanner-rules.js';

export const SECURITY_FLAGS = [
  'is_tor', 'is_proxy', 'is_residential_proxy', 'is_vpn', 'is_relay',
  'is_anonymous', 'is_known_attacker', 'is_bot', 'is_spam',
  'is_cloud_provider', 'is_corporate_gateway'
];

export function cleanTalkPasses(response, ip) {
  if (!response || response.error_no || response.error_message) return false;
  const record = response.data?.[ip];
  if (!record || typeof record !== 'object' || record.error) return false;
  const fields = ['appears', 'in_security', 'in_antispam'];
  const present = fields.filter(key => Object.hasOwn(record, key));
  if (present.some(key => record[key] !== 0 && record[key] !== '0')) return false;
  return present.includes('appears') || (present.includes('in_security') && present.includes('in_antispam'));
}

export function ipSecurityPasses(response, ip) {
  return response?.ip === ip && SECURITY_FLAGS.every(key => response.security?.[key] === false);
}

export function udgerPasses(response, ip) {
  return !response?.error && response?.ip_address?.ip === ip &&
    ['browser', 'mobile_browser'].includes(response?.user_agent?.ua_class_code) &&
    response?.ip_address?.ip_classification_code === 'unrecognized';
}

const stringSignal = value => typeof value === 'string' && value.length > 0 &&
  !['ERROR', 'INIT', 'SKIPPED'].includes(value);
const availableString = value => stringSignal(value) && value !== 'NA';
const numberSignal = value => value === 'NA' || (typeof value === 'number' && Number.isFinite(value) && value > 0);
const boolSignal = value => typeof value === 'boolean';

export function fingerprintPasses(fingerprint, userAgent) {
  try {
    const s = fingerprint.signals;
    const a = s.automation;
    const d = s.device;
    const b = s.browser;
    const g = s.graphics;
    const l = s.locale;
    if (!['webdriver', 'webdriverWritable', 'selenium', 'cdp', 'playwright'].every(key => boolSignal(a[key]))) return false;
    if (b.userAgent !== userAgent || !availableString(b.userAgent) || !availableString(d.platform)) return false;
    if (!numberSignal(d.memory) || !numberSignal(d.cpuCount) || d.cpuCount === 'NA') return false;
    if (!['width', 'height', 'availableWidth', 'availableHeight', 'innerWidth', 'innerHeight'].every(key =>
      typeof d.screenResolution[key] === 'number' && Number.isFinite(d.screenResolution[key]) && d.screenResolution[key] > 0)) return false;
    if (!boolSignal(b.features.chrome) || !Number.isInteger(b.etsl) || b.etsl <= 0 || !stringSignal(b.highEntropyValues.platform)) return false;
    if (!stringSignal(g.webGL.vendor) || !stringSignal(g.webGL.renderer)) return false;
    if (typeof g.webgpu.vendor !== 'string' || ['ERROR', 'INIT', 'SKIPPED'].includes(g.webgpu.vendor)) return false;
    if (!availableString(l.internationalization.timezone) || !availableString(l.languages.language)) return false;
    if (!Array.isArray(l.languages.languages) || !l.languages.languages.length || !l.languages.languages.every(availableString)) return false;
    for (const context of [s.contexts.iframe, s.contexts.webWorker]) {
      if (!availableString(context.userAgent) || !availableString(context.platform)) return false;
    }
    if (!boolSignal(s.contexts.iframe.webdriver)) return false;
    if (!boolSignal(s.contexts.webWorker.webdriver) && s.contexts.webWorker.webdriver !== 'NA') return false;
    if (!stringSignal(s.contexts.webWorker.vendor) || !stringSignal(s.contexts.webWorker.renderer)) return false;
    return detectionRules.length === 21 && detectionRules.every(([key, test]) =>
      fingerprint.fastBotDetectionDetails?.[key]?.detected === false && test(fingerprint) === false);
  } catch {
    return false;
  }
}
