import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { build } = require(process.env.ESBUILD_PATH || 'esbuild');
const revision = '4255cfd8a23fef5ea714147518d8c6ae1e5426d3';
const directory = await mkdtemp(join(tmpdir(), 'checkout-fpscanner-'));
const output = resolve('vendor');
const rules = [
  ['headlessChromeScreenResolution', 'hasHeadlessChromeScreenResolution'],
  ...['hasWebdriver', 'hasWebdriverWritable', 'hasSeleniumProperty', 'hasCDP',
    'hasPlaywright', 'hasImpossibleDeviceMemory', 'hasHighCPUCount', 'hasMissingChromeObject',
    'hasWebdriverIframe', 'hasWebdriverWorker', 'hasMismatchWebGLInWorker',
    'hasMismatchPlatformIframe', 'hasMismatchPlatformWorker', 'hasSwiftshaderRenderer',
    'hasUTCTimezone', 'hasMismatchLanguages', 'hasInconsistentEtsl', 'hasBotUserAgent',
    'hasGPUMismatch', 'hasPlatformMismatch'].map(name => [name, name])
];

try {
  execFileSync('git', ['clone', '--quiet', 'https://github.com/antoinevastel/fpscanner.git', directory]);
  execFileSync('git', ['checkout', '--quiet', revision], { cwd: directory });
  const workerPath = join(directory, 'src/signals/worker.ts');
  let worker = await readFile(workerPath, 'utf8');
  worker = worker.replace('const workerData = {', 'const workerData = { webdriver: INIT,')
    .replace('var fingerprintWorker = {', "var fingerprintWorker = { webdriver: 'NA',")
    .replace('fingerprintWorker.userAgent = navigator.userAgent;', "fingerprintWorker.webdriver = typeof navigator.webdriver === 'undefined' ? 'NA' : navigator.webdriver;\n fingerprintWorker.userAgent = navigator.userAgent;")
    .replace('workerData.vendor = pick(e.data.vendor);', 'workerData.webdriver = pick(e.data.webdriver);\n workerData.vendor = pick(e.data.vendor);');
  await writeFile(workerPath, worker);
  const gpuPath = join(directory, 'src/signals/webgpu.ts');
  const gpu = (await readFile(gpuPath, 'utf8')).replace('webGPUData.description = adapter.info.description;\n            }', 'webGPUData.description = adapter.info.description;\n            } else {\n                setObjectValues(webGPUData, NA);\n            }');
  await writeFile(gpuPath, gpu);
  const client = await build({ entryPoints: [join(directory, 'src/index.ts')], bundle: true,
    write: false, format: 'iife', globalName: 'CheckoutFPScanner', minify: true,
    legalComments: 'none', target: 'es2020', define: { '__FP_ENCRYPTION_KEY__': '""' } });
  await mkdir(output, { recursive: true });
  await writeFile(join(output, 'fpscanner-browser.js'), 'export const browserSource = ' + JSON.stringify(client.outputFiles[0].text) + ';\n');
  const entry = rules.map(([, name]) => `import { ${name} } from './src/detections/${name}';`).join('\n') +
    '\nexport const detectionRules = [' + rules.map(([key, name]) => `[${JSON.stringify(key)}, ${name}]`).join(',') + '];';
  const entryPath = join(directory, 'rules.ts');
  await writeFile(entryPath, entry);
  const server = await build({ entryPoints: [entryPath], bundle: true, write: false,
    format: 'esm', minify: true, legalComments: 'none', target: 'es2020' });
  await writeFile(join(output, 'fpscanner-rules.js'), server.outputFiles[0].text);
  await writeFile(join(output, 'FPScanner-LICENSE.txt'), await readFile(join(directory, 'LICENSE')));
  console.log('Built FPScanner at ' + revision);
} finally {
  await rm(directory, { recursive: true, force: true });
}
