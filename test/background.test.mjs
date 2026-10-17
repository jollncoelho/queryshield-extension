/**
 * Tests du service worker (background.js) en contexte simule.
 * Usage : node test/background.test.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';
import vm from 'node:vm';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire('C:/Users/josel/.workbuddy-ai/binaries/node/workspace/package.json');

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { passed++; console.log('  ok   ' + label); }
  else { failed++; console.log('  FAIL ' + label); }
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, timeout = 3000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (cond()) return true;
    await wait(25);
  }
  return false;
}

/* --------------------------------------------------- bac a sable du worker */

function createWorkerContext(fetchImpl) {
  const state = {
    badge: '',
    badgeColor: null,
    notifications: [],
    onUpdatedListener: null,
    onMessageListener: null,
    alarmListener: null,
    installListener: null,
    localStore: {},
    syncStore: {},
    sendMessageResponses: [],
  };

  const chromeMock = {
    storage: {
      local: {
        async get(key) {
          if (key === null) return { ...state.localStore };
          return { [key]: state.localStore[key] };
        },
        async set(obj) { Object.assign(state.localStore, obj); },
        async clear() { state.localStore = {}; },
      },
      sync: {
        async get(key) { return { [key]: state.syncStore[key] }; },
        async set(obj) { Object.assign(state.syncStore, obj); },
      },
    },
    action: {
      _badge: '',
      async setBadgeText({ text }) { state.badge = text; },
      async setBadgeBackgroundColor({ color }) { state.badgeColor = color; },
    },
    notifications: {
      async create(id, opts) { state.notifications.push({ id, ...opts }); },
      async clear() {},
      onClicked: { addListener() {} },
    },
    tabs: {
      onUpdated: { addListener(fn) { state.onUpdatedListener = fn; } },
      onActivated: { addListener() {} },
      async query() { return [{ url: 'https://example.com' }]; },
      async create() {},
    },
    alarms: {
      create() {},
      onAlarm: { addListener(fn) { state.alarmListener = fn; } },
    },
    runtime: {
      onInstalled: { addListener(fn) { state.installListener = fn; } },
      onMessage: { addListener(fn) { state.onMessageListener = fn; } },
    },
  };

  const sandbox = {
    chrome: chromeMock,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Date,
    URL,
    fetch: fetchImpl,
    __state: state,
  };
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.importScripts = (path) => {
    vm.runInContext(readFileSync(join(ROOT, path), 'utf8'), ctx, { filename: path });
  };

  const ctx = vm.createContext(sandbox);
  vm.runInContext(readFileSync(join(ROOT, 'shared/api.js'), 'utf8'), ctx, { filename: 'shared/api.js' });
  vm.runInContext(readFileSync(join(ROOT, 'background.js'), 'utf8'), ctx, { filename: 'background.js' });
  return { sandbox, state, chromeMock };
}

const okResponse = (data, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: { get: () => null },
  json: async () => data,
});

/* ---------------------------------------------------------------- tests */

async function testPhishingAlert() {
  console.log('\n[navigation vers un site phishing]');
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url, body: opts.body ? JSON.parse(opts.body) : null });
    return okResponse({
      verdict: 'phishing',
      score: 88,
      summary: 'impots-gouv.secure-login.xyz imite le service des impots.',
      officialBrand: null,
      impersonatedBrands: ['Impots.gouv.fr'],
    });
  };
  const { state } = createWorkerContext(fetchImpl);

  // On active la surveillance (defaut) et on simule une navigation.
  state.onUpdatedListener(1, { status: 'complete', url: 'https://impots-gouv.secure-login.xyz/' }, { url: 'https://impots-gouv.secure-login.xyz/' });

  const done = await waitFor(() => state.badge === '!');
  assert(done, 'badge rouge "!" apres detection phishing');
  assert(state.badgeColor === '#ff3b5c', 'couleur de badge rouge');
  assert(state.notifications.length === 1, 'une notification declenchee');
  assert(state.notifications[0].title.includes('phishing'), 'titre de la notification');
  assert(calls.length === 1 && calls[0].body.url === 'impots-gouv.secure-login.xyz', 'domaine envoye sans schema');
  const history = state.localStore['qs.history'];
  assert(history && history[0].verdict === 'phishing', 'historique enregistre');
}

async function testSafeDomainClearsBadge() {
  console.log('\n[navigation vers un site officiel]');
  const fetchImpl = async () => okResponse({
    verdict: 'official',
    score: 0,
    summary: 'laposte.fr est le domaine officiel de La Poste.',
    officialBrand: { name: 'La Poste' },
    impersonatedBrands: [],
  });
  const { state } = createWorkerContext(fetchImpl);

  state.onUpdatedListener(1, { status: 'complete', url: 'https://www.laposte.fr/' }, { url: 'https://www.laposte.fr/' });

  await waitFor(() => fetchCallsDone(state), 1000).catch(() => {});
  const done = await waitFor(() => state.notifications.length === 0 && state.localStore['qs.cache'] !== undefined, 3000);
  assert(done, 'domaine mis en cache sans notification');
  await wait(100);
  assert(state.badge === '', 'badge efface');
  const cache = state.localStore['qs.cache'];
  assert(cache && cache['laposte.fr'] && cache['laposte.fr'].verdict === 'official', 'cache contient laposte.fr');
}

async function fetchCallsDone() { return false; }

async function testSuspiciousBadge() {
  console.log('\n[navigation vers un site suspect sous le seuil]');
  const fetchImpl = async () => okResponse({
    verdict: 'suspicious',
    score: 65,
    summary: 'Anomalies structurelles.',
    officialBrand: null,
    impersonatedBrands: [],
  });
  const { state } = createWorkerContext(fetchImpl);

  state.onUpdatedListener(7, { status: 'complete', url: 'https://colis-relais.xyz/' }, { url: 'https://colis-relais.xyz/' });
  const done = await waitFor(() => state.badge === '?');
  assert(done, 'badge ambre "?" pour score >= seuil');
  assert(state.notifications.length === 0, 'pas de notification pour un site suspect');
}

async function testQuotaPause() {
  console.log('\n[quota epuise pendant la surveillance]');
  const fetchImpl = async () => okResponse(
    { error: 'quota_exceeded', message: 'Quota quotidien atteint (10 verifications).', retryAfterSeconds: 900 },
    429,
  );
  const { state } = createWorkerContext(fetchImpl);

  state.onUpdatedListener(9, { status: 'complete', url: 'https://inconnu.boutique/' }, { url: 'https://inconnu.boutique/' });
  const done = await waitFor(() => state.badge === 'OFF');
  assert(done, 'badge OFF quand le quota est epuise');
  assert(state.localStore['qs.state'] && state.localStore['qs.state'].pausedUntil > Date.now(), 'surveillance en pause');
}

async function testInternalPagesSkipped() {
  console.log('\n[pages internes ignorees]');
  let called = false;
  const fetchImpl = async () => { called = true; return okResponse({}); };
  const { state } = createWorkerContext(fetchImpl);

  state.onUpdatedListener(3, { status: 'complete', url: 'chrome://extensions/' }, { url: 'chrome://extensions/' });
  state.onUpdatedListener(4, { status: 'complete', url: 'about:blank' }, { url: 'about:blank' });
  await wait(400);
  assert(called === false, 'aucun appel API pour chrome:// et about:');
}

async function testMessageBridge() {
  console.log('\n[pont de messages avec le popup]');
  const fetchImpl = async () => okResponse({
    verdict: 'phishing',
    score: 91,
    summary: 'arnaque confirmee',
    officialBrand: null,
    impersonatedBrands: ['Chronopost'],
  });
  const { state } = createWorkerContext(fetchImpl);

  // Le popup demande une verification forcee.
  const response = await new Promise((resolve) => {
    state.onMessageListener({ type: 'check-domain', domain: 'chronopost.xyz', force: true }, null, resolve);
  });
  assert(response.result && response.result.verdict === 'phishing', 'verification forcee renvoyee au popup');

  const cached = await new Promise((resolve) => {
    state.onMessageListener({ type: 'get-cached-domain', domain: 'chronopost.xyz' }, null, resolve);
  });
  assert(cached.result && cached.result.score === 91, 'resultat en cache renvoye');
}

/* ---------------------------------------------------------------- main */

(async () => {
  await testPhishingAlert();
  await testSafeDomainClearsBadge();
  await testSuspiciousBadge();
  await testQuotaPause();
  await testInternalPagesSkipped();
  await testMessageBridge();

  console.log(`\n${passed} ok, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
