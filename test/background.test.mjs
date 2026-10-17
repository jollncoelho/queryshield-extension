/**
 * Tests du service worker v2 (background.js) en contexte simule.
 * Usage : node test/background.test.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { passed++; console.log('  ok   ' + label); }
  else { failed++; console.log('  FAIL ' + label); }
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, timeout = 4000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (cond()) return true;
    await wait(25);
  }
  return false;
}

/* --------------------------------------------------- bac a sable du worker */

function createWorkerContext(fetchImpl, overrides = {}) {
  const state = {
    badge: '',
    badgeColor: null,
    notifications: [],
    tabsUpdates: [],
    sentToContent: [],
    localStore: {},
    syncStore: {},
    dnrRules: [],
    beforeNavigate: null,
    onMessage: null,
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
      async setBadgeText({ text }) { state.badge = text; },
      async setBadgeBackgroundColor({ color }) { state.badgeColor = color; },
    },
    notifications: {
      async create(id, opts) { state.notifications.push({ id, ...opts }); },
      async clear() {},
      onClicked: { addListener() {} },
    },
    tabs: {
      onUpdated: { addListener() {} },
      onActivated: { addListener() {} },
      onRemoved: { addListener() {} },
      async query() { return [{ id: 42, url: 'https://example.com' }]; },
      async get() { return { url: 'https://example.com' }; },
      async update(tabId, opts) { state.tabsUpdates.push({ tabId, ...opts }); },
      async create() {},
      async goBack() {},
    },
    webNavigation: {
      onBeforeNavigate: { addListener(fn) { state.beforeNavigate = fn; } },
    },
    declarativeNetRequest: {
      async updateDynamicRules({ removeRuleIds = [], addRules = [] }) {
        state.dnrRules = state.dnrRules.filter((r) => !removeRuleIds.includes(r.id));
        state.dnrRules.push(...addRules);
      },
    },
    alarms: { create() {}, onAlarm: { addListener() {} } },
    runtime: {
      onInstalled: { addListener() {} },
      onStartup: { addListener() {} },
      onMessage: { addListener(fn) { state.onMessage = fn; } },
      getURL: (path) => 'chrome-extension://fake/' + path,
      sendMessage: async (msg) => state.onMessage(msg, null, () => {}),
    },
  };

  // hooks de test supplementaires
  Object.assign(chromeMock.tabs, overrides.tabs || {});
  if (overrides.sendToContent) {
    chromeMock.tabs.sendMessage = async (tabId, msg) => {
      state.sentToContent.push({ tabId, msg });
    };
  }

  const sandbox = {
    chrome: chromeMock,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Date,
    URL,
    URLSearchParams,
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

const okResponse = (data) => ({
  ok: true,
  status: 200,
  headers: { get: () => null },
  json: async () => data,
});

const blockedResponse = (data, retryAfterSeconds) => ({
  ok: false,
  status: 429,
  headers: { get: (k) => (k.toLowerCase() === 'retry-after' ? String(retryAfterSeconds || 900) : null) },
  json: async () => data,
});

/* ---------------------------------------------------------------- tests */

async function testPhishingBlocksNavigation() {
  console.log('\n[navigation vers un site phishing → blocage]');
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url, body: opts.body ? JSON.parse(opts.body) : null });
    return okResponse({
      verdict: 'phishing',
      score: 91,
      summary: 'impots-gouv.secure-login.xyz imite le service des impots.',
      officialBrand: null,
      impersonatedBrands: ['Impots.gouv.fr'],
      findings: [{ id: 'site-impersonates-brand', severity: 'critical', title: 'Usurpation de marque' }],
      recommendations: [{ id: 'r', text: 'Ne saisissez aucun identifiant.' }],
      meta: { active: true, durationMs: 8 },
    });
  };
  const { state } = createWorkerContext(fetchImpl);

  state.beforeNavigate({
    tabId: 7,
    frameId: 0,
    url: 'https://impots-gouv.secure-login.xyz/connexion',
  });

  const redirected = await waitFor(() =>
    state.tabsUpdates.some((t) => String(t.url || '').includes('blocked/blocked.html')));
  assert(redirected, 'onglet redirige vers la page de blocage');

  const blockRules = state.dnrRules.filter((r) => r.action.type === 'block');
  assert(blockRules.length === 1, 'regle DNR de blocage creee');
  assert(
    blockRules[0].condition.requestDomains.includes('impots-gouv.secure-login.xyz'),
    'regle cible le bon domaine',
  );
  assert(blockRules[0].condition.resourceTypes.includes('main_frame'), 'regle limitee a main_frame');
  assert(state.badge === '!', 'badge rouge "!"');
  assert(state.notifications.length === 1, 'notification de blocage');
  assert(state.badgeColor === '#ff3b5c', 'couleur rouge');
  assert(calls.length === 1, 'un seul appel API');
  assert(calls[0].body.active === true, 'verifications actives demandees');
}

async function testWarnOnlyModeNoBlock() {
  console.log('\n[mode avertissement : pas de blocage]');
  const fetchImpl = async () => okResponse({
    verdict: 'phishing', score: 88, summary: 'phishing', officialBrand: null, impersonatedBrands: [],
    findings: [],
  });
  const { sandbox, state } = createWorkerContext(fetchImpl);
  // desactive le blocage avant la navigation
  await sandbox.QSApi.saveSettings({ blockMode: false });

  state.beforeNavigate({ tabId: 3, frameId: 0, url: 'https://arnaque.xyz/' });

  await waitFor(() => state.badge === '!', 2000).catch(() => {});
  await wait(600);
  assert(state.dnrRules.filter((r) => r.action.type === 'block').length === 0, 'aucune regle DNR');
  assert(state.tabsUpdates.length === 0, 'aucune redirection');
  assert(state.badge === '!', 'badge rouge sans blocage');
}

async function testOfficialClearsBadge() {
  console.log('\n[navigation vers un site officiel]');
  const fetchImpl = async () => okResponse({
    verdict: 'official', score: 0, summary: 'laposte.fr est officiel.',
    officialBrand: { name: 'La Poste' }, impersonatedBrands: [], findings: [],
  });
  const { state } = createWorkerContext(fetchImpl);

  state.beforeNavigate({ tabId: 5, frameId: 0, url: 'https://www.laposte.fr/' });
  const done = await waitFor(() => state.localStore['qs.cache'] !== undefined);
  assert(done, 'domaine mis en cache');
  await wait(100);
  assert(state.badge === '', 'badge efface');
  const cache = state.localStore['qs.cache'];
  assert(cache['laposte.fr'] && cache['laposte.fr'].verdict === 'official', 'cache = official');
}

async function testSuspiciousBadge() {
  console.log('\n[navigation vers un site suspect sous le seuil de blocage]');
  const fetchImpl = async () => okResponse({
    verdict: 'suspicious', score: 65, summary: 'Anomalies.', officialBrand: null,
    impersonatedBrands: [], findings: [],
  });
  const { state } = createWorkerContext(fetchImpl);

  state.beforeNavigate({ tabId: 6, frameId: 0, url: 'https://colis-relais.xyz/' });
  const done = await waitFor(() => state.badge === '?');
  assert(done, 'badge ambre "?"');
  assert(state.dnrRules.filter((r) => r.action.type === 'block').length === 0, 'pas de blocage sous le seuil');
  assert(state.notifications.length === 0, 'pas de notification');
}

async function testBypassFlow() {
  console.log("\n[contournement par l'utilisateur]");
  const fetchImpl = async () => okResponse({
    verdict: 'phishing', score: 90, summary: 'phishing', officialBrand: null,
    impersonatedBrands: [], findings: [],
  });
  const { sandbox, state } = createWorkerContext(fetchImpl);

  state.beforeNavigate({ tabId: 8, frameId: 0, url: 'https://faux-positif.xyz/' });
  await waitFor(() => state.dnrRules.some((r) => r.action.type === 'block'));

  const response = await new Promise((resolve) => {
    state.onMessage(
      { type: 'bypass-domain', tabId: 8, host: 'faux-positif.xyz', url: 'https://faux-positif.xyz/' },
      null,
      resolve,
    );
  });
  assert(response.ok === true, 'reponse ok au contournement');
  const allowRules = state.dnrRules.filter((r) => r.action.type === 'allow');
  assert(allowRules.length === 1, 'regle DNR allow ajoutee');
  assert(allowRules[0].priority > 1, 'priorite allow superieure au blocage');
  await wait(100);
  const bypass = state.localStore['qs.bypass'];
  assert(bypass && bypass.includes('faux-positif.xyz'), 'contournement persiste');
  const backToSite = state.tabsUpdates.some((t) => t.url === 'https://faux-positif.xyz/');
  assert(backToSite, 'onglet renvoye vers le site');
  assert(state.badge === '?', 'badge ambre apres contournement');
}

async function testQuotaPause() {
  console.log('\n[quota epuise pendant la surveillance]');
  const fetchImpl = async () => blockedResponse(
    { error: 'quota_exceeded', message: 'Quota atteint.', retryAfterSeconds: 900 },
    900,
  );
  const { state } = createWorkerContext(fetchImpl);

  state.beforeNavigate({ tabId: 9, frameId: 0, url: 'https://inconnu.boutique/' });
  const done = await waitFor(() => state.badge === 'OFF');
  assert(done, 'badge OFF quand le quota est epuise');
  assert(state.dnrRules.length === 0, 'aucun blocage sans verdict');
  await wait(50);
  const st = state.localStore['qs.state'];
  assert(st && st.pausedUntil > Date.now(), 'surveillance en pause');
}

async function testFormReportEscalation() {
  console.log('\n[rapport de contenu : formulaire de harvesting]');
  const fetchImpl = async () => okResponse({
    verdict: 'unknown', score: 12, summary: 'Domaine inconnu.', officialBrand: null,
    impersonatedBrands: [], findings: [],
  });
  const { state } = createWorkerContext(fetchImpl, { sendToContent: true });

  state.beforeNavigate({ tabId: 11, frameId: 0, url: 'https://connexion-espace.xyz/' });
  await waitFor(() => state.localStore['qs.cache'] !== undefined);

  // Le contenu script signale un formulaire mot de passe.
  const response = await new Promise((resolve) => {
    state.onMessage(
      {
        type: 'page-report',
        report: {
          host: 'connexion-espace.xyz',
          url: 'https://connexion-espace.xyz/',
          passwordForms: 1,
          loginForms: 1,
          hiddenInputs: 3,
          mixedResources: 0,
        },
      },
      { tab: { id: 11 } },
      resolve,
    );
  });
  assert(response.ok === true, 'rapport accuse de reception');
  await wait(100);
  const warns = state.sentToContent.filter((m) => m.msg.type === 'show-form-warning');
  assert(warns.length === 1, 'bandeau d avertissement envoye a la page');
  assert(state.badge === '?', 'badge ambre apres rapport');
}

async function testPhishingBadgeColorWithForms() {
  console.log('\n[formulaire sur domaine phishing confirme]');
  const fetchImpl = async () => okResponse({
    verdict: 'phishing', score: 95, summary: 'Usurpation.', officialBrand: null,
    impersonatedBrands: ['Chronopost'], findings: [],
  });
  const { state } = createWorkerContext(fetchImpl, { sendToContent: true });

  state.beforeNavigate({ tabId: 12, frameId: 0, url: 'https://chronopost-secure.xyz/' });
  await waitFor(() => state.tabsUpdates.some((t) => String(t.url).includes('blocked/blocked.html')));
  assert(state.badge === '!', 'badge rouge confirme');
}

async function testInternalPagesSkipped() {
  console.log('\n[pages internes ignorees]');
  let called = false;
  const fetchImpl = async () => { called = true; return okResponse({}); };
  const { state } = createWorkerContext(fetchImpl);

  state.beforeNavigate({ tabId: 13, frameId: 0, url: 'chrome://extensions/' });
  state.beforeNavigate({ tabId: 14, frameId: 0, url: 'about:blank' });
  state.beforeNavigate({ tabId: 15, frameId: 0, url: 'http://localhost:3000/admin' });
  await wait(500);
  assert(called === false, 'aucun appel API pour les pages internes');
  assert(state.dnrRules.length === 0, 'aucune regle creee');
}

async function testMessageBridge() {
  console.log('\n[pont de messages avec le popup]');
  const fetchImpl = async () => okResponse({
    verdict: 'phishing', score: 91, summary: 'arnaque confirmee', officialBrand: null,
    impersonatedBrands: ['Chronopost'], findings: [],
  });
  const { state } = createWorkerContext(fetchImpl);

  const response = await new Promise((resolve) => {
    state.onMessage({ type: 'check-domain', domain: 'chronopost.xyz', force: true }, null, resolve);
  });
  assert(response.result && response.result.verdict === 'phishing', 'verification forcee renvoyee au popup');

  const cached = await new Promise((resolve) => {
    state.onMessage({ type: 'get-cached-domain', domain: 'chronopost.xyz' }, null, resolve);
  });
  assert(cached.result && cached.result.score === 91, 'resultat en cache renvoye');
}

/* ---------------------------------------------------------------- main */

(async () => {
  await testPhishingBlocksNavigation();
  await testWarnOnlyModeNoBlock();
  await testOfficialClearsBadge();
  await testSuspiciousBadge();
  await testBypassFlow();
  await testQuotaPause();
  await testFormReportEscalation();
  await testPhishingBadgeColorWithForms();
  await testInternalPagesSkipped();
  await testMessageBridge();

  console.log(`\n${passed} ok, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
