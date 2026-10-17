/**
 * Tests de l'extension QueryShield (jsdom + mock Chrome).
 * Usage : node test/run-tests.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// jsdom est resolu depuis le workspace node gere par WorkBuddy.
const require = createRequire('C:/Users/josel/.workbuddy-ai/binaries/node/workspace/package.json');
const { JSDOM } = require('jsdom');

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) {
    passed++;
    console.log('  ok   ' + label);
  } else {
    failed++;
    console.log('  FAIL ' + label);
  }
}

/* ------------------------------------------------------- mock chrome */

function createChromeMock(dom, fetchImpl) {
  const syncStore = {};
  const localStore = {};

  const storage = {
    async get(key) {
      const bag = key === null ? { ...localStore } : { [key]: localStore[key] };
      return bag;
    },
    async set(obj) {
      Object.assign(localStore, obj);
    },
  };

  return {
    storage: {
      sync: {
        async get(key) { return { [key]: syncStore[key] }; },
        async set(obj) { Object.assign(syncStore, obj); },
      },
      local: storage,
    },
    runtime: {
      sendMessage(message, callback) {
        (async () => {
          if (message.type === 'get-active-tab-url') {
            callback({ url: 'https://www.chronopost.fr/suivi?liste=123', title: 'Chronopost' });
          } else if (message.type === 'get-cached-domain') {
            const cache = localStore['qs.cache'] || {};
            callback({ result: cache[message.domain] || null });
          } else {
            callback({ error: 'unknown_message' });
          }
        })();
        return true;
      },
      openOptionsPage() {},
    },
    tabs: {
      async query() { return [{ url: 'https://www.chronopost.fr/suivi?liste=123', title: 'Chronopost' }]; },
      async create() {},
      async get() { return { url: 'https://example.com' }; },
      onUpdated: { addListener() {} },
      onActivated: { addListener() {} },
    },
    action: {
      async setBadgeText({ text }) { this._badge = text; },
      async setBadgeBackgroundColor() {},
    },
    notifications: {
      async create(id, opts) { this._last = { id, ...opts }; },
      async clear() {},
      onClicked: { addListener() {} },
    },
    alarms: { create() {}, onAlarm: { addListener() {} } },
  };
}

/* ------------------------------------------------------- chargement popup */

async function loadPopup(fetchImpl) {
  const dom = await JSDOM.fromFile(join(ROOT, 'popup/popup.html'), {
    runScripts: 'outside-only',
    pretendToBeVisual: true,
    url: 'chrome-extension://fake/popup/popup.html',
  });
  const { window } = dom;

  window.chrome = createChromeMock(dom, fetchImpl);
  window.fetch = fetchImpl;

  window.eval(readFileSync(join(ROOT, 'shared/api.js'), 'utf8'));
  window.eval(readFileSync(join(ROOT, 'popup/popup.js'), 'utf8'));

  return { dom, window };
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, timeout = 2000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (cond()) return true;
    await wait(25);
  }
  return false;
}

/* ------------------------------------------------------------------ tests */

function mockFetch(handler) {
  const calls = [];
  const fn = async (url, opts = {}) => {
    calls.push({ url, body: opts.body ? JSON.parse(opts.body) : null });
    return handler(url, opts);
  };
  fn.calls = calls;
  return fn;
}

const okResponse = (data, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: { get: () => null },
  json: async () => data,
});

const ANALYZE_RESULT = {
  score: 93,
  verdict: 'dangerous',
  summary: 'Message frauduleux : pression et lien de suivi.',
  findings: [
    { id: 'r1', severity: 'critical', title: 'Lien de phishing', detail: 'Domaine imitant chronopost.' },
    { id: 'r2', severity: 'medium', title: 'Urgence artificielle', detail: ' "24h" ' },
  ],
  recommendations: ['Ne cliquez pas.', 'Supprimez le message.'],
  quota: { remaining: 7, limit: 10, exceeded: false },
  plan: 'free',
  meta: { engine: 'queryshield-heuristic', durationMs: 12, channel: 'sms' },
};

const SITE_RESULT_PHISHING = {
  verdict: 'phishing',
  score: 91,
  summary: 'chronopost-secure.xyz imite Chronopost sans en etre le domaine officiel.',
  officialBrand: null,
  impersonatedBrands: ['Chronopost'],
  findings: [{ id: 'site-impersonates-brand', severity: 'critical', title: 'Usurpation de marque', detail: '' }],
  recommendations: [{ id: 'site-rec-no-credentials', text: 'Ne saisissez aucun identifiant.' }],
  meta: { active: false, siteContacted: false, durationMs: 8 },
};

async function testAnalyzeMessage() {
  console.log('\n[analyse de message]');
  const fetchImpl = mockFetch(async (url) => {
    if (url.endsWith('/api/analyze')) return okResponse(ANALYZE_RESULT);
    throw new Error('unexpected ' + url);
  });
  const { window } = await loadPopup(fetchImpl);
  const doc = window.document;

  doc.getElementById('message-input').value = 'Chronopost: votre colis est bloque, cliquez ici';
  doc.getElementById('analyze-btn').click();

  const done = await waitFor(() => !doc.getElementById('result').hidden);
  assert(done, 'le resultat s affiche');
  assert(window.document.getElementById('ring-score').textContent === '93', 'score 93 affiche');
  assert(doc.getElementById('verdict-badge').textContent.includes('frauduleux'), 'verdict dangereux');
  assert(doc.getElementById('findings').children.length === 2, '2 constats affiches');
  assert(fetchImpl.calls.length === 1 && fetchImpl.calls[0].body.text.includes('Chronopost'), 'texte envoye a l API');
  assert(fetchImpl.calls[0].body.channel === 'unknown', 'canal par defaut = unknown');
  assert(!doc.getElementById('quota-line').hidden && doc.getElementById('quota-line').textContent.includes('7/10'), 'quota 7/10');
  window.close();
}

async function testChannelSelection() {
  console.log('\n[selection du canal]');
  const fetchImpl = mockFetch(async (url) => okResponse(ANALYZE_RESULT));
  const { window } = await loadPopup(fetchImpl);
  const doc = window.document;

  doc.querySelector('.qs-chip[data-channel="sms"]').click();
  doc.getElementById('message-input').value = 'test sms suspect';
  doc.getElementById('analyze-btn').click();
  await waitFor(() => !doc.getElementById('result').hidden);

  assert(fetchImpl.calls[0].body.channel === 'sms', 'canal sms envoye');
  window.close();
}

async function testAuditCurrentPage() {
  console.log('\n[auditer cette page]');
  const fetchImpl = mockFetch(async (url) => {
    if (url.endsWith('/api/check-site')) return okResponse(SITE_RESULT_PHISHING);
    throw new Error('unexpected ' + url);
  });
  const { window } = await loadPopup(fetchImpl);
  const doc = window.document;

  await waitFor(() => doc.getElementById('site-input').value.includes('chronopost.fr'));
  assert(doc.getElementById('site-input').value === 'https://www.chronopost.fr/suivi?liste=123', 'URL de l onglet pre-remplie');

  doc.getElementById('audit-page-btn').click();
  await waitFor(() => !doc.getElementById('result').hidden);

  assert(fetchImpl.calls.length === 1, 'un seul appel API');
  assert(fetchImpl.calls[0].url.endsWith('/api/check-site'), 'endpoint check-site');
  assert(fetchImpl.calls[0].body.url === 'https://www.chronopost.fr/suivi?liste=123', 'URL de la page envoyee');
  assert(doc.getElementById('verdict-badge').textContent === 'Phishing — ne pas saisir de donnees', 'verdict phishing');
  assert(doc.getElementById('result-meta').textContent.includes('Chronopost'), 'usurpation affichee');
  window.close();
}

async function testQuotaError() {
  console.log('\n[quota epuise]');
  const fetchImpl = mockFetch(async () =>
    okResponse({ error: 'quota_exceeded', message: 'Quota quotidien atteint (10 analyses par jour).' }, 429));
  const { window } = await loadPopup(fetchImpl);
  const doc = window.document;

  doc.getElementById('message-input').value = 'un message quelconque';
  doc.getElementById('analyze-btn').click();

  await waitFor(() => !doc.getElementById('error-box').hidden);
  assert(doc.getElementById('error-box').textContent.includes('Quota'), 'message de quota affiche');
  assert(doc.getElementById('result').hidden, 'aucun resultat affiche');
  window.close();
}

async function testNetworkError() {
  console.log('\n[reseau indisponible]');
  const fetchImpl = async () => { throw new TypeError('Failed to fetch'); };
  const { window } = await loadPopup(fetchImpl);
  const doc = window.document;

  doc.getElementById('message-input').value = 'un message quelconque';
  doc.getElementById('analyze-btn').click();

  await waitFor(() => !doc.getElementById('error-box').hidden);
  assert(doc.getElementById('error-box').textContent.includes('injoignable'), 'erreur reseau en francais');
  window.close();
}

async function testDomainUtils() {
  console.log('\n[utilitaires de domaine]');
  const { window } = await loadPopup(async () => okResponse({}));
  const api = window.QSApi;

  assert(api.registrableDomain('https://www.chronopost.fr/suivi?x=1') === 'chronopost.fr', 'domaine inscriptible');
  assert(api.isScannableUrl('https://exemple.com') === true, 'URL publique scannable');
  assert(api.isScannableUrl('chrome://extensions') === false, 'chrome:// ignore');
  assert(api.isScannableUrl('http://localhost:3000') === false, 'localhost ignore');
  assert(api.isScannableUrl('http://192.168.1.1') === false, 'IP privee ignoree');
  assert(api.isScannableUrl('https://admin.interne') === false, 'domaine interne ignore');
  assert(api.isScannableUrl('about:blank') === false, 'about: ignore');
  window.close();
}

/**
 * Garde-fou contre le bug de persistance signale par l utilisateur :
 * la page d options reference des champs absents du HTML, ce qui faisait
 * planter load() ET save() sur `null.checked` -> plus aucun reglage
 * n'etait enregistre. On verifie donc que chaque couple HTML/JS est coherent.
 */
async function testPageContract(dir, script, options) {
  const label = dir;
  console.log('\n[' + label + ' : contrat HTML/JS]');

  const html = readFileSync(join(ROOT, dir, dir + '.html'), 'utf8');
  const js = readFileSync(join(ROOT, dir, script), 'utf8');

  // Chaque identifiant demande par le JS existe dans le HTML.
  const wanted = [...new Set([
    ...js.matchAll(/getElementById\('([a-z0-9-]+)'\)/g),
    ...js.matchAll(/getElementById\("([a-z0-9-]+)"\)/g),
    ...js.matchAll(/\$\('([a-z0-9-]+)'\)/g),
  ].map((m) => m[1]))];
  assert(wanted.length > 0, label + ' : le JS reference des champs');
  const missing = wanted.filter((id) => !html.includes(`id="${id}"`));
  assert(missing.length === 0,
    label + ' : aucun champ manquant dans le HTML' + (missing.length ? ' — ' + missing.join(', ') : ''));

  // Les champs du HTML critiques doivent tous etre pilotes par le JS.
  const critical = (options && options.critical) || [];
  const undriven = critical.filter((id) => !wanted.includes(id) && !js.includes(`'${id}'`));
  assert(undriven.length === 0,
    label + ' : tous les champs critiques sont pilotes' + (undriven.length ? ' — ' + undriven.join(', ') : ''));

  // Simulation reelle : chargement des deux fichiers dans jsdom.
  const { window } = new JSDOM(html, {
    runScripts: 'outside-only',
    url: 'chrome-extension://test/' + dir + '/' + dir + '.html',
  });
  const errors = [];
  window.addEventListener('error', (e) => errors.push(e.message));
  const shared = readFileSync(join(ROOT, 'shared/api.js'), 'utf8');
  window.eval(shared);
  window.eval(js);

  const nulls = wanted.filter((id) => !window.document.getElementById(id));
  assert(nulls.length === 0, label + ' : champs accessibles en jsdom' + (nulls.length ? ' — ' + nulls.join(', ') : ''));
  assert(errors.length === 0, label + ' : aucune erreur JS en jsdom' + (errors.length ? ' — ' + errors[0] : ''));
  window.close();
}

async function testOptionsContract() {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  assert(!!(manifest.options_ui && /options\/options\.html$/.test(manifest.options_ui.page)),
    'manifest : page declaree dans options_ui (objet MV3)');
  assert(manifest.options_ui.open_in_tab === true,
    'manifest : options_ui.open_in_tab actif (plein onglet)');
  assert(!('options_page' in manifest),
    'manifest : cle legacy options_page supprimee');

  // Garde-fou CSS : une classe qui impose un `display` (ex. `.qs-panel
  // { display: grid }`) ecrase la regle `[hidden]` du navigateur. C est ce
  // qui affichait les panneaux Message ET Site empiles dans le popup.
  // Chaque feuille doit donc neutraliser explicitement [hidden].
  ['popup/popup.css', 'options/options.css', 'blocked/blocked.css'].forEach((sheet) => {
    const css = readFileSync(join(ROOT, sheet), 'utf8');
    assert(/\[hidden\]\s*\{[^}]*display:\s*none\s*!important/.test(css),
      sheet + ' : regle [hidden] { display: none !important } presente');
  });

  await testPageContract('options', 'options.js', {
    critical: ['protect-enabled', 'block-mode', 'network-checks', 'notify-phishing',
      'threshold', 'block-threshold', 'license', 'api-base', 'save-btn', 'test-btn',
      'clear-cache-btn', 'clear-bypass-btn', 'health-status', 'license-status'],
  });
  await testPageContract('popup', 'popup.js', {
    critical: ['analyze-btn', 'check-site-btn', 'result', 'verdict-badge',
      'findings', 'recommendations', 'message-input', 'site-input',
      'history', 'active-page', 'active-score', 'quota-line', 'error-box'],
  });
  await testPageContract('blocked', 'blocked.js', {
    critical: ['score', 'verdict', 'reasons', 'back-btn', 'bypass-btn'],
  });
}

/* ------------------------------------------------------------------ main */

(async () => {
  await testAnalyzeMessage();
  await testChannelSelection();
  await testAuditCurrentPage();
  await testQuotaError();
  await testNetworkError();
  await testDomainUtils();
  await testOptionsContract();

  console.log(`\n${passed} ok, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
