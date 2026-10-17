/**
 * Tests de la page de blocage (blocked/blocked.js) en jsdom.
 * Usage : node test/blocked.test.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
// jsdom est resolu depuis le workspace node gere par WorkBuddy (ESM ignore NODE_PATH).
const require = createRequire('C:/Users/josel/.workbuddy-ai/binaries/node/workspace/package.json');
const { JSDOM } = require('jsdom');

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { passed++; console.log('  ok   ' + label); }
  else { failed++; console.log('  FAIL ' + label); }
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

const RESULT = {
  verdict: 'phishing',
  score: 91,
  summary: 'impots-gouv.secure-login.xyz imite le service des impots.',
  officialBrand: null,
  impersonatedBrands: ['Impots.gouv.fr'],
  findings: [
    { id: 'site-impersonates-brand', severity: 'critical', title: 'Usurpation de marque' },
    { id: 'site-newly-registered', severity: 'high', title: 'Domaine enregistre recemment' },
    { id: 'info', severity: 'info', title: 'Information ignoree' },
  ],
  recommendations: [{ id: 'r1', text: 'Ne saisissez aucun identifiant.' }],
  network: { rdap: { domainAgeDays: 4 } },
};

async function loadBlockedPage(query) {
  const dom = await JSDOM.fromFile(join(ROOT, 'blocked/blocked.html'), {
    runScripts: 'outside-only',
    pretendToBeVisual: true,
    url: 'chrome-extension://fake/blocked/blocked.html' + query,
  });
  const { window } = dom;

  const sent = [];
  const created = [];
  window.chrome = {
    runtime: {
      sendMessage(message, callback) {
        sent.push(message);
        (async () => {
          if (message.type === 'get-tab-state') {
            callback({
              state: { host: 'impots-gouv.secure-login.xyz', status: 'blocked', result: RESULT },
              pending: { url: 'https://impots-gouv.secure-login.xyz/connexion', host: 'impots-gouv.secure-login.xyz', result: RESULT },
              paused: false,
            });
          } else if (message.type === 'get-block-info') {
            callback({ result: RESULT });
          } else if (message.type === 'go-back') {
            callback({ ok: true });
          } else if (message.type === 'bypass-domain') {
            callback({ ok: true });
          } else {
            callback({ ok: true });
          }
        })();
        return true;
      },
    },
    tabs: {
      async query(opts, cb) { cb && cb([{ id: 3, url: 'chrome-extension://fake/blocked/blocked.html' }]); },
      async update() {},
      async create(opts) { created.push(opts); },
      async goBack() {},
    },
  };

  window.eval(readFileSync(join(ROOT, 'shared/api.js'), 'utf8'));
  window.eval(readFileSync(join(ROOT, 'blocked/blocked.js'), 'utf8'));
  return { dom, window, sent, created };
}

(async () => {
  console.log('\n[page de blocage : rendu]');
  const { window } = await loadBlockedPage(
    '?host=impots-gouv.secure-login.xyz&score=91&verdict=phishing&url=' +
      encodeURIComponent('https://impots-gouv.secure-login.xyz/connexion'),
  );
  const doc = window.document;

  const rendered = await waitFor(() => doc.getElementById('score').textContent === '91');
  assert(rendered, 'score 91 affiche');
  assert(doc.getElementById('host').textContent === 'impots-gouv.secure-login.xyz', 'hote affiche');
  assert(doc.getElementById('verdict').textContent.includes('Phishing'), 'verdict phishing');
  assert(doc.getElementById('summary').textContent.includes('impots'), 'synthese du moteur');
  assert(doc.getElementById('reasons').children.length === 2, '2 motifs graves (hors info)');
  assert(doc.getElementById('recos').children.length === 1, 'recommandation affichee');
  const age = doc.getElementById('domain-age');
  assert(!age.hidden && age.textContent.includes('4 jours'), 'age du domaine affiche');
  const chips = doc.getElementById('iocs');
  assert(chips.textContent.includes('usurpation'), 'usurpation listee');
  assert(chips.textContent.includes('Impots.gouv.fr'), 'marque usurpee listee');
  assert(doc.getElementById('target-meta').textContent.includes('connexion'), 'URL d origine affichee');
  window.close();

  console.log('\n[page de blocage : contournement]');
  const second = await loadBlockedPage('?host=faux-positif.xyz&score=88&verdict=phishing');
  const doc2 = second.window.document;
  await waitFor(() => doc2.getElementById('score').textContent === '91');

  const bypassBox = doc2.getElementById('bypass-confirm');
  assert(bypassBox.hidden === true, 'confirmation masquee au depart');
  doc2.getElementById('bypass-btn').click();
  await wait(50);
  assert(bypassBox.hidden === false, 'confirmation affichee apres clic');
  assert(doc2.getElementById('bypass-host').textContent === 'faux-positif.xyz', 'hote repris');

  doc2.getElementById('bypass-yes').click();
  await waitFor(() => second.sent.some((m) => m.type === 'bypass-domain'));
  const msg = second.sent.find((m) => m.type === 'bypass-domain');
  assert(msg && msg.host === 'faux-positif.xyz', 'message de contournement envoye');
  assert(msg && msg.url === 'https://faux-positif.xyz', 'URL de reprise incluse');
  second.window.close();

  console.log('\n[page de blocage : rapport complet]');
  const third = await loadBlockedPage('?host=chronopost.xyz&score=90&verdict=phishing');
  await waitFor(() => third.window.document.getElementById('score').textContent === '91');
  third.window.document.getElementById('report-btn').click();
  await wait(50);
  assert(
    third.created.length === 1 && third.created[0].url.includes('verifier-site?url='),
    'lien vers le rapport shield.query-intel.com',
  );
  third.window.close();

  console.log(`\n${passed} ok, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
