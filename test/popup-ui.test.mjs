/**
 * Regression UI du popup.
 *
 * Bug signale : dans l onglet Site, « Verifier ce domaine » semblait ne pas
 * fonctionner. En realite la regle CSS `.qs-panel { display: grid }` ecrasait
 * l attribut `hidden` : les panneaux Message ET Site restaient affiches en
 * meme temps, et une erreur laissee par une action precedente
 * (« Saisissez au moins 4 caracteres a analyser. ») s affichait sous le
 * formulaire de domaine, donnant l impression que la verification echouait.
 *
 * Ce test verifie, dans un vrai Chromium :
 *   1. un seul panneau est visible a la fois,
 *   2. l onglet Site affiche bien le panneau Site et masque Message,
 *   3. « Verifier ce domaine » appelle /api/check-site (jamais /api/analyze),
 *   4. le resultat s affiche et aucune erreur ne subsiste,
 *   5. une erreur de l onglet Message disparait quand on change d onglet.
 *
 * Usage : node test/popup-ui.test.mjs
 */
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire('C:/Users/josel/.workbuddy-ai/binaries/node/workspace/package.json');
const { chromium } = require('playwright-core');

const CHROME = 'C:/Users/josel/AppData/Local/ms-playwright/chromium-1234/chrome-win64/chrome.exe';

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { passed++; console.log('  ok   ' + label); }
  else { failed++; console.log('  FAIL ' + label); }
}

(async () => {
  const context = await chromium.launchPersistentContext('', {
    headless: false,
    executablePath: CHROME,
    args: [
      `--disable-extensions-except=${ROOT}`,
      `--load-extension=${ROOT}`,
      '--no-sandbox',
    ],
  });

  try {
    let sw = context.serviceWorkers()[0];
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
    const base = sw.url().replace(/background\.js$/, '');

    const page = await context.newPage();
    const errors = [];
    const apiCalls = [];
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('request', (r) => {
      if (r.url().includes('/api/')) {
        apiCalls.push({ url: r.url(), body: r.postData() || '' });
      }
    });

    await page.goto(base + 'popup/popup.html');
    await page.waitForTimeout(1200);

    const vis = () => page.evaluate(() => {
      const shown = (id) => {
        const el = document.getElementById(id);
        return el !== null && el.offsetParent !== null;
      };
      return {
        message: shown('tab-message'),
        site: shown('tab-site'),
        messageDisplay: getComputedStyle(document.getElementById('tab-message')).display,
        siteDisplay: getComputedStyle(document.getElementById('tab-site')).display,
        siteHiddenAttr: document.getElementById('tab-site').hidden,
      };
    });

    // ---- 1. Au demarrage : un seul panneau visible ----------------------
    const initial = await vis();
    assert(initial.message === true, 'demarrage : panneau Message visible');
    assert(initial.site === false,
      'REGRESSION : panneau Site masque au demarrage (display=' + initial.siteDisplay + ')');
    assert(initial.siteDisplay === 'none',
      'REGRESSION : `hidden` produit bien display:none (recu ' + initial.siteDisplay + ')');

    // ---- 2. Bascule vers l onglet Site ---------------------------------
    await page.evaluate(() => document.querySelector('[data-tab="site"]').click());
    await page.waitForTimeout(250);
    const onSite = await vis();
    assert(onSite.site === true, 'onglet Site : panneau Site affiche');
    assert(onSite.message === false,
      'REGRESSION : panneau Message masque quand on est sur Site (display=' + onSite.messageDisplay + ')');

    // ---- 3. Verification de domaine ------------------------------------
    await page.evaluate(() => {
      const el = document.getElementById('site-input');
      el.value = 'https://searchregister.site/';
      el.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await page.evaluate(() => document.getElementById('check-site-btn').click());
    await page.waitForTimeout(6000);

    const state = await page.evaluate(() => ({
      error: document.getElementById('error-box').hidden
        ? null : document.getElementById('error-box').textContent,
      loading: document.getElementById('loading-box').hidden,
      resultHidden: document.getElementById('result').hidden,
      score: document.getElementById('ring-score').textContent,
      verdict: document.getElementById('verdict-badge').textContent,
      loadingText: document.getElementById('loading-text').textContent,
    }));

    const checkSiteCalls = apiCalls.filter((c) => c.url.includes('/api/check-site'));
    const analyzeCalls = apiCalls.filter((c) => c.url.includes('/api/analyze'));

    assert(checkSiteCalls.length === 1,
      'requete envoyee a /api/check-site (' + checkSiteCalls.length + ')');
    assert(analyzeCalls.length === 0,
      'REGRESSION : aucune requete parasite vers /api/analyze');
    assert(checkSiteCalls[0] && checkSiteCalls[0].body.includes('searchregister.site'),
      'le corps contient le domaine saisi');
    assert(state.error === null, 'aucune erreur affichee' + (state.error ? ' — ' + state.error : ''));
    assert(state.loading === true, 'indicateur de chargement referme');
    assert(state.resultHidden === false, 'bloc de resultat affiche');
    assert(state.score === '31', 'score affiche = 31 (recu ' + state.score + ')');
    assert(/suspect/i.test(state.verdict), 'verdict affiche : ' + state.verdict);

    // ---- 4. Une erreur de Message ne deborde pas sur l onglet Site ------
    await page.evaluate(() => document.querySelector('[data-tab="message"]').click());
    await page.waitForTimeout(200);
    await page.evaluate(() => {
      const ta = document.getElementById('message-input');
      ta.value = '';
      ta.dispatchEvent(new Event('input', { bubbles: true }));
      document.getElementById('analyze-btn').click();
    });
    await page.waitForTimeout(400);
    const msgError = await page.evaluate(() =>
      document.getElementById('error-box').hidden ? null : document.getElementById('error-box').textContent);
    assert(msgError !== null && /4 caracteres/.test(msgError),
      'message vide : erreur de saisie affichee');

    await page.evaluate(() => document.querySelector('[data-tab="site"]').click());
    await page.waitForTimeout(300);
    const afterSwitch = await page.evaluate(() =>
      document.getElementById('error-box').hidden ? null : document.getElementById('error-box').textContent);
    assert(afterSwitch === null,
      'REGRESSION : l erreur du message disparait en passant sur Site' +
      (afterSwitch ? ' — reste : ' + afterSwitch : ''));

    assert(errors.length === 0, 'popup : aucune erreur JS'
      + (errors.length ? ' — ' + errors[0] : ''));
  } finally {
    await context.close();
  }

  console.log(`\n${passed} ok, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
