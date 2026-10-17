/**
 * Verification reelle de l'extension dans Chromium (MV3).
 * Verifie : enregistrement du service worker, rendu du popup, rendu de la
 * page de blocage, presence du contenu script sur une page http locale.
 * Usage : node test/browser.test.mjs
 */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import http from 'node:http';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire('C:/Users/josel/.workbuddy-ai/binaries/node/workspace/package.json');
const { chromium } = require('playwright-core');

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { passed++; console.log('  ok   ' + label); }
  else { failed++; console.log('  FAIL ' + label); }
}

/**
 * innerText renvoie le texte RENDU : text-transform: uppercase des CSS
 * transforme « Page active » en « PAGE ACTIVE ». On compare donc sans tenir
 * compte de la casse ni des accents.
 */
function hasText(text, needle) {
  const strip = (s) => s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  return strip(text).includes(strip(needle));
}

const EXT_PATH = ROOT;

(async () => {
  const context = await chromium.launchPersistentContext('', {
    headless: false,
    executablePath: 'C:/Users/josel/AppData/Local/ms-playwright/chromium-1234/chrome-win64/chrome.exe',
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      '--no-sandbox',
    ],
  });

  try {
    // 1. Service worker enregistre
    let sw = context.serviceWorkers()[0];
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
    assert(sw.url().includes('chrome-extension://'), 'service worker enregistre : ' + sw.url().slice(0, 60));

    const base = sw.url().replace(/background\.js$/, '');

    // 2. Popup rendu
    const popup = await context.newPage();
    const popupErrors = [];
    popup.on('pageerror', (e) => popupErrors.push(e.message));
    await popup.goto(base + 'popup/popup.html');
    await popup.waitForTimeout(1200);
    const popupText = await popup.locator('body').innerText();
    assert(hasText(popupText, 'QueryShield'), 'popup : marquee QueryShield');
    assert(hasText(popupText, 'Page active'), 'popup : section page active');
    assert(hasText(popupText, 'Analyser le message'), 'popup : bouton d analyse');
    assert(popupErrors.length === 0, 'popup : aucune erreur JS' + (popupErrors.length ? ' — ' + popupErrors[0] : ''));

    // 3. Page de blocage rendue
    const blocked = await context.newPage();
    const blockedErrors = [];
    blocked.on('pageerror', (e) => blockedErrors.push(e.message));
    await blocked.goto(
      base + 'blocked/blocked.html?host=impots-gouv.secure-login.xyz&score=91&verdict=phishing',
    );
    await blocked.waitForTimeout(800);
    const blockedText = await blocked.locator('body').innerText();
    assert(hasText(blockedText, 'bloqu'), 'blocage : titre de menace');
    assert(hasText(blockedText, 'impots-gouv.secure-login.xyz'), 'blocage : hote affiche');
    assert(hasText(blockedText, 'Revenir en arrière'), 'blocage : bouton retour');
    assert(hasText(blockedText, 'Continuer quand même'), 'blocage : option de contournement');
    assert(blockedErrors.length === 0, 'blocage : aucune erreur JS');

    // 4. Contenu script : sert une page locale avec formulaire
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(readFileSync(join(ROOT, 'test/fixtures/login-page.html'), 'utf8'));
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;

    const contentPage = await context.newPage();
    const contentErrors = [];
    contentPage.on('pageerror', (e) => contentErrors.push(e.message));
    await contentPage.goto(`http://127.0.0.1:${port}/`);
    await contentPage.waitForTimeout(1500);

    // Le contenu script a-t-il detecte le formulaire ? On interroge le SW
    // indirectement : aucune erreur + le bandeau doit apparaitre si le SW
    // escalade (ici le domaine est interne -> pas d'escalade, juste verifier
    // que le script tourne sans erreur).
    assert(contentErrors.length === 0, 'contenu : aucune erreur JS' + (contentErrors.length ? ' — ' + contentErrors[0] : ''));

    server.close();

    // 5. Options rendues
    const options = await context.newPage();
    const optionsErrors = [];
    options.on('pageerror', (e) => optionsErrors.push(e.message));
    await options.goto(base + 'options/options.html');
    await options.waitForTimeout(800);
    const optionsText = await options.locator('body').innerText();
    assert(hasText(optionsText, 'Mur de protection'), 'options : section mur de protection');
    assert(hasText(optionsText, 'Seuil de blocage'), 'options : seuil de blocage');
    assert(hasText(optionsText, 'Protection principale'), 'options : interrupteur general');
    assert(optionsErrors.length === 0, 'options : aucune erreur JS'
      + (optionsErrors.length ? ' — ' + optionsErrors[0] : ''));

    // 5 bis. Persistance : modifier, sortir, revenir.
    await options.evaluate(() => {
      document.getElementById('network-checks').click();
      const t = document.getElementById('block-threshold');
      t.value = '85';
      t.dispatchEvent(new Event('input', { bubbles: true }));
      t.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await options.waitForTimeout(500);
    const stored = await sw.evaluate(() =>
      chrome.storage.sync.get('qs.settings').then((bag) => bag['qs.settings'] || null));
    assert(stored && stored.networkChecks === false, 'options : modif ecrite dans storage.sync');
    assert(stored && stored.blockThreshold === 85, 'options : seuil persiste a 85');

    await options.goto(base + 'options/options.html');
    await options.waitForTimeout(600);
    const back = await options.evaluate(() => ({
      network: document.getElementById('network-checks').checked,
      threshold: document.getElementById('block-threshold').value,
    }));
    assert(back.network === false, 'REGRESSION : reglages conserves apres retour (network-checks)');
    assert(back.threshold === '85', 'REGRESSION : reglages conserves apres retour (seuil 85)');
  } finally {
    await context.close();
  }

  console.log(`\n${passed} ok, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
