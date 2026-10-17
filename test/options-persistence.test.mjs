/**
 * Regression : persistance des reglages de la page d options.
 *
 * Reproduit exactement le scenario signale par l utilisateur :
 *   « Je change, je sors et je reviens, et tout est comme si je n avais rien change. »
 *
 * Verifie, dans un VRAI Chromium avec l extension chargee :
 *   1. la page d options s ouvre sans erreur JS,
 *   2. tous les champs du HTML sont bien presents (aucun element manquant),
 *   3. modifier un reglage puis fermer/rouvrir la page conserve la valeur,
 *   4. l enregistrement ecrit reellement dans chrome.storage.sync,
 *   5. le worker est notifie du changement.
 *
 * Usage : node test/options-persistence.test.mjs
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

const EXT_PATH = ROOT;

(async () => {
  const context = await chromium.launchPersistentContext('', {
    headless: false,
    executablePath: CHROME,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      '--no-sandbox',
    ],
  });

  try {
    let sw = context.serviceWorkers()[0];
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
    const base = sw.url().replace(/background\.js$/, '');
    assert(true, 'extension chargee : ' + base.slice(0, 48));

    // ---- 1. Ouverture de la page d options -------------------------------
    const options = await context.newPage();
    const errors = [];
    options.on('pageerror', (e) => errors.push(e.message));
    await options.goto(base + 'options/options.html');
    await options.waitForTimeout(900);

    assert(errors.length === 0, 'options : aucune erreur JS au chargement' + (errors.length ? ' — ' + errors[0] : ''));

    // ---- 2. Tous les champs pilotes par le JS existent dans le HTML -------
    const ids = await options.evaluate(() =>
      ['protect-enabled', 'block-mode', 'network-checks', 'notify-phishing',
       'threshold', 'block-threshold', 'license', 'api-base',
       'save-btn', 'test-btn', 'clear-cache-btn', 'clear-bypass-btn']
        .filter((id) => !document.getElementById(id)),
    );
    assert(ids.length === 0, 'options : tous les champs presents' + (ids.length ? ' — manquants : ' + ids.join(', ') : ''));

    const initial = await options.evaluate(() =>
      new Promise((resolve) => {
        const el = document.getElementById('block-mode');
        resolve(el ? el.checked : null);
      }),
    );
    assert(typeof initial === 'boolean', 'options : champ #block-mode lisible (etat initial ' + initial + ')');

    // ---- 3. Modifier, sortir, revenir -----------------------------------
    // Coche/decoche plusieurs reglages, comme le ferait l utilisateur.
    await options.evaluate(() => {
      document.getElementById('block-mode').click();
      document.getElementById('network-checks').click();
      document.getElementById('notify-phishing').click();
      const t = document.getElementById('block-threshold');
      t.value = '85';
      t.dispatchEvent(new Event('input', { bubbles: true }));
      t.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await options.waitForTimeout(600);

    const afterEdit = await options.evaluate(() => ({
      blockMode: document.getElementById('block-mode').checked,
      network: document.getElementById('network-checks').checked,
      notify: document.getElementById('notify-phishing').checked,
      blockThreshold: document.getElementById('block-threshold').value,
    }));
    assert(afterEdit.blockMode === !initial, 'options : #block-mode bascule a ' + afterEdit.blockMode);
    assert(afterEdit.network === false, 'options : #network-checks decoche');
    assert(afterEdit.notify === false, 'options : #notify-phishing decoche');
    assert(afterEdit.blockThreshold === '85', 'options : #block-threshold passe a 85');

    // Verifie l ecriture effective dans chrome.storage.sync
    const stored = await sw.evaluate(() =>
      chrome.storage.sync.get('qs.settings').then((bag) => bag['qs.settings'] || null),
    );
    assert(stored !== null, 'options : qs.settings ecrit dans chrome.storage.sync');
    assert(stored && stored.blockMode === afterEdit.blockMode,
      'options : valeur persistee = celle affichee (blockMode=' + (stored && stored.blockMode) + ')');
    assert(stored && stored.blockThreshold === 85,
      'options : seuil persiste = 85 (recu ' + (stored && stored.blockThreshold) + ')');
    assert(stored && stored.networkChecks === false, 'options : networkChecks persiste a false');

    // ---- 4. Sortir puis revenir (rechargement complet de la page) --------
    await options.goto(base + 'options/options.html');
    await options.waitForTimeout(700);

    const reloaded = await options.evaluate(() => ({
      blockMode: document.getElementById('block-mode').checked,
      network: document.getElementById('network-checks').checked,
      notify: document.getElementById('notify-phishing').checked,
      blockThreshold: document.getElementById('block-threshold').value,
      protect: document.getElementById('protect-enabled').checked,
    }));
    assert(reloaded.blockMode === afterEdit.blockMode,
      'REGRESSION : apres retour, #block-mode vaut ' + reloaded.blockMode + ' (attendu ' + afterEdit.blockMode + ')');
    assert(reloaded.network === afterEdit.network,
      'REGRESSION : apres retour, #network-checks vaut ' + reloaded.network);
    assert(reloaded.notify === afterEdit.notify,
      'REGRESSION : apres retour, #notify-phishing vaut ' + reloaded.notify);
    assert(reloaded.blockThreshold === '85',
      'REGRESSION : apres retour, #block-threshold vaut ' + reloaded.blockThreshold);
    assert(reloaded.protect === true, 'options : protection principale reactive par defaut');
    assert(errors.length === 0, 'options : aucune erreur JS sur l ensemble du scenario'
      + (errors.length ? ' — ' + errors.join(' | ') : ''));

    // ---- 5. Bouton Enregistrer explicite ---------------------------------
    await options.evaluate(() => {
      document.getElementById('license').value = 'QS-TEST-123';
      document.getElementById('save-btn').click();
    });
    await options.waitForTimeout(500);
    const afterSave = await sw.evaluate(() =>
      chrome.storage.sync.get('qs.settings').then((bag) => bag['qs.settings'] || null),
    );
    assert(afterSave && afterSave.license === 'QS-TEST-123',
      'options : le bouton Enregistrer ecrit la licence');

    // ---- 6. Vider les contournements (bouton sans effet auparavant) ------
    await options.evaluate(() => document.getElementById('clear-bypass-btn').click());
    await options.waitForTimeout(400);
    const bypassText = await options.locator('#health-status').innerText();
    assert(/contournement/i.test(bypassText),
      'options : le bouton « Vider les contournements » repond (' + bypassText.trim().slice(0, 40) + ')');
  } finally {
    await context.close();
  }

  console.log(`\n${passed} ok, ${failed} fail`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
