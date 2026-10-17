/**
 * QueryShield — service worker (Manifest V3).
 *
 * Role : surveillance silencieuse des domaines visites.
 *  - chaque nouvel onglet / navigation declenche une verification mettee en cache
 *  - phishing confirme  -> badge rouge "!" + notification systeme
 *  - site suspect       -> badge ambre "?"
 *  - domaine sain       -> badge efface
 *
 * Le service n'est jamais contacte en direct : seules les API QueryShield
 * (shield.query-intel.com) sont appelees, jamais le site analyse.
 */
importScripts('shared/api.js');

const CACHE_KEY = 'qs.cache';       // domaine -> { ts, verdict, score, summary, officialBrand }
const HISTORY_KEY = 'qs.history';   // 20 dernieres analyses
const STATE_KEY = 'qs.state';       // { pausedUntil, lastCallAt }
const CACHE_TTL_MS = 60 * 60 * 1000;      // 1 h
const MIN_CALL_INTERVAL_MS = 2000;        // anti-rafale entre appels API
const pendingTimers = new Map();          // tabId -> timer de debounce (memoire volatile)

/* ------------------------------------------------------------------ badge */

const BADGE_COLORS = {
  phishing: '#ff3b5c',
  suspicious: '#ffb020',
  paused: '#5a6472',
};

async function setBadge(text, color) {
  await chrome.action.setBadgeBackgroundColor({ color: color || '#5a6472' });
  await chrome.action.setBadgeText({ text: text || '' });
}

async function clearBadge() {
  await chrome.action.setBadgeText({ text: '' });
}

/* ------------------------------------------------------------- stockage */

async function readJson(key, fallback) {
  const bag = await chrome.storage.local.get(key);
  return bag[key] || fallback;
}

async function writeJson(key, value) {
  await chrome.storage.local.set({ [key]: value });
}

async function pushHistory(entry) {
  const history = await readJson(HISTORY_KEY, []);
  history.unshift(entry);
  await writeJson(HISTORY_KEY, history.slice(0, 20));
}

/* ------------------------------------------------------ verification site */

async function getCached(domain) {
  const cache = await readJson(CACHE_KEY, {});
  const hit = cache[domain];
  if (!hit) return null;
  if (Date.now() - hit.ts > CACHE_TTL_MS) return null;
  return hit;
}

async function storeCache(domain, entry) {
  const cache = await readJson(CACHE_KEY, {});
  cache[domain] = entry;
  // Nettoyage opportuniste des entrees perimees.
  for (const [key, value] of Object.entries(cache)) {
    if (Date.now() - value.ts > CACHE_TTL_MS) delete cache[key];
  }
  await writeJson(CACHE_KEY, cache);
  if (Object.keys(cache).length > 500) {
    // Filet de securite : on ne conserve jamais plus de 500 domaines.
    const entries = Object.entries(cache).sort((a, b) => b[1].ts - a[1].ts).slice(0, 500);
    await writeJson(CACHE_KEY, Object.fromEntries(entries));
  }
}

async function isPaused() {
  const state = await readJson(STATE_KEY, {});
  return state.pausedUntil && state.pausedUntil > Date.now();
}

async function noteCall() {
  await writeJson(STATE_KEY, { ...(await readJson(STATE_KEY, {})), lastCallAt: Date.now() });
}

/**
 * Verifie un domaine via l'API (avec cache).
 * @returns {Promise<object|null>} resultat normalise ou null si non applicable.
 */
async function checkDomain(domain, { force = false } = {}) {
  if (!QSApi.isScannableUrl('https://' + domain)) return null;

  if (!force) {
    const cached = await getCached(domain);
    if (cached) return { ...cached, fromCache: true };
  }

  if (await isPaused()) {
    await setBadge('OFF', BADGE_COLORS.paused);
    return null;
  }

  // Anti-rafale : espace les appels reseau.
  const state = await readJson(STATE_KEY, {});
  if (!force && state.lastCallAt && Date.now() - state.lastCallAt < MIN_CALL_INTERVAL_MS) {
    await new Promise((r) => setTimeout(r, MIN_CALL_INTERVAL_MS));
  }
  await noteCall();

  const settings = await QSApi.getSettings();
  const result = await QSApi.checkSite(domain, settings);

  if (!result.ok) {
    if (result.status === 429) {
      // Quota ou debit : on met la surveillance en pause et on previendra l'utilisateur.
      const pauseMs = Math.min((result.retryAfter || 900), 24 * 3600) * 1000;
      await writeJson(STATE_KEY, { pausedUntil: Date.now() + pauseMs });
      await setBadge('OFF', BADGE_COLORS.paused);
      await notifyOnce('qs-quota', {
        title: 'QueryShield — surveillance en pause',
        message: result.data.message || 'Quota atteint : reessai automatique plus tard.',
      });
    }
    return null;
  }

  const entry = {
    ts: Date.now(),
    verdict: result.data.verdict,
    score: result.data.score,
    summary: result.data.summary,
    officialBrand: result.data.officialBrand,
    impersonatedBrands: result.data.impersonatedBrands || [],
  };
  await storeCache(domain, entry);
  await pushHistory({
    ts: Date.now(),
    type: 'site',
    label: domain,
    verdict: entry.verdict,
    score: entry.score,
  });

  await applyBadgePolicy(entry, settings, domain);
  return { ...entry, fromCache: false };
}

/** Applique badge + notification selon le verdict et le seuil choisi. */
async function applyBadgePolicy(entry, settings, domain) {
  if (!settings) settings = await QSApi.getSettings();

  if (entry.verdict === 'phishing') {
    await setBadge('!', BADGE_COLORS.phishing);
    if (settings.notifyPhishing) {
      await notifyOnce('qs-alert-' + entry.ts, {
        title: '⚠ Site signale comme phishing',
        message: entry.summary || ('Ne saisissez aucune donnee sur ' + domain + '.'),
        domain,
      });
    }
    return;
  }

  if (entry.score >= settings.alertThreshold) {
    await setBadge('?', BADGE_COLORS.suspicious);
    return;
  }

  await clearBadge();
}

/** Notification unique par cle (evite les doublons lors des navigations repetees). */
async function notifyOnce(id, options) {
  const seen = await readJson('qs.notified', {});
  if (seen[id]) return;
  seen[id] = Date.now();
  // Purge les cles de plus de 24 h.
  for (const [key, ts] of Object.entries(seen)) {
    if (Date.now() - ts > 24 * 3600 * 1000) delete seen[key];
  }
  await writeJson('qs.notified', seen);

  await chrome.notifications.create(id, {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: options.title,
    message: options.message,
    priority: 2,
    silent: false,
  });
  // Memorise le domaine pour le clic sur la notification.
  if (options.domain) {
    await writeJson('qs.lastAlertDomain', { domain: options.domain, ts: Date.now() });
  }
}

/* ------------------------------------------------------------ navigation */

/** Planifie la verification d'un onglet (debounce 800 ms, en memoire). */
async function scheduleTabCheck(tabId, url) {
  const domain = QSApi.registrableDomain(url);
  if (!domain || !QSApi.isScannableUrl(url)) return;
  const settings = await QSApi.getSettings();
  if (!settings.protectEnabled) return;

  const existing = pendingTimers.get(tabId);
  if (existing) clearTimeout(existing);

  const timer = setTimeout(async () => {
    pendingTimers.delete(tabId);
    try {
      await checkDomain(domain);
    } catch {
      /* une erreur reseau ne doit jamais faire echouer la navigation */
    }
  }, 800);

  pendingTimers.set(tabId, timer);
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const url = changeInfo.url || (tab && tab.url);
  if (!url) return;
  // Attend le chargement complet pour ne verifier qu'une fois par page.
  if (changeInfo.status === 'complete' || changeInfo.url) {
    scheduleTabCheck(tabId, url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) scheduleTabCheck(tabId, tab.url);
  } catch {
    /* onglet ferme entre-temps */
  }
});

/* ---------------------------------------------------------- notifications */

chrome.notifications.onClicked.addListener(async (notificationId) => {
  await chrome.notifications.clear(notificationId);
  const last = await readJson('qs.lastAlertDomain', null);
  const target = last && last.domain
    ? 'https://shield.query-intel.com/verifier-site?url=' + encodeURIComponent(last.domain)
    : 'https://shield.query-intel.com/verifier-site';
  await chrome.tabs.create({ url: target });
  await clearBadge();
});

/* ------------------------------------------------------------- messages */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message && message.type === 'check-domain') {
      const result = await checkDomain(message.domain, { force: message.force === true });
      sendResponse({ result });
      return;
    }
    if (message && message.type === 'get-cached-domain') {
      const hit = await getCached(message.domain);
      sendResponse({ result: hit });
      return;
    }
    if (message && message.type === 'get-active-tab-url') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      sendResponse({ url: tab && tab.url ? tab.url : null, title: tab && tab.title ? tab.title : null });
      return;
    }
    if (message && message.type === 'settings-changed') {
      const s = await QSApi.getSettings();
      if (!s.protectEnabled || !(await isPaused())) await clearBadge();
      sendResponse({ ok: true });
      return;
    }
    sendResponse({ error: 'unknown_message' });
  })().catch(() => sendResponse({ error: 'internal' }));
  return true; // reponse asynchrone
});

/* ---------------------------------------------------------------- alarmes */

chrome.alarms.create('qs-cleanup', { periodInMinutes: 1440 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'qs-cleanup') return;
  const cache = await readJson(CACHE_KEY, {});
  let changed = false;
  for (const [key, value] of Object.entries(cache)) {
    if (Date.now() - value.ts > CACHE_TTL_MS) {
      delete cache[key];
      changed = true;
    }
  }
  if (changed) await writeJson(CACHE_KEY, cache);
});

/* ------------------------------------------------------------- cycle de vie */

chrome.runtime.onInstalled.addListener(async () => {
  await QSApi.saveSettings({}); // materialise les reglages par defaut
  await clearBadge();
});
