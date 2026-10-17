/**
 * QueryShield — service worker v2 (Manifest V3).
 *
 * Boucle principale :
 *   1. webNavigation.onBeforeNavigate (zero-click) -> domaine inscriptible
 *   2. cache 1 h -> sinon POST /api/check-site (verifications actives : age, DNS)
 *   3. decision :
 *        phishing / score >= seuil de blocage
 *          -> regle DNR "block main_frame" + redirection vers blocked.html
 *        score >= seuil d'alerte -> badge ambre "?"
 *        domaine officiel / sain -> badge efface
 *   4. rapports du contenu script (formulaires de harvesting) -> escalation
 *
 * Le site analyse n'est JAMAIS contacte : seules les API shield.query-intel.com
 * sont appelees.
 */
importScripts('shared/api.js');

/* ---------------------------------------------------------------- constantes */

const CACHE_KEY = 'qs.cache';
const STATE_KEY = 'qs.state';
const HISTORY_KEY = 'qs.history';
const BYPASS_KEY = 'qs.bypass';
const NOTIFIED_KEY = 'qs.notified';
const CACHE_TTL_MS = 60 * 60 * 1000;
const MIN_CALL_INTERVAL_MS = 2000;
const LAST_CALL_KEY = 'qs.lastCallAt';

const BADGE_COLORS = { phishing: '#ff3b5c', suspicious: '#ffb020', paused: '#5a6472' };

/** declarativeNetRequest (Chrome / Firefox 128+). */
const DNR_AVAILABLE =
  typeof chrome.declarativeNetRequest === 'object' &&
  chrome.declarativeNetRequest !== null &&
  typeof chrome.declarativeNetRequest.updateDynamicRules === 'function';

/* ---------------------------------------------------------------- etat volatile */

/** tabId -> { url, host, status, result, forms, updatedAt } */
const tabState = new Map();
/** tabId -> { url, host, result } : page bloquee en attente de decision. */
const pendingBlocks = new Map();
/** Domaines court-circuites par l'utilisateur (session). */
const sessionBypass = new Set();

/* ------------------------------------------------------------------- badge */

async function setBadge(text, color) {
  await chrome.action.setBadgeBackgroundColor({ color: color || '#5a6472' });
  await chrome.action.setBadgeText({ text: text || '' });
}

async function clearBadge() {
  await chrome.action.setBadgeText({ text: '' });
}

/* ---------------------------------------------------------------- stockage */

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
  await writeJson(HISTORY_KEY, history.slice(0, 30));
}

/* ------------------------------------------------------------------- regles DNR */

function ruleIdFor(host) {
  // Identifiant stable et numerique dans [1, 2^31-1].
  let hash = 0;
  for (let i = 0; i < host.length; i += 1) {
    hash = (hash * 31 + host.charCodeAt(i)) % 2147483647;
  }
  return (hash % 2000000) + 1;
}

async function addBlockRule(host) {
  if (!DNR_AVAILABLE) return;
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleIdFor(host)],
      addRules: [
        {
          id: ruleIdFor(host),
          priority: 1,
          action: { type: 'block' },
          condition: { requestDomains: [host], resourceTypes: ['main_frame'] },
        },
      ],
    });
  } catch {
    /* regle impossible : la redirection reste le filet de securite */
  }
}

async function addBypassRule(host) {
  if (!DNR_AVAILABLE) return;
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [
        {
          id: ruleIdFor(host),
          priority: 10,
          action: { type: 'allow' },
          condition: { requestDomains: [host], resourceTypes: ['main_frame'] },
        },
      ],
    });
  } catch {
    /* ignore */
  }
}

async function persistBypass(host) {
  sessionBypass.add(host);
  const stored = await readJson(BYPASS_KEY, []);
  if (!stored.includes(host)) {
    stored.push(host);
    await writeJson(BYPASS_KEY, stored.slice(0, 200));
  }
}

async function loadBypass() {
  const stored = await readJson(BYPASS_KEY, []);
  stored.forEach((host) => sessionBypass.add(host));
}

/* ------------------------------------------------------------ verification site */

async function getCached(host) {
  const cache = await readJson(CACHE_KEY, {});
  const hit = cache[host];
  if (!hit) return null;
  if (Date.now() - hit.ts > CACHE_TTL_MS) return null;
  return hit;
}

async function storeCache(host, entry) {
  const cache = await readJson(CACHE_KEY, {});
  cache[host] = entry;
  for (const [key, value] of Object.entries(cache)) {
    if (Date.now() - value.ts > CACHE_TTL_MS) delete cache[key];
  }
  if (Object.keys(cache).length > 500) {
    const kept = Object.entries(cache)
      .sort((a, b) => b[1].ts - a[1].ts)
      .slice(0, 500);
    await writeJson(CACHE_KEY, Object.fromEntries(kept));
  } else {
    await writeJson(CACHE_KEY, cache);
  }
}

async function isPaused() {
  const state = await readJson(STATE_KEY, {});
  return Boolean(state.pausedUntil && state.pausedUntil > Date.now());
}

/** Normalise une reponse check-site en entree de cache. */
function buildEntry(data) {
  return {
    ts: Date.now(),
    verdict: data.verdict,
    score: data.score,
    summary: data.summary,
    officialBrand: data.officialBrand || null,
    impersonatedBrands: data.impersonatedBrands || [],
    findings: (data.findings || []).map((f) => ({ id: f.id, severity: f.severity, title: f.title })),
    recommendations: (data.recommendations || []).map((r) => (typeof r === 'string' ? r : r.text)),
    network: data.network || null,
    meta: data.meta || null,
  };
}

/**
 * Verification d'un domaine (cache + anti-rafale + quota).
 * @returns {Promise<object|null>}
 */
async function checkDomain(domain, { force = false, active = true } = {}) {
  if (!QSApi.isScannableUrl('https://' + domain)) return null;

  if (!force) {
    const cached = await getCached(domain);
    if (cached) return { ...cached, fromCache: true };
  }

  if (await isPaused()) {
    await setBadge('OFF', BADGE_COLORS.paused);
    return null;
  }

  const state = await readJson(STATE_KEY, {});
  const lastCall = state[LAST_CALL_KEY];
  if (!force && lastCall && Date.now() - lastCall < MIN_CALL_INTERVAL_MS) {
    await new Promise((r) => setTimeout(r, MIN_CALL_INTERVAL_MS));
  }
  state[LAST_CALL_KEY] = Date.now();
  await writeJson(STATE_KEY, state);

  const settings = await QSApi.getSettings();
  const result = await QSApi.checkSite(domain, settings, active);

  if (!result.ok) {
    if (result.status === 429) {
      const pauseMs = Math.min(result.retryAfter || 900, 24 * 3600) * 1000;
      await writeJson(STATE_KEY, { pausedUntil: Date.now() + pauseMs });
      await setBadge('OFF', BADGE_COLORS.paused);
      await notifyOnce('qs-quota', {
        title: 'QueryShield — surveillance en pause',
        message: result.data.message || 'Quota atteint : reessai automatique plus tard.',
      });
    }
    return null;
  }

  const entry = buildEntry(result.data);
  await storeCache(domain, entry);
  await pushHistory({
    ts: Date.now(),
    type: 'site',
    label: domain,
    verdict: entry.verdict,
    score: entry.score,
  });
  return { ...entry, fromCache: false };
}

/* ---------------------------------------------------------------- decision */

/** Applique badge / blocage selon le verdict et les seuils. */
async function decide(tabId, url, host, entry, settings) {
  const level = QSApi.threatLevel(entry, settings);

  if (level === 'block' && settings.blockMode && !sessionBypass.has(host)) {
    await setBadge('!', BADGE_COLORS.phishing);
    await addBlockRule(host);
    pendingBlocks.set(tabId, { url, host, result: entry });

    if (settings.notifyPhishing) {
      await notifyOnce('qs-alert-' + host, {
        title: '⚠ Site bloque — ' + host,
        message: (entry.summary || 'Ne saisissez aucune donnee sur ce site.').slice(0, 180),
        domain: host,
      });
    }

    const params = new URLSearchParams({
      host,
      score: String(entry.score),
      verdict: entry.verdict,
      src: 'background',
    });
    try {
      await chrome.tabs.update(tabId, { url: chrome.runtime.getURL('blocked/blocked.html') + '?' + params.toString() });
    } catch {
      /* onglet ferme entre-temps */
    }
    return level;
  }

  if (level === 'block') {
    // Mode avertissement seul ou bypass : badge rouge sans blocage.
    await setBadge('!', BADGE_COLORS.phishing);
  } else if (level === 'warn') {
    await setBadge('?', BADGE_COLORS.suspicious);
  } else {
    await clearBadge();
  }
  return level;
}

/** Notification unique par cle (evite les doublons). */
async function notifyOnce(id, options) {
  const seen = await readJson(NOTIFIED_KEY, {});
  if (seen[id]) return;
  seen[id] = Date.now();
  for (const [key, ts] of Object.entries(seen)) {
    if (Date.now() - ts > 24 * 3600 * 1000) delete seen[key];
  }
  await writeJson(NOTIFIED_KEY, seen);

  await chrome.notifications.create(id, {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: options.title,
    message: options.message,
    priority: 2,
    silent: false,
  });
  if (options.domain) {
    await writeJson('qs.lastAlertDomain', { domain: options.domain, ts: Date.now() });
  }
}

/* ---------------------------------------------------------------- navigation */

let navQueue = Promise.resolve();
const inFlight = new Map(); // host -> Promise (evite les doublons simultanes)

async function handleNavigation(tabId, url) {
  if (!url || !QSApi.isScannableUrl(url)) return;
  const host = QSApi.registrableDomain(url);
  if (!host) return;

  const settings = await QSApi.getSettings();
  if (!settings.protectEnabled) {
    await clearBadge();
    return;
  }
  if (await isPaused()) {
    await setBadge('OFF', BADGE_COLORS.paused);
    return;
  }

  const previous = tabState.get(tabId);
  if (previous && previous.host === host && previous.status === 'blocked') return;

  tabState.set(tabId, {
    url,
    host,
    status: 'checking',
    result: null,
    forms: null,
    updatedAt: Date.now(),
  });

  navQueue = navQueue.then(async () => {
    try {
      // Reutilise une verification en cours pour le meme domaine.
      let pending = inFlight.get(host);
      if (!pending) {
        pending = checkDomain(host, { active: settings.networkChecks }).finally(() => inFlight.delete(host));
        inFlight.set(host, pending);
      }
      const entry = await pending;
      if (!entry) return;
      const current = tabState.get(tabId);
      if (current && current.host !== host) return; // l'onglet a change de page
      current && (current.result = entry);
      await decide(tabId, url, host, entry, settings);
    } catch {
      /* une erreur ne doit jamais bloquer la navigation */
    }
  });
  return navQueue;
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  handleNavigation(details.tabId, details.url);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) handleNavigation(tabId, tab.url);
  } catch {
    /* onglet ferme */
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
  pendingBlocks.delete(tabId);
});

/* --------------------------------------------------------- rapports de contenu */

/**
 * Le contenu script signale la structure de la page (formulaires de harvesting).
 * Un formulaire d'identifiants sur un domaine NON VERIFIE (ou suspect) declenche
 * le badge + un bandeau d'avertissement injecte dans la page.
 */
async function handlePageReport(tabId, report) {
  const state = tabState.get(tabId) || { host: null, url: null, result: null, forms: null };
  state.forms = report;
  state.url = report.url || state.url;
  if (report.host) state.host = report.host;
  tabState.set(tabId, state);

  const settings = await QSApi.getSettings();
  const level = QSApi.threatLevel(state.result, settings);
  const unverified = Boolean(
    state.result &&
      state.result.verdict === 'unknown' &&
      !(state.result.officialBrand && state.result.officialBrand.name),
  );
  const credentialForm = Boolean(report.passwordForms && report.passwordForms > 0);
  const escalate =
    settings.protectEnabled && credentialForm &&
    (level === 'warn' || level === 'block' || unverified || !state.result);

  if (escalate) {
    await setBadge('?', BADGE_COLORS.suspicious);
    try {
      await chrome.tabs.sendMessage(tabId, { type: 'show-form-warning', report, level });
    } catch {
      /* contenu script pas encore pret */
    }
  }
}

/* ---------------------------------------------------------------- messages */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message && message.type) {
      case 'check-domain': {
        const entry = await checkDomain(message.domain, {
          force: message.force === true,
          active: message.active === true,
        });
        sendResponse({ result: entry });
        return;
      }

      case 'get-tab-state': {
        const tabId =
          message.tabId ??
          (await chrome.tabs.query({ active: true, currentWindow: true }))[0]?.id;
        const state = tabId == null ? null : tabState.get(tabId) || null;
        const pending = tabId == null ? null : pendingBlocks.get(tabId) || null;
        const bypass = await readJson(BYPASS_KEY, []);
        sendResponse({
          state: state ? { ...state, bypassed: bypass.includes(state.host) } : null,
          pending,
          paused: await isPaused(),
        });
        return;
      }

      case 'page-report': {
        const tabId = sender.tab && sender.tab.id;
        if (tabId != null) await handlePageReport(tabId, message.report);
        sendResponse({ ok: true });
        return;
      }

      case 'get-active-tab-url': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        sendResponse({ url: tab && tab.url ? tab.url : null, title: tab && tab.title ? tab.title : null });
        return;
      }

      case 'get-block-info': {
        const host = message.host;
        const cached = host ? await getCached(host) : null;
        sendResponse({ result: cached });
        return;
      }

      case 'bypass-domain': {
        const { host, url } = message;
        await persistBypass(host);
        await addBypassRule(host);
        const state = tabState.get(message.tabId);
        if (state) {
          state.status = 'bypassed';
          tabState.set(message.tabId, state);
        }
        pendingBlocks.delete(message.tabId);
        await setBadge('?', BADGE_COLORS.suspicious);
        try {
          await chrome.tabs.update(message.tabId, { url: url || 'https://' + host });
        } catch {
          /* onglet ferme */
        }
        sendResponse({ ok: true });
        return;
      }

      case 'go-back': {
        try {
          await chrome.tabs.goBack(message.tabId);
        } catch {
          try {
            await chrome.tabs.update(message.tabId, { url: 'about:blank' });
          } catch {
            /* onglet ferme */
          }
        }
        sendResponse({ ok: true });
        return;
      }

      case 'get-cached-domain': {
        sendResponse({ result: await getCached(message.domain) });
        return;
      }

      case 'settings-changed': {
        const s = await QSApi.getSettings();
        if (!s.protectEnabled || (await isPaused())) await clearBadge();
        sendResponse({ ok: true });
        return;
      }

      case 'get-history': {
        sendResponse({ history: (await readJson(HISTORY_KEY, [])).slice(0, 8) });
        return;
      }

      default:
        sendResponse({ error: 'unknown_message' });
    }
  })().catch(() => sendResponse({ error: 'internal' }));
  return true;
});

/* ---------------------------------------------------------------- notifications */

chrome.notifications.onClicked.addListener(async (notificationId) => {
  await chrome.notifications.clear(notificationId);
  const last = await readJson('qs.lastAlertDomain', null);
  const target = last && last.domain
    ? 'https://shield.query-intel.com/verifier-site?url=' + encodeURIComponent(last.domain)
    : 'https://shield.query-intel.com';
  await chrome.tabs.create({ url: target });
});

/* ---------------------------------------------------------------- alarmes */

chrome.alarms.create('qs-cleanup', { periodInMinutes: 180 });
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

/* ---------------------------------------------------------------- cycle de vie */

chrome.runtime.onInstalled.addListener(async () => {
  await loadBypass();
});

chrome.runtime.onStartup.addListener(async () => {
  await loadBypass();
});

// Les regles DNR dynamques persistent : au demarrage on s'assure que les
// contournements enregistres restent appliques.
loadBypass().catch(() => {});
