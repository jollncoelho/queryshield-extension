/**
 * QueryShield — client API partage (popup, options, background).
 *
 * Toutes les communications passent par https://shield.query-intel.com.
 * Aucun contenu analyse n'est conserve cote extension : seuls les resultats
 * (score, verdict, resumé) sont stockes localement, jamais les messages.
 */
(function (global) {
  'use strict';

  const DEFAULT_API_BASE = 'https://shield.query-intel.com';
  const STORAGE_KEY = 'qs.settings';

  const DEFAULT_SETTINGS = {
    apiBase: DEFAULT_API_BASE,
    license: '',            // Cle de licence QS-... (offre payante), vide = offre gratuite
    protectEnabled: true,   // Surveillance des sites visites
    alertThreshold: 60,     // Score a partir duquel le badge passe en alerte
    notifyPhishing: true,   // Notification systeme sur site signale
  };

  /** Messages d'erreur en francais, alignes sur les erreurs de l'API. */
  const ERROR_LABELS = {
    rate_limited: 'Trop de requetes : patientez quelques secondes.',
    quota_exceeded: 'Quota quotidien atteint. Ajoutez une licence dans les options pour aller plus loin.',
    invalid_json: 'Requete malformee.',
    missing_text: 'Saisissez au moins 4 caracteres a analyser.',
    missing_url: 'Saisissez une adresse a verifier.',
    invalid_url: 'Adresse non exploitable (domaine ou URL complet attendu).',
    payload_too_large: 'Contenu trop volumineux.',
    network_error: 'Service QueryShield injoignable. Verifiez votre connexion.',
    unknown_error: 'Erreur inattendue du service.',
  };

  async function getSettings() {
    try {
      const stored = await chrome.storage.sync.get(STORAGE_KEY);
      return { ...DEFAULT_SETTINGS, ...(stored[STORAGE_KEY] || {}) };
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }

  async function saveSettings(patch) {
    const current = await getSettings();
    const next = { ...current, ...patch };
    await chrome.storage.sync.set({ [STORAGE_KEY]: next });
    return next;
  }

  /**
   * Appel authentifie de l'API QueryShield.
   * @returns {Promise<{ok: boolean, status: number, data: object}>}
   */
  async function callApi(path, body, settings) {
    const s = settings || (await getSettings());
    const headers = { 'Content-Type': 'application/json' };
    if (s.license && s.license.trim()) {
      headers['x-qs-license'] = s.license.trim();
    }
    let response;
    try {
      response = await fetch(s.apiBase.replace(/\/+$/, '') + path, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        credentials: 'omit',
      });
    } catch {
      return { ok: false, status: 0, data: { error: 'network_error', message: ERROR_LABELS.network_error } };
    }

    let data = null;
    try {
      data = await response.json();
    } catch {
      data = { error: 'unknown_error', message: ERROR_LABELS.unknown_error };
    }

    if (!response.ok) {
      const retryAfter = Number(response.headers.get('Retry-After')) || (data && data.retryAfterSeconds) || null;
      const label = ERROR_LABELS[data && data.error] || (data && data.message) || ERROR_LABELS.unknown_error;
      return { ok: false, status: response.status, retryAfter, data: { ...data, message: label } };
    }
    return { ok: true, status: response.status, data };
  }

  /** Analyse d'un message (SMS, e-mail, message instantane). */
  function analyzeMessage(text, channel, settings) {
    return callApi('/api/analyze', { text, channel: channel || 'unknown' }, settings);
  }

  /** Analyse statique d'un site ou domaine. Le site n'est jamais contacte. */
  function checkSite(url, settings) {
    return callApi('/api/check-site', { url, active: false }, settings);
  }

  /** Test de connectivite + etat du service (badge quota dans les options). */
  async function probeHealth(settings) {
    const s = settings || (await getSettings());
    try {
      const r = await fetch(s.apiBase.replace(/\/+$/, '') + '/api/health', { credentials: 'omit' });
      return { ok: r.ok, status: r.status, data: r.ok ? await r.json() : null };
    } catch {
      return { ok: false, status: 0, data: null };
    }
  }

  /** Extrait le domaine inscriptible d'une URL (sans www.). */
  function registrableDomain(rawUrl) {
    try {
      const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl);
      let host = u.hostname.toLowerCase().replace(/\.$/, '');
      if (host.startsWith('www.')) host = host.slice(4);
      return host;
    } catch {
      return null;
    }
  }

  /** Parse une URL en supposant https:// si aucun schema n'est indique. */
  function parseUrl(rawUrl) {
    try {
      return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl);
    } catch {
      return null;
    }
  }

  /** Domaines que l'extension ne doit jamais envoyer a l'API. */
  const PRIVATE_SUFFIXES = [
    '.localhost', '.local', '.internal', '.interne', '.intranet', '.corp',
    '.home', '.lan', '.test', '.example', '.invalid', '.onion', '.home.arpa',
    '.in-addr.arpa',
  ];

  function isScannableUrl(rawUrl) {
    const u = parseUrl(rawUrl);
    if (!u) return false;
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false; // chrome:, about:, file:, extension:...
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    if (host.length < 4 || !host.includes('.')) return false;
    if (host === 'localhost') return false;
    if (PRIVATE_SUFFIXES.some((suffix) => host.endsWith(suffix))) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;              // IPv4 litteral
    if (host.includes(':')) return false;                               // IPv6 litteral
    return true;
  }

  global.QSApi = {
    DEFAULT_API_BASE,
    DEFAULT_SETTINGS,
    ERROR_LABELS,
    getSettings,
    saveSettings,
    callApi,
    analyzeMessage,
    checkSite,
    probeHealth,
    registrableDomain,
    isScannableUrl,
  };
})(typeof self !== 'undefined' ? self : globalThis);
