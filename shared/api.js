/**
 * QueryShield — client API partage (popup, options, background, page de blocage).
 *
 * Toutes les communications passent par https://shield.query-intel.com.
 * Aucun contenu analyse n'est conserve cote extension : seuls les resultats
 * (score, verdict, resume) sont stockes localement, jamais les messages.
 */
(function (global) {
  'use strict';

  const DEFAULT_API_BASE = 'https://shield.query-intel.com';
  const STORAGE_KEY = 'qs.settings';

  const DEFAULT_SETTINGS = {
    apiBase: DEFAULT_API_BASE,
    license: '',              // Cle de licence QS-... (offre payante), vide = offre gratuite
    protectEnabled: true,     // Surveillance des sites visites
    blockMode: true,          // true = bloquer le rendu, false = avertissement seul
    alertThreshold: 60,       // Score a partir duquel le badge passe en alerte
    blockThreshold: 75,       // Score a partir duquel la navigation est bloquee
    networkChecks: true,      // Verifications actives (DNS, RDAP, age du domaine)
    notifyPhishing: true,     // Notification systeme sur site signale
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

  const VERDICTS = {
    official:   { label: 'Domaine officiel',                level: 'safe',    color: '#22c55e' },
    safe:       { label: 'Aucun signal preoccupant',        level: 'safe',    color: '#22c55e' },
    unknown:    { label: 'Non verifie',                     level: 'warn',    color: '#8a94a8' },
    suspicious: { label: 'Suspect — verifier avant d agir', level: 'warn',    color: '#ffb020' },
    phishing:   { label: 'Phishing — ne pas saisir de donnees', level: 'block', color: '#ff3b5c' },
    dangerous:  { label: 'Tres probablement frauduleux',    level: 'block',   color: '#ff3b5c' },
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

  function verdictInfo(verdict) {
    return VERDICTS[verdict] || { label: verdict || 'Inconnu', level: 'warn', color: '#8a94a8' };
  }

  /** Niveau de menace agrege : 'safe' | 'warn' | 'block'. */
  function threatLevel(result, settings) {
    if (!result) return 'safe';
    if (result.verdict === 'phishing' || result.verdict === 'dangerous') return 'block';
    if (settings && result.score >= settings.blockThreshold) return 'block';
    if (settings && result.score >= settings.alertThreshold) return 'warn';
    if (result.verdict === 'suspicious') return 'warn';
    return 'safe';
  }

  /**
   * Appel authentifie de l'API QueryShield.
   * @returns {Promise<{ok: boolean, status: number, retryAfter: number|null, data: object}>}
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
      return { ok: false, status: 0, retryAfter: null, data: { error: 'network_error', message: ERROR_LABELS.network_error } };
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
    return { ok: true, status: response.status, retryAfter: null, data };
  }

  /** Analyse d'un message (SMS, e-mail, message instantane). */
  function analyzeMessage(text, channel, settings) {
    return callApi('/api/analyze', { text, channel: channel || 'unknown' }, settings);
  }

  /** Analyse statique d'un site ou domaine (activable : DNS, RDAP, age). */
  function checkSite(url, settings, active) {
    return callApi('/api/check-site', { url, active: active !== false }, settings);
  }

  async function probeHealth(settings) {
    const s = settings || (await getSettings());
    try {
      const r = await fetch(s.apiBase.replace(/\/+$/, '') + '/api/health', { credentials: 'omit' });
      return { ok: r.ok, status: r.status, data: r.ok ? await r.json() : null };
    } catch {
      return { ok: false, status: 0, data: null };
    }
  }

  function parseUrl(rawUrl) {
    try {
      return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl);
    } catch {
      return null;
    }
  }

  /** Extrait le domaine inscriptible d'une URL (sans www.). */
  function registrableDomain(rawUrl) {
    const u = parseUrl(rawUrl);
    if (!u) return null;
    let host = u.hostname.toLowerCase().replace(/\.$/, '');
    if (host.startsWith('www.')) host = host.slice(4);
    return host;
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
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    if (host.length < 4 || !host.includes('.')) return false;
    if (host === 'localhost') return false;
    if (PRIVATE_SUFFIXES.some((suffix) => host.endsWith(suffix))) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
    if (host.includes(':')) return false;
    return true;
  }

  /** Libelle lisible d'un age de domaine en jours. */
  function domainAgeLabel(days) {
    if (days == null) return null;
    if (days < 1) return "moins d'un jour";
    if (days === 1) return '1 jour';
    if (days < 30) return days + ' jours';
    if (days < 365) {
      const months = Math.round(days / 30);
      return months + (months > 1 ? ' mois' : ' mois');
    }
    const years = (days / 365).toFixed(1).replace('.', ',');
    return years + ' ans';
  }

  global.QSApi = {
    DEFAULT_API_BASE,
    DEFAULT_SETTINGS,
    ERROR_LABELS,
    VERDICTS,
    verdictInfo,
    threatLevel,
    getSettings,
    saveSettings,
    callApi,
    analyzeMessage,
    checkSite,
    probeHealth,
    parseUrl,
    registrableDomain,
    isScannableUrl,
    domainAgeLabel,
  };
})(typeof self !== 'undefined' ? self : globalThis);
