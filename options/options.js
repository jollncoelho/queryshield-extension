/**
 * QueryShield — page d options : reglages persistes dans chrome.storage.sync.
 *
 * Robustesse : chaque element du DOM est verifie au chargement. Si un champ
 * manque dans le HTML, la page affiche une erreur explicite au lieu de planter
 * silencieusement sur `null.checked` (ce qui empechait tout enregistrement).
 * Toute modification est sauvegardee immediatement ; le bouton « Enregistrer »
 * reste disponible pour forcer l ecriture.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const els = {
    protect: $('protect-enabled'),
    blockMode: $('block-mode'),
    networkChecks: $('network-checks'),
    notify: $('notify-phishing'),
    threshold: $('threshold'),
    thresholdValue: $('threshold-value'),
    blockThreshold: $('block-threshold'),
    blockThresholdValue: $('block-threshold-value'),
    license: $('license'),
    licenseStatus: $('license-status'),
    apiBase: $('api-base'),
    healthStatus: $('health-status'),
    save: $('save-btn'),
    test: $('test-btn'),
    clearCache: $('clear-cache-btn'),
    clearBypass: $('clear-bypass-btn'),
  };

  /** Champs indispensables au fonctionnement de la page. */
  const REQUIRED = [
    ['protect', 'protect-enabled'], ['blockMode', 'block-mode'],
    ['networkChecks', 'network-checks'], ['notify', 'notify-phishing'],
    ['threshold', 'threshold'], ['blockThreshold', 'block-threshold'],
    ['license', 'license'], ['apiBase', 'api-base'], ['save', 'save-btn'],
  ];

  const missing = REQUIRED.filter(([key]) => !els[key]).map(([, id]) => '#' + id);

  function setStatus(el, text, state) {
    if (!el) return;
    el.hidden = false;
    el.className = 'qs-status ' + (state || '');
    el.textContent = text;
  }

  async function load() {
    const s = await QSApi.getSettings();
    els.protect.checked = s.protectEnabled;
    els.blockMode.checked = s.blockMode;
    els.networkChecks.checked = s.networkChecks;
    els.notify.checked = s.notifyPhishing;
    els.threshold.value = String(s.alertThreshold);
    els.thresholdValue.textContent = String(s.alertThreshold);
    els.blockThreshold.value = String(s.blockThreshold);
    els.blockThresholdValue.textContent = String(s.blockThreshold);
    els.license.value = s.license || '';
    els.apiBase.value = s.apiBase;
    setStatus(els.licenseStatus, s.license ? 'Licence configuree.' : '', s.license ? 'is-ok' : '');
  }

  function collect() {
    const apiBase = els.apiBase.value.trim() || QSApi.DEFAULT_API_BASE;
    return {
      protectEnabled: els.protect.checked,
      blockMode: els.blockMode.checked,
      networkChecks: els.networkChecks.checked,
      notifyPhishing: els.notify.checked,
      alertThreshold: Number(els.threshold.value),
      blockThreshold: Number(els.blockThreshold.value),
      license: els.license.value.trim(),
      apiBase,
    };
  }

  async function save(options) {
    const opts = options || {};
    const next = await QSApi.saveSettings(collect());
    if (!opts.silent) {
      chrome.runtime.sendMessage({ type: 'settings-changed' });
      setStatus(els.healthStatus, 'Reglages enregistres.', 'is-ok');
    }
    return next;
  }

  async function testConnection() {
    els.test.disabled = true;
    try {
      await save({ silent: true });
      const settings = await QSApi.getSettings();
      const probe = await QSApi.probeHealth(settings);
      if (!probe.ok) {
        setStatus(els.healthStatus, 'API injoignable (' + probe.status + '). Verifiez l adresse et votre connexion.', 'is-error');
        return;
      }
      const h = probe.data || {};
      const lines = [
        'service : ' + (h.service || '?') + ' v' + (h.version || '?'),
        'moteur  : ' + (h.semanticEngine || '?'),
        'stockage: ' + (h.storage ? h.storage.driver : '?') + (h.storage && h.storage.durable ? '' : ' (ephemere)'),
        'licence : ' + (settings.license ? 'configuree' : 'offre gratuite'),
      ];
      setStatus(els.healthStatus, lines.join('\n'), h.status === 'ok' ? 'is-ok' : 'is-warn');
    } catch {
      setStatus(els.healthStatus, 'Echec du test de connexion.', 'is-error');
    } finally {
      els.test.disabled = false;
    }
  }

  async function clearCache() {
    // Vide d abord les contournements via le worker (supprime aussi les regles DNR).
    await clearBypass();
    await chrome.storage.local.clear();
    setStatus(els.healthStatus, 'Cache local, historique et etats interne remis a zero.', 'is-ok');
    chrome.runtime.sendMessage({ type: 'settings-changed' });
  }

  async function clearBypass() {
    const res = await chrome.runtime.sendMessage({ type: 'clear-bypass' });
    const n = (res && res.cleared) || 0;
    if (!n) {
      setStatus(els.healthStatus, 'Aucun domaine en contournement.', 'is-ok');
      return;
    }
    setStatus(els.healthStatus, n + (n > 1 ? ' contournements supprimes.' : ' contournement supprime.'), 'is-ok');
  }

  if (missing.length) {
    // Signale tot : une erreur ici rendait toute la page inerte sans message.
    setStatus(
      $('health-status'),
      'Page de reglages incomplete : champ(s) manquant(s) ' + missing.join(', ') +
        '. Reinstallez l extension.',
      'is-error',
    );
    return;
  }

  els.threshold.addEventListener('input', () => {
    els.thresholdValue.textContent = els.threshold.value;
  });
  els.blockThreshold.addEventListener('input', () => {
    els.blockThresholdValue.textContent = els.blockThreshold.value;
  });

  // Sauvegarde immediate des interrupteurs et des curseurs : plus aucun reglage
  // perdu si l utilisateur oublie de cliquer sur « Enregistrer ».
  [els.protect, els.blockMode, els.networkChecks, els.notify].forEach((el) => {
    el.addEventListener('change', () => {
      save({ silent: true }).then(() => setStatus(els.healthStatus, 'Reglages enregistres.', 'is-ok'));
    });
  });
  [els.threshold, els.blockThreshold, els.apiBase].forEach((el) => {
    el.addEventListener('change', () => {
      save({ silent: true }).then(() => setStatus(els.healthStatus, 'Reglages enregistres.', 'is-ok'));
    });
  });

  els.save.addEventListener('click', save);
  els.test.addEventListener('click', testConnection);
  els.clearCache.addEventListener('click', clearCache);
  els.clearBypass.addEventListener('click', clearBypass);

  load().catch(() => {
    setStatus(els.healthStatus, 'Impossible de charger les reglages.', 'is-error');
  });
})();
