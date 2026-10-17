/**
 * QueryShield — page d options : reglages persistes dans chrome.storage.sync.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const els = {
    protect: $('protect-enabled'),
    notify: $('notify-phishing'),
    threshold: $('threshold'),
    thresholdValue: $('threshold-value'),
    license: $('license'),
    licenseStatus: $('license-status'),
    apiBase: $('api-base'),
    healthStatus: $('health-status'),
    save: $('save-btn'),
    test: $('test-btn'),
    clearCache: $('clear-cache-btn'),
  };

  function setStatus(el, text, state) {
    el.hidden = false;
    el.className = 'qs-status ' + (state || '');
    el.textContent = text;
  }

  async function load() {
    const s = await QSApi.getSettings();
    els.protect.checked = s.protectEnabled;
    els.notify.checked = s.notifyPhishing;
    els.threshold.value = String(s.alertThreshold);
    els.thresholdValue.textContent = String(s.alertThreshold);
    els.license.value = s.license || '';
    els.apiBase.value = s.apiBase;
  }

  async function save() {
    const apiBase = els.apiBase.value.trim() || QSApi.DEFAULT_API_BASE;
    await QSApi.saveSettings({
      protectEnabled: els.protect.checked,
      notifyPhishing: els.notify.checked,
      alertThreshold: Number(els.threshold.value),
      license: els.license.value.trim(),
      apiBase,
    });
    // Signale au worker que les reglages ont change (badge a rafraichir).
    chrome.runtime.sendMessage({ type: 'settings-changed' });
    setStatus(els.healthStatus, 'Reglages enregistres.', 'is-ok');
  }

  async function testConnection() {
    els.test.disabled = true;
    try {
      await save();
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
    await chrome.storage.local.clear();
    setStatus(els.healthStatus, 'Cache local, historique et etats interne remis a zero.', 'is-ok');
    chrome.runtime.sendMessage({ type: 'settings-changed' });
  }

  els.threshold.addEventListener('input', () => {
    els.thresholdValue.textContent = els.threshold.value;
  });
  els.save.addEventListener('click', save);
  els.test.addEventListener('click', testConnection);
  els.clearCache.addEventListener('click', clearCache);

  load();
})();
