/**
 * QueryShield — logique du popup.
 * Aucun contenu analyse n'est conserve : seuls score, verdict et resume
 * sont memorises pour l'historique local.
 */
(function () {
  'use strict';

  /* ------------------------------------------------------------ elements */

  const $ = (id) => document.getElementById(id);
  const els = {
    tabs: document.querySelectorAll('.qs-tab'),
    panels: { message: $('tab-message'), site: $('tab-site') },
    channels: $('channels'),
    messageInput: $('message-input'),
    charCount: $('char-count'),
    analyzeBtn: $('analyze-btn'),
    siteInput: $('site-input'),
    auditPageBtn: $('audit-page-btn'),
    checkSiteBtn: $('check-site-btn'),
    errorBox: $('error-box'),
    loadingBox: $('loading-box'),
    loadingText: $('loading-text'),
    result: $('result'),
    ringArc: $('ring-arc'),
    ringScore: $('ring-score'),
    verdictBadge: $('verdict-badge'),
    resultSummary: $('result-summary'),
    findings: $('findings'),
    recommendations: $('recommendations'),
    resultMeta: $('result-meta'),
    quotaLine: $('quota-line'),
    history: $('history'),
    protectState: $('protect-state'),
    openOptions: $('open-options'),
  };

  const MAX_CHARS = 20000;
  const RING_CIRC = 2 * Math.PI * 52;

  const VERDICTS = {
    safe:       { label: 'Aucun signal preoccupant',        cls: 'is-safe',    color: '#22c55e' },
    official:   { label: 'Domaine officiel',                cls: 'is-safe',    color: '#22c55e' },
    unknown:    { label: 'Non verifie',                     cls: 'is-unknown', color: '#8a94a8' },
    suspicious: { label: 'Suspect — verifier avant d agir', cls: 'is-warn',   color: '#ffb020' },
    dangerous:  { label: 'Tres probablement frauduleux',     cls: 'is-danger', color: '#ff3b5c' },
    phishing:   { label: 'Phishing — ne pas saisir de donnees', cls: 'is-danger', color: '#ff3b5c' },
  };

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  let channel = 'unknown';
  let currentTabId = null;

  /* ------------------------------------------------------------ helpers */

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function showError(message) {
    els.errorBox.textContent = message;
    els.errorBox.hidden = false;
  }

  function clearError() {
    els.errorBox.hidden = true;
  }

  function setLoading(on, label) {
    els.loadingBox.hidden = !on;
    if (on && label) els.loadingText.textContent = label;
    els.analyzeBtn.disabled = on;
    els.checkSiteBtn.disabled = on;
    els.auditPageBtn.disabled = on;
  }

  function send(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
  }

  /* ------------------------------------------------------------ onglets */

  els.tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      els.tabs.forEach((t) => {
        const active = t === tab;
        t.classList.toggle('is-active', active);
        t.setAttribute('aria-selected', String(active));
      });
      const name = tab.dataset.tab;
      els.panels.message.hidden = name !== 'message';
      els.panels.site.hidden = name !== 'site';
    });
  });

  /* ------------------------------------------------------------ canaux */

  els.channels.addEventListener('click', (event) => {
    const chip = event.target.closest('.qs-chip');
    if (!chip) return;
    els.channels.querySelectorAll('.qs-chip').forEach((c) => c.classList.toggle('is-active', c === chip));
    channel = chip.dataset.channel;
  });

  /* ------------------------------------------------------------ compteur */

  els.messageInput.addEventListener('input', () => {
    if (els.messageInput.value.length > MAX_CHARS) {
      els.messageInput.value = els.messageInput.value.slice(0, MAX_CHARS);
    }
    els.charCount.textContent = els.messageInput.value.length + ' / ' + MAX_CHARS;
  });

  /* ------------------------------------------------------------ rendu resultat */

  function renderResult(data, kind) {
    const verdict = VERDICTS[data.verdict] || VERDICTS.unknown;

    // Anneau de score
    els.ringArc.style.stroke = verdict.color;
    els.ringArc.style.strokeDashoffset = String(RING_CIRC * (1 - Math.min(100, Math.max(0, data.score)) / 100));
    els.ringScore.textContent = String(data.score);

    // Badge verdict + synthese
    els.verdictBadge.className = 'qs-verdict ' + verdict.cls;
    els.verdictBadge.textContent = verdict.label;
    els.resultSummary.textContent = data.summary || '';

    // Constats
    const findings = (data.findings || []).slice(0, 8);
    els.findings.innerHTML = findings.length
      ? findings.map((f) => `
          <div class="qs-finding">
            <div class="qs-finding-head">
              <span class="qs-sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
              <span class="qs-finding-title">${escapeHtml(f.title)}</span>
            </div>
            ${f.detail ? `<p class="qs-finding-detail">${escapeHtml(f.detail)}</p>` : ''}
          </div>`).join('')
      : '<p class="qs-note">Aucun signal particulier detecte.</p>';

    const hidden = (data.findings || []).length - findings.length;
    if (hidden > 0) {
      els.findings.insertAdjacentHTML('beforeend',
        `<p class="qs-note">… et ${hidden} autre${hidden > 1 ? 's' : ''} constat${hidden > 1 ? 's' : ''}.</p>`);
    }

    // Recommandations
    const recos = (data.recommendations || []).slice(0, 5);
    els.recommendations.innerHTML = recos.length
      ? `<div class="qs-recos-title">Conduite a tenir</div>` +
        recos.map((r) => `<p class="qs-reco">${escapeHtml(typeof r === 'string' ? r : r.text)}</p>`).join('')
      : '';

    // Meta
    const bits = [];
    if (data.meta) {
      if (kind === 'message') {
        if (data.meta.channel) bits.push('canal=' + data.meta.channel);
        if (data.meta.llmUsed) bits.push('moteur semantique');
      } else {
        if (data.meta.active) bits.push('verifications reseau actives');
        if (data.meta.siteContacted) bits.push('site contacte');
        bits.push('site non contacte');
      }
      if (data.meta.durationMs != null) bits.push(data.meta.durationMs + ' ms');
    }
    if (data.impersonatedBrands && data.impersonatedBrands.length) {
      bits.push('usurpation : ' + data.impersonatedBrands.join(', '));
    }
    if (data.officialBrand && data.officialBrand.name) {
      bits.push('organisation : ' + data.officialBrand.name);
    }
    els.resultMeta.textContent = bits.join(' · ');

    els.result.hidden = false;

    // Quota
    renderQuota(data.quota, data.plan);
  }

  function renderQuota(quota, plan) {
    if (!quota || typeof quota.remaining !== 'number' || typeof quota.limit !== 'number') {
      els.quotaLine.hidden = true;
      return;
    }
    const state = quota.exceeded ? 'is-out' : quota.remaining <= Math.max(1, quota.limit * 0.2) ? 'is-low' : '';
    els.quotaLine.className = 'qs-quota ' + state;
    els.quotaLine.textContent =
      (plan ? 'Offre ' + plan + ' · ' : '') +
      (quota.exceeded
        ? 'quota epuise — renouvellement demain'
        : `quota : ${quota.remaining}/${quota.limit} analyses aujourd hui`);
    els.quotaLine.hidden = false;
  }

  /* ------------------------------------------------------------ actions */

  async function analyzeMessage() {
    const text = els.messageInput.value.trim();
    clearError();
    if (text.length < 4) {
      showError('Saisissez au moins 4 caracteres a analyser.');
      return;
    }
    setLoading(true, 'Analyse du message…');
    try {
      const settings = await QSApi.getSettings();
      const response = await QSApi.analyzeMessage(text, channel, settings);
      if (!response.ok) {
        showError(response.data.message || QSApi.ERROR_LABELS.unknown_error);
        return;
      }
      renderResult(response.data, 'message');
      await pushHistory({
        ts: Date.now(), type: 'message', label: text.slice(0, 60),
        verdict: response.data.verdict, score: response.data.score, text, channel,
      });
      renderHistory();
    } catch {
      showError(QSApi.ERROR_LABELS.network_error);
    } finally {
      setLoading(false);
    }
  }

  async function checkSiteInput() {
    const url = els.siteInput.value.trim();
    clearError();
    if (!url) {
      showError('Saisissez une adresse a verifier.');
      return;
    }
    setLoading(true, 'Verification du domaine…');
    try {
      const settings = await QSApi.getSettings();
      const response = await QSApi.checkSite(url, settings);
      if (!response.ok) {
        showError(response.data.message || QSApi.ERROR_LABELS.unknown_error);
        return;
      }
      renderResult(response.data, 'site');
      await pushHistory({
        ts: Date.now(), type: 'site',
        label: QSApi.registrableDomain(url) || url,
        verdict: response.data.verdict, score: response.data.score,
      });
      renderHistory();
    } catch {
      showError(QSApi.ERROR_LABELS.network_error);
    } finally {
      setLoading(false);
    }
  }

  async function auditCurrentPage() {
    clearError();
    setLoading(true, 'Recuperation de l onglet actif…');
    try {
      const { url } = await send({ type: 'get-active-tab-url' });
      if (!url) {
        showError('Aucun onglet actif exploitable.');
        return;
      }
      if (!QSApi.isScannableUrl(url)) {
        showError('Cette page (chrome://, about://, fichier local…) ne peut pas etre analysee.');
        return;
      }
      els.siteInput.value = url;
      await checkSiteInput();
    } catch {
      showError('Impossible de lire l onglet actif.');
    } finally {
      setLoading(false);
    }
  }

  /* ------------------------------------------------------------ historique */

  async function pushHistory(entry) {
    const bag = await chrome.storage.local.get('qs.history');
    const history = bag['qs.history'] || [];
    history.unshift(entry);
    await chrome.storage.local.set({ 'qs.history': history.slice(0, 20) });
  }

  async function renderHistory() {
    const bag = await chrome.storage.local.get('qs.history');
    const history = (bag['qs.history'] || []).filter((e) => e.type === 'message').slice(0, 6);
    if (!history.length) {
      els.history.innerHTML = '';
      return;
    }
    els.history.innerHTML =
      '<div class="qs-history-title">Analyses recentes</div>' +
      history.map((e, i) => {
        const v = VERDICTS[e.verdict] || VERDICTS.unknown;
        return `
          <button class="qs-hist-item" data-index="${i}">
            <span class="qs-hist-score ${v.cls}">${e.score}</span>
            <span class="qs-hist-label">${escapeHtml(e.label)}</span>
          </button>`;
      }).join('');

    els.history.querySelectorAll('.qs-hist-item').forEach((btn) => {
      btn.addEventListener('click', () => {
        const entry = history[Number(btn.dataset.index)];
        if (!entry) return;
        els.messageInput.value = entry.text || '';
        els.charCount.textContent = els.messageInput.value.length + ' / ' + MAX_CHARS;
        els.tabs[0].click();
      });
    });
  }

  /* ------------------------------------------------------------ demarrage */

  els.analyzeBtn.addEventListener('click', analyzeMessage);
  els.checkSiteBtn.addEventListener('click', checkSiteInput);
  els.auditPageBtn.addEventListener('click', auditCurrentPage);

  els.openOptions.addEventListener('click', () => chrome.runtime.openOptionsPage());

  (async function init() {
    const settings = await QSApi.getSettings();
    els.protectState.textContent = settings.protectEnabled ? '●' : '○';
    els.protectState.className = 'qs-protect ' + (settings.protectEnabled ? 'is-on' : 'is-off');
    els.protectState.title = settings.protectEnabled
      ? 'Surveillance des sites visites : active'
      : 'Surveillance des sites visites : desactivee (reglages)';

    try {
      const { url } = await send({ type: 'get-active-tab-url' });
      if (url && QSApi.isScannableUrl(url)) els.siteInput.value = url;
    } catch { /* pas d onglet actif */ }

    // Affiche immediatement le dernier resultat en cache pour ce domaine.
    if (els.siteInput.value) {
      try {
        const domain = QSApi.registrableDomain(els.siteInput.value);
        const { result } = await send({ type: 'get-cached-domain', domain });
        if (result && els.result.hidden) renderResult(result, 'site');
      } catch { /* cache indisponible */ }
    }

    renderHistory();
  })();
})();
