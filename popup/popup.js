/**
 * QueryShield — logique du popup (console tactique).
 *
 * Sections : etat de la surveillance, page active (logs), audit manuel
 * (message / site), resultat, quota, historique.
 * Aucun contenu analyse n'est conserve : seuls score, verdict et resume
 * sont memorises pour l'historique local.
 */
(function () {
  'use strict';

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
    protectLabel: $('protect-label'),
    protectMode: $('protect-mode'),
    activePage: $('active-page'),
    activeUrl: $('active-url'),
    activeBadge: $('active-badge'),
    activeScore: $('active-score'),
    activeDetails: $('active-details'),
    recheckBtn: $('recheck-btn'),
    openOptions: $('open-options'),
  };

  const MAX_CHARS = 20000;
  const RING_CIRC = 2 * Math.PI * 52;
  let channel = 'unknown';

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
    // Le libelle est toujours rafraichi : sinon un texte laisse par une
    // action precedente (« Analyse en cours… ») s affiche pendant une
    // verification de domaine et induit en erreur.
    if (on) els.loadingText.textContent = label || 'Traitement en cours…';
    els.analyzeBtn.disabled = on;
    els.checkSiteBtn.disabled = on;
    els.auditPageBtn.disabled = on;
    els.recheckBtn.disabled = on;
  }

  function send(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
  }

  function applyVerdictClasses(el, verdict, score, settings) {
    const level = QSApi.threatLevel({ verdict, score: score || 0 }, settings || QSApi.DEFAULT_SETTINGS);
    el.className = 'qs-verdict ' + (
      level === 'block' ? 'is-block' : level === 'warn' ? 'is-warn' : 'is-safe'
    );
    return level;
  }

  /* ------------------------------------------------------------ surveillance */

  async function renderProtection() {
    const settings = await QSApi.getSettings();
    const tabState = await send({ type: 'get-tab-state' });

    if (tabState && tabState.paused) {
      els.protectState.className = 'qs-dot is-paused';
      els.protectLabel.textContent = 'Surveillance en pause (quota)';
    } else if (!settings.protectEnabled) {
      els.protectState.className = 'qs-dot is-off';
      els.protectLabel.textContent = 'Surveillance desactivee';
    } else {
      els.protectState.className = 'qs-dot is-on';
      els.protectLabel.textContent = 'Surveillance active · zero-click';
    }
    els.protectMode.textContent = settings.blockMode ? 'blocage' : 'avertissement';
    els.protectMode.className = 'qs-mode' + (settings.blockMode ? '' : ' is-warn-only');
  }

  /* ------------------------------------------------------------ page active */

  async function renderActivePage() {
    let tab = null;
    try {
      [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    } catch {
      tab = null;
    }

    if (!tab || !tab.url || !QSApi.isScannableUrl(tab.url)) {
      els.activeUrl.textContent = tab && tab.url ? tab.url.replace(/^https?:\/\//, '') : 'aucune page analysable';
      els.activeBadge.className = 'qs-verdict is-unknown';
      els.activeBadge.textContent = 'HORS PERIMETRE';
      els.activeScore.textContent = '—';
      els.activeScore.className = 'qs-active-score';
      els.activeDetails.innerHTML = '';
      return;
    }

    els.activeUrl.textContent = tab.url.replace(/^https?:\/\//, '');

    const settings = await QSApi.getSettings();
    const state = await send({ type: 'get-tab-state', tabId: tab.id });
    const info = state && state.state ? state.state : null;

    if (!info || info.status === 'checking') {
      els.activeBadge.className = 'qs-verdict is-unknown';
      els.activeBadge.textContent = 'Analyse en cours…';
      els.activeScore.textContent = '…';
      els.activeDetails.innerHTML = '';
      return;
    }

    if (info.status === 'blocked') {
      els.activeBadge.className = 'qs-verdict is-block';
      els.activeBadge.textContent = 'BLOQUÉ';
      els.activeScore.className = 'qs-active-score is-block';
      els.activeScore.textContent = info.result ? info.result.score + '/100' : '—';
      els.activeDetails.innerHTML = info.result && info.result.summary
        ? '<div>' + escapeHtml(info.result.summary) + '</div>'
        : '';
      return;
    }

    const result = info.result;
    if (!result) {
      els.activeBadge.className = 'qs-verdict is-unknown';
      els.activeBadge.textContent = info.status === 'bypassed' ? 'CONTOURNÉ' : 'EN ATTENTE';
      els.activeScore.className = 'qs-active-score';
      els.activeScore.textContent = '—';
      els.activeDetails.innerHTML = '';
      return;
    }

    const level = applyVerdictClasses(els.activeBadge, result.verdict, result.score, settings);
    els.activeBadge.textContent = QSApi.verdictInfo(result.verdict).label;
    els.activeScore.className = 'qs-active-score is-' + level;
    els.activeScore.textContent = result.score + '/100';

    const details = [];
    if (result.findings && result.findings.length) {
      const bad = result.findings.filter((f) => f.severity !== 'info').slice(0, 3);
      details.push('<div><b>signaux :</b> ' + escapeHtml(bad.map((f) => f.title).join(' · ')) + '</div>');
    }
    if (info.forms) {
      details.push(
        '<div><b>formulaires :</b> ' +
          (info.forms.passwordForms || 0) + ' identifiants · ' +
          (info.forms.loginForms || 0) + ' champs sensibles · ' +
          (info.forms.hiddenInputs || 0) + ' champs caches · ' +
          (info.forms.mixedResources || 0) + ' ressources mixtes</div>',
      );
    }
    if (info.bypassed) details.push('<div><b>contournement :</b> actif pour ce domaine</div>');
    if (result.fromCache) details.push('<div><b>source :</b> cache local (ttl 1 h)</div>');
    els.activeDetails.innerHTML = details.join('');
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
      // Un message d erreur de l autre onglet n a plus de sens ici.
      clearError();
    });
  });

  els.channels.addEventListener('click', (event) => {
    const chip = event.target.closest('.qs-chip');
    if (!chip) return;
    els.channels.querySelectorAll('.qs-chip').forEach((c) => c.classList.toggle('is-active', c === chip));
    channel = chip.dataset.channel;
  });

  els.messageInput.addEventListener('input', () => {
    if (els.messageInput.value.length > MAX_CHARS) {
      els.messageInput.value = els.messageInput.value.slice(0, MAX_CHARS);
    }
    els.charCount.textContent = els.messageInput.value.length + ' / ' + MAX_CHARS;
  });

  /* ------------------------------------------------------------ rendu resultat */

  function renderResult(data, kind) {
    const settings = { ...QSApi.DEFAULT_SETTINGS };
    const verdict = QSApi.verdictInfo(data.verdict);

    els.ringArc.style.stroke = verdict.color;
    els.ringArc.style.strokeDashoffset = String(RING_CIRC * (1 - Math.min(100, Math.max(0, data.score)) / 100));
    els.ringScore.textContent = String(data.score);

    els.verdictBadge.className = 'qs-verdict ' + (
      verdict.level === 'block' ? 'is-block' : verdict.level === 'warn' ? 'is-warn' : 'is-safe'
    );
    els.verdictBadge.textContent = verdict.label;
    els.resultSummary.textContent = data.summary || '';

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

    const recos = (data.recommendations || []).slice(0, 5);
    els.recommendations.innerHTML = recos.length
      ? `<div class="qs-recos-title">Conduite a tenir</div>` +
        recos.map((r) => `<p class="qs-reco">${escapeHtml(typeof r === 'string' ? r : r.text)}</p>`).join('')
      : '';

    const bits = [];
    if (data.meta) {
      if (kind === 'message') {
        if (data.meta.channel) bits.push('canal=' + data.meta.channel);
      } else if (data.meta.active) {
        bits.push('verifications actives (DNS/RDAP)');
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
    // Une adresse non analysable (chrome://, fichier local, IP privee, hote
    // sans point…) doit etre refusee ici, avec un message clair, plutot que
    // de partir a l API pour revenir en erreur generique.
    if (!QSApi.isScannableUrl(url)) {
      showError('Cette adresse ne peut pas etre analysee : utilisez un nom de domaine public (exemple.com).');
      return;
    }
    setLoading(true, 'Verification du domaine…');
    try {
      const settings = await QSApi.getSettings();
      const response = await QSApi.checkSite(url, settings, settings.networkChecks !== false);
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

  async function recheckPage() {
    const tab = await send({ type: 'get-active-tab-url' });
    if (!tab || !tab.url || !QSApi.isScannableUrl(tab.url)) return;
    const domain = QSApi.registrableDomain(tab.url);
    setLoading(true, 'Re-analyse forcee…');
    try {
      const settings = await QSApi.getSettings();
      const response = await send({
        type: 'check-domain',
        domain,
        force: true,
        active: settings.networkChecks !== false,
      });
      if (response && response.result) {
        await renderActivePage();
      }
    } finally {
      setLoading(false);
    }
  }

  /* ------------------------------------------------------------ historique */

  async function pushHistory(entry) {
    const bag = await chrome.storage.local.get('qs.history');
    const history = bag['qs.history'] || [];
    history.unshift(entry);
    await chrome.storage.local.set({ 'qs.history': history.slice(0, 30) });
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
        const info = QSApi.verdictInfo(e.verdict);
        return `
          <button class="qs-hist-item" data-index="${i}">
            <span class="qs-hist-score is-${info.level}">${e.score}</span>
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
  els.recheckBtn.addEventListener('click', recheckPage);
  els.openOptions.addEventListener('click', () => chrome.runtime.openOptionsPage());

  // Des que l utilisateur corrige sa saisie, l erreur affichee n est plus
  // pertinente : on la retire pour ne pas laisser un message trompeur.
  [els.messageInput, els.siteInput].forEach((el) => {
    el.addEventListener('input', clearError);
  });

  (async function init() {
    await renderProtection();
    await renderActivePage();

    // Pre-remplissage de l'onglet actif dans l'onglet Site.
    try {
      const { url } = await send({ type: 'get-active-tab-url' });
      if (url && QSApi.isScannableUrl(url)) els.siteInput.value = url;
    } catch {
      /* pas d onglet actif */
    }

    renderHistory();
  })();
})();
