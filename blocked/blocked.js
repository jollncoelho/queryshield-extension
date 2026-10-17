/**
 * QueryShield — logique de la page de blocage.
 * Les details complets viennent du service worker (cache local) ;
 * l'URL ne porte que l'essentiel (hote, score, verdict).
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const host = params.get('host') || '';
  const originalUrl = params.get('url') || '';
  let currentTabId = null;

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function send(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
  }

  function verdictLabel(verdict) {
    const info = QSApi.verdictInfo(verdict);
    return info.label;
  }

  function renderBasic() {
    $('host').textContent = host;
    $('score').textContent = params.get('score') || '—';
    $('verdict').textContent = verdictLabel(params.get('verdict'));
    $('target-meta').textContent = originalUrl || ('https://' + host);
  }

  function renderFull(result) {
    $('score').textContent = String(result.score);
    $('verdict').textContent = verdictLabel(result.verdict);
    $('summary').textContent = result.summary || '';

    const reasons = document.getElementById('reasons');
    reasons.innerHTML = (result.findings && result.findings.length)
      ? result.findings
          .filter((f) => f.severity !== 'info')
          .slice(0, 8)
          .map((f) => `<li>${escapeHtml(f.title)}</li>`)
          .join('')
      : '<li>Verdict automatique du moteur heuristique.</li>';

    const recos = document.getElementById('recos');
    recos.innerHTML = (result.recommendations && result.recommendations.length)
      ? result.recommendations
          .slice(0, 5)
          .map((r) => `<li>${escapeHtml(r)}</li>`)
          .join('')
      : '<li>Ne saisissez aucune donnee sur ce site. Revenez en arriere.</li>';

    // Age du domaine (verifications actives) si disponible.
    const ageBox = document.getElementById('domain-age');
    const days = result.network && result.network.domainAgeDays;
    if (days != null) {
      const label = QSApi.domainAgeLabel(days);
      ageBox.hidden = false;
      ageBox.textContent = '⏳ Domaine enregistre depuis ' + label + (days < 180 ? ' — la jeunesse du domaine est un signal de mefiance.' : '.');
    }

    // IOC : marques usurpees.
    const chips = document.getElementById('iocs');
    const brands = result.impersonatedBrands || [];
    const brand = result.officialBrand && result.officialBrand.name;
    const items = [];
    if (brand) items.push('organisation officielle connue : ' + brand);
    brands.forEach((b) => items.push('usurpation : ' + b));
    items.push('domaine : ' + host);
    chips.innerHTML = items.map((i) => `<span class="qs-chip">${escapeHtml(i)}</span>`).join('');
  }

  (async function init() {
    renderBasic();

    try {
      const tabs = await new Promise((resolve) => chrome.tabs.query({ active: true, currentWindow: true }, resolve));
      currentTabId = tabs && tabs[0] ? tabs[0].id : null;
    } catch {
      currentTabId = null;
    }

    // Meme hote que celui bloque dans cet onglet ?
    const tabState = await send({ type: 'get-tab-state', tabId: currentTabId });
    let result = tabState && tabState.pending && tabState.pending.result;

    if (!result) {
      const cached = await send({ type: 'get-block-info', host });
      result = cached && cached.result;
    }
    if (result) renderFull(result);
    else $('summary').textContent = 'Ce domaine a ete signale comme malveillant par le moteur QueryShield.';
  })();

  /* ------------------------------------------------------------- actions */

  document.getElementById('back-btn').addEventListener('click', async () => {
    await send({ type: 'go-back', tabId: currentTabId });
    // Repli : si aucun historique, on ferme l'onglet.
    setTimeout(() => chrome.tabs.get(currentTabId, () => {
      if (chrome.runtime.lastError) return;
    }), 300);
  });

  const bypassBox = document.getElementById('bypass-confirm');
  document.getElementById('bypass-btn').addEventListener('click', () => {
    document.getElementById('bypass-host').textContent = host;
    bypassBox.hidden = false;
  });
  document.getElementById('bypass-no').addEventListener('click', () => {
    bypassBox.hidden = true;
  });

  document.getElementById('bypass-yes').addEventListener('click', async () => {
    await send({ type: 'bypass-domain', tabId: currentTabId, host, url: originalUrl || 'https://' + host });
  });

  document.getElementById('report-btn').addEventListener('click', () => {
    chrome.tabs.create({
      url: 'https://shield.query-intel.com/verifier-site?url=' + encodeURIComponent(originalUrl || host),
    });
  });
})();
