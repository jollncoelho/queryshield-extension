/**
 * QueryShield — contenu script.
 *
 * Analyse la structure de la page chargee (zero-click) :
 *   - formulaires de connexion (champ mot de passe) → risque de harvesting
 *   - champs caches, iframes, ressources mixtes (http://)
 *   - lien vers le domaine courant
 * puis envoie le rapport au service worker, qui croise avec le verdict
 * du domaine pour declencher badge et bandeau d'avertissement.
 */
(function () {
  'use strict';

  let lastReportAt = 0;
  let bannerInjected = false;

  function safeCount(fn) {
    try {
      return fn();
    } catch {
      return 0;
    }
  }

  function collectReport() {
    const forms = Array.from(document.forms || []);
    let passwordForms = 0;
    let loginForms = 0;
    let hiddenInputs = 0;

    for (const form of forms) {
      const fields = Array.from(form.querySelectorAll('input, textarea, select'));
      let hasPassword = false;
      let hasLogin = false;
      for (const field of fields) {
        const type = (field.getAttribute('type') || '').toLowerCase();
        const name = (field.getAttribute('name') || '') + ' ' + (field.id || '');
        if (type === 'password') hasPassword = true;
        if (/user|login|email|mail|identifiant|compte|account/i.test(name)) hasLogin = true;
        if (type === 'hidden') hiddenInputs += 1;
      }
      if (hasPassword) passwordForms += 1;
      if (hasLogin && fields.length <= 6) loginForms += 1;
    }

    const inputs = safeCount(() => document.querySelectorAll('input').length);
    const iframes = safeCount(() => document.querySelectorAll('iframe').length);
    const externalScripts = safeCount(
      () => document.querySelectorAll('script[src^="http://"], script[src^="https://"]').length,
    );
    const mixedResources = safeCount(
      () => document.querySelectorAll('img[src^="http://"], link[href^="http://"], script[src^="http://"]').length,
    );

    return {
      host: location.hostname.toLowerCase().replace(/^www\./, ''),
      url: location.href,
      title: document.title || '',
      forms: forms.length,
      passwordForms,
      loginForms,
      inputs,
      hiddenInputs,
      iframes,
      externalScripts,
      mixedResources,
      at: Date.now(),
    };
  }

  function sendReport() {
    const now = Date.now();
    if (now - lastReportAt < 1000) return; // debounce SPA
    lastReportAt = now;
    try {
      chrome.runtime.sendMessage({ type: 'page-report', report: collectReport() }, () => {
        void chrome.runtime.lastError; // popup ferme : ignorer
      });
    } catch {
      /* extension rechargee */
    }
  }

  /** Bandeau d'avertissement injecte (domaine non verifie + formulaire d'identifiants). */
  function injectFormWarning(report, level) {
    if (bannerInjected) return;
    bannerInjected = true;

    const color = level === 'block' ? '#ff3b5c' : '#ffb020';
    const banner = document.createElement('div');
    banner.id = 'qs-form-warning';
    banner.setAttribute('role', 'alert');
    banner.style.cssText = [
      'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
      'background:#0b0d14', `border-bottom:2px solid ${color}`,
      'color:#e8edf7', 'font:13px/1.45 system-ui,sans-serif',
      'padding:10px 14px', 'display:flex', 'gap:12px', 'align-items:center',
      'box-shadow:0 6px 24px rgba(0,0,0,.5)',
    ].join(';');

    const icon = document.createElement('span');
    icon.textContent = '⚠';
    icon.style.cssText = `color:${color};font-size:18px;flex:none;`;

    const text = document.createElement('span');
    text.innerHTML = report.passwordForms
      ? `<b>QueryShield — formulaire d'identifiants sur un domaine non verifie.</b><br>
         Ce domaine ne correspond a aucune organisation de notre referentiel
         (ou presente des anomalies). Ne saisissez pas vos identifiants.`
      : `<b>QueryShield — page signalee comme suspecte.</b><br>
         Verifiez l'adresse avant de fournir la moindre information.`;

    const close = document.createElement('button');
    close.textContent = '✕';
    close.style.cssText =
      'margin-left:auto;background:none;border:1px solid #1e2330;border-radius:6px;color:#8a94a8;padding:4px 9px;cursor:pointer;flex:none';
    close.addEventListener('click', () => banner.remove());

    banner.append(icon, text, close);
    (document.body || document.documentElement).prepend(banner);
    document.documentElement.style.scrollPaddingTop = '64px';
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'show-form-warning') {
      injectFormWarning(message.report || {}, message.level || 'warn');
      sendResponse({ ok: true });
    }
    return true;
  });

  // Analyse au chargement + surveillance des mutations (SPA).
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    sendReport();
  } else {
    window.addEventListener('DOMContentLoaded', sendReport);
  }

  let mutationTimer = null;
  const observer = new MutationObserver(() => {
    if (mutationTimer) return;
    mutationTimer = setTimeout(() => {
      mutationTimer = null;
      sendReport();
    }, 1500);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  window.addEventListener('beforeunload', () => observer.disconnect());
})();
