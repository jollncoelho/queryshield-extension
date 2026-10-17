# QueryShield — Extension navigateur

Extension de navigateur (Chrome / Edge / Firefox, Manifest V3) qui branche
QueryShield directement dans le navigateur : analyse de messages suspects,
vérification de domaines, et alerte en temps réel sur les sites de phishing.

## Fonctionnalités

| Fonction | Détail |
|---|---|
| **Analyse de message** | Collez un SMS, e-mail ou message instantané → score 0-100, verdict, constats détaillés et conduite à tenir |
| **Auditer cette page** | Un clic récupère l'URL de l'onglet actif et l'envoie au moteur |
| **Vérification de domaine** | Saisie libre d'un domaine ou d'une URL complète |
| **Surveillance silencieuse** | Chaque page visitée est comparée au référentiel (cache 1 h, anti-rafale 2 s) |
| **Badge d'alerte** | Rouge `!` = phishing confirmé · Ambre `?` = score ≥ seuil · Badge effacé = rien à signaler |
| **Notification système** | Alerte immédiate sur site de phishing, clic → rapport complet sur shield.query-intel.com |
| **Locale first** | Saisie d'une clé de licence dans les options (offre payante) |
| **Vie privée** | Aucun contenu analysé n'est stocké ; seuls score/verdict/résumé restent en cache local |

## Structure

```
queryshield-extension/
├── manifest.json          # Manifest V3 (Chrome/Edge/Firefox 109+)
├── background.js          # service worker : surveillance, badge, notifications
├── popup/
│   ├── popup.html         # interface du popup
│   ├── popup.css          # thème sombre tactique (cyan #00f2fe)
│   └── popup.js           # logique d'analyse et de rendu
├── options/
│   ├── options.html       # réglages : surveillance, seuil, licence
│   ├── options.css
│   └── options.js
├── shared/
│   └── api.js             # client API partagé (popup / options / background)
├── icons/                 # 16 / 48 / 128 px
└── tools/
    └── make_icons.py      # régénération des icônes
```

## Installation (développement)

1. Ouvrez `chrome://extensions` (ou `edge://extensions`, `about:debugging#/runtime/this-firefox` sous Firefox).
2. Activez le **mode développeur**.
3. **Charger l'extension non empaquetée** → sélectionnez ce dossier.
4. L'icône apparaît dans la barre d'outils ; épinglez-la pour un accès rapide.

> Sous Firefox, utilisez `about:debugging` → « Ce Firefox » → « Charger un module
> temporaire » → choisissez `manifest.json`.

## Architecture — pourquoi pas d'interception réseau ?

En Manifest V3, le blocage `webRequest` a été retiré d'Chrome : une extension
ne peut plus intercepter et retarder une requête pour appeler une API. La
surveillance s'appuie donc sur `tabs.onUpdated` :

```
navigation → debounce 800 ms → domaine inscriptible
   → cache local (TTL 1 h) ─── hit ─→ badge + notification si besoin
   → miss → POST /api/check-site (anti-rafale 2 s)
        → phishing  → badge rouge "!" + notification
        → score ≥ seuil → badge ambre "?"
        → sinon → badge effacé
```

C'est la vérification **la plus fiable disponible sans bloquer la navigation** :
l'utilisateur est averti dès l'arrivée sur la page, sans jamais être ralenti.

## Sécurité & quotas

- **Le site analysé n'est jamais contacté** : seules les API
  `shield.query-intel.com` sont appelées.
- L'offre gratuite est limitée (quota quotidien). En cas de dépassement, la
  surveillance se met en pause (`OFF` sur le badge) et reprend automatiquement.
- La clé de licence voyage dans l'en-tête `x-qs-license`, uniquement vers
  `shield.query-intel.com` (déclaré dans `host_permissions`).
- Les domaines internes (localhost, `.local`, IP privées, pages `chrome://`)
  ne sont jamais envoyés.

## Publication

- **Chrome Web Store** : compresser ce dossier en `.zip` (`tools/../*`, sans les
  fichiers de dev), uploader sur le [dashboard développateur](https://chrome.google.com/webstore/dev/dashboard)
  (compte unique de 5 $). L'icône 128 px et des captures du popup sont demandées.
- **Firefox Add-ons** : [addons.mozilla.org](https://addons.mozilla.org/developers/),
  gratuit, soumission d'un zip identique. L'identifiant gecko
  `extension@query-intel.com` est déjà déclaré dans le manifest.

## Développement

```bash
# régénérer les icônes
python tools/make_icons.py

# tests (logique popup + API, jsdom)
node test/run-tests.mjs
```
