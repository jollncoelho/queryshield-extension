# QueryShield — Extension navigateur (Manifest V3 v2)

Extension **Chrome / Edge / Firefox 128+** qui branche QueryShield directement
dans le navigateur : analyse **zéro-clic** de chaque page visitée, détection
des **formulaires de harvesting**, **blocage actif** des sites de phishing, et
console tactique consolidée.

## Fonctionnalités

| Fonction | Détail |
|---|---|
| **Analyse comportementale zéro-clic** | À chaque navigation (`webNavigation.onBeforeNavigate`), l'URL, l'âge du domaine (RDAP) et la structure de la page sont analysés en arrière-plan |
| **Détection de formulaires suspects** | Le contenu script compte les formulaires mot de passe, champs cachés, iframes et ressources mixtes → escalade badge + bandeau injecté sur domaine non vérifié |
| **Le Mur de Protection** | Verdict `phishing` ou score ≥ seuil → règle `declarativeNetRequest` bloquant le `main_frame` **+ redirection** vers une page d'alerte rouge plein écran (le rendu est intercepté avant affichage) |
| **Page d'alerte tactique** | Score, verdict, motifs détaillés, âge du domaine, conduite à tenir, IOC. Bouton « Revenir en arrière » + **contournement avancé** (liste de faux positifs persistée localement) |
| **Badge dynamique** | 🔴 `!` = bloqué/phishing · 🟠 `?` = suspect ou formulaire sur domaine non vérifié · ⚪ aucun badge = sûr |
| **Popup console** | État de surveillance, page active (verdict, signaux, formulaires), audit manuel message/site, quota, historique |
| **Locale first** | Clé de licence `QS-…` dans les options (offre payante) |
| **Vie privée** | Aucun contenu analysé n'est stocké ; seuls score/verdict/résumé restent en cache local (TTL 1 h) |

## Comment le blocage marche en MV3

Manifest V3 a supprimé le `webRequest` bloquant de Chrome. Le blocage utilise
donc les deux briques légales :

```
navigation détectée (webNavigation)
   → verdict phishing / score ≥ seuil de blocage
      1. updateDynamicRules : { action: block, resourceTypes: [main_frame],
                                requestDomains: [domaine] }
      2. chrome.tabs.update → blocked/blocked.html?host=… (page d'alerte)
         (si la règle bloque d'abord, ERR_BLOCKED_BY_CLIENT est neutralisé
          par la redirection)
```

Le **contournement** ajoute une règle `allow` de priorité supérieure (10 > 1)
plus une entrée persistée dans `chrome.storage.local` (`qs.bypass`) — elle
survit au redémarrage du navigateur.

Sur Firefox sans `declarativeNetRequest`, l'extension se dégrade
automatiquement en « redirection seule » (la page clignote puis est remplacée
par l'alerte).

## Structure

```
queryshield-extension/
├── manifest.json            # MV3 : DNR, webNavigation, contenu script
├── background.js            # surveillance, blocage, badge, notifications
├── content.js               # analyse DOM : formulaires, champs cachés, mixtes
├── blocked/
│   ├── blocked.html         # page d'alerte rouge plein écran
│   ├── blocked.css
│   └── blocked.js           # rendu + retour + contournement
├── popup/                   # console tactique
├── options/                 # réglages : mode, seuils, licence, vérifications actives
├── shared/api.js            # client API (popup / options / background / blocked)
├── icons/                   # 16 / 48 / 128 px
├── tools/make_icons.py      # régénération des icônes
└── test/                    # 75 tests (jsdom + worker simulé)
```

## Tests

```bash
node test/run-tests.mjs       # 24 tests : popup (jsdom + mock Chrome)
node test/background.test.mjs # 35 tests : service worker (vm + mock API)
node test/blocked.test.mjs    # 16 tests : page de blocage
```

Couvert : blocage phishing (règle DNR + redirection + badge + notif),
mode avertissement seul, domaine officiel (badge effacé), suspect sous le
seuil, contournement (règle allow + persistance), quota épuisé (pause),
rapport de formulaire (escalade + bandeau), pages internes ignorées,
pont de messages popup, rendu complet de la page de blocage.

## Installation (développement)

1. `chrome://extensions` → activer le **mode développeur**
2. **Charger l'extension non empaquetée** → ce dossier **dézippé**
   (si vous avez téléchargé le ZIP du bouton vert « Code », faites
   clic droit → *Extraire tout…* puis sélectionnez le dossier extrait —
   **pas** le .zip)
3. Épingler l'icône dans la barre d'outils

Firefox : `about:debugging#/runtime/this-firefox` → *Ce Firefox* →
*Charger un module temporaire* → `manifest.json`.

## Réglages par défaut

| Réglage | Défaut |
|---|---|
| Surveillance | activée |
| Mode | blocage (désactivable → avertissement seul) |
| Seuil d'alerte (badge) | 60/100 |
| Seuil de blocage | 75/100 |
| Vérifications actives (âge du domaine) | activées |
| Notifications phishing | activées |

## Sécurité & quotas

- Le site analysé n'est **jamais contacté** : seules les API
  `shield.query-intel.com` sont appelées.
- Offre gratuite limitée (quota quotidien) : en cas de dépassement, la
  surveillance se met en pause (badge `OFF`) et reprend automatiquement.
- Anti-rafale : 2 s minimum entre deux appels API.
- Domaines internes (`localhost`, `.local`, `.interne`, IP privées,
  `chrome://`, `about:`) jamais transmis.

## Publication

- **Chrome Web Store** : zip de ce dossier (sans `test/`, `tools/`), upload sur
  le [dashboard](https://chrome.google.com/webstore/dev/dashboard) (5 $ unique).
- **Firefox Add-ons** : gratuit, même zip. ID gecko déjà déclaré.
- Les permissions larges (`<all_urls>`, `declarativeNetRequestWithHostAccess`)
  nécessitent une justification détaillée au moment de la soumission —
  le README et le code montrent un usage strictement défensif.
