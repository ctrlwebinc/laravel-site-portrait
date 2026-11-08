# laravel-site-portrait — analyse et proposition (étape 1)

Statut : **implémenté (étape 2)**, rien n'est encore commité. Voir « Suivi de l'implémentation » en fin de document.

Sources lues : `site-portrait/docs/PROTOCOL.md` (v1, schéma 1.0.0), `docs/schema/*.json`,
`includes/` (crypto, signature, appairage, API REST, collecteurs), `tests/` (vecteurs,
e2e Playground), `bin/reference-client.mjs` et `bin/lib/*.mjs`, et le code consommateur
de `ctrlweb-self-serve` (§3).

---

## 1. Le protocole en bref

| Aspect | Ce que dit la spec v1 |
|---|---|
| **Rôles** | Le *site* (ici : l'app Laravel) expose une API REST signée en lecture seule ; le *service* (ex. ctrlweb-self-serve) la lit. Aucun secret partagé : chaque partie a sa paire Ed25519 et épingle la clé publique de l'autre. |
| **Découverte** (§3) | Le site fait `GET {service}/.well-known/site-portrait` : HTTPS, pas de redirection, ≤ 64 Kio, endpoints de même origine. Document : `protocol_versions`, `service.{name, privacy_policy_url…}`, `authorization_endpoint`, `token_endpoint`, `revocation_endpoint`, `scopes_supported/requested`, `scope_reasons`, `jwks`. |
| **Appairage** (§4) | OAuth 2.0 *authorization code* + PKCE S256, le site étant un client non enregistré. Le site génère sa paire de clés, `state`, `code_verifier`, garde un appairage *en attente* 15 min, redirige le navigateur de l'admin vers `authorize` (`client_id` = origine du site, `redirect_uri`, `scope`, `site_key_thumbprint`, `site_name`, `protocol_version=1`). Retour sur `redirect_uri` avec `code` + `state`. Le site échange le code par un `POST token_endpoint` **signé avec sa clé** (preuve de possession) en envoyant `site_jwk`, `endpoints` (status/portrait/revoke), `mode`, `scopes`, `plugin_version`. Réponse : `pairing_id`, `scopes`, `jwks` du service (épinglées seulement si présentes dans la découverte), `account_hint`. |
| **Confirmation** (§4.5) | Le service appelle `GET /status` signé ; la réponse doit être signée par la clé du site et renvoyer le bon `pairing_id`. Sinon le service jette l'appairage après 15 min. |
| **Signatures** (§5) | RFC 9421 (HTTP Message Signatures), Ed25519, label `sp`, `tag="site-portrait/1"`, `created`/`expires` (fenêtre 300 s), `nonce` 16–64 car. à usage unique, `keyid` = empreinte RFC 7638 de la JWK. Composants couverts : GET → `@method @authority @path @query` ; POST → + `content-type content-digest` (RFC 9530, sha-256). `@path`/`@query` tels que reçus sur le fil ; `@authority` comparé à l'hôte configuré du site (pas à l'en-tête Host). **Toutes** les réponses (erreurs comprises) sont signées par le site : `@status content-type content-digest` + `"signature";req;key="sp"` (liaison à la requête) quand la requête était valablement signée. |
| **Anti-rejeu** (§5.4) | Mémoriser `(keyid, nonce)` au moins `expires − now + 60` s. |
| **Endpoints du site** (§6) | `GET /status` (identité, `scopes_granted` qui fait foi, `site_jwks`, `rate_limit`, `server_time`), `GET /portrait?scopes=a,b`, `POST /revoke` (révocation par le service), `GET /sites` (multisite uniquement). En-têtes : `Cache-Control: no-store`, `Site-Portrait-Protocol: 1`. Les URL sont fournies au service, qui ne doit jamais les reconstruire → **préfixe libre côté Laravel**. |
| **Scopes** (§7) | `core`, `plugins`, `themes`, `server`, `database`, `content`, `users_counts`. Scope inconnu → 400 ; connu mais non accordé → omis + `scopes_denied` ; aucun accordé → 403. |
| **Document** (§8) | Enveloppe : `schema_version` (SemVer, mineure = ajouts optionnels), `protocol_version`, `generated_at`, `generation_time_ms`, `pairing_id`, `mode`, `site_id`, `site{home_url, site_url, name}`, `plugin{version}`, `scopes_returned`, `scopes_denied`, `data.<scope>`, `warnings[]`. Valeur inconnue = `null` (jamais omise) ; collecteur en échec = `data.<scope> = null` + avertissement. Extensions tierces sous `extensions.<slug>`. Règles de minimisation normatives (§8.3). |
| **Erreurs** (§9) | Format REST WordPress `{"code","message","data":{"status"}}`, codes `site_portrait_*` (signature_missing/malformed/expired/invalid, unknown_key, replay, digest_mismatch, invalid_scope, scope_denied, ip_not_allowed, https_required, pairing_mismatch, rate_limited + `Retry-After`, internal_error) et `rest_no_route` (404) quand il n'y a pas d'appairage. Côté service : erreurs OAuth (`invalid_grant`…). |
| **Révocation** (§10) | Côté site : suppression locale immédiate puis notification signée best-effort au `revocation_endpoint` (`revoked_by_site`, `plugin_uninstalled`, `key_compromised`). Côté service : `POST /revoke`, réponse signée avec la clé qu'on vient de jeter. |
| **Rotation de clés** (§11) | Par *endorsements* : `Ed25519(T, "site-portrait/1 key-endorsement " + kid(N))`. Service : clé inconnue → relecture de la découverte (≤ 1×/h) et épinglage des clés endossées. Site : nouvelle clé endossée, ancienne publiée 7 jours dans `/status`. |
| **Politiques** (§12) | 60 req/h par appairage (fenêtre glissante) ; échecs d'auth limités à 30/h par IP (les requêtes valides ne sont jamais bloquées) ; liste d'IP autorisées optionnelle (CIDR v4/v6) ; journal d'accès 90 j / 10 000 entrées. |
| **Versionnement** | Protocole `"1"` (découverte, namespace `site-portrait/v1`, `tag`, en-tête `Site-Portrait-Protocol`) ; schéma de portrait `1.x.y` indépendant. |
| **Mode dev** (§14.6) | HTTP et IP privées seulement si constante dev + environnement local + hôtes `.test`/`.localhost`/loopback. |
| **Vecteurs** (§15) | Clés dérivées de graines 0x01/0x02/0x03, PKCE, requête signée, réponse signée, endorsement. |

### 1.1 Ce qui est propre à WordPress (à transposer ou à faire évoluer)

1. **Scopes `core`, `plugins`, `themes`, `content`** : le schéma `portrait-v1` exige des champs WP
   (`wp_version`, `permalink_structure`, constantes `WP_*`, cron WP, extensions/thèmes, types de
   contenu, commentaires, tailles `wp-content`…). Inutilisables tels quels pour Laravel.
2. **Scopes réutilisables quasi tels quels** : `server` (100 % portable ; seul le volume du disque
   passe de `wp-content` à `storage_path()`), `database` (portable sauf `options`,
   `transients_count`, `tables.site_count`, qui devront être `null`, et l'énumération `engine`
   qui ne connaît pas PostgreSQL/SQL Server), `users_counts` (total + `by_role`, `none` sans rôles).
3. **Enveloppe** : `plugin.version` (→ version du package), `mode` `single`/`network` +
   `site_id` + `/sites` (multisite WP ; pas d'équivalent → toujours `single`).
4. **Appairage piloté depuis wp-admin** : formulaire de consentement protégé par nonce WP,
   capacité `manage_options`, callback `admin-post.php?action=…&_wpnonce=…`. Laravel n'a pas
   d'admin standard → il faut un autre point d'entrée (§2.5).
5. **Stockage** : options/transients WP, `$_SERVER['REQUEST_URI']`, `home_url()`, `is_ssl()`,
   `wp_safe_remote_get()` (anti-SSRF), filtres (`site_portrait_rate_limit`,
   `site_portrait_client_ip`, `site_portrait_scope_data`…), `uninstall.php`.
6. **Format d'erreur** : copie du format REST WP (`code`/`message`/`data.status`) — à reproduire
   à l'identique, y compris `rest_no_route`.
7. **Client de référence** : la liste `SCOPES` est codée en dur dans `bin/lib/service.mjs` et
   `/authorize` rejette tout scope hors de cette liste.

---

## 2. Conception Laravel proposée

### 2.1 Identité

| | Proposition |
|---|---|
| Package | `ctrlweb/laravel-site-portrait` |
| Namespace | `Ctrlweb\SitePortrait` |
| Config | `config/site-portrait.php` (publiable, tag `site-portrait-config`) |
| Migrations | publiables (tag `site-portrait-migrations`) et chargées automatiquement si non publiées |
| Laravel | **11, 12, 13** (13.x est la version courante ; 11 est hors support mais très présent sur les sites à évaluer — c'est justement le public d'un outil d'aide à la migration d'hébergement) |
| PHP | **8.2 → 8.5** (8.3+ pour Laravel 13) |
| Dépendances runtime | `illuminate/*` uniquement + `paragonie/sodium_compat` (repli si `ext-sodium` est désactivée, comme le fait WordPress) |
| Licence | **MIT** (décidé, §6) |
| Distribution | **Packagist public** (décidé) |

Laravel 10 est écarté : il est hors support depuis février 2025, et le minimum retenu est PHP 8.2.

### 2.2 Architecture

```
src/
  SitePortraitServiceProvider.php
  Facades/SitePortrait.php
  Protocol/              # indépendant de Laravel, port fidèle du code WP testé
    Crypto.php           # b64url, Ed25519, thumbprint RFC 7638, JWK, PKCE, Content-Digest, endorsements
    StructuredFields.php # RFC 8941 (dictionnaires, inner lists, bytes, params)
    HttpSignature.php    # sign/verify requête et réponse, signature base RFC 9421
    SignatureException.php
    Scopes.php           # noms, validation ^[a-z][a-z0-9_]{1,31}$
  Pairing/
    PairingManager.php   # begin / complete / confirm / setScopes / rotateSiteKey / disconnect / forget
    DiscoveryClient.php  # GET .well-known, validations §3, garde anti-SSRF
    ServiceClient.php    # POST signés vers token/revocation endpoints (Http client Laravel)
    KeyRefresher.php     # §11.1, au plus 1×/h
  Http/
    Controllers/StatusController, PortraitController, RevokeController, PairingCallbackController
    Middleware/AuthenticateSitePortraitRequest  # HTTPS, IP, digest, signature, nonce, quotas
    Middleware/SignSitePortraitResponse         # sérialisation + signature de TOUTES les réponses
    ErrorResponse.php                           # format {code,message,data.status}
  Collectors/
    Collector.php (contrat) + CollectContext (warnings, budget temps)
    ServerCollector, DatabaseCollector, LaravelCollector, PackagesCollector,
    StorageCollector, UsersCountsCollector
  Support/SystemInfo.php  # /proc + cgroup v1/v2 (port de class-system-info.php)
  Portrait/PortraitBuilder.php
  Models/Pairing.php, Nonce.php, AccessLogEntry.php (Prunable)
  Console/ (§2.6)
  Events/ PairingCompleted, PairingConfirmed, PairingRevoked, PortraitServed
routes/site-portrait.php
database/migrations/
config/site-portrait.php
```

`Protocol/` reste sans dépendance Laravel : il pourra être extrait plus tard en
`ctrlweb/site-portrait-protocol` si un service PHP (côté consommateur) en a besoin.

### 2.3 Routes

```
GET  {prefix}/status       → StatusController
GET  {prefix}/portrait     → PortraitController
POST {prefix}/revoke       → RevokeController
GET  {callback_path}       → PairingCallbackController  (navigateur, voir §2.5)
```

* `prefix` par défaut `site-portrait/v1` (configurable, ainsi que le domaine). Les URL absolues
  envoyées au service sont construites avec `URL::to()` sur l'URL du site configurée.
* Groupe de middlewares **dédié** (ni `web` ni `api`) : pas de session, pas de CSRF, pas de
  throttle Laravel ; uniquement nos deux middlewares. Compatible `route:cache` : les routes sont
  **toujours enregistrées**, et sans appairage actif elles répondent `404 rest_no_route` (au lieu
  de « ne pas exister » comme dans WP — comportement observable identique pour le service).
* `/sites` n'est pas enregistré (mode `single` seulement en v1 ; multi-tenant hors périmètre).
* `config('site-portrait.enabled')` (défaut `true`) permet de couper totalement les routes.

Points d'attention transposés :

* `@path`/`@query` lus sur la cible brute `$request->server('REQUEST_URI')` (pas `getPathInfo()`,
  qui retire le base path et décode) ; validés en ASCII imprimable.
* `@authority` comparé à l'hôte de `site-portrait.site_url` (défaut `app.url`), jamais à `Host`.
* HTTPS via `$request->isSecure()` (dépend de `TrustProxies` — documenté).
* IP client via `$request->ip()` (idem `TrustProxies`), configurable par closure
  (`SitePortrait::resolveClientIpUsing()`), équivalent du filtre `site_portrait_client_ip`.
* Réponse construite à la main : corps `json_encode(..., JSON_UNESCAPED_SLASHES)` sérialisé une
  seule fois, `Content-Type: application/json; charset=UTF-8` exact (couvert par la signature),
  puis signature. Les exceptions levées dans le groupe sont converties en erreurs protocole
  **dans** le middleware pour qu'elles soient aussi signées (le handler global ne les voit pas).

### 2.4 Stockage

| Donnée | Choix | Raison |
|---|---|---|
| Appairage (actif ou en attente) | Table `site_portrait_pairings` (une ligne active au plus ; `status` = pending/active) | Durable, partagée entre serveurs/workers, inspectable. |
| Clé privée du site | Colonne chiffrée (cast `encrypted`, donc `APP_KEY`) | Mieux que WP (option en clair). La rotation d'`APP_KEY` reste possible via `APP_PREVIOUS_KEYS` ; sinon il faut ré-appairer (documenté). |
| Clés de service épinglées, anciennes clés du site | JSON dans la même ligne | Petites, lues à chaque requête. |
| Nonces anti-rejeu | Table `site_portrait_nonces`, index unique `(kid, nonce)`, `expires_at` | Insertion atomique fiable même sur plusieurs serveurs (le cache `file` ne l'est pas). Option `nonce_store: cache` pour qui a Redis. |
| Journal d'accès + quotas | Table `site_portrait_access_log` (`Prunable` : 90 j / 10 000 lignes) | Fenêtre glissante d'1 h comptée sur le journal, comme WP (le `RateLimiter` de Laravel est à fenêtre fixe). |
| Config non secrète | `config/site-portrait.php` + `.env` | Liste d'IP, quotas, préfixe, mode dev, scopes proposés, budgets. |

Pas de stockage dans le cache pour l'appairage : un `cache:clear` ne doit pas casser la
connexion.

### 2.5 Appairage sans wp-admin

Le consentement reste explicite et fait par une personne qui contrôle le serveur :

1. `php artisan site-portrait:pair https://service.example` → découverte, affichage du service
   (nom, origine, politique de confidentialité), choix des scopes (cases pré-cochées selon
   `scopes_requested`, avec `scope_reasons`), confirmation. Génère la paire de clés, `state`,
   PKCE, enregistre l'appairage en attente (15 min) et **affiche l'URL d'autorisation** à ouvrir
   dans un navigateur (où l'on se connecte au service et approuve).
2. Le service redirige vers `{site}/site-portrait/callback?token=…&code=…&state=…`. Le `token`
   (32 octets aléatoires, usage unique, lié à l'appairage en attente) joue le rôle du nonce WP ;
   `state` est comparé en temps constant. La page de callback fait l'échange de code (§4.4) et
   affiche un résultat minimal (Blade sans dépendance front).
3. Le service confirme via `/status` ; `confirmed_at` est enregistré.

Option : protéger aussi le callback par une Gate `viewSitePortrait` / un middleware configurable
(comme Horizon/Telescope) pour les apps qui ont une authentification admin. Une petite page
d'administration web (état, scopes, déconnexion) est envisageable en phase 2, pas en v1.

Le mode non interactif (`--scopes=server,database --yes`) permet l'automatisation (déploiement,
Forge/Envoyer).

### 2.6 Commandes artisan

| Commande | Rôle |
|---|---|
| `site-portrait:install` | Publie la config, lance les migrations, rappelle les prérequis (HTTPS, `TrustProxies`, `APP_URL`). |
| `site-portrait:pair {url} {--scopes=} {--yes}` | Appairage (§2.5). |
| `site-portrait:status` | Service, `pairing_id`, scopes accordés, confirmation, clés (kid), dernières requêtes, quota restant. |
| `site-portrait:scopes {--grant=} {--deny=}` | Modifie les scopes accordés sans ré-appairer (`/status` fait foi). |
| `site-portrait:show {--scopes=} {--json}` | Affiche localement **exactement** le portrait qui serait envoyé (transparence ; utile aussi pour la revue de confidentialité). |
| `site-portrait:log {--limit=}` | Journal d'accès. |
| `site-portrait:rotate-key` | Rotation de la clé du site (§11.2). |
| `site-portrait:disconnect {--reason=revoked_by_site}` | Révocation locale + notification au service (§10.1). |
| `site-portrait:forget` | Suppression locale sans notification (secours). |

Nettoyage : modèles `Prunable` (nonces expirés, journal) → `php artisan model:prune` ; le
provider n'ajoute rien au scheduler de l'app sans option explicite (`schedule_pruning: true`).
Pas d'`uninstall.php` en Composer : `site-portrait:disconnect --reason=plugin_uninstalled` est
documenté comme étape de désinstallation.

### 2.7 Scopes et collecteurs Laravel

Principe : **réutiliser les scopes génériques de la spec quand le schéma convient**, et ajouter
des scopes propres à Laravel pour le reste (nécessite une évolution de la spec, §5).

| Scope | Statut | Contenu (Laravel) |
|---|---|---|
| `server` | existant, schéma inchangé | Port direct : OS, archi, conteneur, `SERVER_SOFTWARE`, PHP (version, SAPI, extensions, limites ini, OPcache), CPU/mémoire via `/proc` + cgroup v1/v2, disque du volume de `storage_path()`, bibliothèques (curl, openssl, gd, imagick, icu, sodium). Jamais d'hôte, d'IP ni de chemin. |
| `database` | existant, schéma inchangé | Connexion **par défaut** : moteur (mysql/mariadb/sqlite, `other` pour pgsql/sqlsrv tant que l'énumération n'est pas étendue), version serveur, client (pdo_* / mysqlnd), charset/collation, taille données/index, nb de tables, 10 plus grosses tables (préfixe de connexion retiré) via `Schema::getTables()`, variables (`max_connections`, `max_allowed_packet`, `innodb_buffer_pool_size`). `options` / `transients_count` / `site_count` → `null`. Jamais d'hôte, de nom de base, d'utilisateur. |
| `users_counts` | existant, schéma inchangé | Total du modèle du provider `auth.providers.users` ; `by_role` via spatie/laravel-permission si présent, sinon `{"none": total}`. Jamais d'identifiant ni de courriel. |
| `laravel` | **nouveau** | Version de Laravel, `environment_type` (mappé sur l'énumération + valeur brute), `debug` (booléen), mode maintenance, timezone, locale/fallback, HTTPS de `APP_URL`, caches d'optimisation (config/routes/events/views compilés), **pilotes seulement** : cache, session, queue, mail, broadcasting, filesystem par défaut/cloud, log ; Octane (serveur), Horizon/Pulse/Telescope/Reverb/Nova/Filament/Livewire/Inertia détectés ; **files d'attente** : connexions et pilotes, nombre de jobs en attente par connexion (`Queue::size()` sur la file par défaut), jobs échoués (`queue:failed` provider), batches ; **scheduler** : nombre de tâches planifiées et répartition par fréquence (jamais la commande ni ses arguments), présence d'un heartbeat (optionnel) ; nombre de routes, de commandes artisan. |
| `packages` | **nouveau** (équivalent de `plugins`) | Depuis `Composer\InstalledVersions` / `vendor/composer/installed.json` : nom, version, type, directe ou transitive, `dev`. Compteurs (total, directs, dev). Plateforme requise (`php`, `ext-*`) du `composer.lock`. Optionnel : dépendances JS directes de `package.json` (nom + contrainte). Pas de `update` (null) : aucune requête réseau. Jamais d'URL de dépôt (`dist.url`/`source.url` peuvent contenir des jetons). Masquage configurable (`packages.hide` : motifs, ex. `acme/*`). |
| `storage` | **nouveau** (équivalent de `content.sizes`) | Tailles avec budget temps et cache 1 h (`computed_at`) : `storage/app`, `storage/app/public`, `storage/logs`, `storage/framework/{cache,sessions,views}`, `public`, `vendor`, `node_modules` si présent ; disques déclarés : nom → pilote, taille seulement pour les disques `local` (S3 & co : `null`, pas de listage coûteux). Volumes de données : nombre de lignes approximatif déjà fourni par `database.tables.largest`. |

Forme proposée à la spec (noms de champs partagés avec le service) :

```
laravel: version, environment_type (production|staging|development|local), debug, maintenance,
  timezone, locale, https,
  optimizations{config_cached, routes_cached, events_cached},
  drivers{cache, session, queue, mail, broadcasting, filesystem, filesystem_cloud, log},
  octane{enabled, server}, ecosystem[] (noms de paquets détectés : horizon, pulse, livewire…),
  queue{pending_jobs, failed_jobs, batches}, schedule{tasks_count, by_frequency{}},
  routes_count, commands_count, extensions
packages: counts{total, direct, dev, direct_dev},
  items[{name, version, type, direct, dev}], platform{php, extensions[]}, extensions
storage: sizes{app, app_public, logs, framework_cache, framework_sessions, framework_views,
  public, vendor, node_modules, computed_at},
  disks[{name, driver, default, size}], extensions
```

Toutes les tailles sont des entiers en octets ou `null`. Les valeurs inconnues valent `null`,
comme dans le reste du schéma.

Équivalences des collecteurs WP :

| WordPress | Laravel |
|---|---|
| `core` | `laravel` |
| `plugins` (+ mu-plugins, drop-ins) | `packages` |
| `themes` | — (pas d'équivalent ; éventuellement pile front détectée dans `laravel`) |
| `content` (types de contenu, médias, taxonomies, commentaires, tailles) | `storage` (tailles) + `database.tables.largest` (volumes) ; pas de comptage par modèle Eloquent en v1 |
| `server`, `database`, `users_counts` | identiques |

Extensibilité (équivalent du filtre `site_portrait_scope_data`) :
`SitePortrait::extend('laravel', 'vendor-slug', fn (CollectContext $c) => [...])` ajoute sous
`data.<scope>.extensions.<slug>` ; ne peut ni retirer ni modifier les membres du cœur. Les
collecteurs eux-mêmes sont remplaçables via la config (classe par scope).

### 2.8 Enveloppe du portrait

```json
{
  "schema_version": "1.0.0",
  "protocol_version": "1",
  "generated_at": "…", "generation_time_ms": 120,
  "pairing_id": "…", "mode": "single", "site_id": null,
  "site": { "home_url": "{APP_URL}", "site_url": "{APP_URL}", "name": "{APP_NAME}" },
  "plugin": { "version": "{version du package}" },
  "scopes_returned": ["laravel", "server"], "scopes_denied": [],
  "data": { … }, "warnings": [ … ]
}
```

Proposition additive (spec, §5) : membre `platform: {"name": "laravel", "version": "13.40.0"}`
dans le portrait, `/status` et la requête de token, pour que le service sache quels scopes
attendre sans deviner.

### 2.9 Confidentialité (jamais exposé)

* Aucune lecture de `.env`, aucune valeur de `config()` hors liste blanche (noms de pilotes,
  booléens, version, timezone, locale). Pas de `APP_KEY`, mots de passe, jetons, DSN, hôtes,
  noms de base/utilisateur, URL de services (Redis, S3, SMTP, Sentry…), adresses courriel.
* Pas de chemins absolus, noms d'hôte, IP (hors journal d'accès local), noms de tables préfixés,
  noms de files ou de canaux, commandes planifiées, URI de routes, contenu de logs, variables
  d'environnement (même leurs noms).
* Pas d'URL de dépôts Composer ; option de masquage de paquets privés.
* `site-portrait:show` permet de vérifier ce qui sort. Test automatisé « canari » : on injecte
  des secrets reconnaissables dans la config/env de test et on vérifie qu'aucun n'apparaît
  dans le JSON du portrait, du `/status` ni des erreurs.

### 2.10 Sécurité

* Ordre de vérification de §5.3 respecté ; étapes 1–6 sans écriture en base ; comparaisons
  `hash_equals` ; nonce consommé seulement après signature valide (insertion unique atomique).
* HTTPS obligatoire (403 `https_required`) sauf mode dev (config `dev_mode` **et**
  `app()->environment('local','development')` **et** hôtes `.test`/`.localhost`/loopback).
* Découverte : HTTPS, pas de redirection, 64 Kio max, endpoints de même origine, résolution DNS
  refusant IP privées/réservées (équivalent `wp_safe_remote_get`), délais courts.
* Quotas : 60 req/h par appairage (configurable), 30 échecs/h par IP, `Retry-After`.
* Liste d'IP (CIDR v4/v6 via `Symfony\Component\HttpFoundation\IpUtils`).
* Révocation : par le service (`POST /revoke`) ou par l'admin (commande) ; suppression des clés
  et nonces.
* Clé privée chiffrée au repos ; jamais journalisée ; messages d'erreur sans valeurs attendues.
* Collecte en lecture seule, aucune commande shell (`exec`, `Process`), aucune requête réseau
  pendant la collecte.
* Points connus partagés avec WP : un proxy qui réécrit le chemin, ou une compression à la
  volée qui modifie le corps, casse la vérification (comportement voulu par la spec, documenté).

---

## 3. Compatibilité avec ctrlweb-self-serve

Le service (`ctrlweb-self-serve`, Laravel + Filament) joue le rôle de serveur d'autorisation.
Il ne découvre pas le site : c'est le site qui lit la découverte du service et lance
l'appairage. Il a sa propre implémentation PHP du protocole
(`app/Services/SitePortrait/Protocol/HttpMessageSignature.php`, `Jwk.php`, vecteurs dans
`tests/Unit/SitePortrait/ProtocolVectorsTest.php`).

**Ce qui marche tel quel avec un site Laravel** : les URL d'endpoints sont libres et
utilisées telles quelles (les paramètres sont ajoutés avec `&` si l'URL contient déjà `?`, et
les virgules ne sont pas encodées). La signature et les clés ne dépendent pas de la plateforme.
Le portrait est stocké brut. `mode=single` et `site_id=null` sont acceptés.

**Contraintes à respecter côté package** (toutes déjà prévues au §2) :

* Signer toutes les réponses 2xx avec la liaison `"signature";req;key="sp"` et un
  `Content-Digest` calculé sur les octets exacts du corps. Sinon le service lève une exception.
* Renvoyer les erreurs au format `{code, message, data.status}`. **Attention : le service
  passe l'appairage à `revoked` (`pairing_gone`) sur tout 404 de `/status` ou `/portrait`**
  dont le `code` n'est pas `site_portrait_unknown_site`. Les URL publiées doivent donc rester
  stables (pas de changement de préfixe après l'appairage, pas de redirection de slash final,
  http→https ou www : une redirection est traitée comme une erreur). Le 404 `rest_no_route`
  sans appairage reste correct.
* `/status` doit renvoyer `pairing_id`, `scopes_granted` (qui remplace les scopes stockés côté
  service) et `site_jwks` (rotation). `plugin_version` est lu et tronqué à 32 caractères.
* Le service confirme l'appairage par des relances pendant 15 min à partir de 5 s après le
  token : l'enregistrement local doit être fait avant la réponse au navigateur, ce qui est le
  cas dans le flux du §2.5.
* Types : les tailles et `server.php.ini.memory_limit` doivent être des entiers (octets). Les
  booléens doivent être de vrais booléens.

**Ce qui bloque aujourd'hui** :

1. **Liste blanche de scopes.** `/site-portrait/authorize` rejette tout scope hors de
   `core, plugins, themes, server, database, content, users_counts`
   (`config/site_portrait.php:35`, `ShowSitePortraitAuthorizationRequest.php:38`). Les scopes
   `laravel`, `packages` et `storage` seront refusés tant que la config du service n'est pas
   étendue.
   - Le package ne propose déjà que l'intersection avec `scopes_supported` de la découverte.
     Un appairage limité à `server`, `database` et `users_counts` est donc possible **dès
     maintenant**.
2. **Calcul de recommandation centré WP.** `SizeRecommendationService.php:52-70` lit
   `plugins.counts.active`, `database.size.total` et `content.sizes.uploads`. Dès qu'un
   portrait existe, le décompte d'extensions du scraping est remplacé par
   `plugins.counts.active`. Pour un site Laravel sans ce champ, le critère disparaît au lieu de
   revenir au scraping.
   - `database.size.total` fonctionnera tel quel.
   - Équivalents proposés pour le reste :
     - `content.sizes.uploads` → `storage.sizes.app_public` (ou `storage.sizes.app`) ;
     - `plugins.counts.active` → `packages.counts.direct`, avec une pondération différente.
3. **Pas de notion de plateforme.** Le service ne lit aucun champ `platform`. Il devra
   distinguer WP et Laravel, d'où la proposition `platform {name, version}` (§2.8). En
   attendant, la présence de `data.laravel` suffit à le déduire.
4. **Textes affichés.** La page d'approbation, la page d'erreur et le configurateur disent
   « site WordPress » et « Réglages › Site Portrait ». Ça ne bloque rien, mais c'est trompeur
   pour un site Laravel.

**Option écartée : réutiliser les noms WP** (`core` = framework, `plugins` = paquets Composer)
pour éviter de toucher au service. Elle violerait le schéma `portrait-v1`, qui exige
`wp_version`, les champs de thèmes, etc., et ferait échouer `reference-client --validate`.
Elle entretiendrait aussi une ambiguïté durable. Je recommande des scopes Laravel distincts et
une petite évolution coordonnée du service (§7).

**Points relevés côté service, hors périmètre du package** (à transmettre) :
- pas de cache de nonces : un avis `/revoke` peut être rejoué pendant 300 s, ce qui est sans
  gravité puisqu'il est idempotent ;
- l'endpoint `sites` est exigé en mode `network` mais n'est jamais appelé.

**Test de contrat** : les doublures de `tests/Feature/SitePortrait/SitePortraitTestHelpers.php`
(lignes 56-124) donnent la forme exacte attendue de `/status` et `/portrait`. Le package aura un
test qui vérifie que ses réponses contiennent au moins ces champs avec ces types. Les vecteurs
du service et ceux de la spec doivent rester identiques.

---

## 4. Stratégie de tests

1. **Unitaires (PHPUnit, sans Laravel)** sur `Protocol/` : port des tests WP
   (`StructuredFieldsTest`, `HttpSignatureTest`, `IpAllowlistTest`, `SystemInfoTest` avec
   fixtures `/proc` et cgroup v1/v2) et **vecteurs §15** (`VectorsTest`) : clés et kid, PKCE,
   vérification de la requête signée, signature de réponse identique à l'octet, endorsement.
   Les vecteurs sont lus depuis un fichier JSON unique (proposition : le publier dans la spec,
   §5) pour éviter les copies divergentes.
2. **Feature (Orchestra Testbench)** : routes et middlewares avec un faux service (clé de test
   0x01, `Http::fake()` pour découverte/token/révocation) :
   appairage complet (commande + callback), confirmation, chaque code d'erreur du §9, rejeu,
   fenêtre de temps (horloge figée), quotas et `Retry-After`, liste d'IP, HTTPS, scopes
   (inconnu/refusé/partiel), révocation dans les deux sens, rotation des clés (service et site),
   signature de **toutes** les réponses y compris 404/429/500, test canari de confidentialité.
3. **Collecteurs** : sqlite en local ; MySQL 8, MariaDB et PostgreSQL en CI (services Docker)
   pour `database` ; cas « valeur indisponible → null + warning ».
4. **Validation de schéma** : chaque portrait produit en test est validé contre
   `portrait-v1.schema.json` (`opis/json-schema` en dev) ; les schémas sont copiés depuis le
   dépôt de la spec à une version épinglée (script de synchro + vérification en CI).
5. **Interopérabilité de bout en bout** avec `bin/reference-client.mjs` / `bin/lib/*.mjs` :
   une app Testbench *workbench* servie par `php artisan serve` (mode dev, hôte `127.0.0.1`),
   le service de référence lancé en `--auto-approve`, un script Node qui exécute
   `site-portrait:pair --yes`, suit l'URL d'autorisation jusqu'au callback, attend la
   confirmation, puis `status`, `portrait --validate`, `rotate-key` + nouvel appel, `revoke`.
   En CI, le dépôt site-portrait est récupéré à une révision épinglée (`actions/checkout` avec
   `repository:`/`ref:`) ; en local via `SP_REFERENCE_DIR=../site-portrait`.
   Tant que le client de référence n'accepte pas les nouveaux scopes, l'e2e couvre
   `server`, `database`, `users_counts`.
6. **Contrat avec ctrlweb-self-serve** : voir §3.

## 5. Outillage

* **Pint** (preset `laravel`), **Larastan** niveau 8 au départ (objectif `max` sur `Protocol/`),
  **PHPUnit** via Testbench (plus simple à faire tourner sur toute la matrice que Pest).
* `composer` scripts : `lint`, `analyse`, `test`, `test:e2e`.
* **GitHub Actions** :
  * `tests` : matrice PHP 8.2/8.3/8.4/8.5 × Laravel 11/12/13 (exclusions : L13 sans 8.2),
    `prefer-lowest` et `prefer-stable`, sqlite ;
  * `database` : MySQL 8.4, MariaDB 11, PostgreSQL 17 sur la dernière combinaison ;
  * `e2e` : Node 22 + checkout épinglé de site-portrait ;
  * `static` : Pint `--test` + Larastan ;
  * sans `ext-sodium` une fois (repli sodium_compat).
* `.gitattributes` `export-ignore` pour tests/outillage, `CHANGELOG.md`, `README.md` (FR/EN ?).

---

## 6. Décisions

1. **Licence : MIT** pour le package. L'extension WP reste en GPL, chaque projet suivant le
   standard de son écosystème. Daniel Le Blanc est l'unique auteur des commits de
   l'extension : le code porté peut être relicencié. Le fichier `LICENSE` doit mentionner que la spec et les schémas copiés restent
   sous CC-BY-4.0.
2. **Versions : PHP 8.2 minimum, Laravel 11, 12 et 13.**
3. **Scopes : `laravel`, `packages` et `storage`**, plus `server`, `database` et
   `users_counts`.
4. **Retour d'appairage** : jeton à usage unique et `state` par défaut. Option
   `site-portrait.callback_middleware` (par ex. `['web', 'auth', 'can:manageSitePortrait']`)
   pour exiger en plus l'authentification de l'app.
   - Dans WP, le retour (`admin-post.php`) exige quatre conditions : une session admin
     connectée avec `manage_options`, un nonce WP lié à cet utilisateur et à sa session (inclus
     dans `redirect_uri`), un appairage en attente **de ce même utilisateur** (transient de
     15 min), et un `state` égal en temps constant.
   - Sans auth Laravel standard, la session et le nonce sont remplacés par un jeton aléatoire
     à usage unique lié à l'appairage en attente, lancé depuis la console par quelqu'un qui a
     accès au serveur.
5. **Publication : Packagist public.**
6. **Compatibilité du service** : on adapte ctrlweb-self-serve pour accepter les deux
   plateformes. Les changements sont additifs (§7).
   - L'extension WP filtre déjà les scopes inconnus de la découverte (`Scopes::sanitize`,
     `class-service-client.php:107-111`). Les sites WP ne voient donc pas les scopes Laravel.
   - Le package Laravel fera de même avec les scopes WP.

## 7. Évolutions de spec à proposer (à l'agent site-portrait — non modifiées ici)

Côté **ctrlweb-self-serve** (à transmettre à son agent, pas à faire ici) :
- ajouter `laravel`, `packages` et `storage` à `config/site_portrait.php`, avec des libellés
  neutres ;
- rendre `SizeRecommendationService` dépendant de la plateforme, avec repli sur le scraping si
  le champ est absent ;
- neutraliser les textes « WordPress ».

Côté **spec** (agent site-portrait) :

1. Définir dans `portrait-v1.schema.json` (version mineure 1.1.0) les scopes `laravel`,
   `packages`, `storage`, et rendre la liste des scopes extensible par plateforme dans §7.
2. Ajouter `platform {name, version}` (portrait, `/status`, requête de token) ; préciser que
   `plugin.version` désigne l'implémentation.
3. Étendre l'énumération `database.engine` (`pgsql`, `sqlsrv`) et rendre `options`,
   `transients_count`, `tables.site_count` explicitement « WordPress seulement / null ailleurs ».
4. Généraliser le texte WP-centré (§4.1 consentement, `redirect_uri` wp-admin, `rest_url`,
   `home_url`, `$_SERVER['REQUEST_URI']`) en « implémentation de site » avec WP comme exemple.
5. Client de référence : liste de scopes non codée en dur (option `--scopes` ou dérivée de la
   découverte) pour l'e2e Laravel.
6. Publier les vecteurs §15 dans un fichier JSON lisible par machine.

---

## 8. Suivi de l'implémentation (2026-11-08)

**État des vérifications**
- PHPUnit : 71 tests passent sur Laravel 13 / PHP 8.5, et aussi sur Laravel 11 (copie temporaire).
- Pint passe.
- Larastan niveau 8 passe sans aucune suppression.
- Le test e2e passe face au service de référence (`node --test tests/e2e/interop.test.mjs`).

**Écarts par rapport au plan**
- **Scopes Laravel alignés sur le schéma 1.1.0 de l'agent site-portrait** :
  - `ecosystem` contient des identifiants courts (`horizon`, `livewire`…) ;
  - `schedule.by_frequency` est indexé par expression cron, avec `sub_minute` pour les tâches répétées plus d'une fois par minute ;
  - `environment_type` vaut `null` pour `testing`.
- **`PairingManager` ne garde rien en cache**. C'est un singleton qui survit d'une requête à l'autre sous Octane et dans les workers.
- **Pas d'option `stream` dans le client HTTP sortant**. Avec elle, Guzzle passe à son `StreamHandler`, qui ignore les options cURL : l'épinglage de l'adresse résolue (`CURLOPT_RESOLVE`, anti-SSRF) aurait été désactivé. La taille des réponses est désormais limitée par `on_headers` et `progress`.
- **Nouveau réglage `key_refresh_interval`**, équivalent du filtre WP `site_portrait_key_refresh_interval`.
- **Les schémas et les vecteurs sont copiés** dans `resources/schema/` et `tests/fixtures/`. La CI vérifie qu'ils restent identiques au dépôt de la spec.

**À noter**
- **Laravel 11** : toutes les versions 11.x ont des avis de sécurité non corrigés (branche en fin de vie), et Composer 2.10 refuse de les installer par défaut.
  - La contrainte `^11.0` est conservée ; la CI désactive ce blocage pour ce seul job.
  - Un site en Laravel 11 qui installe le package devra faire de même, ou passer à Laravel 12.
- **`Cache-Control`** : Symfony envoie `no-store, private` au lieu de `no-store`. C'est sans effet sur le protocole, car cet en-tête n'est pas signé.
- **Mode maintenance** : `php artisan down` renvoie un 503 non signé sur toutes les routes, endpoints compris. Le service le traite comme une erreur temporaire, pas comme une révocation.
- **Dépôts distants** : le dépôt de la spec n'a pas encore de remote. La CI lit son emplacement dans les variables `SP_REFERENCE_REPOSITORY` et `SP_REFERENCE_REF` (par défaut `ctrlwebinc/site-portrait@main`). Le `homepage` de `composer.json` suppose `github.com/ctrlwebinc/laravel-site-portrait`.
