# Cycle de vie des publications CERT-FR (ANSSI)

## 1. Objectif de cette section

Cette section décrit le **cycle de vie** des publications du CERT-FR (ANSSI), notamment :

* la fréquence et les mécanismes de mise à jour ;
* l’évolution d’un bulletin (Alerte / Avis / CTI) dans le temps ;
* l’impact sur les **CVE**, les recommandations, les correctifs et les indicateurs d’exploitation ;
* les bonnes pratiques pour synchroniser et maintenir un **référentiel interne** à jour.

---

## 2. Comprendre le modèle CERT-FR

Contrairement à la NVD (qui publie des *enregistrements CVE*), le CERT-FR publie des **bulletins éditoriaux**.

### 2.1 Types de publications

* **Alerte** (`/alerte/` – identifiant `CERTFR-YYYY-ALE-XXX`)

  * communication **urgente**
  * généralement exploitation active, impact large ou criticité élevée

* **Avis** (`/avis/` – identifiant `CERTFR-YYYY-AVI-XXXX`)

  * bulletin vulnérabilité **standard/informatif**
  * souvent corrélé à des publications éditeurs (patch Tuesday, CPU Oracle, etc.)

* **CTI** (`/cti/`)

  * rapports menaces / incidents
  * davantage orienté TTP / campagnes / incidents

> 📌 Pour un “référentiel vulnérabilités”, l’essentiel est **Alerte + Avis**.

---

## 3. Fréquence et mécanismes de mise à jour

Le CERT-FR est une source vivante : les bulletins peuvent être **mis à jour** après publication.

Une publication peut évoluer suite à :

* disponibilité de correctifs éditeur (patch)
* publication de PoC / exploitation confirmée
* ajout d’éléments techniques (IoC, logs, méthodes de détection)
* clarification de périmètre (produits/versions affectés)
* ajout/suppression de références (éditeur, CISA, exploit-db, etc.)

### 3.1 Points d’entrée machine-readable

CERT-FR fournit des **flux RSS** (XML) :

* Tous : `https://www.cert.ssi.gouv.fr/feed/`
* Alertes : `https://www.cert.ssi.gouv.fr/alerte/feed/`
* Avis : `https://www.cert.ssi.gouv.fr/avis/feed/`

> ⚠️ Ces flux ne contiennent qu’un **nombre limité d’items récents** (fenêtre glissante) — pas l’historique complet.

---

## 4. Cycle de vie d’un bulletin CERT-FR

### 4.1 Étapes typiques

1. **Publication initiale**

   * création d’un bulletin `CERTFR-YYYY-ALE/AVI-...`
   * titre, résumé, premières recommandations
   * listes CVE parfois incomplètes (ou absentes dans le RSS)

2. **Mises à jour / enrichissements**

   * ajout de correctifs / versions corrigées
   * ajout d’un contexte d’exploitation (in the wild)
   * ajout de méthodes de détection / journaux à vérifier
   * ajout de liens externes (éditeur, CISA, KEV, etc.)

3. **Stabilisation**

   * bulletin “mature”
   * l’essentiel des informations est figé

4. **Obsolescence (implicite)**

   * bulletin reste consultable
   * mais la recommandation peut devenir “historique” (versions EOL / patch déployé)

---

## 5. Les indicateurs de mise à jour (équivalent CERT-FR de `lastModified`)

Contrairement à la NVD, CERT-FR ne fournit pas un champ standard `lastModified` dans le RSS.

### 5.1 Indices disponibles

#### A) Mention explicite de mise à jour dans le titre

Exemples fréquents :

* `[MàJ] Vulnérabilité ...`
* `Mise à jour du ...`

➡️ **Signal fort** qu’il faut re-synchroniser la publication.

#### B) Contenu HTML

Le bulletin contient souvent dans le texte :

* `Mise à jour du JJ mois AAAA`
* ajouts/sections (patch, IoC, exploitation)

➡️ Pour un pipeline sérieux, il faut parser le contenu HTML.

#### C) Horodatages techniques (HTTP)

En pratique, on peut exploiter :

* l’en-tête HTTP `Last-Modified` (si exposé)
* `ETag`

➡️ utile pour détecter un changement du contenu même si le titre ne change pas.

> ✅ Recommandation : stocker `etag` + `fetched_at` pour détection de drift.

---

## 6. Évolution des données CVE dans CERT-FR

### 6.1 Où sont les CVE ?

* Dans le **contenu HTML** du bulletin (souvent section dédiée)
* Parfois dans le **RSS `<description>`**

> ⚠️ Le RSS n’est pas une source exhaustive des CVE.

### 6.2 Changements possibles

Une mise à jour CERT-FR peut impacter :

* ajout de nouvelles CVE
* suppression d’une CVE (erreur / correction)
* changement de criticité / positionnement (alerte vs simple contexte)
* ajout de conditions d’exploitation

---

## 7. Champs “critiques” à capturer dans une base interne

### 7.1 Identité

* `certfr_id` (ex: `CERTFR-2026-ALE-001`)
* `type` : `ALE` ou `AVI`
* `url`
* `title`
* `published_date` (RSS `pubDate`)

### 7.2 Contenu

* `summary` (RSS `description`)
* `full_html` (optionnel mais recommandé — pour reproductibilité)
* `update_markers` (liste des dates “Mise à jour du ...”)

### 7.3 Vulnérabilités liées

* `cve_ids[]`
* `vendors[]` / `products[]` (si extractible)

### 7.4 Références

* `references[]` (liens éditeurs, CISA, bulletins, etc.)

### 7.5 Détection de changements

* `etag`
* `last_modified_header`
* `fetched_at`
* `content_hash` (SHA256 du HTML nettoyé)

---

## 8. Bonnes pratiques pour synchronisation (pipeline)

### 8.1 Import initial (historique)

Objectif : reconstruire un référentiel complet.

* crawler `/alerte/` + `/avis/` avec pagination
* extraire tous les `CERTFR-...`
* télécharger le HTML de chaque bulletin
* extraire les CVE (`CVE-\d{4}-\d+`)

✅ Bonnes pratiques :

* conserver le HTML brut
* normaliser dans un modèle interne
* dédupliquer les CVE

---

### 8.2 Synchronisation incrémentale (recommandée)

Objectif : ingestion continue des nouveautés.

* poll RSS (alerte + avis) toutes les X heures
* pour chaque item :

  * fetch bulletin HTML
  * re-hasher
  * comparer ETag/hash

✅ Stratégie :

* RSS = découverte
* HTML = vérité

---

### 8.3 Détection des changements critiques

Surveiller particulièrement :

* apparition du marqueur `[MàJ]`
* ajout d’un CVE critique dans un bulletin existant
* changement de recommandations (patch/mitigation)
* ajout de “exploitation active / massivement exploitée”

---

## 9. Résumé (à retenir)

* CERT-FR publie des **bulletins**, pas des CVE “records” comme la NVD
* Les flux RSS sont utiles mais **non exhaustifs** et **non historisés**
* Les bulletins peuvent évoluer : `[MàJ]` est un signal d’enrichissement
* Pour une base interne fiable :

  * RSS pour détecter
  * HTML pour extraire (CVE, recommandations)
  * ETag/hash pour resynchroniser
* Meilleure méthode :

  * import historique via crawl `/avis/` + `/alerte/`
  * incrémental via RSS + contrôle de changement
