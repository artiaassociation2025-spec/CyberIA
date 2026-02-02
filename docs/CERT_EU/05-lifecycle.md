## Table des matières

1. [Introduction et contexte CERT-EU](./01-introduction.md)
2. [Typologie : Advisory / Vulnerability Note / Threat Intelligence](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail & Flux)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)
---


# Cycle de vie des publications CERT-EU

## 1. Objectif de cette section

Cette section décrit le **cycle de vie** des publications du CERT-EU, notamment :

* la fréquence et les mécanismes de mise à jour ;
* l’évolution d’un advisory / note / analyse dans le temps ;
* l’impact sur les **CVE**, les recommandations, les correctifs et les indicateurs d’exploitation ;
* les bonnes pratiques pour synchroniser et maintenir un **référentiel interne** à jour.

---

## 2. Comprendre le modèle CERT-EU

Contrairement à la NVD (enregistrements *CVE*) ou à KEV (liste priorisée), CERT-EU publie des **documents opérationnels** destinés aux environnements des institutions et agences de l’UE.

Les publications CERT-EU :

* peuvent regrouper plusieurs vulnérabilités,
* peuvent intégrer un contexte menace (campagne active),
* incluent souvent des recommandations techniques,
* sont susceptibles d’évoluer dans le temps (mises à jour / versions).

### 2.1 Types de publications (grandes familles)

Selon l’organisation du portail CERT-EU (susceptible d’évoluer), on retrouve typiquement :

* **Security Advisory**

  * focus vulnérabilités / patch / produits affectés
  * souvent associé à des CVE

* **Vulnerability Note / Security Warning**

  * publication courte, très orientée action
  * sert d’alerte rapide

* **Threat Intelligence / Threat Landscape**

  * analyses de menace (campagnes, tactiques, tendances)
  * davantage orienté TTP / acteurs / techniques

> 📌 Pour un “référentiel vulnérabilités”, l’essentiel est généralement **Security Advisories + Vulnerability Notes**.

---

## 3. Fréquence et mécanismes de mise à jour

CERT-EU est une source vivante : certaines publications peuvent être **mises à jour** après publication.

Un document peut évoluer suite à :

* publication de correctifs par l’éditeur
* changement de périmètre (versions réellement vulnérables)
* publication d’un PoC / exploitation confirmée
* apparition de preuves d’exploitation (*in the wild*)
* ajout de recommandations (hardening, détection, logs)
* enrichissement des références (vendor advisory, CVE, KEV, etc.)

### 3.1 Indicateurs de version

Dans les advisories CERT-EU, le contenu inclut souvent une section **History** (ex: `v1.0`, `Initial publication`).

✅ Cette information est critique pour le versioning.

---

## 4. Cycle de vie d’une publication CERT-EU

### 4.1 Étapes typiques

1. **Publication initiale**

   * création d’un document (ex. `2026-001`)
   * résumé + sections initiales
   * recommandations de base

2. **Mises à jour / enrichissements**

   * ajout de CVE manquantes
   * ajout d’éléments d’exploitation active
   * ajout de versions affectées / corrigées
   * ajout de guidance de détection
   * mise à jour de la section `History`

3. **Stabilisation**

   * recommandations consolidées
   * périmètre généralement stabilisé

4. **Obsolescence (implicite)**

   * advisory reste consultable et archivé
   * mais pertinence opérationnelle diminue (patch déployé / versions EOL)

---

## 5. Indicateurs de mise à jour (équivalent CERT-EU de `lastModified`)

CERT-EU peut ne pas exposer de champ unique standard type `lastModified` dans un flux.

### 5.1 Indices disponibles

#### A) Section `History` dans le contenu

Exemple typique :

* `30/01/2026 --- v1.0 -- Initial publication`

➡️ **Signal fort** : permet de tracer l’évolution.

#### B) Métadonnées front matter

Le `content_markdown` contient souvent :

* `version`
* `original_date`
* `date`

➡️ Exploitable pour construire une notion de :

* `created_at` vs `updated_at`.

#### C) Horodatages techniques (HTTP)

En ingestion, exploiter :

* header HTTP `Last-Modified` (si présent)
* `ETag`

✅ Recommandation : stocker `etag` + `fetched_at` pour détecter un changement silencieux.

#### D) Hash de contenu

Calculer :

* `content_hash` = SHA256 du texte normalisé

➡️ Permet d’identifier tout drift.

---

## 6. Évolution des données vulnérabilités (CVE)

### 6.1 Où sont les CVE ?

Souvent présentes dans les sections :

* `Technical Details`
* parfois `Summary`

Extraction recommandée : regex

* `CVE-\d{4}-\d+`

### 6.2 Changements possibles

Une mise à jour CERT-EU peut impacter :

* ajout de nouvelles CVE
* correction sur la criticité (ex. CVSS)
* clarification sur prérequis d’exploitation
* ajout d’IoC ou de recommandations de détection
* modification des versions affectées

---

## 7. Champs “critiques” à capturer dans une base interne

### 7.1 Identité

* `cert_eu_id` : `serial_number` (ex. `2026-001`)
* `doc_type` : dérivé du répertoire (`security-advisories`, etc.)
* `title`
* `url` (canonical)
* `source_file` (ex. `CERT-EU-SA2026-001.pdf`)

### 7.2 Contenu

* `summary` (`description`)
* `content_markdown` (source pivot)
* `content_html` (optionnel)
* `history[]` (versions/date)

### 7.3 Vulnérabilités liées

* `cve_ids[]`
* `vendors[]` / `products[]`
* `affected_versions[]`

### 7.4 Références

* `references[]` (liens éditeurs, blogs, etc.)

### 7.5 Détection de changements

* `etag`
* `last_modified_header`
* `fetched_at`
* `content_hash`

---

## 8. Bonnes pratiques pour synchronisation (pipeline)

### 8.1 Import initial (historique)

Objectif : reconstruire un référentiel complet.

* crawler les sections (ex. *Security Advisories*)
* lister les publications
* télécharger les PDF associés
* extraire texte → reconstruire `content_markdown`
* extraire CVE / produits / versions

✅ Bonnes pratiques :

* conserver le document brut (PDF)
* conserver le markdown reconstruit
* dédupliquer par `serial_number`

---

### 8.2 Synchronisation incrémentale (recommandée)

Objectif : ingestion continue.

* crawler index (daily / hourly selon criticité)
* pour chaque item :

  * fetch le document
  * comparer `etag` / `hash`
  * si changement → reprocess

✅ Stratégie :

* Index portail = découverte
* PDF/HTML = vérité
* JSON pivot = exploitation

---

### 8.3 Détection des changements critiques

Surveiller particulièrement :

* apparition d’un indicateur “exploited in the wild”
* ajout d’une CVE critique à un document existant
* ajout de versions affectées supplémentaires
* changement majeur des recommandations (patch/mitigation)

---

## 9. Résumé (à retenir)

* CERT-EU publie des **documents opérationnels**, pas des “CVE records” comme la NVD

* Les publications peuvent être mises à jour (History/version)

* Pour une base interne fiable :

  * portail = découverte
  * PDF/HTML/Markdown = extraction
  * ETag/hash = détection update

* Meilleure méthode :

  * import historique via crawl des sections
  * incrémental via crawl + contrôle de drift
