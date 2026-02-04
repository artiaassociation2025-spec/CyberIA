## Table des matières

1. [Introduction et contexte CERT-EU](./01-introduction.md)
2. [Typologie : Advisory / Vulnerability Note / Threat Intelligence](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail & Flux)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)
---


# 3. Structure des données — CERT-EU (publications & modèle JSON)

## 3.1 Objectif de cette section

Cette section décrit la structure des données exploitable côté CERT-EU, afin de permettre :

* l’ingestion des publications depuis les répertoires (ex. *security-advisories*),
* l’extraction des métadonnées (numéro, dates, titre),
* le parsing du contenu riche (Markdown/HTML),
* la normalisation vers un modèle interne (CVE, produits affectés, recommandations, liens).

L’objectif est de comprendre **où se trouve chaque information** dans un objet JSON agrégé : identifiant documentaire, dates, description, contenu complet, liens, licence.

---

## 3.2 Format général des données

Contrairement au CERT-FR qui fournit nativement un flux **RSS (XML)**, CERT-EU publie des documents principalement sous forme **HTML/PDF**, souvent structurés par sections (*Security Advisories*, *Threat Intelligence*, etc.).

Dans une chaîne d’ingestion, il est fréquent de construire une représentation normalisée en **JSON**, issue de :

* l’index de fichiers (liste de PDF/advisories),
* l’extraction OCR/texte,
* la conversion Markdown/HTML,
* l’enrichissement (CVE, références, scores, tags).

Ce JSON devient le format pivot :

* stockage (data lake / DB),
* indexation (OpenSearch/Elastic),
* exploitation SOC/CTI.

---

## 3.3 Modèle de données (JSON) — champ par champ

> Exemple : objet représentant un **CERT-EU Security Advisory**.

### 3.3.1 `file_item`

Objet décrivant la **source documentaire** (fichier).

#### `file_item.filepath`

* **Type** : string
* **Exemple** : `security-advisories`
* **Signification** : catégorie / répertoire logique de publication.
* **Usage** :

  * routage (pipeline différent selon catégorie),
  * filtrage (SA, TI, etc.),
  * partitionnement (stockage/data lake).

#### `file_item.filename`

* **Type** : string
* **Exemple** : `CERT-EU-SA2026-001.pdf`
* **Signification** : nom de fichier brut.
* **Usage** :

  * clé technique stable,
  * récupération / reprocessing,
  * traçabilité (provenance).

---

### 3.3.2 `title`

* **Type** : string
* **Exemple** : `Critical vulnerabilities in Ivanti EPMM`
* **Signification** : titre fonctionnel (lecture humaine).
* **Usage** :

  * affichage dashboard,
  * classification (vendor/product),
  * feature NLP (topic modelling, embeddings).

⚠️ **Point de vigilance** : le titre peut évoluer avec une republication/MAJ.

---

### 3.3.3 `serial_number`

* **Type** : string
* **Exemple** : `2026-001`
* **Signification** : numéro de publication.
* **Usage** :

  * identifiant documentaire (fonctionnel),
  * regroupement de versions (v1.0, v1.1, …),
  * pivot pour dédoublonner.

✅ Bonnes pratiques :

* utiliser `serial_number` comme **ID logique**,
* utiliser `file_item.filename` comme **ID technique**.

---

### 3.3.4 `publish_date`

* **Type** : string (datetime)
* **Exemple** : `30-01-2026 09:09:06`
* **Signification** : date/heure de publication (ou extraction).
* **Usage** :

  * ingestion incrémentale,
  * ordering,
  * détection de MAJ.

✅ Recommandation : normaliser en **ISO-8601** (`2026-01-30T09:09:06Z`) au moment de l’ingestion.

---

### 3.3.5 `description`

* **Type** : string
* **Exemple** : résumé avec `\u003Cbr\u003E` (HTML escaped)
* **Signification** : résumé court (souvent le *lead* du document).
* **Usage** :

  * preview / snippet,
  * classification rapide,
  * extraction initiale des signaux ("exploited", "RCE", vendor).

⚠️ **Point de vigilance** : peut contenir du HTML encodé (`<br>` échappé).

---

### 3.3.6 `url_title`

* **Type** : string
* **Exemple** : `2026-001`
* **Signification** : slug / segment utilisé dans l’URL publique.
* **Usage** : construction d’URL canonical (`base_url + url_title`).

---

### 3.3.7 `content_markdown`

* **Type** : string (Markdown)
* **Contenu** : le document complet (corps) converti.

On retrouve souvent :

* un **front matter YAML** (`---`),
* des sections structurées (`Summary`, `Technical Details`, `Affected Products`, `Recommendations`, `References`).

**Usage** :

* parsing structuré (regex/LLM)
* extraction de champs :

  * CVE (`CVE-YYYY-NNNN`),
  * scores (CVSS),
  * versions affectées,
  * recommandations.

✅ Bonnes pratiques :

* stocker le Markdown comme **source de vérité texte**,
* conserver la version brute pour reprocessing.

---

### 3.3.8 `content_html`

* **Type** : string (HTML)
* **Signification** : rendu HTML du contenu (ou extraction depuis la page).
* **Usage** :

  * affichage web,
  * extraction DOM (sélecteurs CSS),
  * conservation fidèle de la structure.

⚠️ **Point de vigilance** : HTML souvent échappé (ex. `\u003C` au lieu de `<`).

---

### 3.3.9 `licence`

Objet décrivant les conditions d’utilisation des données.

#### `licence.title`

* **Type** : string
* **Exemple** : `Creative Commons Attribution 4.0 International (CC-BY 4.0)`
* **Usage** : compliance / redistribution interne.

#### `licence.link`

* **Type** : URL
* **Exemple** : `https://creativecommons.org/licenses/by/4.0/`

#### `licence.restrictions`

* **Type** : URL
* **Exemple** : `https://cert.europa.eu/legal-notice`
* **Usage** : contraintes légales additionnelles (mention, limitations).

#### `licence.author`

* **Type** : string
* **Exemple** : `The Cybersecurity Service for the Union institutions, bodies, offices and agencies`
* **Usage** : attribution.

---

## 3.4 Mapping vers un modèle interne (recommandé)

Pour l’exploitation CTI/SOC, il est recommandé de normaliser les champs ci-dessus vers un schéma interne :

* `doc_id` : `serial_number` (ex. `2026-001`)
* `doc_type` : dérivé de `file_item.filepath` (ex. `security-advisory`)
* `source` : `CERT-EU`
* `source_file` : `file_item.filename`
* `published_at` : parsing `publish_date`
* `summary` : `description`
* `content_md` : `content_markdown`
* `content_html` : `content_html`
* `cve_list[]` : extraction dans contenu (`CVE-...`)
* `vendor/product` : extraction NLP (ex. Ivanti / EPMM)
* `recommendations` : extraction section `Recommendations`
* `references[]` : extraction section `References`
* `licence` : objet conservé tel quel

✅ Cela permet ensuite de corréler automatiquement :

* CERT-EU ↔ CVE ↔ NVD
* CERT-EU ↔ KEV / EPSS
* CERT-EU ↔ Assets internes (CMDB)

# EXEMPLE:
``` json
{
  "file_item": {
    "filepath": "security-advisories",
    "filename": "CERT-EU-SA2026-001.pdf"
  },
  "title": "Critical vulnerabilities in Ivanti EPMM",
  "serial_number": "2026-001",
  "publish_date": "30-01-2026 09:09:06",
  "description": "On 29 January 2026, Ivanti released a security advisory addressing two critical vulnerabilities in their EPMM products. An attacker could exploit those flaws to achieve unauthenticated remote code execution on the vulnerable device. One of these vulnerabilities have been exploited in a limited number of cases.<br>\n",
  "url_title": "2026-001",
  "content_markdown": "---    \ntitle: 'Critical vulnerabilities in Ivanti EPMM'\nnumber: '2026-001'\nversion: '1.0'\noriginal_date: '2026-01-29'\ndate: '2026-01-30'\n---\n\n_History:_\n\n* _30/01/2026 --- v1.0 -- Initial publication_\n\n# Summary\n\nOn 29 January 2026, Ivanti released a security advisory addressing two critical vulnerabilities in their EPMM products. An attacker could exploit those flaws to achieve unauthenticated remote code execution on the vulnerable device. One of these vulnerabilities have been exploited in a limited number of cases [1].\n\n# Technical Details\n\nThe vulnerability **CVE-2026-1281**, with a CVSS score of 9.8, is a code injection vulnerability in Ivanti Endpoint Manager Mobile.\n\nThe vulnerability **CVE-2026-1340**, with a CVSS score of 9.8, is a code injection vulnerability in Ivanti Endpoint Manager Mobile.\n\n# Affected Products\n\nThe following versions of Ivanti's Endpoint Manager Mobile (EPMM) are affected:\n\n- 12.5.1.0 and prior.\n- 12.6.1.0 and prior.\n- 12.7.0.0 and prior.\n\n# Recommendations\n\nCERT-EU recommends securing forensic evidence to detect any signs of exploitation. CERT-EU also recommends following the vendor's guidance to apply the hotfix (i.e. RPM 12.x.0 or RPM 12.x.1) on vulnerable appliances. As noted by the vendor, the applied RPM script will not survive a version upgrade which means that the script will need to be reapplied after an upgrade to a new version. The permanent fix for this vulnerability will be included in the release 12.8.0.0 which is planned for Q1 2026.\n\n\n# References\n\n[1] <https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-CVE-2026-1281-CVE-2026-1340?language=en_US>",
  "content_html": "<p><em>History:</em></p><ul><li><em>30/01/2026 --- v1.0 -- Initial publication</em></li></ul><h2 id=\"summary\">Summary</h2><p>On 29 January 2026, Ivanti released a security advisory addressing two critical vulnerabilities in their EPMM products. An attacker could exploit those flaws to achieve unauthenticated remote code execution on the vulnerable device. One of these vulnerabilities have been exploited in a limited number of cases [1].</p><h2 id=\"technical-details\">Technical Details</h2><p>The vulnerability <strong>CVE-2026-1281</strong>, with a CVSS score of 9.8, is a code injection vulnerability in Ivanti Endpoint Manager Mobile.</p><p>The vulnerability <strong>CVE-2026-1340</strong>, with a CVSS score of 9.8, is a code injection vulnerability in Ivanti Endpoint Manager Mobile.</p><h2 id=\"affected-products\">Affected Products</h2><p>The following versions of Ivanti's Endpoint Manager Mobile (EPMM) are affected:</p><ul><li>12.5.1.0 and prior.</li><li>12.6.1.0 and prior.</li><li>12.7.0.0 and prior.</li></ul><h2 id=\"recommendations\">Recommendations</h2><p>CERT-EU recommends securing forensic evidence to detect any signs of exploitation. CERT-EU also recommends following the vendor's guidance to apply the hotfix (i.e. RPM 12.x.0 or RPM 12.x.1) on vulnerable appliances. As noted by the vendor, the applied RPM script will not survive a version upgrade which means that the script will need to be reapplied after an upgrade to a new version. The permanent fix for this vulnerability will be included in the release 12.8.0.0 which is planned for Q1 2026.</p><h2 id=\"references\">References</h2><p>[1] <a rel=\"noopener\" target=\"_blank\" href=\"https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-CVE-2026-1281-CVE-2026-1340?language=en_US\">https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-CVE-2026-1281-CVE-2026-1340?language=en_US</a></p>",
  "licence": {
    "title": "Creative Commons Attribution 4.0 International (CC-BY 4.0)",
    "link": "https://creativecommons.org/licenses/by/4.0/",
    "restrictions": "https://cert.europa.eu/legal-notice",
    "author": "The Cybersecurity Service for the Union institutions, bodies, offices and agencies"
  }
}
```