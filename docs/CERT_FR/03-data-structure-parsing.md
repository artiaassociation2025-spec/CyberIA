
# 3. Structure des données — CERT-FR (OpenAPI & modèle JSON)

## 3.1 Objectif de cette section

Cette section décrit la structure des données exploitable côté **CERT-FR (CERT-SSI / ANSSI)**, afin de permettre :

* l’ingestion automatisée via **OpenAPI JSON** (machine-readable),
* l’extraction des métadonnées (référence, dates, titre),
* la normalisation des objets structurants : **CVE, systèmes affectés, risques, révisions, solutions**,
* l’exploitation SOC/CTI (priorisation remédiation, corrélation vulnérabilités, reporting).

L’objectif est de comprendre **où se trouve chaque information** dans un objet JSON CERT-FR et comment la mapper vers un modèle interne.

---

## 3.2 Format général des données (OpenAPI)

CERT-FR expose un modèle JSON documenté via un schéma OpenAPI.

* **Schéma de référence** :

  * `$ref: https://www.cert.ssi.gouv.fr/openapi.json`

Dans une chaîne d’ingestion, l’approche recommandée est :

* collecter les items (AVI / ALE / ACT selon typologie)
* stocker le JSON brut
* normaliser vers un JSON pivot interne

✅ Avantage clé : les champs vulnérabilités (CVE) et affectations sont structurés (moins de parsing texte qu’un PDF).

---

## 3.3 Modèle de données (JSON CERT-FR) — champ par champ

> Exemple : objet représentant un **CERTFR-AVI** (Avis).

### 3.3.1 `$ref`

Référence vers la documentation OpenAPI.

* **Type** : string (URL)
* **Exemple** : `https://www.cert.ssi.gouv.fr/openapi.json`
* **Usage** :

  * validation schéma
  * versioning/détection d’évolution du format

---

### 3.3.2 `reference`

Identifiant unique de la publication CERT-FR.

* **Type** : string
* **Exemple** : `CERTFR-2026-AVI-0001`
* **Signification** : identifiant documentaire stable.
* **Usage** :

  * clé primaire technique
  * dédoublonnage
  * pivot de corrélation (SI interne, tickets, dashboards)

---

### 3.3.3 `title`

Titre de l’avis.

* **Type** : string
* **Exemple** : `Multiples vulnérabilités dans le noyau Linux de SUSE`
* **Usage** :

  * affichage
  * classification vendor/product
  * NLP topic extraction

---

### 3.3.4 `summary`

Résumé fonctionnel / impact.

* **Type** : string
* **Exemple** : "De multiples vulnérabilités ont été découvertes..."
* **Usage** :

  * snippet d’affichage
  * extraction rapide de signaux (DoS, RCE, priv esc, etc.)

---

### 3.3.5 `content`

Corps principal (souvent en Markdown).

* **Type** : string
* **Exemple** : section `## Solutions ...`
* **Usage** :

  * affichage
  * extraction recommandations (patch/mitigation)

⚠️ Point de vigilance : certains items peuvent intégrer des fragments HTML/Markdown.

---

### 3.3.6 `affected_systems[]`

Liste structurée des systèmes/produits affectés.

* **Type** : array(object)

Chaque élément contient :

#### `affected_systems[].description`

* **Type** : string
* **Exemple** : `SUSE Linux Enterprise Server 15 SP3`
* **Usage** :

  * affichage
  * matching CMDB

#### `affected_systems[].product`

Objet produit.

##### `affected_systems[].product.name`

* **Type** : string
* **Exemple** : `N/A`
* **Remarque** : la granularité produit peut être portée par `description`.

##### `affected_systems[].product.vendor`

###### `affected_systems[].product.vendor.name`

* **Type** : string
* **Exemple** : `SUSE`

###### `affected_systems[].product.vendor.scada`

Indique si le produit appartient au périmètre SCADA/ICS.

* **Type** : boolean
* **Exemple** : `false`
* **Usage** :

  * classification IT vs OT/ICS
  * routage priorisation (périmètre critique)

---

### 3.3.7 `affected_systems_content`

Champ texte additionnel sur les systèmes affectés.

* **Type** : string
* **Exemple** : `""` (vide)
* **Usage** : fallback si la liste structurée est insuffisante.

---

### 3.3.8 `cves[]`

Liste explicite des vulnérabilités CVE.

* **Type** : array(object)

#### `cves[].name`

* **Type** : string
* **Exemple** : `CVE-2025-40121`

#### `cves[].url`

* **Type** : string (URL)
* **Exemple** : `https://www.cve.org/CVERecord?id=CVE-2025-40121`

**Usage SOC/CTI :**

* corrélation NVD
* enrichissement CVSS/CWE
* corrélation CISA KEV
* EPSS scoring

✅ Bonnes pratiques :

* utiliser `cves[].name` comme source de vérité (pas regex)

---

### 3.3.9 `risks[]`

Impacts/risques exprimés sous forme textuelle.

* **Type** : array(object)

#### `risks[].description`

* **Type** : string
* **Exemples** :

  * `Atteinte à l'intégrité des données`
  * `Déni de service`

**Usage :**

* mapping vers une taxonomie interne (CIA triad, kill chain, etc.)
* priorisation (DoS vs RCE)

---

### 3.3.10 `vendor_advisories[]`

Références éditeur (bulletins).

* **Type** : array(object)

#### `vendor_advisories[].published_at`

* **Type** : string (date)
* **Exemple** : `2025-12-29`

#### `vendor_advisories[].title`

* **Type** : string
* **Exemple** : `Bulletin de sécurité SUSE SUSE-SU-2025:4530-1`

#### `vendor_advisories[].url`

* **Type** : string (URL)

**Usage :**

* retrouver patch notes officielles
* enrichir versions affectées/corrigées

---

### 3.3.11 `links[]`

Liste de liens additionnels.

* **Type** : array
* **Exemple** : `[]`
* **Usage** :

  * sources annexes (blogs, writeups, etc.)

---

### 3.3.12 `revisions[]`

Historique des versions du document.

* **Type** : array(object)

#### `revisions[].description`

* **Type** : string
* **Exemple** : `Version initiale`

#### `revisions[].revision_date`

* **Type** : string (datetime)
* **Exemple** : `2026-01-02T00:00:00.000000`

**Usage :**

* versioning
* identification updates

✅ Recommandation : normaliser en ISO-8601 UTC.

---

## 3.4 Mapping vers un modèle interne (recommandé)

Schéma pivot interne recommandé :

* `doc_id` : `reference`
* `doc_type` : dérivé du préfixe (AVI / ALE / ACT)
* `source` : `CERT-FR`
* `title` : `title`
* `published_at` : première `revisions[].revision_date`
* `updated_at` : dernière `revisions[].revision_date`
* `summary` : `summary`
* `content_md` : `content`
* `cve_list[]` : `cves[].name`
* `vendor` : `affected_systems[].product.vendor.name`
* `affected_products[]` : `affected_systems[].description`
* `risks[]` : `risks[].description`
* `references[]` : `vendor_advisories[].url` + `links[]`
* `raw_json` : JSON brut

✅ Corrélations possibles :

* CERT-FR ↔ CVE ↔ NVD
* CERT-FR ↔ KEV / EPSS
* CERT-FR ↔ actifs internes (CMDB)

---

## 3.5 Points de vigilance

* `affected_systems[].product.name` peut être `N/A` : le champ `description` porte souvent la granularité réelle.
* `risks[]` : taxonomie non normalisée (texte libre) → mapping interne conseillé.
* `revisions[]` : indispensable pour l’ingestion incrémentale.
* contenu `content` : exploitable pour extraction patch/mitigation mais non totalement structuré.

# EXEMPLE:

``` json
{
  "$ref": "https://www.cert.ssi.gouv.fr/openapi.json",
  "affected_systems": [
    {
      "description": "SUSE Manager Proxy 4.2",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise High Performance Computing LTSS 15 SP3",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Micro for Rancher 5.2",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Live Patching 15-SP3",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise High Availability Extension 15 SP3",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Server 15 SP3 Business Critical Linux",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Manager Retail Branch Server 4.2",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Server 15 SP3",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Micro 5.2",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Enterprise Storage 7.1",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Manager Server 4.2",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise High Performance Computing 15 SP3",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Server for SAP Applications 15 SP3",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Server 15 SP3 LTSS",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "SUSE Linux Enterprise Micro 5.1",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    },
    {
      "description": "openSUSE Leap 15.3",
      "product": {
        "name": "N/A",
        "vendor": {
          "name": "SUSE",
          "scada": false
        }
      }
    }
  ],
  "affected_systems_content": "",
  "content": "## Solutions\n\nSe référer au bulletin de sécurité de l'éditeur pour l'obtention des correctifs (cf. section Documentation).",
  "cves": [
    {
      "name": "CVE-2025-40121",
      "url": "https://www.cve.org/CVERecord?id=CVE-2025-40121"
    },
    {
      "name": "CVE-2025-40204",
      "url": "https://www.cve.org/CVERecord?id=CVE-2025-40204"
    },
    {
      "name": "CVE-2023-53659",
      "url": "https://www.cve.org/CVERecord?id=CVE-2023-53659"
    },
    {
      "name": "CVE-2022-50280",
      "url": "https://www.cve.org/CVERecord?id=CVE-2022-50280"
    },
    {
      "name": "CVE-2025-40040",
      "url": "https://www.cve.org/CVERecord?id=CVE-2025-40040"
    },
    {
      "name": "CVE-2023-53717",
      "url": "https://www.cve.org/CVERecord?id=CVE-2023-53717"
    },
    {
      "name": "CVE-2025-40154",
      "url": "https://www.cve.org/CVERecord?id=CVE-2025-40154"
    },
    {
      "name": "CVE-2023-53676",
      "url": "https://www.cve.org/CVERecord?id=CVE-2023-53676"
    }
  ],
  "links": [],
  "reference": "CERTFR-2026-AVI-0001",
  "revisions": [
    {
      "description": "Version initiale",
      "revision_date": "2026-01-02T00:00:00.000000"
    }
  ],
  "risks": [
    {
      "description": "Atteinte à l'intégrité des données"
    },
    {
      "description": "Déni de service"
    }
  ],
  "summary": "De multiples vulnérabilités ont été découvertes dans le noyau Linux de SUSE. Elles permettent à un attaquant de provoquer une atteinte à l'intégrité des données et un déni de service.",
  "title": "Multiples vulnérabilités dans le noyau Linux de SUSE",
  "vendor_advisories": [
    {
      "published_at": "2025-12-29",
      "title": "Bulletin de sécurité SUSE SUSE-SU-2025:4530-1",
      "url": "https://www.suse.com/support/update/announcement/2025/suse-su-20254530-1"
    }
  ]
}
```
