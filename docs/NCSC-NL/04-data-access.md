# 4. Accès aux données — NCSC-NL (Vulnerabilities & CSAF)

## 4.1 Vue d’ensemble

L’accès aux données du **NCSC-NL (National Cyber Security Centre Netherlands)** est conçu dès l’origine pour une **consommation automatisée**, contrairement à de nombreux CERT reposant sur des documents éditoriaux.

Le NCSC-NL met à disposition :

* un **catalogue web** permettant la recherche et le filtrage temporel des vulnérabilités,
* un **répertoire CSAF public**, structuré par années, contenant les fichiers JSON machine-readable,
* des métadonnées riches facilitant l’ingestion, le versioning et la corrélation.

Cette architecture permet une intégration directe dans des pipelines **ETL / vuln management / CTI**, sans phase lourde de parsing HTML ou PDF.

---

## 4.2 Points d’entrée officiels

### 4.2.1 Catalogue des vulnérabilités (interface web)

**URL** : [https://vulnerabilities.ncsc.nl/](https://vulnerabilities.ncsc.nl/)

**Description** :

* Interface web de consultation des vulnérabilités suivies par le NCSC-NL
* Recherche par :

  * date de publication / mise à jour
  * identifiant CVE
  * produit / éditeur
  * score / sévérité

**Usage recommandé** :

* validation manuelle
* analyse ponctuelle
* exploration et investigation

⚠️ **Limite** :

> Le catalogue web n’est pas la source primaire pour l’ingestion automatisée à grande échelle.

---

### 4.2.2 Répertoire CSAF public (source primaire)

**URL racine** : [https://vulnerabilities.ncsc.nl/csaf/](https://vulnerabilities.ncsc.nl/csaf/)

Ce répertoire expose directement les **fichiers CSAF 2.0 (JSON)** publiés ou agrégés par le NCSC-NL.

#### Organisation des dossiers

```text
/csaf/
├── 2023/
├── 2024/
├── 2025/
├── 2026/
└── ...
```

Chaque dossier annuel contient l’ensemble des documents CSAF correspondant aux CVE publiées ou mises à jour sur l’année.

**Caractéristiques** :

* accès direct par HTTP GET
* pas d’authentification
* format stable
* fichiers versionnés via le champ `document.tracking`

---

## 4.3 Structure des fichiers CSAF

* **Un fichier = un document CSAF** (généralement 1 CVE)
* Format : JSON conforme CSAF 2.0
* Nom de fichier : non garanti comme identifiant unique → **toujours utiliser `document.tracking.id`**

Champs essentiels pour l’ingestion :

* `document.tracking.id`
* `document.tracking.version`
* `document.tracking.current_release_date`
* `document.tracking.status`

---

## 4.4 Méthodes d’accès recommandées

### 4.4.1 Collecte incrémentale par année

**Approche** :

* parcourir les dossiers `/csaf/YYYY/`
* lister l’ensemble des fichiers
* ingérer les nouveaux documents ou nouvelles versions

**Avantages** :

* simple
* robuste
* pas de dépendance à une API instable

---

### 4.4.2 Détection des mises à jour (versioning CSAF)

Le NCSC-NL ne supprime généralement pas les fichiers, mais **met à jour leur contenu**.

La détection d’un changement doit se faire via :

* `document.tracking.version`
* `document.tracking.current_release_date`
* éventuellement un hash du fichier JSON

⚠️ **Important** :

> Un même CVE peut être mis à jour plusieurs fois (scores, produits, remédiations).

---

### 4.4.3 Construction d’un index interne

Le format recommandé côté plateforme est de produire un **objet pivot interne**, par exemple :

```json
{
  "source": "NCSC-NL",
  "doc_id": "CVE-2026-0421",
  "doc_version": 8,
  "doc_status": "interim",
  "published_at": "2026-01-16T12:05:42Z",
  "cve": "CVE-2026-0421",
  "has_explicit_remediation": false,
  "has_implicit_fix": false,
  "references": [ ... ]
}
```

---

## 4.5 Bonnes pratiques d’ingestion

### Recommandations clés

* Toujours considérer **CSAF comme source de vérité**, pas le HTML
* Conserver une **copie brute** des JSON (audit / reprocessing)
* Dédoublonner par `(tracking.id + tracking.version)`
* Ne jamais supposer qu’un document `final` est figé

---

## 4.6 Fréquence de mise à jour

* Publications **quasi quotidiennes**
* Enrichissements progressifs (nouveaux produits, scores, remédiations)
* Latence variable entre publication CVE et disponibilité d’une solution

Pipeline recommandé :

* collecte quotidienne (ou plus)
* recalcul de l’actionnabilité à chaque mise à jour

---

## 4.7 Résumé opérationnel

* **Catalogue web** : exploration humaine
* **Répertoire CSAF** : ingestion automatisée
* **Versioning CSAF** : mécanisme clé de détection des changements
* **Pas d’API nécessaire** : HTTP + JSON suffisent

> Phrase de synthèse :
>
> **NCSC-NL fournit un accès CSAF nativement exploitable, pensé pour l’automatisation à grande échelle.**
