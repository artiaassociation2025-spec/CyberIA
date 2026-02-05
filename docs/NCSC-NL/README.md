# Documentation technique — NCSC-NL (Vulnerabilities & Advisories / CSAF)

## Objectif

Cette documentation a pour objectif de fournir une référence technique sur les publications **vulnérabilités** et **avis de sécurité** du **NCSC-NL (National Cyber Security Centre Netherlands)**, afin de permettre aux équipes techniques et sécurité de **comprendre**, **exploiter** et **intégrer** efficacement ces données dans leurs processus de **priorisation correctifs**, **gestion des vulnérabilités**, **CTI** et **automatisation** (dashboards, SIEM, CMDB, outils de patching).

La documentation vise en particulier l’usage des formats **CSAF 2.0** (Common Security Advisory Framework) publiés/agrégés par NCSC-NL, incluant :

* la **modélisation produits** (product_tree / product_status)
* les **scores** (CVSS, EPSS, scoring NCSC)
* les **remediations** (vendor_fix, workaround, etc.) quand disponibles
* la gestion des **révisions** (tracking, interim/final)

## Audience

* Ingénieurs sécurité / SOC
* Équipes vulnérabilités / Patch management
* CTI / Threat Intel
* GRC / Risk management
* Data Engineers / Data Analysts (ingestion CSAF, pipelines, data lake)
* Développeurs intégrant les données dans des outils internes (SIEM, dashboards, CMDB)
* Développeurs IA / ML Engineers (priorisation automatisée, scoring interne, corrélation actif ↔ vuln exploitable)

## Portée

* Compréhension du rôle et fonctionnement des publications NCSC-NL
* Différence **Vulnerabilities** vs **Advisories**
* Structure des données **CSAF 2.0** (JSON) et champs clés
* Accès aux données (portails, endpoints, versioning, historique)
* Intégration dans des workflows de priorisation vulnérabilités / patching
* Bonnes pratiques (corrélation CMDB/CPE/CVE) + limites

## Table des matières

1. [Introduction](./01-introduction.md)
2. [Présentation générale (NCSC-NL / vulnérabilités / avis / CSAF)](./02-overview-ncsc-nl.md)
3. [Structure des données (CSAF 2.0 / JSON)](./03-data-structure.md)
4. [Accès aux données (portails, sources, endpoints)](./04-data-access.md)
5. [Cycle de vie des entrées (tracking, interim/final, revision_history)](./05-lifecycle.md)

---

## Notes de cadrage (à compléter dans les chapitres)

### Terminologie minimale

* **CVE** : identifiant de vulnérabilité.
* **NVD (NIST)** : base US d’enrichissement CVE (CVSS, CWE, etc.).
* **CSAF** : format JSON standard pour avis de sécurité machine-readable.
* **Remediation** : action recommandée (patch/upgrade, mitigation, workaround).
* **product_tree** : arborescence des produits / versions.
* **product_status** : mapping « known_affected / fixed / under_investigation / known_not_affected ».

### Règle pratique « solution ou non »

* Une entrée **contient une solution** si et seulement si `vulnerabilities[].remediations[]` est présent.
* `tracking.status = "interim"` indique un document **susceptible d’évoluer** (pas un indicateur fiable de présence/absence de correctif).

### Résultat attendu

À la fin, cette documentation doit permettre :

* d’ingérer automatiquement les CSAF NCSC-NL
* d’identifier les entrées **actionnables** (correctif/workaround)
* de relier CVE ↔ actifs (CPE/produits) ↔ priorité (CVSS/EPSS/NCSC Score)
* d’alimenter des tableaux de bord et des tickets patching
