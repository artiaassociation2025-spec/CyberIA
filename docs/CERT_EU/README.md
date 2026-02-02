# Documentation technique — CERT-EU (Advisories & Security Alerts)

## Objectif

Cette documentation a pour objectif de fournir une référence technique sur les flux de veille du **CERT-EU (Computer Emergency Response Team for the EU institutions)**. Elle vise à permettre aux équipes techniques, CTI et SOC de comprendre, collecter et exploiter les publications CERT-EU (advisories, security alerts, analyses) afin de **contextualiser la menace**, **prioriser la remédiation** et enrichir les processus de détection.

## Audience

* Analystes CTI (Cyber Threat Intelligence)
* Ingénieurs sécurité / SOC (veille opérationnelle, triage, détection)
* Data Engineers / Data Analysts (ingestion RSS/Atom, scraping, parsing HTML/PDF, normalisation)
* Développeurs d’outils internes (corrélation vulnérabilités, scoring, dashboards)
* Responsables sécurité (RSSI) pour la priorisation et la communication interne

## Portée

* Compréhension de la **typologie CERT-EU** (Advisory, Vulnerability Notes, Security Alerts, Threat Intelligence)
* Méthodes d’accès aux publications (portail web, flux RSS/Atom si disponibles)
* Structure des données (HTML, PDF, metadata)
* Corrélation avec **CVE / NVD**, CISA KEV et scoring (CVSS/EPSS) si applicable
* Bonnes pratiques d’ingestion (dédoublonnage, versioning, mises à jour)
* Exemples de normalisation vers un modèle interne (IOC, CVE, produits, vendors)

## Table des matières

1. [Introduction et contexte CERT-EU](./01-introduction.md)
2. [Typologie : Advisory / Vulnerability Note / Threat Intelligence](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail & Flux)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)
---
