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

# 1. Introduction

## Contexte

La gestion des vulnérabilités repose sur la capacité à identifier, qualifier et prioriser rapidement les failles affectant les actifs d’un système d’information.

Le **CERT-EU** (Computer Emergency Response Team for the EU Institutions) publie des contenus de veille et d’alerte visant à soutenir les institutions, organes et agences de l’Union européenne dans la prévention et la réponse aux incidents de cybersécurité.

Les publications CERT-EU (Advisories, Vulnerability Notes, Security Warnings/Alerts, analyses de menace) permettent notamment de :

* signaler des **vulnérabilités critiques** affectant des produits et services largement utilisés au sein des environnements IT,
* partager des informations sur des **campagnes actives** (exploitation de vulnérabilités, intrusions, ransomware, supply chain),
* fournir des **mesures de mitigation** et des recommandations de détection/remédiation.

Ces contenus constituent une source opérationnelle complémentaire aux bases exhaustives (ex. **NVD**) : ils fournissent du **contexte sectoriel (institutions UE)**, une **mise en perspective de la menace**, et parfois des éléments actionnables (vecteurs d’attaque, IoC, TTP) permettant de renforcer le triage SOC et la priorisation patch.

## Objectifs

* Comprendre le rôle et la typologie des publications du **CERT-EU** (Advisories, Vulnerability Notes, Threat Intelligence)
* Décrire la structure et la nature des données disponibles (pages web, PDF/HTML, métadonnées)
* Documenter l’accès et l’utilisation des canaux officiels (portail, flux RSS/Atom lorsqu’ils existent)
* Présenter les bonnes pratiques d’exploitation (priorisation patch, corrélation avec actifs, enrichissement CVE)
* Identifier les limites et points de vigilance (couverture, disponibilité machine-readable, mises à jour)

## Livrable

Documentation technique (Markdown), exploitable de manière autonome.
