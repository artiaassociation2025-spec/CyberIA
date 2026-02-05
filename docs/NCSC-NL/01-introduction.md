# 1. Introduction

## Contexte

La gestion des vulnérabilités repose sur la capacité à **identifier**, **qualifier** et **prioriser** rapidement les failles affectant les actifs d’un système d’information, en tenant compte non seulement de leur sévérité théorique, mais aussi de leur **actionnabilité réelle** (correctifs disponibles, contournements, maturité des informations).

Le **NCSC-NL (National Cyber Security Centre Netherlands)** publie et agrège des informations de vulnérabilités et des avis de sécurité destinés aux acteurs publics et privés néerlandais, mais également exploitables à l’échelle internationale. Ces publications s’appuient largement sur le standard **CSAF 2.0 (Common Security Advisory Framework)**, permettant une consommation **machine-readable** et une intégration directe dans des outils de sécurité.

Contrairement à des bases exhaustives comme la **NVD (NIST)**, dont l’objectif principal est l’enrichissement générique des **CVE** (descriptions, scores CVSS, CWE), les données diffusées par le NCSC-NL visent une **exploitation opérationnelle** :

* identification précise des **produits et versions affectés**,
* mise à disposition de **correctifs éditeur** ou de **mesures de mitigation** lorsque disponibles,
* consolidation de sources multiples (éditeurs, CERT partenaires, autres autorités nationales),
* ajout d’un **scoring NCSC** et d’indicateurs complémentaires (EPSS, maturité de l’information).

Les publications NCSC-NL constituent ainsi une **couche d’enrichissement et de priorisation**, complémentaire aux référentiels CVE/NVD, particulièrement adaptée aux besoins des équipes SOC, vulnérabilités et patch management.

## Objectifs

Cette documentation a pour objectifs de :

* Comprendre le rôle et le positionnement du **NCSC-NL** dans l’écosystème CVE / CERT / éditeurs
* Décrire les types de contenus publiés (vulnerabilities, advisories) et leur logique de diffusion
* Présenter les formats et structures de données disponibles, en particulier **CSAF 2.0 (JSON)**
* Documenter l’accès aux sources officielles (portails, endpoints, fichiers, mises à jour)
* Expliquer comment identifier les informations **actionnables** (correctifs, workarounds)
* Fournir des clés de lecture pour l’intégration dans des workflows de :

  * priorisation des correctifs,
  * gestion des vulnérabilités,
  * CTI et corrélation avec l’exploitation réelle,
  * automatisation (dashboards, SIEM, CMDB, outils de patching)
* Mettre en évidence les limites et points de vigilance (couverture, statut interim/final, dépendance aux sources éditeurs)

## Livrable

Documentation technique au format **Markdown**, exploitable de manière autonome, destinée à servir de **référence opérationnelle** pour l’intégration et l’utilisation des données NCSC-NL dans des environnements de production (SOC, plateformes de gestion des vulnérabilités, data platforms).
