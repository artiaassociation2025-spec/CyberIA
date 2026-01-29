# 1. Introduction

## Contexte
La gestion des vulnérabilités repose sur la capacité à identifier, qualifier et prioriser rapidement les failles affectant les actifs d’un système d’information.

Le **catalogue KEV (Known Exploited Vulnerabilities Catalog)**, maintenu par la **CISA**, fournit une liste ciblée de vulnérabilités publiques (**CVE**) dont l’exploitation a été **confirmée “in the wild”**. Il constitue une source opérationnelle permettant de concentrer les efforts de remédiation sur les vulnérabilités les plus critiques du point de vue de la menace réelle.

Contrairement à des bases exhaustives comme la NVD, KEV vise principalement la **priorisation** et la **réduction du risque immédiat**, en s’appuyant sur des signaux d’exploitation active observés.

## Objectifs
- Comprendre le rôle et le fonctionnement du catalogue CISA KEV
- Décrire la structure des données KEV (CSV / JSON)
- Documenter l’accès et l’utilisation des feeds officiels (téléchargement, mises à jour)
- Présenter les bonnes pratiques d’exploitation (priorisation patch, corrélation avec actifs)
- Identifier les limites et points de vigilance liés au catalogue KEV

## Livrable
Documentation technique (Markdown), exploitable de manière autonome.
