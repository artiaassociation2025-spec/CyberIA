# 1. Introduction

## Contexte

La gestion des vulnérabilités repose sur la capacité à identifier, qualifier et prioriser rapidement les failles affectant les actifs d’un système d’information.

Le **CERT-FR** (opéré par l’**ANSSI**) publie régulièrement des contenus de veille et d’alerte (Avis, Alertes, Bulletins) permettant d’identifier :

* des **vulnérabilités critiques** affectant des produits largement déployés,
* des **campagnes d’exploitation actives** observées en France ou à l’international,
* des **recommandations de remédiation** applicables rapidement.

Ces publications constituent une source de renseignement opérationnel complémentaire à des bases exhaustives (ex. **NVD**) : elles apportent un **contexte national et institutionnel**, des **détails techniques**, et parfois des **indicateurs d’exploitation** (IoC, TTP), permettant de prioriser les actions de défense et de patch management.

## Objectifs

* Comprendre le rôle et le fonctionnement des publications du **CERT-FR** (Avis, Alertes, Bulletins)
* Décrire les formats et structures de données disponibles (**RSS**, **CSAF 2.0**, pages HTML)
* Documenter l’accès et l’utilisation des flux officiels (collecte, parsing, mises à jour)
* Présenter les bonnes pratiques d’exploitation (priorisation patch, corrélation avec actifs)
* Identifier les limites et points de vigilance (versioning, enrichissement, couverture)

## Livrable

Documentation technique (Markdown), exploitable de manière autonome.
