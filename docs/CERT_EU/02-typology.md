## Table des matières

1. [Introduction et contexte CERT-EU](./01-introduction.md)
2. [Typologie : Advisory / Vulnerability Note / Threat Intelligence](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail & Flux)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)
---


# 2. Présentation générale — CERT-EU / Institutions UE / Publications

## 2.1 CERT-EU

Le **CERT-EU (Computer Emergency Response Team for the EU Institutions)** est l’équipe de réponse aux incidents et de veille cyber dédiée aux **institutions, organes et agences de l’Union européenne**.

Dans ce contexte, CERT-EU joue un rôle de **coordination opérationnelle**, de diffusion d’alertes et de production de renseignement technique, en lien avec l’écosystème européen (CSIRTs nationaux, ENISA, partenaires internationaux).

## 2.2 Identifiants et typologie CERT-EU

Contrairement à une **CVE** qui identifie une faille unique, une publication CERT-EU correspond à un **document de synthèse** (souvent composite) pouvant regrouper :

* plusieurs vulnérabilités (multiples CVE),
* un produit ou un éditeur,
* un contexte de menace (exploitation active, campagne APT/ransomware),
* des recommandations défensives.

CERT-EU utilise des identifiants propres selon le format et le type de publication (ex. *Security Advisory*, *Threat Intelligence*, *Vulnerability Note*). L’identifiant sert de pivot documentaire pour le cycle de veille.

Le document fournit principalement :

* une description du risque / impact opérationnel,
* **les identifiants CVE associés** (si applicables),
* les produits affectés et conditions d’exploitation,
* des recommandations de remédiation et de mitigation,
* parfois des éléments actionnables (IoC, TTP, tactiques d’attaque).

## 2.3 Rôle du CERT-EU

Le **CERT-EU** ne vise pas l’exhaustivité (rôle de la NVD), mais la **qualification**, la **priorisation** et la **diffusion rapide** d’informations exploitables pour les environnements des institutions UE.

### Mission principale

* Filtrer le signal (se concentrer sur les sujets à impact réel et/ou urgent)
* Contextualiser la menace (campagnes en cours, exploitation active, vecteurs)
* Diffuser des recommandations opérationnelles (patch, mitigation, détection)
* Faciliter la coordination inter-entités (partage, alignement des réponses)

### Données qualifiées disponibles

* **Typologie de publication** : Advisory / Vulnerability Note / Threat Intelligence
* **Mapping CVE** : Lien vers les identifiants internationaux
* **Produits/versions affectés** : informations de portée technique
* **Mesures défensives** : recommandations de patch + contrôles compensatoires
* **Éléments de détection** : IoC, TTP, références MITRE ATT&CK (selon les cas)

> Phrase de synthèse : **NVD = Base exhaustive (Dictionnaire) ; CERT-EU = Veille qualifiée (Coordination/Action).**

## 2.4 Cas d’usage

* Veille opérationnelle quotidienne pour les équipes SOC/CSIRT
* Priorisation "fast-track" des correctifs sur exposition élevée
* Enrichissement CTI (liens campagne ↔ vulnérabilités ↔ techniques)
* Aide à la coordination et à la communication (messages synthétiques, guidance)
* Support conformité / gouvernance (suivi d’alertes et recommandations sectorielles)