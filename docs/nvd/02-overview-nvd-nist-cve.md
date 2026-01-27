# 2. Présentation générale — NVD / NIST / CVE

## 2.1 NIST
Le **NIST (National Institute of Standards and Technology)** est un organisme gouvernemental américain produisant des standards, recommandations et ressources de cybersécurité.

Dans ce contexte, le NIST maintient la **NVD**.

## 2.2 CVE
Une **CVE (Common Vulnerabilities and Exposures)** est une *identité unique* attribuée à une vulnérabilité logicielle ou matérielle.

Exemple : `CVE-1999-1500`

La CVE fournit principalement :
- un identifiant
- une description
- des références

## 2.3 NVD
La **NVD (National Vulnerability Database)** est une base publique qui **enrichit** les CVE pour permettre leur exploitation opérationnelle.

### Mission principale
- Centraliser l’accès aux vulnérabilités
- Fournir des données techniques et normalisées
- Faciliter la priorisation et l’intégration en outillage

### Données enrichies disponibles via NVD
- Scores **CVSS** (v2, v3.x, v4.0 selon disponibilité)
- **CWE** (type de faiblesse)
- **CPE** (produits / versions affectés)
- Métadonnées : dates, status, références

> Phrase de synthèse : **MITRE = CVE (identité / catalogue) ; NIST = NVD (enrichissement / exploitation).**

## 2.4 Cas d’usage
- Veille sécurité (nouveaux CVE + changements)
- Gestion des vulnérabilités (priorisation / patching)
- Corrélation CVE ↔ assets (inventaire)
- SOC / SIEM : détection des vulnérabilités critiques exposées
- Tableaux de bord risques / posture sécurité
