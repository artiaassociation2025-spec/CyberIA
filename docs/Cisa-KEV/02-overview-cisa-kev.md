# 2. Présentation générale — CISA / KEV / CVE

## 2.1 CISA
La **CISA (Cybersecurity and Infrastructure Security Agency)** est une agence gouvernementale américaine en charge de la cybersécurité nationale et de la résilience des infrastructures critiques.

Dans ce contexte, la CISA maintient le **catalogue KEV** (*Known Exploited Vulnerabilities Catalog*), qui sert de référence opérationnelle pour identifier les vulnérabilités **activement exploitées**.

## 2.2 CVE
Une **CVE (Common Vulnerabilities and Exposures)** est une *identité unique* attribuée à une vulnérabilité logicielle ou matérielle.

Exemple : `CVE-2021-44228`

La CVE fournit principalement :
- un identifiant
- une description
- des références

> La CVE est un identifiant standard partagé entre la majorité des référentiels de vulnérabilités (NVD, KEV, avis éditeurs, scanners).

## 2.3 KEV
Le **KEV (Known Exploited Vulnerabilities Catalog)** est un catalogue public qui référence exclusivement des CVE :
- **confirmées comme exploitées dans la nature** (*exploited in the wild*)
- présentant un **risque immédiat et opérationnel**

### Mission principale
- Identifier les vulnérabilités à **prioriser en correction**
- Réduire le risque réel lié à l’**exploitation active**
- Fournir un référentiel “actionnable” pour le patch management et la cyberdéfense

### Données disponibles via KEV
- `cveID` : identifiant CVE
- `vendorProject` : éditeur / projet
- `product` : produit affecté
- `vulnerabilityName` : nom court
- `dateAdded` : date d’ajout au catalogue
- `shortDescription` : description synthétique
- `requiredAction` : action requise (souvent renvoi vers correctifs éditeur)
- `dueDate` : échéance recommandée/attendue de remédiation
- `knownRansomwareCampaignUse` : indicateur d’usage par ransomware (si applicable)
- `notes` : commentaires supplémentaires (optionnel)

> Phrase de synthèse : **NVD = toutes les CVE enrichies ; KEV = les CVE exploitées à corriger en priorité.**

## 2.4 Cas d’usage
- Priorisation patch / remédiation (top urgences)
- Pilotage des campagnes de correction (SLA, backlog)
- Réduction du risque immédiat (exploitation active)
- Threat Intelligence (corrélation exploitations observées ↔ SI)
- SOC / SIEM : focus sur les vulnérabilités exploitées
- Tableaux de bord risques : suivi des KEV non corrigées dans le SI