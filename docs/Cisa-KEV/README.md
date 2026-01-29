# Documentation technique — CISA KEV (Known Exploited Vulnerabilities)

## Objectif
Cette documentation a pour objectif de fournir une référence technique sur le **catalogue KEV (Known Exploited Vulnerabilities Catalog)** maintenu par la **CISA**, afin de permettre aux équipes techniques et sécurité de comprendre, exploiter et intégrer efficacement les données du catalogue dans leurs processus de **priorisation correctifs**, **gestion des vulnérabilités**, **CTI** et **automatisation** (dashboards, SIEM, CMDB, outils de patching).

## Audience
- Ingénieurs sécurité / SOC
- Équipes vulnérabilités / Patch management
- GRC / Risk management
- Data Engineers / Data Analysts (intégration du feed KEV, pipelines, data lake)
- Développeurs intégrant les données dans des outils internes (SIEM, dashboards, CMDB)
- Développeurs IA / ML Engineers (priorisation automatisée, scoring interne, corrélation actif ↔ vuln exploitable)

## Portée
- Compréhension du rôle et fonctionnement du catalogue KEV
- Structure des données (CSV / JSON)
- Exploitation de la source officielle (download, MAJ, versioning)
- Intégration dans des workflows de priorisation vulnérabilités / patching
- Bonnes pratiques (corrélation CMDB/CPE/CVE) + limites

## Table des matières
1. [Introduction](./01-introduction.md)  
2. [Présentation générale (CISA / KEV / Exploitation “in the wild”)](./02-overview-cisa-kev.md)  
3. [Structure des données (CSV / JSON)](./03-data-structure.md)  
4. [Data Model “kev entry”](./04-data-model-kev.md)  
5. [Accès aux données (feeds, sources, endpoints)](./05-data-access.md)  
6. [Cycle de vie des entrées KEV](./06-lifecycle.md)  
7. [Bonnes pratiques + limites](./07-best-practices-and-limitations.md)
