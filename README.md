# Documentation technique — NVD (NIST)

## Objectif
Cette documentation a pour objectif de fournir une référence technique sur la **NVD (National Vulnerability Database)** maintenue par le **NIST**, afin de permettre aux équipes techniques et sécurité de comprendre, exploiter et intégrer efficacement les données liées aux vulnérabilités (**CVE, CVSS, CWE, CPE**) dans leurs outils et processus.

## Audience
- Ingénieurs sécurité / SOC
- Équipes vulnérabilités / GRC
- Data Engineers / Data Analysts (intégration et exploitation des feeds NVD, pipelines, data lake)
- Développeurs intégrant les données dans des outils internes (SIEM, dashboards, CMDB)
- Développeurs IA / ML Engineers (enrichissement, scoring interne, classification, priorisation automatisée)

## Portée
- Compréhension du rôle et fonctionnement de la NVD
- Structure des données (JSON / modèle CVE)
- Exploitation de l’API NVD (endpoints, filtres, pagination, API Key)
- Bonnes pratiques de synchronisation et d’intégration
- Limites et points de vigilance

## Table des matières
1. [Introduction](./docs/01-introduction.md)
2. [Présentation générale (NVD / NIST / CVE)](./docs/02-overview-nvd-nist-cve.md)
3. [Structure des données JSON](./docs/03-data-structure-json.md)
4. [Data Model vulnerability](./docs/04-data-model-vuln.md)
5. [API NVD](./docs/05-nvd-api.md)
6. [lifeCyle](./docs/06-lifecycle.md)
7. [Les bonnes pratiques et les limites](./docs/07-best-practices-and-limitations.md)

