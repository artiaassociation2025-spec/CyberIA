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
1. [Introduction](./01-introduction.md)
2. [Présentation générale (NVD / NIST / CVE)](./02-overview-nvd-nist-cve.md)
3. [Structure des données JSON](./03-data-structure-json.md)
4. [CVSS (v2, v3.x, v4.0)](./04-cvss.md)
5. [CWE](./05-cwe.md)
6. [CPE](./06-cpe.md)
7. [API NVD](./07-nvd-api.md)
8. [Cycle de vie des vulnérabilités](./08-lifecycle.md)
9. [Bonnes pratiques](./09-best-practices.md)
10. [Limites et points de vigilance](./10-limitations.md)
11. [Annexes](./99-annexes.md)
12. [Sources](./sources.md)
