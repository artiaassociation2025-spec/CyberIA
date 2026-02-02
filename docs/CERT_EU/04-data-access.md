## Table des matières

1. [Introduction et contexte CERT-EU](./01-introduction.md)
2. [Typologie : Advisory / Vulnerability Note / Threat Intelligence](./02-typology.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (Portail & Flux)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)
---


# 4. Accès aux données (CERT-EU)

## 4.1 Vue d’ensemble

L’accès aux publications du **CERT-EU** se fait principalement via le **portail web officiel** et des répertoires thématiques (ex. *Security Advisories*).

Contrairement au CERT-FR (RSS natif), CERT-EU ne garantit pas nécessairement un flux RSS unique et stable pour tous les types de publications : l’ingestion se fait souvent via :

* navigation portail (pages HTML),
* téléchargement de documents (**PDF**),
* extraction/normalisation interne (construction JSON pivot),
* éventuellement flux RSS/Atom s’ils sont disponibles sur certaines sections.

L’objectif opérationnel est donc de disposer de mécanismes d’accès automatisables pour :

* détecter les nouvelles publications,
* récupérer les documents source,
* historiser et dédoublonner,
* alimenter les pipelines CTI/SOC.

---

## 4.2 Points d’entrée officiels (Portail / Sections)

Voici les points d’entrée à configurer dans vos outils de collecte (Ingestion / ETL) :

| Type de contenu                            | Point d’accès                                 | Description et usage                                                                                                                                                           |
| :----------------------------------------- | :-------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Portail CERT-EU**                        | `https://cert.europa.eu/`                     | **Contenu :** point central d’accès aux publications, informations et ressources CERT-EU. <br>**Usage :** point de départ pour crawler/recenser toutes les catégories.         |
| **Security Advisories**                    | Section *Security Advisories*                 | **Contenu :** advisories techniques, souvent associées à des CVE, versions impactées et recommandations. <br>**Usage :** ingestion vulnérabilités / patch management priorisé. |
| **Threat Intelligence / Threat Landscape** | Section *Threat Intelligence*                 | **Contenu :** analyses de menace (campagnes, acteurs, tendances). <br>**Usage :** enrichissement CTI, contextualisation SOC, mapping MITRE ATT&CK.                             |
| **Vulnerability / Security Warnings**      | Sections dédiées (selon structure du portail) | **Contenu :** alertes / warnings rapides à portée opérationnelle. <br>**Usage :** surveillance haute fréquence / triggers incident response.                                   |

⚠️ **Note** : la segmentation exacte des sections peut évoluer (refonte du site, nouvelles catégories). Il est recommandé de baser l’ingestion sur :

* une liste de chemins contrôlée (allowlist),
* une logique de découverte (crawler avec règles),
* une détection de changements.

---

## 4.3 Méthodes d’accès recommandées

### 4.3.1 Collecte par HTTP GET (HTML)

* **Approche** : requêtes HTTP vers les pages d’index, puis extraction des liens.
* **Avantages** : simple, robuste, pas dépendant d’un flux RSS.
* **Limites** : parsing HTML fragile si structure change.

✅ Bonnes pratiques :

* parser par sélecteurs DOM (CSS/XPath) plutôt que regex,
* conserver une copie brute des pages index (audit/debug),
* mettre des garde-fous (timeouts, retries, user-agent explicite).

---

### 4.3.2 Téléchargement des PDF

* **Approche** : récupérer les PDF listés (ex: `CERT-EU-SA2026-001.pdf`).
* **Avantages** : source primaire stable et archivable.
* **Limites** : parsing plus complexe (OCR, extraction texte).

✅ Bonnes pratiques :

* checksum (SHA256) pour détecter les modifications,
* stockage versionné (par date d’acquisition),
* extraction texte + reconstruction `content_markdown`.

---

### 4.3.3 Construction d’un feed interne (JSON pivot)

Le format recommandé côté data pipeline est de produire un objet **JSON normalisé** (voir section 3), regroupant :

* métadonnées (titre, numéro, dates),
* contenu Markdown + HTML,
* liens et références,
* licence.

Ce JSON est ensuite :

* indexé (OpenSearch),
* joint à des sources vulnérabilités (NVD/EPSS/KEV),
* corrélé aux actifs internes.

---

## 4.4 Note technique (ingestion incrémentale)

En absence de pagination standardisée type RSS :

* construire un **state store** : dernier `serial_number` ou dernière date traitée,
* dédoublonner par **(serial_number + version)** ou par hash contenu,
* conserver l’historique des versions (v1.0 → v1.1 etc.),
* déclencher une alerte si un document déjà vu change (update silencieux).

✅ Objectif SOC/CTI : garantir la traçabilité et éviter les “missed updates”.
