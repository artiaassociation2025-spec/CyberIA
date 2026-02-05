# 2. Typologie — NCSC-NL / Publications / CSAF

## 2.1 Positionnement général du NCSC-NL

Le **NCSC-NL (National Cyber Security Centre Netherlands)** agit comme autorité nationale de cybersécurité pour les Pays-Bas. À ce titre, il assure un rôle de **collecte**, **corrélation**, **enrichissement** et **diffusion** d’informations de sécurité à destination :

* des administrations et organismes publics,
* des opérateurs de services essentiels et infrastructures critiques,
* des entreprises et partenaires concernés par la cybersécurité nationale.

Contrairement à des équipes comme CERT-EU, orientées coordination institutionnelle et renseignement de menace, le NCSC-NL se concentre principalement sur la **gestion opérationnelle des vulnérabilités**, avec un fort accent sur l’**automatisation** et l’**exploitation machine-readable** via le standard **CSAF 2.0**.

---

## 2.2 Logique documentaire NCSC-NL

Les publications NCSC-NL ne sont pas pensées comme des « bulletins éditoriaux », mais comme des **objets de données structurés**, destinés à être :

* ingérés automatiquement,
* corrélés à des inventaires techniques (CMDB, CPE, actifs),
* utilisés dans des chaînes de priorisation et de patch management.

Le **pivot documentaire** principal reste la **CVE**, mais enrichie par :

* des données produits détaillées,
* des scores complémentaires (EPSS, score NCSC),
* des informations de remédiation quand disponibles,
* des liens vers des sources de confiance (éditeurs, CERT partenaires).

---

## 2.3 Typologie des contenus NCSC-NL

### 2.3.1 Vulnerability (entrée vulnérabilité)

Il s’agit du **type de publication le plus courant**.

Une entrée « Vulnerability » correspond à une **CVE individuelle**, enrichie et normalisée par le NCSC-NL.

Caractéristiques principales :

* 1 CVE = 1 entrée CSAF
* Mapping détaillé des **produits et versions affectés** (`product_tree`, `product_status`)
* Intégration de scores :

  * CVSS (v3.1 et/ou v4)
  * EPSS
  * Score interne NCSC
* Agrégation de sources multiples (NVD, éditeur, autres CERT)

> Ces entrées peuvent être **purement informatives** ou **actionnables**, selon la disponibilité des remédiations.

---

### 2.3.2 Vulnerability avec remédiation

Sous-catégorie fonctionnelle des entrées « Vulnerability ».

Une vulnérabilité devient **actionnable** lorsque le document CSAF contient un bloc :

```json
"remediations": [ ... ]
```

Types de remédiations possibles :

* `vendor_fix` : correctif éditeur (patch, upgrade, firmware)
* `workaround` : contournement ou mesure de réduction de risque
* `mitigation` : mesure défensive complémentaire

Ces entrées constituent la **matière première du patch management automatisé**.

---

### 2.3.3 Advisory (avis de sécurité agrégé)

Dans certains cas, le NCSC-NL publie ou relaie des **avis de sécurité** plus larges, généralement issus :

* d’éditeurs (Vendor CSAF),
* d’autres CERT nationaux (ex. CERT-Bund),
* de coordinations multi-vulnérabilités.

Caractéristiques :

* Peut regrouper **plusieurs CVE**
* Porte sur un **produit, une gamme ou un éditeur**
* Contient presque toujours des **recommandations de remédiation**
* Sert de point d’entrée « macro » pour des campagnes de patch

---

### 2.3.4 Entrée intermédiaire (tracking / interim)

Certaines publications NCSC-NL sont diffusées avec le statut :

```json
"tracking": { "status": "interim" }
```

Cela indique que :

* l’information est **incomplète ou évolutive**,
* les produits affectés peuvent encore évoluer,
* les remédiations ne sont pas encore disponibles ou publiables.

> `interim` **n’est pas un type de publication**, mais un **état de maturité**.

---

## 2.4 Comparaison rapide des typologies

| Source  | Unité principale    | Objectif              | Actionnabilité     |
| ------- | ------------------- | --------------------- | ------------------ |
| NVD     | CVE                 | Exhaustivité          | Faible             |
| CERT-EU | Advisory            | Coordination / menace | Élevée (sélective) |
| NCSC-NL | CVE enrichie (CSAF) | Patch & priorisation  | Variable → élevée  |

> Phrase de synthèse : **CVE = Identité ; NVD = Enrichissement générique ; NCSC-NL = Enrichissement opérationnel.**

---

## 2.5 Cas d’usage principaux

* Priorisation automatisée des vulnérabilités
* Détection des CVE réellement **actionnables**
* Corrélation CVE ↔ produits ↔ actifs (CMDB)
* Alimentation des outils de patch management
* Construction de tableaux de bord risque / exposition
* Support SOC (connaissance du périmètre vulnérable)
