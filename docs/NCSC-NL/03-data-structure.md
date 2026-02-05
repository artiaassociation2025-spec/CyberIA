# 3. Structure des données — NCSC-NL (CSAF 2.0)

Cette section décrit la **structure réelle des fichiers JSON** publiés par le **NCSC-NL**, basés sur le standard **CSAF 2.0**, ainsi que les **bonnes pratiques d’interprétation opérationnelle** issues des cas observés.

L’objectif n’est pas de décrire le standard CSAF de manière théorique, mais de documenter **comment NCSC-NL l’utilise concrètement**, avec ses forces, limites et particularités.

---

## 3.1 Vue d’ensemble

Un fichier CSAF NCSC-NL est structuré autour de quatre blocs principaux :

```text
root
├── document
├── product_tree
├── vulnerabilities
└── (optionnel) signatures / extensions
```

Chaque fichier correspond généralement à **un CVE unique**, enrichi à partir de multiples sources (NVD, éditeur, autres CERT, EPSS, etc.).

---

## 3.2 Bloc `document`

Le bloc `document` décrit le **contexte éditorial** du CSAF : métadonnées, responsabilité, cycle de vie et statut.

### Champs clés

| Champ              | Description                            | Usage opérationnel      |
| ------------------ | -------------------------------------- | ----------------------- |
| `category`         | Type de document (souvent `csaf_base`) | Classification CSAF     |
| `csaf_version`     | Version du standard (2.0)              | Validation schéma       |
| `distribution.tlp` | Marquage TLP (souvent WHITE)           | Partage / diffusion     |
| `lang`             | Langue principale                      | Parsing / affichage     |
| `publisher`        | NCSC-NL (éditeur du document)          | Source institutionnelle |
| `title`            | Identifiant principal (souvent CVE)    | Pivot documentaire      |

### `tracking`

Le sous-bloc `tracking` est **fondamental** pour le suivi temporel.

Champs importants :

* `id` : identifiant logique (souvent le CVE)
* `status` : `interim` ou `final`
* `version` : version du document CSAF
* `revision_history` : historique détaillé des enrichissements

⚠️ **Point clé**

> `tracking.status = interim` **ne signifie pas** qu’il n’existe pas de correctif.
>
> Cela signifie uniquement que le document peut encore évoluer (nouveaux produits, scores, remédiations).

---

## 3.3 Bloc `product_tree`

Le `product_tree` décrit **l’univers des produits affectés ou corrigés**, sous forme hiérarchique :

```text
vendor
└── product_name
    └── product_version / product_version_range
```

### Concepts importants

* **vendor** : éditeur (Juniper, Lenovo, Aruba, etc.)
* **product_name** : famille de produits
* **product_version_range** : plages de versions vulnérables ou corrigées
* **product_id** : identifiant interne CSAF (pivot technique)

Ces `product_id` sont utilisés dans tout le reste du document :

* `known_affected`
* `fixed`
* `remediations`
* `scores`

---

## 3.4 Bloc `vulnerabilities`

C’est le cœur opérationnel du document.

Chaque entrée correspond généralement à **une vulnérabilité (CVE)**.

### Champs structurants

| Champ            | Description                           |
| ---------------- | ------------------------------------- |
| `cve`            | Identifiant CVE                       |
| `cwe`            | Faiblesse logicielle (si disponible)  |
| `notes`          | Descriptions, scores, contexte        |
| `product_status` | État des produits (affecté / corrigé) |
| `references`     | Sources externes                      |
| `scores`         | CVSS, EPSS, scores NCSC               |
| `remediations`   | Correctifs / mitigations (optionnel)  |

---

## 3.5 `product_status` — champ critique

```json
"product_status": {
  "known_affected": [ ... ],
  "fixed": [ ... ]
}
```

### Interprétation

* `known_affected` : versions **confirmées vulnérables**
* `fixed` : versions **confirmées corrigées**

✅ **Présence de `fixed` = existence d’une solution**, même si aucune remédiation détaillée n’est fournie.

⚠️ L’absence de `fixed` n’implique pas forcément qu’aucune solution n’existe, mais qu’elle n’est **pas encore confirmée dans le CSAF**.

---

## 3.6 `remediations` — solution explicite (optionnel)

```json
"remediations": [
  {
    "category": "vendor_fix",
    "details": "Upgrade to version X",
    "product_ids": [ ... ]
  }
]
```

### Rôle

* Décrit **comment corriger** (patch, upgrade, workaround)
* Structuré et directement exploitable par des outils

### Réalité NCSC-NL

* Ce champ est **rarement présent**
* Beaucoup de CVE ont une solution **implicite** (via `fixed`) mais pas formalisée ici

---

## 3.7 `notes` — enrichissement multi-source

Le champ `notes` est un conteneur libre utilisé pour :

* descriptions NVD / CVE.org / éditeur
* score EPSS
* score NCSC
* facteurs d’augmentation / diminution du score
* évaluations éditeur

⚠️ Les `notes` ne sont **pas normalisées** :

* parsing fragile
* utile pour affichage humain
* usage automatique limité

---

## 3.8 `references`

Liste des sources externes :

* NVD / CVE.org
* Bulletins éditeur
* Autres CERT (CERT-Bund, HKCERT, etc.)

📌 Souvent, **les détails de remédiation sont dans les références**, même quand `remediations` est absent.

---

## 3.9 Détermination de l’existence d’une solution

### Logique recommandée

```text
IF remediations exist
  → solution explicite
ELSE IF product_status.fixed exists
  → solution implicite (upgrade)
ELSE IF vendor advisory reference exists
  → solution possible (validation manuelle)
ELSE
  → aucune solution connue
```

### Erreurs courantes à éviter

* Confondre `interim` avec "pas de correctif"
* Chercher uniquement `remediations`
* Ignorer `product_status.fixed`

---

## 3.10 Résumé opérationnel

* **CSAF NCSC-NL = enrichissement et agrégation**, pas toujours normalisation parfaite
* Une **solution peut exister sans être explicitement décrite**
* `product_status.fixed` est le **signal le plus fiable** après `remediations`
* L’automatisation nécessite une **logique multi-signaux**, pas un champ unique

> Phrase de synthèse :
>
> **NCSC-NL CSAF = CVE enrichi + contexte + état des correctifs, mais remédiation souvent implicite.**
