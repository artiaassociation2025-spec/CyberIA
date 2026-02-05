# 5. Cycle de vie des publications NCSC-NL (CSAF)

## 1. Objectif de cette section

Cette section décrit le **cycle de vie réel** des publications du **NCSC-NL**, basées sur le standard **CSAF 2.0**, afin de comprendre :

* comment une entrée vulnérabilité apparaît et évolue dans le temps,
* quand et comment les informations sont enrichies (produits, scores, correctifs),
* l’impact de ces évolutions sur la **priorisation**, le **patch management** et l’automatisation,
* les bonnes pratiques pour maintenir un **référentiel interne synchronisé et fiable**.

Contrairement à CERT-FR (bulletins éditoriaux), le NCSC-NL publie des **objets de données structurés**, dont le cycle de vie est explicitement modélisé dans le champ `tracking`.

---

## 2. Comprendre le modèle de cycle de vie NCSC-NL

### 2.1 Unité de cycle de vie

L’unité principale est le **document CSAF**, généralement **aligné sur une CVE**.

* 1 CVE → 1 document CSAF
* le document est **versionné**
* le document peut être **mis à jour plusieurs fois** sans changer d’URL

---

### 2.2 Différence clé avec NVD / CERT-FR

| Source      | Unité              | Évolution                              |
| ----------- | ------------------ | -------------------------------------- |
| NVD         | Enregistrement CVE | Enrichissements internes (scores, CWE) |
| CERT-FR     | Bulletin           | Mises à jour éditoriales               |
| **NCSC-NL** | **Document CSAF**  | **Versions explicites + historique**   |

Le NCSC-NL rend le cycle de vie **machine-readable**, ce qui est un avantage majeur pour l’automatisation.

---

## 3. Les états du cycle de vie (`tracking.status`)

Le champ `document.tracking.status` indique la **maturité** de l’information.

### 3.1 `interim`

État le plus fréquent lors des premières publications.

Signification :

* la vulnérabilité est **confirmée**
* les informations sont **partielles ou évolutives**
* certains éléments peuvent manquer :

  * remédiations structurées
  * versions corrigées exhaustives
  * scores stabilisés

⚠️ **Point critique** :

> `interim` **ne signifie pas** "pas de solution".
> Une solution peut exister implicitement (via `product_status.fixed`) ou apparaître plus tard.

---

### 3.2 `final`

État indiquant que le document est considéré comme **stabilisé**.

Signification :

* le périmètre produit est consolidé
* les scores sont établis
* aucune mise à jour majeure n’est anticipée

⚠️ En pratique :

> `final` **n’exclut pas** de futures mises à jour (ex. correction d’erreur, ajout tardif).

---

## 4. Versioning et historique (`revision_history`)

Chaque modification du document entraîne :

* une **incrémentation de `tracking.version`**
* l’ajout d’une entrée dans `revision_history[]`

### 4.1 Types de modifications observées

Les mises à jour peuvent inclure :

* ajout/suppression de produits affectés
* ajout de versions corrigées (`fixed`)
* ajout de scores (EPSS, score NCSC)
* mise à jour des scores existants
* ajout de références éditeur ou CERT partenaire
* ajout ultérieur de `remediations`

➡️ **Une vulnérabilité peut passer de non-actionnable à actionnable sans changer d’identifiant**.

---

## 5. Apparition des solutions dans le cycle de vie

### 5.1 Chronologie typique

1. **Publication initiale**

   * CVE connue
   * produits affectés partiels
   * pas de solution structurée
   * statut `interim`

2. **Enrichissement produit**

   * ajout de `product_tree`
   * consolidation de `known_affected`

3. **Disponibilité d’un correctif**

   * apparition de `product_status.fixed` → **solution implicite**

4. **Normalisation de la remédiation (optionnelle)**

   * ajout de `remediations.vendor_fix` → **solution explicite**

5. **Stabilisation**

   * passage éventuel à `final`

---

## 6. Indicateurs techniques de changement

Pour détecter les évolutions, utiliser :

* `document.tracking.version`
* `document.tracking.current_release_date`
* comparaison de hash du fichier JSON

⚠️ Ne jamais se baser uniquement sur :

* le nom du fichier
* le statut `final`

---

## 7. Bonnes pratiques de synchronisation

### 7.1 Import initial (historique)

* parcourir tous les dossiers `/csaf/YYYY/`
* ingérer tous les documents
* conserver les JSON bruts
* construire un index par `(tracking.id)`

---

### 7.2 Synchronisation incrémentale

* collecte régulière (quotidienne ou plus)
* détection des nouvelles versions
* recalcul des indicateurs internes :

  * actionnabilité
  * exposition produit
  * priorité

---

### 7.3 Gestion des transitions critiques

Surveiller particulièrement :

* passage **sans solution → solution implicite** (`fixed` apparaît)
* passage **solution implicite → explicite** (`remediations` apparaît)
* ajout tardif de produits critiques
* changement significatif de score

---

## 8. Champs critiques à stocker dans un référentiel interne

* `tracking.id`
* `tracking.version`
* `tracking.status`
* `tracking.current_release_date`
* `product_status.known_affected`
* `product_status.fixed`
* `remediations`
* `scores`
* `references`

---

## 9. Résumé opérationnel

* Le NCSC-NL publie des **CSAF versionnés**, pas des bulletins figés
* Le cycle de vie est **progressif et incrémental**
* Une solution peut apparaître **après la publication initiale**
* `fixed` et `remediations` doivent être surveillés en continu

> Phrase de synthèse :
>
> **NCSC-NL CSAF = vulnérabilité vivante, enrichie au fil du temps, dont l’actionnabilité peut émerger tardivement.**
