# 6. Cycle de vie des vulnérabilités (NVD)

## 6.1 Objectif de cette section
Cette section décrit le **cycle de vie** des vulnérabilités dans la NVD, notamment :
- la fréquence et les mécanismes de mise à jour,
- l’évolution des données d’une CVE dans le temps,
- l’impact sur les scores CVSS, CWE, CPE et métadonnées,
- les bonnes pratiques pour synchroniser et maintenir un référentiel interne à jour.

---

## 6.2 Fréquence de mise à jour des données
La NVD est une source vivante : les entrées **peuvent évoluer après publication**.

Une même CVE peut être mise à jour suite à :
- nouvelles informations techniques,
- correction ou ajout de produits affectés (CPE),
- ajout ou correction de CWE,
- recalcul ou ajustement du score CVSS,
- enrichissements supplémentaires et références.

📌 Champ clé :
- `lastModified` doit être utilisé comme référence technique pour détecter les changements.

---

## 6.3 Évolution d’une CVE dans le temps
### 6.3.1 Étapes typiques
1. **Publication initiale**
   - création de la CVE
   - description initiale parfois courte
   - données techniques parfois incomplètes

2. **Enrichissement progressif**
   - ajout de CVSS (v2 / v3.1 / v4.0 selon contexte)
   - ajout/clarification CWE
   - ajout/ajustement des configurations CPE (produits affectés)

3. **Stabilisation**
   - la CVE est “complète” et analysée
   - seules des corrections ponctuelles surviennent ensuite

---

## 6.4 Le champ `vulnStatus` (statut NVD)
Le champ `vulnStatus` indique l’état de traitement d’une CVE dans la NVD et donne des indications sur la **complétude** de l’entrée.

### 6.4.1 Statuts courants
- `Received`
- `Analyzed`
- `Modified`
- `Deferred`
- `Rejected`

---

### 6.4.2 Signification des statuts
#### `Received`
- la CVE vient d’être reçue/publiée
- certaines données peuvent être absentes ou incomplètes :
  - CVSS non présent
  - CPE non présent
  - CWE non présent

✅ Recommandation :
- intégrer la CVE mais prévoir une mise à jour future (poll via `lastModified`)

---

#### `Analyzed`
- la CVE a été analysée
- les informations principales (CVSS/CWE/CPE) sont généralement disponibles

✅ Recommandation :
- statut attendu pour exploitation “standard”
- score CVSS fiable pour priorisation

---

#### `Modified`
- la CVE a été modifiée après publication
- modifications possibles :
  - changement de score
  - ajout/suppression de CPE
  - correction description ou références

✅ Recommandation :
- mettre à jour l’entrée interne et recalculer la priorité

---

#### `Deferred`
- la CVE est présente dans la NVD mais mise de côté
- enrichissement NVD limité (analyse incomplète possible)

✅ Recommandation :
- ne pas considérer la CVE comme “complète”
- accepter qu’il manque certains enrichissements (CVSS/CPE/CWE)

---

#### `Rejected`
- la CVE est rejetée (non valide / doublon / erreur)

✅ Recommandation :
- exclure des pipelines d’analyse/priorisation
- optionnel : conserver en base uniquement pour audit/historique

---

## 6.5 Impact des mises à jour sur les scores et métadonnées
Les mises à jour NVD peuvent impacter directement les décisions opérationnelles.

### 6.5.1 Changements possibles
- CVSS :
  - modification de `baseScore`
  - modification de `baseSeverity`
  - modification du `vectorString`
  - apparition d’une nouvelle version (ex : ajout CVSS v4.0)

- CPE :
  - ajout de nouveaux produits affectés
  - correction de version ranges
  - modifications dans `configurations`

- CWE :
  - ajout d’une weakness précise (ex : `CWE-787`)
  - remplacement d’un placeholder (`NVD-CWE-Other`)

---

## 6.6 Bonnes pratiques pour un pipeline de synchronisation
### 6.6.1 Import initial
Lors du premier import :
- effectuer un chargement par tranches (ex : par années, par fenêtres de temps)
- persister la donnée brute JSON (raw)
- construire un modèle normalisé interne

---

### 6.6.2 Synchronisation incrémentale (recommandée)
Stratégie recommandée :
- effectuer une synchronisation régulière (ex : toutes les 2h ou quotidienne)
- utiliser exclusivement `lastModified` comme critère d’incrément

✅ Objectif :
- capter les changements de score CVSS, CPE, CWE

---

### 6.6.3 Détection des changements critiques
Dans un contexte SOC / vuln management, surveiller spécifiquement :
- hausse de score vers `HIGH` / `CRITICAL`
- apparition d’un score CVSS là où il n’y en avait pas
- ajout d’un CPE correspondant à un produit interne critique

---

### 6.6.4 Gestion d’historique (optionnel)
Deux approches possibles :
- **mise à jour en place** (state actuel seulement)
- **historisation** (garder versions précédentes)

L’historisation est utile pour :
- audit
- justification de priorisation
- analyse “score a changé à telle date”

---

## 6.7 Résumé (à retenir)
- Une CVE NVD peut évoluer longtemps après sa publication
- `lastModified` est la clé pour suivre ces évolutions
- `vulnStatus` est critique pour interpréter la complétude :
  - `Received` : trop récent / incomplet
  - `Analyzed` : complet
  - `Modified` : à re-synchroniser
  - `Deferred` : incomplet / mis de côté
  - `Rejected` : à exclure
- Une synchronisation incrémentale par fenêtres `lastModified` est la méthode recommandée
