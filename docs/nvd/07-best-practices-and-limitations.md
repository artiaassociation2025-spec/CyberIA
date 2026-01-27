# 7. Bonnes pratiques & limites — Exploitation IA / Data (NVD)

## 7.1 Objectif de cette section
Cette section présente les bonnes pratiques et limites spécifiques à l’usage des données NVD dans des cas IA / Data :
- ingestion à grande échelle et structuration dataset,
- préparation de features (CVSS/CWE/CPE),
- entraînement de modèles IA (classification, scoring, priorisation),
- risques de biais, incohérences et données manquantes.

Objectif : permettre la création d’un dataset exploitable pour du **Machine Learning / NLP / LLM / analytics sécurité**.

---

## 7.2 Bonnes pratiques (orientées IA / Data Engineering)

### 7.2.1 Construire un dataset robuste (raw + normalized)
Pour des usages IA, il est recommandé de conserver 2 versions :

✅ `raw layer` (source de vérité)
- stockage de l’entrée NVD brute (JSON)
- permet le reprocessing complet si le modèle de données change

✅ `normalized layer` (dataset ML/BI)
- format tabulaire/graph exploitable (Parquet/Delta/Iceberg)
- fields unifiés (CVSS multi-versions, CWE normalisées, CPE aplaties)

Recommandation :
- stocker dans un data lake : `raw/` + `silver/` + `gold/` (méthode medallion)

---

### 7.2.2 Stratégie d’ingestion incrémentale pour dataset ML
Pour éviter le recalcul complet du dataset :
- synchronisation incrémentale basée sur `lastModified`
- ingestion périodique (toutes les 2h / quotidienne)

✅ Recommandations :
- conserver `last_ingestion_timestamp`
- assurer l’idempotence (pas de doublons)
- rejouer les dernières heures (buffer de sécurité) pour éviter de rater des changements

---

### 7.2.3 Gérer les changements de labels/features dans le temps (concept drift)
Dans la NVD, les données changent :
- scores CVSS modifiés
- nouveaux CPE ajoutés
- CWE enrichies
- passage vers CVSS v4 sur CVE récentes

⚠️ Impact IA :
- les **features** évoluent
- les **labels** (severity) peuvent changer
- les distributions peuvent dériver (drift)

✅ Bonnes pratiques IA :
- versionner le dataset (dataset v1/v2)
- historiser la CVE à différents timestamps (snapshots)
- tracer le “moment d’extraction” des données (important pour reproducibility)

---

### 7.2.4 Feature engineering recommandé
#### A) CVSS
Créer des features stables :
- `cvss_score_selected`
- `cvss_severity_selected`
- `cvss_version_selected`

Créer des features dérivées depuis le vecteur :
- `attack_vector = NETWORK/LOCAL/...`
- `user_interaction_required = true/false`
- `privileges_required = NONE/LOW/HIGH`
- `scope_changed = true/false`

#### B) CWE
Transformer les CWE en variables exploitables :
- one-hot encoding (top CWE)
- mapping par catégories (ex : Memory Safety / Injection / Auth / Crypto)
- “CWE family features”

#### C) CPE
La donnée CPE peut être transformée en :
- vendor/product tokens
- embeddings produit (NLP)
- top affected vendors
- features d’exposition (ex : `is_os`, `is_browser`, `is_server`)

---

### 7.2.5 NLP / LLM : exploitation des descriptions
Le champ `descriptions[].value` est exploitable pour du NLP.

✅ Cas d’usage IA :
- classification automatique (type vulnérabilité)
- extraction d’entités (produits, versions)
- résumé automatique / explanation
- clustering / similarity search

Recommandations :
- nettoyage texte (lowercase, remove stopwords optionnel)
- conserver texte original (raw)
- génération d’embeddings versionnés (ex: `embedding_model_version`)

---

### 7.2.6 Constitution de labels (supervisé)
Le dataset NVD permet de créer des labels :
- `baseSeverity` (classification 4 classes)
- seuils CVSS (classification binaire “critical”)
- CWE categories

⚠️ Attention :
`baseSeverity` est dérivée du score CVSS → si ton modèle apprend juste CVSS → label, ça ne crée pas de valeur.

✅ Recommandation :
- choisir des objectifs ML utiles :
  - prédire “exploitation probable”
  - prédire “asset impact”
  - recommander priorité patch en fonction contexte

---

### 7.2.7 Enrichissements externes recommandés pour IA
Pour améliorer la valeur ML, enrichir NVD avec :
- inventaire interne / CMDB
- données d’exposition (internet-facing)
- EPSS (probabilité exploitation)
- CISA KEV (Known Exploited Vulnerabilities)
- threat intel (IOC, campagnes)
- vuln scanner outputs

✅ Objectif :
passer de “severity CVSS” à “risque réel”.

---

## 7.3 Limites et points de vigilance (orientés IA)

### 7.3.1 Données incomplètes et Missing Values
Certaines CVE sont incomplètes :
- `Received` : pas encore enrichies
- `Deferred` : enrichissement limité
- absence de CVSS/CPE/CWE

⚠️ Impact IA :
- features manquantes = biais dataset
- nécessité d’imputation / fallback

✅ Recommandations :
- créer un champ `is_complete`
- filtrer / exclure certaines CVE pour training
- distinguer “missing” vs “not applicable”

---

### 7.3.2 Biais temporels (dataset shift)
Les CVE anciennes :
- CVSS v2 uniquement
- CWE souvent `NVD-CWE-Other`
- descriptions moins structurées

⚠️ Impact IA :
- un modèle entraîné sur 1999–2005 ne généralise pas sur 2024+
- “shift” dû aux changements de standards et pratiques

✅ Recommandations :
- entraîner sur une période cohérente (ex : 2016 → maintenant)
- utiliser cross-validation temporelle
- normaliser multi-version CVSS

---

### 7.3.3 Coexistence multi-version CVSS
Le dataset contient potentiellement :
- v2 / v3.0 / v3.1 / v4.0

⚠️ Impact IA :
- features incohérentes si tu mixes sans logique
- champs incompatibles

✅ Recommandations :
- appliquer une règle unique de sélection
- ou stocker plusieurs features et laisser le modèle apprendre (avec précautions)

---

### 7.3.4 CVSS ne représente pas l’exploitation réelle
CVSS mesure une sévérité technique standardisée.

⚠️ Impact IA :
si on entraîne un modèle à prédire “priorité patch” uniquement avec CVSS → le modèle ne fait que reproduire CVSS.

✅ Recommandation :
utiliser des labels / enrichissements orientés “exploitability réelle” (EPSS, KEV, threat intel).

---

### 7.3.5 Matching CPE difficile (bruit)
Le CPE est complexe (versions, produits, éditions).

⚠️ Impact IA :
- erreurs de matching = bruit label (noisy labels)
- mauvais mapping product → faux positifs

✅ Recommandations :
- créer un mapping interne contrôlé
- filtrer les CPE trop génériques
- limiter aux vendors/produits connus

---

## 7.4 Résumé (à retenir)
- conserver raw JSON + dataset normalisé
- ingestion incrémentale via `lastModified`
- versionner dataset + embeddings (reproductibilité)
- attention aux données manquantes (`Received`, `Deferred`)
- gérer le drift temporel / shift (v2/v3/v4)
- enrichir NVD avec EPSS/KEV/inventaire pour IA utile
