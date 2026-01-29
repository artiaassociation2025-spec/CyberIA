# 7. Bonnes pratiques & limites — Exploitation IA / Data (CISA KEV)

## 7.1 Objectif de cette section
Cette section présente les bonnes pratiques et limites spécifiques à l’usage des données **CISA KEV** dans des cas IA / Data :
- ingestion à grande échelle et structuration dataset,
- préparation de features (dates, vendor/product, ransomware, dueDate),
- entraînement de modèles IA (classification, scoring, priorisation),
- risques de biais, incohérences et données manquantes.

Objectif : permettre la création d’un dataset exploitable pour du **Machine Learning / NLP / LLM / analytics sécurité** à partir des données KEV.

---

## 7.2 Bonnes pratiques (orientées IA / Data Engineering)

### 7.2.1 Construire un dataset robuste (raw + normalized)
Pour des usages IA/Data, il est recommandé de conserver 2 versions :

✅ `raw layer` (source de vérité)
- stockage du catalogue KEV brut (JSON ou CSV)
- permet le reprocessing complet si le modèle de données change

✅ `normalized layer` (dataset ML/BI)
- format tabulaire exploitable (Parquet/Delta/Iceberg)
- champs normalisés et typés :
  - `cve_id`, `vendor`, `product`, `date_added`, `due_date`, `known_ransomware`

Recommandation :
- stockage dans un data lake : `raw/` + `silver/` + `gold/` (méthode medallion)

---

### 7.2.2 Stratégie d’ingestion incrémentale pour dataset ML
Le catalogue KEV est publié sous forme de liste complète.
L’ingestion incrémentale se fait par **diff** entre versions :

✅ Approches courantes :
- comparer la version N et N-1
- détecter les nouvelles entrées par `cveID`
- détecter les changements de champs (rare, mais possible)

✅ Recommandations :
- conserver `last_catalog_version_ingested`
- historiser au moins les snapshots (daily)
- assurer idempotence (pas de doublons)

---

### 7.2.3 Gérer les changements dans le temps (concept drift)
Dans KEV, la base évolue :
- ajout régulier de nouvelles entrées
- possible changement de certains champs (ex : ransomware flag, notes)

⚠️ Impact IA :
- distribution des vendors/produits varie
- nouvelles familles d’attaques observées
- évolution des patterns (ex : explosion de CVE sur appliances edge)

✅ Bonnes pratiques IA :
- versionner le dataset
- tracer le “moment d’extraction” (snapshot timestamp)
- entraîner des modèles sur des fenêtres temporelles (ex : 12–24 mois)

---

### 7.2.4 Feature engineering recommandé
KEV fournit des champs très exploitables en ML car simples et stables.

#### A) Dates
Créer des features :
- `days_since_added = today - dateAdded`
- `days_until_due = dueDate - today` (si présent)
- `is_overdue = dueDate < today`

#### B) Ransomware
Créer des features :
- `ransomware_known = (knownRansomwareCampaignUse == "Known")`

#### C) Vendor / Product
Transformer en variables exploitables :
- `vendor_project` (catégorie)
- `product` (catégorie)
- tokenisation vendor/product pour NLP

#### D) Required Action / Notes
Ces champs peuvent alimenter du NLP :
- `requiredAction`
- `notes`
- `shortDescription`

---

### 7.2.5 NLP / LLM : exploitation des descriptions
Les champs textuels KEV sont directement utilisables pour NLP :
- `shortDescription`
- `vulnerabilityName`
- `requiredAction`
- `notes`

✅ Cas d’usage IA :
- classification automatique par type de vulnérabilité (edge device, web app, etc.)
- extraction d’entités (vendor, produit, techno)
- résumé et génération automatique de tickets
- clustering / similarity search sur campagnes d’exploitation

Recommandations :
- conserver texte original (raw)
- versionner embeddings (ex : `embedding_model_version`)

---

### 7.2.6 Constitution de labels (supervisé)
KEV permet de construire des labels très utiles, car orientés “terrain”.

✅ Labels possibles :
- `is_kev = true` (label exploitation confirmée)
- `ransomware_known` (binaire)
- `overdue` (binaire basé sur dueDate)
- classes de priorité (P0/P1/P2) dérivées des règles internes

⚠️ Attention :
KEV n’est pas une liste complète des CVE exploitables.
Donc KEV doit être utilisée comme un signal **fort**, mais pas comme vérité totale sur l’exploitation.

---

## 7.3 Limites et points de vigilance (orientés IA)

### 7.3.1 Dataset partiel (biais de sélection)
KEV contient uniquement :
- des CVE exploitées confirmées

⚠️ Impact IA :
- KEV n’est pas représentatif de toutes les vulnérabilités
- si on entraîne uniquement sur KEV, on perd la notion “non exploité / inconnu”

✅ Recommandation :
- considérer KEV comme un dataset “positive class”
- être prudent sur les généralisations

---

### 7.3.2 `Unknown` ne signifie pas absence de ransomware
Le champ `knownRansomwareCampaignUse` a une valeur :

- `Known` : confirmé
- `Unknown` : non confirmé

⚠️ Impact IA :
- `Unknown` ≠ “non ransomware”
- risque de mauvaise interprétation (label noise)

✅ Recommandation :
- encoder `Unknown` comme “missing/unknown”
- pas comme “false”

---

### 7.3.3 `dueDate` parfois absent
Certaines entrées n’ont pas de `dueDate`.

⚠️ Impact IA :
- valeurs manquantes (missing)
- biais si imputation incorrecte

✅ Recommandations :
- conserver `has_due_date` (bool)
- distinguer :
  - `dueDate missing`
  - `dueDate present`

---

### 7.3.4 Variabilité vendor/product (normalisation difficile)
Les champs :
- `vendorProject`
- `product`

ne sont pas garantis comme strictement normalisés (variantes, alias).

⚠️ Impact IA :
- explosion du nombre de catégories
- bruit dans le training

✅ Recommandations :
- mapping interne (dictionnaire alias → vendor canonique)
- regroupement par familles (ex : “Microsoft”, “Windows”, “Exchange”)

---

### 7.3.5 Modification possible des champs
Bien que rare, certains champs peuvent être corrigés/modifiés :
- `requiredAction`
- `notes`
- `dueDate`
- `knownRansomwareCampaignUse`

⚠️ Impact IA :
- drift entre snapshots
- besoin de versionner

✅ Recommandations :
- historiser snapshots
- garder `catalogVersion` + `dateReleased`
- comparer les changements

---

## 7.4 Résumé (à retenir)
- conserver raw KEV + dataset normalisé
- ingestion incrémentale via diff entre snapshots
- versionner dataset + embeddings (reproductibilité)
- attention : KEV = dataset partiel (biais de sélection)
- `Unknown` ransomware ≠ “false”
- `dueDate` peut être absent ou déjà dépassé
- normaliser vendor/product pour réduire bruit et améliorer exploitation IA
