# 5. Accès aux données CISA KEV (Feed officiel)

## 5.1 Objectif de cette section
Cette section documente l’accès aux données du **catalogue CISA KEV** via les sources officielles afin de permettre :
- la récupération automatisée du catalogue (ingestion initiale et mises à jour),
- l’intégration des données KEV dans un pipeline (ETL/ELT, data lake),
- la consommation dans des outils sécurité (SOC/SIEM, dashboards, vuln management).

---

## 5.2 Présentation générale
Le catalogue **CISA Known Exploited Vulnerabilities (KEV)** est publié sous forme de **catalogue complet** régulièrement mis à jour.

Contrairement à des API de recherche (filtrage/pagination), KEV suit une logique simple :
- la CISA publie la **liste complète** des vulnérabilités KEV,
- les organisations téléchargent le catalogue,
- les recherches/filtrages sont réalisés côté SI (base interne / outil).

Le catalogue permet notamment :
- récupérer la liste à jour des vulnérabilités KEV,
- détecter les nouvelles entrées ajoutées (`dateAdded`),
- exploiter les deadlines (`dueDate`),
- intégrer l’indicateur ransomware (`knownRansomwareCampaignUse`).

---

## 5.3 Formats disponibles
Le catalogue est disponible en deux formats :

- **JSON** : format structuré (recommandé pour intégration applicative)
- **CSV** : format tabulaire (recommandé pour ingestion rapide / reporting)

✅ Bonnes pratiques :
- définir un format principal (JSON ou CSV)
- standardiser l’ingestion (même structure, mêmes types)

---

## 5.4 Sources officielles (liens CISA)
Les données KEV sont accessibles via la documentation officielle CISA.

### 5.4.1 Catalogue JSON (complet)
- fichier JSON contenant :
  - métadonnées (`catalogVersion`, `dateReleased`, `count`)
  - entrées (`vulnerabilities[]`)

Exemple :
- téléchargement du JSON
- ingestion complète du JSON

---

### 5.4.2 Catalogue CSV (complet)
- fichier CSV contenant une entrée par vulnérabilité KEV

Exemple :
- téléchargement du CSV
- ingestion complète du CSV

---

## 5.5 Endpoints / modèle d’accès
KEV ne fonctionne pas comme une API REST de recherche.

📌 Modèle d’accès recommandé :
1. télécharger le catalogue complet (JSON/CSV)
2. stocker la version brute
3. comparer la nouvelle version à la précédente (diff)

---

## 5.6 Stratégie de synchronisation

### 5.6.1 Import initial
- télécharger le catalogue complet
- ingestion brute (raw)
- stockage de la version et date de collecte

✅ Bonnes pratiques :
- conserver un snapshot daté (ex : `/raw/kev/2026-01-29.json`)
- conserver aussi les métadonnées :
  - `catalogVersion`
  - `dateReleased`
  - `count`

---

### 5.6.2 Mise à jour incrémentale (diff)
Le catalogue KEV étant consolidé, l’incrémental se fait par comparaison entre deux versions.

Approches possibles :
- **diff par `cveID`**
  - détecter les nouvelles CVE ajoutées
- **diff par date**
  - filtrer les entrées dont `dateAdded` est dans une fenêtre récente

✅ Bonnes pratiques :
- exécuter une synchronisation régulière :
  - quotidienne (minimum)
  - ou plusieurs fois par jour (selon les besoins)
- historiser les snapshots pour audit et reproductibilité

---

## 5.7 Contrôles d’intégrité (recommandés)
Le champ `count` correspond au nombre total d’entrées attendues.

✅ Contrôles recommandés :
- vérifier `count == nombre d’entrées dans vulnerabilities[]`
- vérifier unicité des `cveID`
- vérifier format des dates :
  - `dateAdded` (obligatoire)
  - `dueDate` (peut être vide)
- vérifier cohérence des valeurs :
  - `knownRansomwareCampaignUse` ∈ {`Known`, `Unknown`}

---

## 5.8 Limites et points de vigilance
- pas de pagination
- pas de paramètres de requête serveur (filtres côté CISA)
- pas d’API Key
- disponibilité dépendante de la source publique CISA

✅ Bonnes pratiques :
- retry avec backoff exponentiel si échec de téléchargement
- conserver une version “last known good”
- journaliser chaque synchronisation (date, version, count)

---

## 5.9 Exemples de requêtes / opérations (recommandés)

### 5.9.1 Télécharger le catalogue JSON
Exemple : téléchargement du JSON complet

### 5.9.2 Télécharger le catalogue CSV
Exemple : téléchargement du CSV complet

### 5.9.3 Détecter les nouvelles entrées KEV
Exemple :
- comparer version N et N-1
- extraire les nouvelles `cveID`

### 5.9.4 Suivre les vulnérabilités proches de la deadline
Exemple :
- lister les entrées avec `dueDate <= today + 7`

---

## 5.10 Recommandations d’intégration (pipeline)
Pour intégrer KEV efficacement :

1. **Import initial**
   - ingestion complète (JSON/CSV)

2. **Mode incrémental**
   - synchronisation régulière
   - détection des nouvelles entrées via diff `cveID` ou fenêtre `dateAdded`

3. **Stockage**
   - conserver la version brute (raw)
   - conserver la version transformée (si applicable)

4. **Observabilité**
   - logs + métriques :
     - nb entrées (`count`)
     - nb nouvelles CVE
     - erreurs de téléchargement
     - temps d’ingestion


- Catalogue **KEV (page officielle)** :  
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

- Catalogue **KEV JSON** :  
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

- Catalogue **KEV CSV** :  
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv
