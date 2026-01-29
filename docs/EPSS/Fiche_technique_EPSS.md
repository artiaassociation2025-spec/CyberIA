# EPSS (FIRST) — Documentation technique (one page)

## 1. Définition
**EPSS (Exploit Prediction Scoring System)** est un score maintenu par **FIRST** (*Forum of Incident Response and Security Teams*).

EPSS fournit une estimation **probabiliste** de l’exploitation d’une vulnérabilité (**CVE**) dans la réalité.

📌 EPSS répond à :
> **“Quelle est la probabilité que cette CVE soit exploitée ?”**

---

## 2. Différence EPSS vs CVSS vs KEV
✅ **CVSS** = sévérité technique (gravité)  
✅ **EPSS** = probabilité d’exploitation (likelihood)  
✅ **CISA KEV** = exploitation confirmée (*exploited in the wild*)

---

## 3. Comment EPSS est calculé (principe)
EPSS n’est **pas** une formule comme CVSS : c’est un modèle **statistique / Machine Learning**.

Le modèle se base sur :
- des données CVE (âge, caractéristiques, contexte)
- des signaux d’activité / exploitation / tendances
- des patterns historiques d’exploitation

➡️ Le résultat est un score de **0 à 1**.

---

## 4. Champs / colonnes EPSS (dataset officiel)
Le dataset EPSS est publié au format **CSV** et **JSON** avec les colonnes suivantes :

| Colonne | Type | Description |
|---|---|---|
| `cve` | string | Identifiant CVE (`CVE-YYYY-NNNN`) |
| `epss` | float | Score EPSS (0 → 1) |
| `percentile` | float | Percentile (0 → 1) |
| `date` | date | Date de publication du score |

### Interprétation rapide
- `epss` proche de **1** → exploitation très probable
- `epss` proche de **0** → exploitation peu probable
- `percentile` proche de **1** → la CVE est dans le top des plus exploitables

---

## 5. Exemples EPSS

### Exemple CSV (1 ligne)
***csv
cve,epss,percentile,date
CVE-2021-44228,0.97,0.999,2024-07-09
***

### Exemple JSON (1 entrée)
***json
{
  "cve": "CVE-2021-44228",
  "epss": 0.97,
  "percentile": 0.999,
  "date": "2024-07-09"
}
***

---

## 6. Bonnes pratiques d’exploitation
- utiliser EPSS pour compléter CVSS (priorisation plus réaliste)
- définir des seuils internes :
  - ex : `epss >= 0.5`
  - ou `percentile >= 0.95`
- historiser le score (car EPSS évolue dans le temps)

⚠️ EPSS reste probabiliste :
- EPSS élevé ≠ exploitation certaine
- EPSS faible ≠ exploitation impossible

---

## 7. Liens officiels EPSS

### 📌 EPSS — Source officielle FIRST
- EPSS (page officielle) :  
  https://www.first.org/epss/

### 📥 Dataset EPSS (CSV)
- EPSS scores (CSV) :  
  https://epss.cyentia.com/epss_scores-current.csv.gz

### 📥 Dataset EPSS (JSON)
- EPSS scores (JSON) :  
  https://epss.cyentia.com/epss_scores-current.json.gz
