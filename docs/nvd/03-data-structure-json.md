# 3. Structure des données — Format JSON (NVD)

## 3.1 Objectif de cette section
Cette section décrit la structure des données NVD au format **JSON**, afin de permettre :
- l’ingestion des vulnérabilités (ETL/ELT),
- l’exploitation dans des outils internes (SIEM, SOC, dashboards),
- la normalisation des champs (modèle interne).

L’objectif est de comprendre **où se trouve chaque information** : CVE ID, description, dates, CVSS (v2/v3/v4), CWE, CPE, références.

---

## 3.2 Format général des données NVD
Les données NVD sont exposées sous forme d’objets JSON.
Chaque vulnérabilité est représentée par une entrée de type **CVE**.

### Champs globaux clés (top-level)
Une entrée NVD est généralement structurée autour des champs suivants :

- `id`
- `sourceIdentifier`
- `published`
- `lastModified`
- `vulnStatus`
- `descriptions[]`
- `metrics`
- `weaknesses[]`
- `configurations[]`
- `references[]`

---

## 3.3 Détail champ par champ (modèle de données)

### 3.3.1 `id` — Identifiant CVE
- **Type** : string
- **Exemple** : `CVE-1999-1500`
- **Usage** :
  - clé primaire dans une base de données / data lake,
  - identifiant de corrélation dans le SIEM/SOC,
  - pivot pour enrichissements (assets / patch / threat intel).

✅ Bonnes pratiques :
- stocker comme `cve_id` (unique)
- normaliser en uppercase

---

### 3.3.2 `sourceIdentifier` — Origine de la publication
- **Type** : string
- **Exemples** :
  - `cve@mitre.org`
  - `cve_disclosure@tech.gov.sg`
- **Usage** :
  - identifier l’émetteur (CNA),
  - interpréter la fiabilité / nature des champs (ex: score fourni par la source).

---

### 3.3.3 `published` et `lastModified` — Dates
- **Type** : datetime ISO-8601
- **Champs** :
  - `published` : date initiale de publication
  - `lastModified` : date dernière mise à jour (NVD/CNA)

✅ Usage opérationnel :
- ingestion incrémentale : `lastModified`
- détection d’événements : *“un score CVSS a changé”*
- synchronisation quotidienne / horaire

⚠️ Point important :
`lastModified` peut changer longtemps après `published` (scores, CPE, CWE ajoutés/modifiés).

---

### 3.3.4 `vulnStatus` — Statut de la CVE
- **Type** : string
- **Exemples observés** :
  - `Received`
  - `Deferred`

📌 Ce champ indique l’état de traitement/complétude de la CVE.
Certaines CVE peuvent être présentes mais **incomplètes** (pas de CVSS ou pas de CPE).

✅ Bonne pratique :
- intégrer `vulnStatus` dans la logique de qualité / confiance des données.

---

### 3.3.5 `descriptions[]` — Description fonctionnelle
- **Type** : tableau d’objets (`lang`, `value`)
- **Exemple** :
```json
"descriptions": [
  { "lang": "en", "value": "..." }
]
```
✅ Usage :
- affichage dans dashboards / tickets
- extraction de mots clés (NLP/IA)
- classification (catégorisation par type d’attaque)

✅ Bonnes pratiques :
- conserver la description originale
- sélectionner `lang=en` en premier, si multi-langues

---

## 3.4 Champ `metrics` — Scores CVSS (v2 / v3.x / v4.0)

### 3.4.1 Objectif du champ
Le champ `metrics` contient les informations de scoring CVSS :
- vecteur CVSS (`vectorString`)
- score (`baseScore`)
- sévérité (`baseSeverity`)
- détails des métriques (AV/AC/PR/UI, etc.)

⚠️ Important :  
Une CVE peut contenir plusieurs versions ou plusieurs sources de scoring.

---

### 3.4.2 CVSS v2.0 (ancien format)
Structure typique :
- `metrics.cvssMetricV2[]`

Exemple :

```json
"metrics": {
  "cvssMetricV2": [
    {
      "source": "nvd@nist.gov",
      "type": "Primary",
      "cvssData": {
        "version": "2.0",
        "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
        "baseScore": 5.0
      },
      "baseSeverity": "MEDIUM"
    }
  ]
}
```
✅ Champs clés v2 :
- `vectorString` (AV/AC/Au/C/I/A)
- `baseScore`
- `baseSeverity`

📌 Interprétation :
- utilisé majoritairement dans les CVE anciennes
- moins précis (ne prend pas en compte certaines réalités modernes)

---

### 3.4.3 CVSS v3.0 / v3.1 (format actuel le plus courant)
Structures typiques :
- `metrics.cvssMetricV30[]`
- `metrics.cvssMetricV31[]`

Exemple de structure attendue :
- `cvssData.version = "3.1"`
- `vectorString = "CVSS:3.1/..."`

✅ Champs clés v3.x :
- `attackVector (AV)`
- `attackComplexity (AC)`
- `privilegesRequired (PR)`
- `userInteraction (UI)`
- `scope (S)`
- impacts `C/I/A`
- `baseScore`
- `baseSeverity`

📌 Interprétation :
- v3.1 doit être priorisé si disponible
- plus adapté à la priorisation opérationnelle

---

### 3.4.4 CVSS v4.0 (nouveau format)
Structure typique :
- `metrics.cvssMetricV40[]`

Exemple observé :

```json
"metrics": {
  "cvssMetricV40": [
    {
      "source": "cve_disclosure@tech.gov.sg",
      "type": "Secondary",
      "cvssData": {
        "version": "4.0",
        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/...",
        "baseScore": 10.0,
        "baseSeverity": "CRITICAL"
      }
    }
  ]
}
```
📌 Points importants :
- CVSS v4 introduit davantage de métriques, plus détaillées (et adaptées aux contextes modernes)
- présence plus fréquente sur les CVE très récentes
- nécessite une logique d’ingestion compatible (nouveaux champs)

✅ Bonne pratique :
- supporter `cvssMetricV40` même si l’outillage interne reste centré v3.1

---

### 3.4.5 Règle de sélection recommandée (pipeline)
Lorsque plusieurs versions sont présentes, une règle standard de choix est :

- prendre CVSS v4.0 si présent
- sinon CVSS v3.1
- sinon CVSS v3.0
- sinon CVSS v2.0
- sinon → “non scoré”

---

## 3.5 `weaknesses[]` — CWE (type de faiblesse)
Type : tableau d’objets contenant des identifiants CWE

Exemples :
- CWE-120 (Buffer Copy without Checking Size)
- CWE-787 (Out-of-bounds Write)
- NVD-CWE-Other (catégorie générique)

Structure :

```json
"weaknesses": [
  {
    "description": [
      { "lang": "en", "value": "CWE-120" }
    ]
  }
]
```
✅ Usage :
- catégorisation
- reporting
- analytics (classement des faiblesses dominantes)

⚠️ Anciennes CVE :
- CWE parfois non renseignée ou trop générique.

---

## 3.6 `configurations[]` — CPE (produits affectés)
Ce champ contient les produits/versions vulnérables via des critères CPE (`cpe:2.3:...`).

Structure typique :
- `configurations[].nodes[].cpeMatch[]`

Exemple :

```json
"configurations": [
  {
    "nodes": [
      {
        "operator": "OR",
        "cpeMatch": [
          {
            "vulnerable": true,
            "criteria": "cpe:2.3:a:true_north:internet_anywhere_mail_server:2.3:*:*:*:*:*:*:*"
          }
        ]
      }
    ]
  }
]
```
✅ Usage :
- matching automatique avec un inventaire applicatif / CMDB
- identification rapide des assets potentiellement exposés

⚠️ Points de vigilance :
- risques de faux positifs si les assets ne sont pas normalisés
- subtilités sur les versions / ranges

---

## 3.7 `references[]` — Références externes
Type : tableau d’URLs

Contient :
- advisories éditeur
- patch / commits / PR GitHub
- publications et exploit reports

✅ Usage :
- contextualisation technique
- triage SOC
- patch validation

---

## 3.8 Résumé exploitation (à retenir)
Pour exploiter une CVE NVD dans un outil :

- utiliser `id` comme identifiant unique
- utiliser `lastModified` pour la synchro incrémentale
- supporter plusieurs versions de CVSS via `metrics` :
  - v2 / v3.0 / v3.1 / v4.0
- extraire CWE depuis `weaknesses[]`
- extraire CPE depuis `configurations[]`
- exploiter les `references[]` pour enrichissement/triage
