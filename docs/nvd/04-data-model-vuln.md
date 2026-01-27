# 4. CVSS — Sévérité des vulnérabilités (v2 / v3.x / v4.0)

## 4.1 Objectif de cette section
Cette section explique comment la NVD représente la sévérité des vulnérabilités via le standard **CVSS (Common Vulnerability Scoring System)**, et comment interpréter et exploiter :
- le **score** (`baseScore`)
- la **sévérité** (`baseSeverity`)
- le **vecteur** (`vectorString`)
- la coexistence de plusieurs versions (**v2**, **v3.0/v3.1**, **v4.0**)

Objectif opérationnel : permettre aux équipes SOC/SIEM/Vuln Mgmt d’intégrer CVSS correctement et de prioriser les vulnérabilités.

---

## 4.2 Définition de CVSS
CVSS est un standard permettant d’attribuer à une vulnérabilité :
- un **score numérique** entre 0.0 et 10.0 (ex : 9.8)
- une **catégorie de sévérité** (LOW / MEDIUM / HIGH / CRITICAL)
- un **vecteur** qui décrit les conditions d’exploitation et les impacts

Dans la NVD, les informations CVSS se trouvent dans le champ `metrics`.

---

## 4.3 Différence entre Score et Severity

### 4.3.1 `baseScore`
- valeur numérique (0.0 → 10.0)
- utilisée pour le tri / priorisation / seuils

### 4.3.2 `baseSeverity`
- catégorisation textuelle associée au score
- utile pour affichage et règles simples dans des outils

📌 À noter :
- la severity est dérivée du score mais reste la représentation la plus simple pour les dashboards.

---

## 4.4 Lecture du vecteur CVSS (`vectorString`)
Le champ `vectorString` décrit les facteurs du score.

### 4.4.1 Pourquoi le vecteur est important
Le score seul ne suffit pas à décider.
Le vecteur permet de répondre à des questions comme :
- Est-ce exploitable à distance ?
- Est-ce que l’attaquant doit être authentifié ?
- Est-ce que l’utilisateur doit cliquer ?
- Quel impact sur la confidentialité / intégrité / disponibilité ?

---

## 4.5 CVSS v2.0 (ancien)

### 4.5.1 Où le trouver dans la NVD
Le v2 est présent dans :
- `metrics.cvssMetricV2[]`

Exemple :
```json
"metrics": {
  "cvssMetricV2": [
    {
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
### 4.5.2 Métriques principales v2
- `AV` : Access Vector (LOCAL / ADJACENT / NETWORK)
- `AC` : Access Complexity (LOW / MEDIUM / HIGH)
- `Au` : Authentication (NONE / SINGLE / MULTIPLE)
- impacts : `C/I/A`

📌 Limites v2 :
- moins précis sur les conditions d’exploitation modernes
- ne modélise pas correctement certains cas (privileges, interaction utilisateur, scope)

---

## 4.6 CVSS v3.0 / v3.1 (standard le plus utilisé)

### 4.6.1 Où le trouver dans la NVD
- `metrics.cvssMetricV30[]`
- `metrics.cvssMetricV31[]`

Exemple :
```json
"metrics": {
  "cvssMetricV31": [
    {
      "cvssData": {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "baseScore": 9.8
      },
      "baseSeverity": "CRITICAL"
    }
  ]
}
```

---
### 4.6.2 Métriques importantes v3.x
- `AV` : Attack Vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)
- `AC` : Attack Complexity
- `PR` : Privileges Required
- `UI` : User Interaction
- `S` : Scope (CHANGED / UNCHANGED)
- impacts : `C/I/A`

✅ Pourquoi v3.x est important :
- plus représentatif de la réalité
- meilleur pour la priorisation opérationnelle

---

## 4.7 CVSS v4.0 (nouveau)

### 4.7.1 Où le trouver dans la NVD
CVSS v4 se trouve dans :
- `metrics.cvssMetricV40[]`

Exemple :
```json
"metrics": {
  "cvssMetricV40": [
    {
      "cvssData": {
        "version": "4.0",
        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/...",
        "baseScore": 10.0,
        "baseSeverity": "CRITICAL"
      }
    }
  ]
}

```
### 4.7.2 Points importants v4.0
- v4.0 introduit des métriques supplémentaires et une granularité supérieure
- v4.0 est particulièrement visible sur des CVE récentes
- nécessite une ingestion capable de supporter de nouveaux champs / vecteurs

✅ Bonne pratique :
- supporter la présence de v4.0 même si les règles internes restent basées sur v3.1

---

## 4.8 Gestion multi-version CVSS (v2 + v3 + v4)

### 4.8.1 Pourquoi plusieurs versions peuvent coexister
Selon l’âge de la CVE et son niveau d’enrichissement NVD, il est possible d’avoir :
- uniquement v2 (CVE très anciennes)
- v2 + v3.1 (cas courant)
- v4.0 (CVE récentes)

📌 Conclusion :  
un pipeline NVD doit être capable de lire plusieurs versions.

### 4.8.2 Règle de sélection recommandée
Dans un outil interne, pour un champ “score principal”, utiliser :

1. CVSS v4.0 si présent
2. sinon CVSS v3.1
3. sinon CVSS v3.0
4. sinon CVSS v2.0
5. sinon : non scoré

---

## 4.9 Bonnes pratiques d’exploitation CVSS (SOC / SIEM / Vuln Mgmt)

### 4.9.1 Ne pas confondre score et risque
CVSS mesure une sévérité technique standardisée.

⚠️ CVSS ≠ risque métier.  
La priorisation doit tenir compte de :
- l’exposition (internet vs interne)
- l’existence d’un exploit public
- la criticité de l’application
- les mesures compensatoires existantes

---

### 4.9.2 Alerting SOC / SIEM (exemple de règles)
Exemples de règles simples :

- alerter si `baseSeverity = CRITICAL`
- alerter si `baseScore >= 9.0` ET `AV = NETWORK`
- alerter si `baseScore >= 7.5` ET vulnérabilité touche un asset critique

---

### 4.9.3 Stockage recommandé (modèle interne)
Pour faciliter l’exploitation, stocker :
- `cvss_version_selected`
- `cvss_vector_selected`
- `cvss_baseScore_selected`
- `cvss_baseSeverity_selected`
- garder aussi les versions natives :
  - `cvss_v2`
  - `cvss_v31`
  - `cvss_v40`

---

## 4.10 Points de vigilance
- les scores peuvent évoluer (mise à jour NVD/CNA)
- une CVE peut ne pas être scorée au début (`vulnStatus = Received`)
- certaines sources peuvent fournir un score “Secondary” avant analyse complète
- l’absence de score ne signifie pas absence de risque (juste absence d’analyse)
