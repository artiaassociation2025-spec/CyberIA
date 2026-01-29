# 4. Priorisation KEV vs CVSS (et autres scores)

## 4.1 Objectif de cette section
Cette section explique comment exploiter le catalogue **CISA KEV** dans une logique de **priorisation opérationnelle**, et comment interpréter KEV par rapport à :
- les scores **CVSS** (issus de la NVD / CNA),
- la sévérité “technique” vs le risque réel,
- les signaux complémentaires (exploitation active, ransomware, dueDate).

Objectif opérationnel : permettre aux équipes SOC/SIEM/Vuln Mgmt de **prioriser correctement** en s’appuyant sur KEV.

---

## 4.2 KEV n’est pas un score
Contrairement à la NVD, le catalogue KEV :
- ne fournit **pas de score numérique** (comme CVSS),
- ne fournit **pas de severity LOW/MEDIUM/HIGH/CRITICAL**,
- ne fournit pas de vecteur d’exploitation (`vectorString`).

KEV est un **signal de menace réel** :
> “Cette vulnérabilité est exploitée dans la nature”.

➡️ En pratique : **KEV = priorisation directe**, sans calcul de score.

---

## 4.3 Différence entre CVSS et KEV (Severity vs Threat)

### 4.3.1 CVSS (NVD)
CVSS représente une **sévérité technique** basée sur :
- conditions d’exploitation (vecteur),
- impact sur C/I/A,
- prérequis (auth, interaction user, etc.).

📌 CVSS répond à :  
> “À quel point c’est grave techniquement ?”

### 4.3.2 KEV (CISA)
KEV représente une **preuve d’exploitation active**.

📌 KEV répond à :  
> “Est-ce que c’est réellement attaqué maintenant (in the wild) ?”

✅ Conclusion :
- CVSS = sévérité technique standardisée
- KEV = criticité opérationnelle (threat-driven)

---

## 4.4 Pourquoi KEV est prioritaire sur CVSS
Le CVSS seul ne suffit pas à décider.

Exemples de situations fréquentes :
- CVSS élevé mais exploitation rare/non observée
- CVSS moyen (ex: 6–7) mais exploitation massive “in the wild”
- vuln avec exploit public, wormable, scans massifs

➡️ KEV est une preuve “terrain”, donc **très actionnable**.

✅ Règle recommandée :
> Toute vulnérabilité KEV doit être traitée en priorité, même si son CVSS est moyen.

---

## 4.5 Champ `dueDate` (SLA opérationnel)
Le champ `dueDate` est un élément clé de priorisation.

### Pourquoi c’est important
Il fournit une **échéance de remédiation attendue**, initialement liée aux obligations fédérales (BOD), mais très utile pour tout programme vulnérabilités.

✅ Usage opérationnel :
- suivi SLA patching
- backlog management
- escalade automatique (si dueDate dépassée)

⚠️ Point important :
- `dueDate` peut être vide selon les entrées
- ne doit pas être interprété comme “la vuln n’est pas urgente” si absent

---

## 4.6 Champ `knownRansomwareCampaignUse`
Le champ `knownRansomwareCampaignUse` indique si la vulnérabilité est associée à des campagnes ransomware observées.

### Valeurs
- `Known` : exploitation liée à ransomware confirmée
- `Unknown` : non confirmé (≠ non utilisé)

✅ Usage opérationnel :
- augmenter la priorité (P0/P1)
- reporting “ransomware exposure”
- focus direction / risques

---

## 4.7 Approche de priorisation recommandée (KEV + enrichissement)
KEV donne le signal “prioritaire”, mais pour piloter une remédiation complète il faut enrichir avec :
- **NVD** : CVSS, CWE, CPE, références techniques
- **scanners vuln** : preuve d’exposition réelle sur asset
- **CMDB/inventaire** : criticité asset, exposition internet, env PROD

---

## 4.8 Règles pratiques de scoring interne (exemple)
Pour créer une logique simple de priorisation automatisée :

### 4.8.1 Priorité immédiate (P0)
- CVE ∈ KEV
- ET (`knownRansomwareCampaignUse = Known` **OU** `dueDate` < aujourd’hui)

### 4.8.2 Haute priorité (P1)
- CVE ∈ KEV
- ET asset exposé internet ou critique (PROD)

### 4.8.3 Priorité standard (P2)
- CVE ∈ KEV
- ET asset non exposé + faible criticité

---

## 4.9 Bonnes pratiques d’exploitation KEV (SOC / SIEM / Vuln Mgmt)

### 4.9.1 Ne pas confondre “présence KEV” et “impact local”
KEV confirme l’exploitation, mais cela ne signifie pas que :
- ton environnement est affecté
- ton produit/version est vulnérable

➡️ Il faut valider via :
- CPE/NVD
- inventaire interne
- scan vuln / preuve locale

---

### 4.9.2 Alerting SOC / SIEM (exemple de règles)
Exemples de règles simples (opérationnelles) :
- alerter si vulnérabilité d’un asset ∈ KEV
- alerter si vulnérabilité ∈ KEV + exposée internet
- alerter si vulnérabilité ∈ KEV + `knownRansomwareCampaignUse = Known`
- alerter si vulnérabilité ∈ KEV + `dueDate` dépassée

---

### 4.9.3 Stockage recommandé (modèle interne)
Pour faciliter exploitation et reporting, stocker :
- `is_kev` (bool)
- `kev_date_added`
- `kev_due_date`
- `kev_required_action`
- `kev_known_ransomware_use`
- `kev_catalog_version`
- enrichissements associés :
  - `cvss_selected_version`
  - `cvss_selected_score`
  - `cvss_selected_severity`
  - `cpe_list` (depuis NVD)
  - `epss_score` (si utilisé)

---
### 4.9.4 Comprendre et exploiter `dueDate` (SLA / Urgence)

Le champ **`dueDate`** correspond à une **date limite** indiquant à quel moment la vulnérabilité KEV doit être corrigée.

📌 Interprétation :
- `dueDate` représente une **deadline de remédiation** (SLA),
- elle ne correspond pas à la date de publication de la CVE,
- elle ne signifie pas que l’exploitation commence à cette date : la CVE est déjà exploitée (*KEV = exploited in the wild*).

---

#### Exemple — `dueDate` dans le futur (encore dans les temps)
Supposons :
- **today = 2026-01-29**
- **dueDate = 2026-03-10**

➡️ Interprétation :
- ✅ tu es encore dans les temps
- ✅ tu peux planifier la correction (tests, change)
- ⚠️ mais la vulnérabilité est déjà exploitée, donc il faut éviter d’attendre la dernière minute

---

#### Exemple — `dueDate` dans le passé (retard / overdue)
Supposons :
- **today = 2026-01-29**
- **dueDate = 2025-12-15**

➡️ Interprétation :
- 🚨 tu es en retard
- 🚨 vuln KEV overdue = priorité maximale
- ✅ escalade / traitement immédiat recommandé

---

✅ Bonnes pratiques :
- calculer `days_remaining = dueDate - today`
- définir un statut :
  - `ON_TRACK` si `days_remaining > 0`
  - `DUE_SOON` si `days_remaining <= 7` (seuil configurable)
  - `OVERDUE` si `days_remaining < 0`
- si asset exposé Internet → correction ASAP même si `dueDate` est loin
---

## 4.10 Points de vigilance
- KEV ne donne pas de CVSS : enrichissement nécessaire
- `Unknown` ransomware ≠ safe
- `requiredAction` est souvent générique (patch exact à trouver chez l’éditeur)
- le catalogue KEV évolue régulièrement (nouvelles entrées)
- une CVE peut être exploitée avant d’apparaître dans KEV (délai d’ajout)
