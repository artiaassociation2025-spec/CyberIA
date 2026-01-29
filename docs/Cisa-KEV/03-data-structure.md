# 3. Structure des données — Format JSON / CSV (CISA KEV)

## 3.1 Objectif de cette section
Cette section décrit la structure des données du **catalogue CISA KEV** aux formats **JSON** et **CSV**, afin de permettre :
- l’ingestion des vulnérabilités KEV (ETL/ELT),
- l’exploitation dans des outils internes (SIEM, SOC, dashboards),
- la normalisation des champs (modèle interne),
- la priorisation de remédiation basée sur une source “exploitation confirmée”.

L’objectif est de comprendre **où se trouve chaque information** : CVE ID, vendor/product, description, date d’ajout, actions requises, échéances (dueDate), indicateurs ransomware, notes.

---

## 3.2 Format général des données KEV
Les données KEV sont publiées et maintenues par la CISA sous la forme :
- d’un **fichier CSV** (très utilisé pour ingestion rapide / Excel / BI),
- d’un **fichier JSON** (plus adapté aux intégrations applicatives et pipelines data).

Chaque vulnérabilité KEV est une entrée représentant une **CVE** reconnue comme **activement exploitée**.

> Contrairement à NVD, KEV ne contient pas l’ensemble des CVE mais une liste restreinte de CVE priorisées (exploitation confirmée).

---

## 3.3 Format CSV (KEV)
Le format CSV contient une ligne par vulnérabilité KEV.
C’est le format le plus simple pour ingestion dans :
- data lake (zone raw/bronze),
- outils de reporting,
- extraction quotidienne.

### Colonnes usuelles
Les colonnes les plus importantes sont :
- `cveID`
- `vendorProject`
- `product`
- `vulnerabilityName`
- `dateAdded`
- `shortDescription`
- `requiredAction`
- `dueDate`
- `knownRansomwareCampaignUse`
- `notes`

✅ Bonnes pratiques :
- ingérer le CSV dans une zone “raw” inchangée
- normaliser les types (dates, booléens)
- conserver un hash du fichier ou une version par date de collecte

---

## 3.4 Format JSON (KEV)

### 3.4.1 Structure top-level
Le JSON KEV suit généralement une structure contenant des métadonnées + une liste d’entrées.

Structure attendue : **exemple**
```json
{
"title": "CISA Known Exploited Vulnerabilities Catalog",
"catalogVersion": "2024.07.09",
"dateReleased": "2024-07-09",
"count": 1130,
"vulnerabilities": [
{
"cveID": "CVE-2021-44228",
"vendorProject": "Apache",
"product": "Log4j",
"vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
"dateAdded": "2021-12-10",
"shortDescription": "Apache Log4j2 vulnerability may allow remote code execution.",
"requiredAction": "Apply updates per vendor instructions.",
"dueDate": "2021-12-24",
"knownRansomwareCampaignUse": "Known",
"notes": ""
}
]
}
```
> ⚠️ Les champs top-level peuvent évoluer dans le temps (ajout ou modification de métadonnées).  
> L’ingestion doit être tolérante aux champs additionnels.

### Champs globaux clés (top-level)
- `catalogVersion`
- `dateReleased`
- `count`
- `vulnerabilities[]`

✅ Usage opérationnel :
- `dateReleased` et `catalogVersion` peuvent être utilisés pour :
  - détecter les mises à jour,
  - tracer les versions ingérées,
  - fiabiliser l’audit et la reproductibilité des analyses.

---

## 3.5 Détail champ par champ (modèle de données KEV)

### 3.5.1 `cveID` — Identifiant CVE
- **Type** : string
- **Exemple** : `CVE-2021-44228`
- **Usage** :
  - clé primaire naturelle dans un data lake / base interne,
  - pivot de corrélation avec NVD, EPSS, scanners et CTI,
  - identifiant commun entre les systèmes de gestion vulnérabilités.

✅ Bonnes pratiques :
- stocker sous `cve_id` (unique)
- normaliser en uppercase
- appliquer une validation regex (`CVE-YYYY-NNNN...`)

---

### 3.5.2 `vendorProject` — Éditeur / projet
- **Type** : string
- **Exemple** :`Apache`, `Microsoft`, `Cisco`

📌 Interprétation :
- représente l’éditeur ou le projet associé à la CVE au sens CISA,
- ne correspond pas toujours strictement aux nomenclatures CPE/NVD.

✅ Usage :
- regroupement par éditeur (reporting),
- attribution d’ownership (équipes responsables),
- segmentation des actions correctives par vendor.

⚠️ Point de vigilance :
- valeurs non strictement normalisées (variantes possibles),
- recommandation d’utiliser un mapping interne.

---

### 3.5.3 `product` — Produit affecté
- **Type** : string
- **Exemple** : `Log4j`, `Exchange Server`, `FortiOS`, `Chrome`

✅ Usage :
- identification du périmètre technique,
- matching avec inventaire logiciel / CMDB (via règles internes),
- alimentation de dashboards patch management.

⚠️ Important :
KEV ne fournit généralement pas de CPE.  
Le matching assets → KEV nécessite :
- un mapping vendor/product interne,
- ou un enrichissement par NVD/CPE.

---

### 3.5.4 `vulnerabilityName` — Nom court / libellé
- **Type** : string
- **Exemple** : `Log4Shell`, `ProxyLogon`, `Follina`

✅ Usage :
- affichage dashboard / ticketing,
- regroupement en campagnes (familles de vulnérabilités),
- communication (comités, reporting opérationnel).

---

### 3.5.5 `dateAdded` — Date d’ajout au catalogue KEV
- **Type** : date (ISO `YYYY-MM-DD`)
- **Exemple** : `2021-12-10`

📌 Interprétation :
- date à laquelle la CISA a ajouté la CVE au catalogue KEV,
- reflète un signal d’exploitation confirmée.

✅ Usage opérationnel :
- ingestion incrémentale,
- déclenchement d’un workflow (ticket, incident, campagne),
- mesure de réactivité (MTTR depuis KEV).

⚠️ Point important :
- `dateAdded` ne correspond pas à la date de publication initiale de la CVE,
- une CVE ancienne peut être ajoutée tardivement.

---

### 3.5.6 `shortDescription` — Description synthétique
- **Type** : string
- **Exemple** : `Apache Log4j2 vulnerability may allow remote code execution.`

✅ Usage :
- triage rapide,
- description dans les tickets,
- classification (NLP / IA / tags internes).

✅ Bonnes pratiques :
- conserver le texte original KEV,
- enrichir via NVD/advisories si besoin de détails techniques.

---

### 3.5.7 `requiredAction` — Action requise
- **Type** : string
- **Exemple** :  `Apply updates per vendor instructions.`

✅ Usage :
- champ directement exploitable dans les tickets,
- justification de la correction (audit, conformité),
- base pour automatiser les actions (patch/mitigation).

⚠️ Limite :
- l’action est souvent générique,
- absence fréquente de :
  - patch exact,
  - bulletin/KB,
  - URL directe.

➡️ Recommandation :
enrichir via avis éditeur et/ou references NVD.

---

### 3.5.8 `dueDate` — Échéance de remédiation attendue
- **Type** : date (ISO `YYYY-MM-DD`)
- **Exemple** : `2021-12-24`

✅ Usage :
- pilotage SLA,
- gestion du backlog,
- priorisation automatique.

📌 Interprétation :
- utilisé par la CISA dans un contexte de conformité (BOD),
- constitue un excellent signal de criticité opérationnelle.

✅ Bonnes pratiques :
- calculer `delta = dueDate - today`,
- déclencher alerting lorsque proche ou dépassée,
- mapper vers une priorité interne (P0/P1/P2).

---

### 3.5.9 `knownRansomwareCampaignUse` — Usage ransomware
- **Type** : string (`Known` / `Unknown`)
- **Exemple** : `Known`

📌 Interprétation :
- indique si la vulnérabilité est associée à des campagnes ransomware observées.

✅ Usage :
- augmentation automatique de priorité,
- reporting “ransomware exposure”,
- alerting direction / risques.

⚠️ Limite :
- indicateur non exhaustif,
- ne signifie pas que l’exploitation est exclusivement ransomware.

---

### 3.5.10 `notes` — Informations complémentaires
- **Type** : string (optionnel)
- **Exemple** : `Widely exploited vulnerability impacting multiple sectors.`

✅ Usage :
- enrichissement contexte,
- gestion d’exceptions,
- exploitation CTI.

---

## 3.6 Modèle interne recommandé (normalisation)
Pour ingestion et exploitation, un modèle minimal recommandé :

- `cve_id`
- `vendor`
- `product`
- `vuln_name`
- `short_description`
- `date_added`
- `due_date`
- `required_action`
- `known_ransomware_use`
- `notes`
- `source` (valeur constante : `CISA_KEV`)
- `ingested_at` (timestamp pipeline)
- `catalog_version` (si disponible)

---

## 3.7 Règles d’exploitation recommandées (pipeline)
KEV étant une source de priorisation, les règles suivantes sont recommandées :

1. **Toute CVE présente dans KEV doit être considérée comme prioritaire**
2. pondérer la priorité selon :
   - `knownRansomwareCampaignUse = Known` → priorité augmentée
   - `dueDate` proche ou dépassée → criticité maximale
3. enrichir systématiquement par NVD :
   - CVSS, CWE, CPE (périmètre produit/version)
4. corréler avec inventaire :
   - matching vendor/product,
   - mapping vers CPE dès que possible.

---

## 3.8 Résumé exploitation (à retenir)
Pour exploiter KEV efficacement :

- utiliser `cveID` comme identifiant unique
- utiliser `dateAdded` pour synchro incrémentale et déclenchement de workflow
- exploiter `dueDate` pour la priorisation/SLA
- exploiter `requiredAction` comme base actionnable (ticketing)
- exploiter `knownRansomwareCampaignUse` comme signal de menace forte
- enrichir par NVD/éditeur pour obtenir patch exact et périmètre produit (CPE)
