# 6. Cycle de vie des vulnérabilités (CISA KEV)

## 6.1 Objectif de cette section
Cette section décrit le **cycle de vie** des vulnérabilités dans le catalogue **CISA KEV**, notamment :
- la fréquence et les mécanismes de mise à jour du catalogue,
- l’évolution d’une entrée KEV dans le temps,
- l’impact des mises à jour sur les champs (`dateAdded`, `dueDate`, ransomware, etc.),
- les bonnes pratiques pour synchroniser et maintenir un référentiel interne KEV à jour.

---

## 6.2 Fréquence de mise à jour du catalogue KEV
Le catalogue KEV est une source vivante : la CISA publie régulièrement des mises à jour.

Les changements typiques sont :
- **ajout de nouvelles entrées** (nouveaux `cveID`)
- mise à jour de certains champs (rare, mais possible) :
  - `requiredAction`
  - `dueDate`
  - `notes`
  - `knownRansomwareCampaignUse`

📌 Champs clés :
- `catalogVersion` et `dateReleased` permettent d’identifier les mises à jour du catalogue.
- `dateAdded` permet d’identifier quand une CVE a rejoint KEV.

---

## 6.3 Évolution d’une entrée KEV dans le temps

### 6.3.1 Étapes typiques
1. **Exploitation observée**
   - la vulnérabilité est exploitée dans la nature (*in the wild*)

2. **Ajout dans KEV**
   - la CVE est intégrée au catalogue
   - attribution de :
     - `dateAdded`
     - `requiredAction`
     - souvent `dueDate`

3. **Exploitation continue et maintien**
   - l’entrée reste présente dans le catalogue KEV
   - la vulnérabilité peut rester plusieurs années dans la liste
   - la `dueDate` peut devenir “historique” (souvent dans le passé)

---

## 6.4 Gestion des changements dans KEV (différences vs NVD)

Contrairement à la NVD :
- KEV ne contient pas d’état de traitement type `vulnStatus`
- KEV ne ré-analyse pas techniquement les CVE (pas de CVSS/CPE/CWE)
- KEV fonctionne comme une liste de priorisation “exploitation confirmée”

### Types de mises à jour possibles
- ajout de nouvelles CVE
- modification ponctuelle des champs informatifs :
  - correction vendor/product
  - précision `vulnerabilityName`
  - update de `requiredAction`
  - update `knownRansomwareCampaignUse`

✅ Conclusion :
le cycle de vie KEV est majoritairement :
> **ADD + MAINTAIN** (ajout + maintien)

---

## 6.5 Impact des mises à jour KEV sur le pilotage opérationnel

### 6.5.1 Changements possibles
- `count` :
  - augmente avec les nouvelles entrées
- `catalogVersion` / `dateReleased` :
  - évoluent à chaque publication
- `dueDate` :
  - peut être ajoutée ou ajustée
- `knownRansomwareCampaignUse` :
  - peut passer de `Unknown` à `Known` selon les observations
- `requiredAction` / `notes` :
  - peut être précisé ou corrigé

### 6.5.2 Impacts opérationnels
- entrée KEV nouvellement ajoutée :
  - déclenchement immédiat de workflow (ticket / campagne)
- `dueDate` proche :
  - escalade et accélération des corrections
- `dueDate` dépassée :
  - statut “overdue” dans le SI

---

## 6.6 Bonnes pratiques pour un pipeline de synchronisation KEV

### 6.6.1 Import initial
Lors du premier import :
- télécharger le catalogue complet (JSON/CSV)
- persister la donnée brute (raw)
- enregistrer :
  - `catalogVersion`
  - `dateReleased`
  - `count`

---

### 6.6.2 Synchronisation incrémentale (recommandée)
Stratégie recommandée :
- synchronisation régulière (quotidienne minimum)
- détection des changements par comparaison de versions :
  - nouvelles CVE (`cveID` non présent en N-1)
  - changements de champs sur CVE existantes (rare mais possible)

✅ Objectif :
- détecter rapidement les nouvelles entrées KEV
- mettre à jour localement les deadlines (`dueDate`) et indicateurs ransomware

---

### 6.6.3 Détection des changements critiques
Dans un contexte SOC / vuln management, surveiller spécifiquement :
- nouvelles entrées KEV ajoutées (`dateAdded` récent)
- vulnérabilités dont `dueDate` approche
- vulnérabilités dont `dueDate` est dépassée
- bascule `knownRansomwareCampaignUse` vers `Known`

---

### 6.6.4 Gestion d’historique (optionnel)
Deux approches possibles :
- **mise à jour en place** (état actuel uniquement)
- **historisation** (snapshots successifs du catalogue)

L’historisation est utile pour :
- audit / preuve de conformité
- analyse temporelle (ajouts par mois)
- justification de priorisation (entrée ajoutée à telle date)

---

## 6.7 Résumé (à retenir)
- Une entrée KEV correspond à une CVE **exploitée dans la nature**
- KEV évolue principalement par **ajout** de nouvelles CVE
- l’entrée reste souvent longtemps dans le catalogue
- `catalogVersion` / `dateReleased` permettent d’identifier les releases
- `dateAdded` indique la date d’entrée d’une CVE dans KEV
- `dueDate` sert de **deadline de remédiation** et peut devenir historique
- une synchronisation régulière + diff entre versions est la méthode recommandée
