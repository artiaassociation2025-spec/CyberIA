##  Issue 1 — Mise en place du JSON Schema et Validation

### Fichiers concernés
- `schemas/threat_graph.schema.json`
- `scripts/validate_json.py`
- `tests/fixtures/sample.json`

### Description
Cette étape définit la “source de vérité” du projet.  
Le JSON Schema précise :

- Les champs obligatoires (ex : `schema_version`, `entities`)
- Le type des données
- Les formats attendus (ex : ISO8601 pour les dates)

### Rôle principal
Vérifier qu’un fichier JSON est valide avant toute utilisation en Python.

### Spécificité
Il s’agit d’une validation **statique**, réalisée avant l’exécution du programme.

---

##  Issue 2 — Modèles Pydantic pour les entités

### Fichier concerné
- `src/common/schemas/threat_graph_entities.py`

### Description
Cette étape traduit le JSON Schema en classes Python à l’aide de Pydantic.

Elle permet de :

- Garantir le typage des données
- Structurer les objets complexes (Sources, Entities, Relationships)
- Sécuriser les données en mémoire

### Rôle principal
Créer une représentation fiable et typée du threat graph en Python.

### Spécificité
Il s’agit d’une validation **dynamique**, appliquée à l’exécution.

Elle facilite également l’autocomplétion et la détection d’erreurs dans l’IDE.

---

## Issue 3 — Parser et point d’entrée de validation

### Fichier concerné
src/normalization_api/parsers/threat_graph_json.py

### Description
Cette étape met en place la fonction principale qui permet de transformer un JSON en objet Python.

La fonction `parse_threat_graph(payload: dict)` :
- Prend un JSON en entrée
- Vérifie que les champs obligatoires existent (ex : schema_version)
- Convertit les données en objet ThreatGraph
- Lève des erreurs claires si le JSON est invalide

### Rôle principal
Servir de point d’entrée pour charger et valider un threat graph.

### Spécificité
C’est la première validation côté Python.  
Elle garantit que les données sont exploitables dans le code.

### Acceptance Criteria
- Un test appelle parse_threat_graph avec sample.json
- Si schema_version manque → erreur explicite

---

## Issue 4 — Nettoyage et Stabilisation des données (Cleaning)

### Fichier concerné
src/normalization_api/cleaning/threat_graph_cleaner.py

### Description
Cette étape consiste à nettoyer les données pour les rendre propres et cohérentes.

Le module permet de :
- Supprimer les espaces inutiles dans les chaînes
- Transformer les chaînes vides ("") en None
- Supprimer les doublons dans les listes
- Uniformiser les données

### Rôle principal
Garantir que les données sont propres avant validation.

### Spécificité
C’est la phase de nettoyage.  
Elle évite les doublons et les valeurs vides.

### Acceptance Criteria
- Un test prouve que "" devient None
- Un test prouve que ["Windows","Windows"] devient ["Windows"]

---

## Issue 5 — Validation de l’intégrité référentielle (Refs)

### Fichier concerné
src/normalization_api/validators/threat_graph_refs.py

### Description
Cette étape vérifie que toutes les références du graphe existent.

Le validateur vérifie que :
- Les from_id existent
- Les to_id existent
- Les références internes existent

### Rôle principal
Éviter les liens invalides dans le graphe.

### Spécificité
Si un ID est manquant, une erreur est levée avec la liste des IDs manquants.

### Acceptance Criteria
- Si une ref est invalide → erreur
- Test avec sample.json
- Test avec ID inconnu → échec