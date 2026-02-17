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

##  Issue 3 — Parser et point d’entrée de validation

### Fichier concerné
- `src/normalization_api/parsers/threat_graph_json.py`

### Description
Cette étape met en place la fonction principale :