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
- `src/normalization_api/parsers/threat_graph_json.py`

### Description
Mise en place de la fonction `parse_threat_graph(payload: dict)` qui transforme un JSON en objet Python et lève des erreurs claires en cas d'invalidité.

### Rôle principal
Servir de point d’entrée pour charger et valider un threat graph.

---

## Issue 4 — Nettoyage et Stabilisation des données (Cleaning)

### Fichier concerné
- `src/normalization_api/cleaning/threat_graph_cleaner.py`

### Description
Nettoyage des données : suppression des espaces inutiles, transformation des chaînes vides en `None` et suppression des doublons.

### Rôle principal
Garantir que les données sont propres avant validation.

---

## Issue 5 — Validation de l’intégrité référentielle (Refs)

### Fichier concerné
- `src/normalization_api/validators/threat_graph_refs.py`

### Description
Vérifie que tous les liens (`from_id`, `to_id`) pointent bien vers des entités existantes dans le graphe.

### Rôle principal
Éviter les liens invalides dans le graphe.

---

## Issue 6 — Canonicalisation et Sortie JSON Stable

### Fichier concerné
- `src/normalization_api/canonicalizer/threat_graph_canonicalizer.py`

### Description
Cette étape transforme le ThreatGraph en un dictionnaire dont l'ordre est fixe. Elle trie les entités par leur identifiant unique et les clés par ordre alphabétique.

### Rôle principal
Garantir que la sortie JSON est déterministe et identique à chaque exécution.

### Acceptance Criteria
- Les entités sont triées par ID dans le fichier final.
- Le fichier `data/curated/threat_graph.json` est généré.

---

## Issue 7 — Centralisation des préfixes et construction d’IRIs

### Fichiers concernés
- `src/ontology_api/ttl_builder/namespaces.py`
- `src/ontology_api/ttl_builder/iri.py`

### Description
Passage du JSON au Web sémantique par la création d’IRIs (Internationalized Resource Identifiers).
- Définition des Namespaces via `BASE_IRI`.
- Création des fonctions `iri_for` et `iri_source`.

### Rôle principal
Attribuer une identité unique et globale à chaque élément pour permettre l'interconnexion en RDF.

### Acceptance Criteria
- La `BASE_IRI` est configurable.
- Les IRIs générées sont stables (stabilité prouvée par test).