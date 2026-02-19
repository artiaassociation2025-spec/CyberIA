import os
import json
from typing import List, Set
from src.common.schemas.threat_graph_entities import ThreatGraph
from src.normalization_api.parsers.threat_graph_json import parse_threat_graph

def validate_references(graph: ThreatGraph):
    """
    Vérifie l'intégrité référentielle du graphe.
    Lève une ValueError si des IDs sont manquants.
    """
    # 1. On récupère TOUS les IDs d'entités valides
    all_valid_ids: Set[str] = set(graph.entities.keys())
    
    missing_ids = []

    # 2. Vérification des Relations (from / to)
    for rel in graph.relationships:
        if rel.from_id not in all_valid_ids:
            missing_ids.append(f"Relationship source inconnue: {rel.from_id}")
        if rel.to_id not in all_valid_ids:
            missing_ids.append(f"Relationship destination inconnue: {rel.to_id}")

    # 3. Vérification des liens internes (ex: techniques -> tactics)
    for entity in graph.entities.values():
        if hasattr(entity, 'tactic_refs') and entity.tactic_refs:
            for tactic_id in entity.tactic_refs:
                if tactic_id not in all_valid_ids:
                    missing_ids.append(f"Tactic manquante pour l'entité {entity.id}: {tactic_id}")

    # 4. Rapport d'erreur
    if missing_ids:
        error_msg = "\n".join(missing_ids)
        raise ValueError(f"Erreur d'intégrité référentielle :\n{error_msg}")

    return True

# --- TEST AVEC LE VRAI SAMPLE.JSON ---

if __name__ == "__main__":
    print(" Test de l'Issue 5 : Validation des refs avec sample.json...")

    # Chemin vers ton fichier de test
    file_path = "tests/fixtures/sample.json"

    if not os.path.exists(file_path):
        print(f" Erreur : Le fichier {file_path} est introuvable.")
    else:
        try:
            # 1. Charger et parser le vrai JSON
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            graph_object = parse_threat_graph(data)
            
            # 2. Lancer la validation
            validate_references(graph_object)
            print(" Test réussi : Toutes les références du sample.json sont valides !")
            
        except ValueError as e:
            print(f" Test échoué : Des erreurs de références ont été trouvées :\n{e}")
        except Exception as e:
            print(f" Erreur inattendue : {e}")