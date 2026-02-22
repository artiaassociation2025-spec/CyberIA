import json
import os
from typing import Dict, Any
from src.common.schemas.threat_graph_entities import ThreatGraph


def canonicalize_threat_graph(graph: ThreatGraph, output_path: str = None) -> Dict[str, Any]:
    """
    Canonicalise le ThreatGraph :
    - Trie les entités par ID
    - Trie les relations
    - Génère un JSON stable
    - Sauvegarde si output_path est fourni
    """

    # Convertir en dict
    graph_dict = graph.model_dump()

    # Trier les entités par ID
    if "entities" in graph_dict:
        graph_dict["entities"] = dict(sorted(graph_dict["entities"].items()))

    # Trier les relations
    if "relationships" in graph_dict:
        graph_dict["relationships"] = sorted(
            graph_dict["relationships"],
            key=lambda r: (r.get("from_id", ""), r.get("to_id", ""))
        )

    # Sauvegarde si demandé
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                graph_dict,
                f,
                indent=2,
                sort_keys=True
            )

    return graph_dict

# --- TEST AVEC SAMPLE.JSON ---

if __name__ == "__main__":
    import json
    from src.normalization_api.parsers.threat_graph_json import parse_threat_graph

    print("Test Issue 6 - Canonicalizer")

    # Charger sample.json
    with open("tests/fixtures/sample.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    graph = parse_threat_graph(data)

    # Chemin de sortie
    output_path = "data/curated/threat_graph.json"

    # Exécution 1 + export vers curated 
    result1 = canonicalize_threat_graph(graph,output_path)
    print("Export réussi :", output_path)

    # Exécution 2
    result2 = canonicalize_threat_graph(graph)

    # Test 1 — JSON stable
    assert result1 == result2
    #print(result1,result2)
    print(" Test ordre stable : OK")

    # Test 2 — IDs triés
    entity_ids = list(result1["entities"].keys())
    sorted_ids = sorted(entity_ids)

    assert entity_ids == sorted_ids
    print("Test tri par ID : OK")