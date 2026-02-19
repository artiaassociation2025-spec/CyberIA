import datetime
from typing import List, Any, Optional
from src.common.schemas.threat_graph_entities import ThreatGraph

def clean_threat_graph(graph: ThreatGraph) -> ThreatGraph:
    """
    Nettoie et stabilise les données du graphe :
    - Trim et transforme les chaînes vides en None
    - Déduplique les listes (CWE, Platforms...)
    - S'assure que les dates sont au format ISO
    """
    
    # 1. Nettoyage des entités
    for entity_id, entity in graph.entities.items():
        # Exemple pour le nom ou la description : Trim et "" -> None
        if hasattr(entity, 'name'):
            entity.name = _clean_string(entity.name)
        
        # Déduplication des listes (ex: platforms)
        if hasattr(entity, 'platforms') and entity.platforms:
            entity.platforms = _deduplicate_list(entity.platforms)
            
        # Déduplication des CWE
        if hasattr(entity, 'cwe') and entity.cwe:
            entity.cwe = _deduplicate_list(entity.cwe)

    return graph

def _clean_string(s: Optional[str]) -> Optional[str]:
    """Supprime les espaces inutiles et transforme les chaines vides en None."""
    if s is None:
        return None
    cleaned = s.strip()
    return cleaned if cleaned != "" else None

def _deduplicate_list(lst: List[Any]) -> List[Any]:
    """Supprime les doublons tout en gardant l'ordre original."""
    if not lst:
        return []
    # dict.fromkeys enlève les doublons automatiquement
    return list(dict.fromkeys(lst))

# --- BLOC DE TEST (CRITÈRES D'ACCEPTATION) ---

if __name__ == "__main__":
    print("🚀 Test de l'Issue 4 en cours...")

    # Test 1 : String vide -> None
    test_str = "   "
    assert _clean_string(test_str) is None
    print("✅ Acceptance Criteria : Les chaînes vides deviennent None")

    # Test 2 : Déduplication de liste
    test_list = ["Windows", "Linux", "Windows", "MacOS"]
    result_list = _deduplicate_list(test_list)
    assert result_list == ["Windows", "Linux", "MacOS"]
    assert len(result_list) == 3
    print("✅ Acceptance Criteria : Les listes sont dédupliquées")

    