from pydantic import ValidationError
from src.common.schemas.threat_graph_entities import ThreatGraph

def parse_threat_graph(payload: dict) -> ThreatGraph:
    """
    Parse et valide un dictionnaire JSON vers le modèle ThreatGraphRoot.
    Lève une ValueError avec un message clair en cas d'erreur.
    """
    
    # 1. Vérification explicite de la version (Acceptance Criteria)
    if "schema_version" not in payload:
        raise ValueError("Erreur de validation : Le champ obligatoire 'schema_version' est manquant à la racine du JSON.")

    try:
        # 2. Validation globale via Pydantic
        return ThreatGraph(**payload)
        
    except ValidationError as e:
        # 3. Transformation des erreurs Pydantic en messages "user-friendly"
        # On récupère le premier message d'erreur pour rester simple
        error = e.errors()[0]
        location = " -> ".join([str(loc) for loc in error['loc']])
        message = error['msg']
        
        raise ValueError(f"Structure JSON invalide au niveau de [{location}] : {message}")
    

if __name__ == "__main__":
    import json
    # On utilise un chemin relatif par rapport à la racine du projet
    import os

    print("Lancement des tests...")

    file_path = "tests/fixtures/sample.json"
    
    if not os.path.exists(file_path):
        print(f"❌ Erreur : Le fichier {file_path} est introuvable.")
    else:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Test 1 : JSON valide
        try:
            result = parse_threat_graph(data)
            print("✅ Test valide : OK")
        except Exception as e:
            print("❌ Test valide : ERREUR ->", e)

        # Test 2 : schema_version manquant
        try:
            bad_data = data.copy()
            if "schema_version" in bad_data:
                bad_data.pop("schema_version")
            parse_threat_graph(bad_data)
            print("❌ Test schema_version : ERREUR NON LEVÉE")
        except ValueError as e:
            print("✅ Test schema_version : OK (Erreur bien capturée) ->", e)