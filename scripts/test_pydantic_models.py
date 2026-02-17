import json
import sys
from pathlib import Path
from pydantic import ValidationError

# Import du modèle (assure-toi que le nom du dossier src est correct)
try:
    from src.common.schemas.threat_graph_entities import ThreatGraph
except ImportError:
    # Au cas où le chemin d'import pose encore problème
    from CyberIA.src.common.schemas.threat_graph_entities import ThreatGraph

def test_models():
    # 1. Calculer le chemin vers sample.json de manière robuste
    # On part du script actuel -> Dossier scripts -> Dossier CyberIA -> tests...
    base_path = Path(__file__).resolve().parent.parent
    sample_path = base_path / "tests" / "fixtures" / "sample.json"
    
    print(f"🔍 Recherche du fichier : {sample_path}")
    
    if not sample_path.exists():
        print(f"❌ Erreur : Le fichier est introuvable à l'adresse : {sample_path}")
        return

    # 2. Charger les données
    with open(sample_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 3. Valider avec Pydantic
    try:
        graph = ThreatGraph(**data)
        print("✅ Pydantic : Importation et instanciation réussies !")
        print(f"   Version : {graph.schema_version}")
        print(f"   Entités trouvées : {list(graph.entities.keys())}")
        
    except ValidationError as e:
        print("❌ Erreur de validation Pydantic :")
        print(e)

if __name__ == "__main__":
    test_models()