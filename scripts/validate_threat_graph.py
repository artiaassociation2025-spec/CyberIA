import json
import sys
from jsonschema import validate, ValidationError
from pathlib import Path

# --- CONFIGURATION DES CHEMINS ---
# Le script est dans : CyberIA/scripts/validate_threat_graph.py
SCRIPT_PATH = Path(__file__).resolve()
# Racine du projet (Projet IA)
ROOT_DIR = SCRIPT_PATH.parent.parent.parent

SCHEMA_PATH = ROOT_DIR / "CyberIA" / "src" / "common" / "schemas" / "threat_graph_input.schema.json"

def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main(json_to_test):
    try:
        # On charge le schéma
        schema = load_json(SCHEMA_PATH)
        
        # On charge le fichier à tester (chemin relatif ou absolu)
        target_path = Path(json_to_test).resolve()
        data = load_json(target_path)
        
        # Validation
        validate(instance=data, schema=schema)
        print(f"✅ VALIDE : {target_path.name}")

    except ValidationError as ve:
        print(f"❌ ERREUR DE VALIDATION dans {json_to_test} :")
        print(f"   -> Message: {ve.message}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"⚠️ ERREUR DE FICHIER : {e}")
        sys.exit(1)
    except Exception as e:
        print(f"💥 ERREUR INATTENDUE : {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_threat_graph.py <fichier_a_tester>")
        sys.exit(1)
    main(sys.argv[1])