from rdflib import URIRef
from src.ontology_api.ttl_builder.namespaces import CYBER, SOURCE

def iri_for(entity_id: str) -> URIRef:
    """Transforme un ID d'entité en IRI stable."""
    # Règle : on nettoie l'ID et on l'attache au namespace CYBER
    clean_id = entity_id.strip()
    return CYBER[clean_id]

def iri_source(source_id: str) -> URIRef:
    """Transforme un ID de source en IRI stable."""
    clean_id = source_id.strip()
    return SOURCE[clean_id]

# --- TEST UNITAIRE (Acceptance Criteria) ---
if __name__ == "__main__":
    print("Test de l'Issue 7 : Génération d'IRI...")
    
    test_ids = [
        "vuln--CVE-2024-12345",
        "server--prod-01",
        "indicator--malicious-ip"
    ]
    
    for testid in test_ids:
        iri = iri_for(testid)
        print(f"ID: {testid}  --->  IRI: {iri}")
        
    # Vérification de la stabilité
    assert str(iri_for("A")) == str(iri_for("A"))
    print("\n Acceptance Criteria : Les IRIs sont stables.")