import os
from rdflib import Namespace

# 1. On essaie de lire la variable 'CYBERIA_BASE_IRI' sur l'ordi
# 2. Si elle n'existe pas, on utilise l'adresse par défaut (le "fallback")
BASE_IRI = os.getenv("CYBERIA_BASE_IRI", "https://cyberia.org/data/")

# On crée les namespaces basés sur cette adresse
CYBER = Namespace(BASE_IRI + "entity/")
SOURCE = Namespace(BASE_IRI + "source/")