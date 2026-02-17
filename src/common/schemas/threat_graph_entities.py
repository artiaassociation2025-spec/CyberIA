from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Optional, Any

class Source(BaseModel):
    id: str
    name: str
    type: str
    trust: float = Field(..., ge=0.0, le=1.0)

class Relationship(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: Optional[str] = None
    type: str
    from_id: str = Field(..., alias="from")
    to: str

# --- Toutes les entités de l'Issue #2 ---
class EntityBase(BaseModel):
    id: str
    name: Optional[str] = None

class Tactic(EntityBase): pass
class Technique(EntityBase): pass
class Group(EntityBase): pass
class Software(EntityBase): pass
class Product(EntityBase): pass
class CVE(EntityBase): 
    cvss_score: Optional[float] = None
class Advisory(EntityBase): pass
class ENISAThreat(EntityBase): pass
class NIS2Sector(EntityBase): pass
class Control(EntityBase): pass
class Indicator(EntityBase): pass

class ThreatGraph(BaseModel):
    schema_version: str
    generated_at: str
    sources: List[Source]
    entities: Dict[str, List[Dict[str, Any]]] 
    relationships: List[Relationship]