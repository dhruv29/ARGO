"""STIX 2.1 bundle export for CTI interoperability."""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

from .retrieve import Evidence


class STIXExporter:
    """Export CTI data to STIX 2.1 bundles."""
    
    def __init__(self):
        self.bundle_id = f"bundle--{uuid.uuid4()}"
        self.objects = []
        self.relationships = []
    
    def add_actor(self, actor_id: str, aliases: List[str], evidence: List[Evidence]) -> str:
        """Add threat actor to STIX bundle."""
        stix_actor_id = f"threat-actor--{uuid.uuid4()}"
        
        # Create threat actor object
        actor_obj = {
            "type": "threat-actor",
            "id": stix_actor_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": actor_id,
            "aliases": aliases,
            "threat_level": "medium",  # Default, could be enhanced
            "labels": ["cti", "argo-generated"],
            "external_references": [
                {
                    "source_name": "argo",
                    "external_id": actor_id
                }
            ]
        }
        
        self.objects.append(actor_obj)
        
        # Add evidence as observed data
        for ev in evidence:
            self._add_evidence(ev, stix_actor_id)
        
        return stix_actor_id
    
    def add_technique(self, technique_id: str, name: str, evidence: List[Evidence]) -> str:
        """Add ATT&CK technique to STIX bundle."""
        stix_technique_id = f"attack-pattern--{uuid.uuid4()}"
        
        # Create attack pattern object
        technique_obj = {
            "type": "attack-pattern",
            "id": stix_technique_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": name,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id}"
                }
            ],
            "labels": ["cti", "argo-generated", "mitre-attack"]
        }
        
        self.objects.append(technique_obj)
        
        # Add evidence
        for ev in evidence:
            self._add_evidence(ev, stix_technique_id)
        
        return stix_technique_id
    
    def add_vulnerability(self, cve_id: str, description: str, evidence: List[Evidence]) -> str:
        """Add CVE vulnerability to STIX bundle."""
        stix_vuln_id = f"vulnerability--{uuid.uuid4()}"
        
        # Create vulnerability object
        vuln_obj = {
            "type": "vulnerability",
            "id": stix_vuln_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": cve_id,
            "description": description,
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
            ],
            "labels": ["cti", "argo-generated", "cve"]
        }
        
        self.objects.append(vuln_obj)
        
        # Add evidence
        for ev in evidence:
            self._add_evidence(ev, stix_vuln_id)
        
        return stix_vuln_id
    
    def _add_evidence(self, evidence: Evidence, related_to: str) -> str:
        """Add evidence as observed data to STIX bundle."""
        stix_evidence_id = f"observed-data--{uuid.uuid4()}"
        
        # Create observed data object
        evidence_obj = {
            "type": "observed-data",
            "id": stix_evidence_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "first_observed": datetime.now(timezone.utc).isoformat(),
            "last_observed": datetime.now(timezone.utc).isoformat(),
            "number_observed": 1,
            "object_refs": [],
            "external_references": [
                {
                    "source_name": "argo",
                    "external_id": evidence.chunk_id,
                    "description": f"Evidence from document {evidence.document_id}, page {evidence.page}"
                }
            ],
            "labels": ["cti", "argo-generated", "evidence"],
            "confidence": evidence.confidence
        }
        
        self.objects.append(evidence_obj)
        
        # Create relationship between evidence and related object
        relationship = {
            "type": "relationship",
            "id": f"relationship--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "relationship_type": "indicates",
            "source_ref": stix_evidence_id,
            "target_ref": related_to
        }
        
        self.relationships.append(relationship)
        
        return stix_evidence_id
    
    def add_relationship(self, source_type: str, source_id: str, target_type: str, target_id: str, relationship_type: str):
        """Add custom relationship between STIX objects."""
        relationship = {
            "type": "relationship",
            "id": f"relationship--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "relationship_type": relationship_type,
            "source_ref": source_id,
            "target_ref": target_id,
            "labels": ["cti", "argo-generated"]
        }
        
        self.relationships.append(relationship)
    
    def export_bundle(self, output_path: Path) -> Dict[str, Any]:
        """Export STIX bundle to file."""
        # Add all relationships to objects
        all_objects = self.objects + self.relationships
        
        bundle = {
            "type": "bundle",
            "id": self.bundle_id,
            "objects": all_objects
        }
        
        # Write to file
        with open(output_path, 'w') as f:
            json.dump(bundle, f, indent=2)
        
        return {
            "bundle_id": self.bundle_id,
            "objects_count": len(all_objects),
            "output_path": str(output_path),
            "export_time": datetime.now(timezone.utc).isoformat()
        }
    
    def get_bundle_summary(self) -> Dict[str, Any]:
        """Get summary of STIX bundle contents."""
        object_types = {}
        for obj in self.objects:
            obj_type = obj.get("type", "unknown")
            object_types[obj_type] = object_types.get(obj_type, 0) + 1
        
        return {
            "bundle_id": self.bundle_id,
            "total_objects": len(self.objects),
            "total_relationships": len(self.relationships),
            "object_types": object_types,
            "created": datetime.now(timezone.utc).isoformat()
        }


def export_orpheus_results_to_stix(
    actor: str,
    aliases: List[str],
    techniques: List[str],
    cves: List[str],
    evidence: List[Evidence],
    output_dir: Path
) -> Dict[str, Any]:
    """
    Export Orpheus results to STIX 2.1 bundle.
    
    Args:
        actor: Actor name
        aliases: List of actor aliases
        techniques: List of ATT&CK techniques
        cves: List of CVEs
        evidence: List of evidence items
        output_dir: Output directory for STIX file
    
    Returns:
        Export metadata
    """
    exporter = STIXExporter()
    
    # Add actor
    actor_id = exporter.add_actor(actor, aliases, evidence)
    
    # Add techniques
    technique_ids = []
    for technique in techniques:
        # Find evidence related to this technique
        technique_evidence = [
            ev for ev in evidence 
            if hasattr(ev, 'techniques') and ev.techniques and technique in ev.techniques
        ]
        technique_id = exporter.add_technique(technique, technique, technique_evidence)
        technique_ids.append(technique_id)
        
        # Link technique to actor
        exporter.add_relationship("threat-actor", actor_id, "attack-pattern", technique_id, "uses")
    
    # Add CVEs
    cve_ids = []
    for cve in cves:
        # Find evidence related to this CVE
        cve_evidence = [
            ev for ev in evidence 
            if hasattr(ev, 'cves') and ev.cves and cve in ev.cves
        ]
        cve_id = exporter.add_vulnerability(cve, f"CVE {cve}", cve_evidence)
        cve_ids.append(cve_id)
        
        # Link CVE to actor
        exporter.add_relationship("threat-actor", actor_id, "vulnerability", cve_id, "exploits")
    
    # Create output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"stix_orpheus_{actor}_{timestamp}.json"
    
    # Export bundle
    export_result = exporter.export_bundle(output_path)
    
    # Add summary
    export_result.update(exporter.get_bundle_summary())
    
    return export_result
