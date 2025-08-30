"""Enhanced evidence pack generation with rich metadata and validation."""

import os
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class EnhancedEvidencePack:
    """Enhanced evidence pack with rich metadata and validation."""
    
    def __init__(self, evidence: List[Dict[str, Any]], actor: str, metadata: Dict[str, Any]):
        self.evidence = evidence
        self.actor = actor
        self.metadata = metadata
        self.timestamp = datetime.now(timezone.utc)
        self.pack_id = self._generate_pack_id()
    
    def _generate_pack_id(self) -> str:
        """Generate unique pack ID."""
        timestamp_str = self.timestamp.strftime("%Y%m%d_%H%M%S")
        actor_hash = hashlib.md5(self.actor.encode()).hexdigest()[:8]
        return f"evidence_pack_{actor_hash}_{timestamp_str}"
    
    def create_enhanced_pack(self) -> List[Dict[str, Any]]:
        """Create enhanced evidence pack with rich metadata."""
        enhanced_pack = []
        
        for i, item in enumerate(self.evidence, 1):
            enhanced_item = self._enhance_evidence_item(item, i)
            enhanced_pack.append(enhanced_item)
        
        logger.info(f"Created enhanced evidence pack with {len(enhanced_pack)} items for {self.actor}")
        return enhanced_pack
    
    def _enhance_evidence_item(self, item: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Enhance individual evidence item with additional metadata."""
        enhanced = {
            # Core evidence information
            'evidence_id': f"{self.pack_id}_item_{index:03d}",
            'item_index': index,
            'actor': self.actor,
            'timestamp': self.timestamp.isoformat(),
            
            # Document information
            'document_id': item.get('document_id'),
            'page': item.get('page'),
            'chunk_id': item.get('chunk_id'),
            'bbox': item.get('bbox', []),
            
            # Content
            'snippet': item.get('snippet', item.get('text', '')),
            'snippet_length': len(item.get('snippet', item.get('text', ''))),
            'snippet_hash': self._hash_snippet(item.get('snippet', item.get('text', ''))),
            
            # Scoring and confidence
            'score': item.get('score', 0.0),
            'confidence': item.get('confidence', 1.0),
            'semantic_score': getattr(item, 'semantic_score', None),
            'lexical_score': getattr(item, 'lexical_score', None),
            'layout_score': getattr(item, 'layout_score', None),
            'entity_density': getattr(item, 'entity_density', None),
            'recency_score': getattr(item, 'recency_score', None),
            
            # Source and classification
            'source': item.get('source', 'unknown'),
            'tlp': item.get('tlp', 'CLEAR'),
            'namespace': item.get('namespace', 'personal'),
            
            # Extracted entities
            'actors': item.get('actors', []),
            'techniques': item.get('techniques', []),
            'cves': item.get('cves', []),
            'tools': item.get('tools', []),
            'infrastructure': item.get('infrastructure', []),
            
            # Quality metrics
            'quality_flags': self._assess_quality_flags(item),
            'corroboration_score': self._calculate_corroboration_score(item),
            'relevance_score': self._calculate_relevance_score(item),
            
            # Metadata
            'extraction_method': item.get('extraction_method', 'hybrid'),
            'processing_timestamp': item.get('timestamp'),
            'version': '1.0'
        }
        
        return enhanced
    
    def _hash_snippet(self, snippet: str) -> str:
        """Generate hash for snippet content."""
        if not snippet:
            return ""
        return hashlib.sha256(snippet.encode()).hexdigest()
    
    def _assess_quality_flags(self, item: Dict[str, Any]) -> List[str]:
        """Assess quality flags for evidence item."""
        flags = []
        
        # Confidence-based flags
        confidence = item.get('confidence', 0.0)
        if confidence >= 0.8:
            flags.append("high_confidence")
        elif confidence < 0.5:
            flags.append("low_confidence")
        
        # Source-based flags
        source = item.get('source', 'unknown')
        if source == 'faiss':
            flags.append("semantic_match")
        elif source == 'bm25':
            flags.append("lexical_match")
        elif source == 'counter_evidence':
            flags.append("counter_evidence")
        
        # Content-based flags
        snippet = item.get('snippet', '')
        if len(snippet) < 50:
            flags.append("short_snippet")
        elif len(snippet) > 500:
            flags.append("long_snippet")
        
        # Entity-based flags
        if item.get('actors'):
            flags.append("actor_mentioned")
        if item.get('techniques'):
            flags.append("technique_identified")
        if item.get('cves'):
            flags.append("cve_identified")
        
        return flags
    
    def _calculate_corroboration_score(self, item: Dict[str, Any]) -> float:
        """Calculate corroboration score based on multiple sources."""
        # This is a simplified version - could be enhanced with actual corroboration logic
        doc_id = item.get('document_id')
        page = item.get('page')
        
        # Count how many other evidence items reference the same document/page
        corroborating_items = 0
        for other_item in self.evidence:
            if (other_item.get('document_id') == doc_id and 
                other_item.get('page') == page and 
                other_item != item):
                corroborating_items += 1
        
        # Normalize to 0-1 scale
        max_corroboration = 5  # Cap at 5 corroborating items
        return min(corroborating_items / max_corroboration, 1.0)
    
    def _calculate_relevance_score(self, item: Dict[str, Any]) -> float:
        """Calculate relevance score based on content and context."""
        relevance = 0.0
        
        # Base relevance from confidence
        relevance += item.get('confidence', 0.0) * 0.4
        
        # Boost for entity mentions
        if item.get('actors'):
            relevance += 0.2
        if item.get('techniques'):
            relevance += 0.2
        if item.get('cves'):
            relevance += 0.1
        
        # Boost for counter-evidence
        if item.get('source') == 'counter_evidence':
            relevance += 0.1
        
        return min(relevance, 1.0)
    
    def generate_pack_summary(self) -> Dict[str, Any]:
        """Generate summary statistics for the evidence pack."""
        if not self.evidence:
            return {"error": "No evidence available"}
        
        # Basic statistics
        total_items = len(self.evidence)
        unique_documents = len(set(e.get('document_id') for e in self.evidence))
        unique_sources = len(set(e.get('source') for e in self.evidence))
        
        # Confidence distribution
        confidence_scores = [e.get('confidence', 0.0) for e in self.evidence]
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        high_confidence = len([c for c in confidence_scores if c >= 0.8])
        low_confidence = len([c for c in confidence_scores if c < 0.5])
        
        # Source distribution
        source_counts = {}
        for e in self.evidence:
            source = e.get('source', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        # Entity counts
        total_actors = sum(len(e.get('actors', [])) for e in self.evidence)
        total_techniques = sum(len(e.get('techniques', [])) for e in self.evidence)
        total_cves = sum(len(e.get('cves', [])) for e in self.evidence)
        
        # Quality assessment
        quality_flags = []
        for e in self.evidence:
            quality_flags.extend(self._assess_quality_flags(e))
        
        flag_counts = {}
        for flag in quality_flags:
            flag_counts[flag] = flag_counts.get(flag, 0) + 1
        
        summary = {
            "pack_id": self.pack_id,
            "actor": self.actor,
            "timestamp": self.timestamp.isoformat(),
            "total_items": total_items,
            "unique_documents": unique_documents,
            "unique_sources": unique_sources,
            "confidence_stats": {
                "average": round(avg_confidence, 3),
                "high_confidence_count": high_confidence,
                "low_confidence_count": low_confidence,
                "distribution": {
                    "high": high_confidence,
                    "medium": total_items - high_confidence - low_confidence,
                    "low": low_confidence
                }
            },
            "source_distribution": source_counts,
            "entity_counts": {
                "actors": total_actors,
                "techniques": total_techniques,
                "cves": total_cves
            },
            "quality_flags": flag_counts,
            "metadata": self.metadata
        }
        
        return summary
    
    def validate_pack(self) -> Dict[str, Any]:
        """Validate the evidence pack for quality and completeness."""
        validation_results = {
            "valid": True,
            "warnings": [],
            "errors": [],
            "quality_score": 0.0
        }
        
        if not self.evidence:
            validation_results["valid"] = False
            validation_results["errors"].append("No evidence items found")
            return validation_results
        
        # Check for required fields
        required_fields = ['document_id', 'snippet', 'confidence']
        for i, item in enumerate(self.evidence):
            for field in required_fields:
                if not item.get(field):
                    validation_results["warnings"].append(f"Item {i+1} missing {field}")
        
        # Check confidence scores
        low_confidence_items = [e for e in self.evidence if e.get('confidence', 0) < 0.3]
        if low_confidence_items:
            validation_results["warnings"].append(f"{len(low_confidence_items)} items have very low confidence")
        
        # Check for duplicate snippets
        snippets = [e.get('snippet', '') for e in self.evidence]
        duplicate_snippets = len(snippets) - len(set(snippets))
        if duplicate_snippets > 0:
            validation_results["warnings"].append(f"{duplicate_snippets} duplicate snippets detected")
        
        # Calculate quality score
        quality_score = self._calculate_overall_quality()
        validation_results["quality_score"] = quality_score
        
        # Determine if pack is valid
        if validation_results["errors"]:
            validation_results["valid"] = False
        elif quality_score < 0.5:
            validation_results["warnings"].append("Overall quality score below threshold")
        
        return validation_results
    
    def _calculate_overall_quality(self) -> float:
        """Calculate overall quality score for the evidence pack."""
        if not self.evidence:
            return 0.0
        
        # Quality factors
        confidence_scores = [e.get('confidence', 0.0) for e in self.evidence]
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        
        # Source diversity
        unique_sources = len(set(e.get('source') for e in self.evidence))
        source_diversity = min(unique_sources / 3.0, 1.0)  # Normalize to 3+ sources
        
        # Document diversity
        unique_docs = len(set(e.get('document_id') for e in self.evidence))
        doc_diversity = min(unique_docs / 2.0, 1.0)  # Normalize to 2+ docs
        
        # Entity richness
        total_entities = sum(len(e.get('actors', [])) + len(e.get('techniques', [])) + len(e.get('cves', [])) for e in self.evidence)
        entity_richness = min(total_entities / (len(self.evidence) * 2), 1.0)  # Normalize to 2 entities per item
        
        # Weighted quality score
        quality_score = (
            avg_confidence * 0.4 +
            source_diversity * 0.2 +
            doc_diversity * 0.2 +
            entity_richness * 0.2
        )
        
        return min(quality_score, 1.0)
    
    def export_to_jsonl(self, output_path: str) -> str:
        """Export evidence pack to JSONL format."""
        enhanced_pack = self.create_enhanced_pack()
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for item in enhanced_pack:
                    f.write(json.dumps(item, default=str) + '\n')
            
            logger.info(f"Exported enhanced evidence pack to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to export evidence pack: {e}")
            raise
    
    def export_to_json(self, output_path: str) -> str:
        """Export evidence pack to JSON format with summary."""
        enhanced_pack = self.create_enhanced_pack()
        pack_summary = self.generate_pack_summary()
        validation_results = self.validate_pack()
        
        export_data = {
            "metadata": {
                "pack_id": self.pack_id,
                "actor": self.actor,
                "timestamp": self.timestamp.isoformat(),
                "version": "1.0"
            },
            "summary": pack_summary,
            "validation": validation_results,
            "evidence_items": enhanced_pack
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported enhanced evidence pack to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to export evidence pack: {e}")
            raise


def create_enhanced_evidence_pack(evidence: List[Dict[str, Any]], actor: str, metadata: Dict[str, Any]) -> EnhancedEvidencePack:
    """Create an enhanced evidence pack."""
    return EnhancedEvidencePack(evidence, actor, metadata)
