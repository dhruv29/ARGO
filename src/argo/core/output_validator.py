"""Output validation and quality checking for Orpheus reports and evidence packs."""

import os
import re
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class OutputValidator:
    """Validate and quality-check Orpheus outputs."""
    
    def __init__(self):
        self.validation_rules = self._load_validation_rules()
    
    def _load_validation_rules(self) -> Dict[str, Any]:
        """Load validation rules for different output types."""
        return {
            "markdown_report": {
                "required_sections": [
                    "Executive Summary",
                    "Evidence Analysis", 
                    "Methodology"
                ],
                "citation_pattern": r'\[Evidence \d+\]',
                "min_citations": 3,
                "min_length": 1000,
                "max_length": 50000
            },
            "evidence_pack": {
                "required_fields": [
                    "evidence_id", "actor", "document_id", "snippet", "confidence"
                ],
                "min_confidence": 0.1,
                "max_confidence": 1.0,
                "min_snippet_length": 10,
                "max_snippet_length": 2000
            },
            "stix_export": {
                "required_objects": ["threat-actor", "attack-pattern", "vulnerability"],
                "min_objects": 5,
                "required_properties": ["id", "type", "created", "modified"]
            }
        }
    
    def validate_markdown_report(self, report_content: str, evidence_count: int) -> Dict[str, Any]:
        """Validate markdown report content and structure."""
        validation = {
            "valid": True,
            "score": 0.0,
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        try:
            # Check required sections
            missing_sections = []
            for section in self.validation_rules["markdown_report"]["required_sections"]:
                if section not in report_content:
                    missing_sections.append(section)
            
            if missing_sections:
                validation["errors"].append(f"Missing required sections: {', '.join(missing_sections)}")
                validation["valid"] = False
            
            # Check citations
            citations = re.findall(self.validation_rules["markdown_report"]["citation_pattern"], report_content)
            citation_count = len(citations)
            min_citations = self.validation_rules["markdown_report"]["min_citations"]
            
            if citation_count < min_citations:
                validation["warnings"].append(f"Low citation count: {citation_count} < {min_citations}")
            
            # Check citation validity
            citation_numbers = [int(re.search(r'\d+', c).group()) for c in citations if re.search(r'\d+', c)]
            invalid_citations = [c for c in citation_numbers if c < 1 or c > evidence_count]
            
            if invalid_citations:
                validation["errors"].append(f"Invalid citation numbers: {invalid_citations}")
                validation["valid"] = False
            
            # Check length
            content_length = len(report_content)
            min_length = self.validation_rules["markdown_report"]["min_length"]
            max_length = self.validation_rules["markdown_report"]["max_length"]
            
            if content_length < min_length:
                validation["errors"].append(f"Report too short: {content_length} < {min_length}")
                validation["valid"] = False
            elif content_length > max_length:
                validation["warnings"].append(f"Report very long: {content_length} > {max_length}")
            
            # Check for uncited claims
            uncited_claims = self._detect_uncited_claims(report_content)
            if uncited_claims:
                validation["warnings"].append(f"Potential uncited claims detected: {len(uncited_claims)}")
            
            # Calculate quality score
            validation["score"] = self._calculate_report_score(
                citation_count, evidence_count, content_length, 
                len(missing_sections), len(invalid_citations)
            )
            
            # Generate recommendations
            validation["recommendations"] = self._generate_report_recommendations(validation)
            
        except Exception as e:
            validation["errors"].append(f"Validation error: {str(e)}")
            validation["valid"] = False
            logger.error(f"Failed to validate markdown report: {e}")
        
        return validation
    
    def _detect_uncited_claims(self, report_content: str) -> List[str]:
        """Detect potential uncited claims in the report."""
        # Common claim patterns that should be cited
        claim_patterns = [
            r'\b(?:uses|employs|utilizes|deploys)\s+\w+',
            r'\b(?:targets|attacks|compromises)\s+\w+',
            r'\b(?:originates|originated)\s+from\s+\w+',
            r'\b(?:since|since\s+\d{4})',
            r'\b(?:first\s+seen|discovered)\s+in\s+\d{4}',
            r'\b(?:primary|main|key)\s+(?:technique|tool|infrastructure)',
            r'\b(?:sophisticated|advanced|novel)\s+\w+'
        ]
        
        uncited_claims = []
        lines = report_content.split('\n')
        
        for i, line in enumerate(lines, 1):
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in claim_patterns):
                # Check if line has citations
                if not re.search(r'\[Evidence \d+\]', line):
                    # Check if it's in a section that doesn't require citations
                    if not any(section in line for section in ['#', '##', '###', '---', '**Generated by:**']):
                        uncited_claims.append(f"Line {i}: {line.strip()}")
        
        return uncited_claims
    
    def _calculate_report_score(self, citation_count: int, evidence_count: int, 
                               content_length: int, missing_sections: int, 
                               invalid_citations: int) -> float:
        """Calculate quality score for the report."""
        score = 0.0
        
        # Citation score (40%)
        if evidence_count > 0:
            citation_ratio = min(citation_count / evidence_count, 1.0)
            score += citation_ratio * 0.4
        
        # Content length score (20%)
        length_score = min(content_length / 2000, 1.0)  # Normalize to 2000 chars
        score += length_score * 0.2
        
        # Section completeness score (20%)
        section_score = max(0, 1.0 - (missing_sections * 0.33))
        score += section_score * 0.2
        
        # Citation validity score (20%)
        validity_score = max(0, 1.0 - (invalid_citations * 0.5))
        score += validity_score * 0.2
        
        return min(score, 1.0)
    
    def _generate_report_recommendations(self, validation: Dict[str, Any]) -> List[str]:
        """Generate recommendations for improving the report."""
        recommendations = []
        
        if validation["score"] < 0.5:
            recommendations.append("Consider significant revision - quality score below 50%")
        
        if validation["warnings"]:
            recommendations.append("Address warnings to improve report quality")
        
        if validation["errors"]:
            recommendations.append("Fix errors before publication")
        
        if validation["score"] >= 0.8:
            recommendations.append("Excellent report quality - ready for publication")
        elif validation["score"] >= 0.6:
            recommendations.append("Good report quality - minor improvements recommended")
        else:
            recommendations.append("Report needs revision before publication")
        
        return recommendations
    
    def validate_evidence_pack(self, evidence_pack: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate evidence pack structure and content."""
        validation = {
            "valid": True,
            "score": 0.0,
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        try:
            if not evidence_pack:
                validation["errors"].append("Evidence pack is empty")
                validation["valid"] = False
                return validation
            
            # Check required fields
            missing_fields = []
            for i, item in enumerate(evidence_pack):
                for field in self.validation_rules["evidence_pack"]["required_fields"]:
                    if not item.get(field):
                        missing_fields.append(f"Item {i+1} missing {field}")
            
            if missing_fields:
                validation["errors"].extend(missing_fields)
                validation["valid"] = False
            
            # Check confidence scores
            confidence_issues = []
            for i, item in enumerate(evidence_pack):
                confidence = item.get('confidence', 0.0)
                min_conf = self.validation_rules["evidence_pack"]["min_confidence"]
                max_conf = self.validation_rules["evidence_pack"]["max_confidence"]
                
                if confidence < min_conf:
                    confidence_issues.append(f"Item {i+1} confidence too low: {confidence} < {min_conf}")
                elif confidence > max_conf:
                    confidence_issues.append(f"Item {i+1} confidence too high: {confidence} > {max_conf}")
            
            if confidence_issues:
                validation["warnings"].extend(confidence_issues)
            
            # Check snippet lengths
            length_issues = []
            for i, item in enumerate(evidence_pack):
                snippet = item.get('snippet', '')
                snippet_length = len(snippet)
                min_length = self.validation_rules["evidence_pack"]["min_snippet_length"]
                max_length = self.validation_rules["evidence_pack"]["max_snippet_length"]
                
                if snippet_length < min_length:
                    length_issues.append(f"Item {i+1} snippet too short: {snippet_length} < {min_length}")
                elif snippet_length > max_length:
                    length_issues.append(f"Item {i+1} snippet too long: {snippet_length} > {max_length}")
            
            if length_issues:
                validation["warnings"].extend(length_issues)
            
            # Check for duplicates
            snippets = [item.get('snippet', '') for item in evidence_pack]
            duplicate_count = len(snippets) - len(set(snippets))
            if duplicate_count > 0:
                validation["warnings"].append(f"{duplicate_count} duplicate snippets detected")
            
            # Calculate quality score
            validation["score"] = self._calculate_evidence_pack_score(
                len(evidence_pack), len(missing_fields), 
                len(confidence_issues), len(length_issues), duplicate_count
            )
            
            # Generate recommendations
            validation["recommendations"] = self._generate_evidence_pack_recommendations(validation)
            
        except Exception as e:
            validation["errors"].append(f"Validation error: {str(e)}")
            validation["valid"] = False
            logger.error(f"Failed to validate evidence pack: {e}")
        
        return validation
    
    def _calculate_evidence_pack_score(self, total_items: int, missing_fields: int,
                                      confidence_issues: int, length_issues: int, 
                                      duplicate_count: int) -> float:
        """Calculate quality score for evidence pack."""
        score = 1.0
        
        # Penalize for missing fields
        score -= (missing_fields / total_items) * 0.4 if total_items > 0 else 0.4
        
        # Penalize for confidence issues
        score -= (confidence_issues / total_items) * 0.2 if total_items > 0 else 0.2
        
        # Penalize for length issues
        score -= (length_issues / total_items) * 0.2 if total_items > 0 else 0.2
        
        # Penalize for duplicates
        score -= (duplicate_count / total_items) * 0.2 if total_items > 0 else 0.2
        
        return max(score, 0.0)
    
    def _generate_evidence_pack_recommendations(self, validation: Dict[str, Any]) -> List[str]:
        """Generate recommendations for improving evidence pack."""
        recommendations = []
        
        if validation["score"] < 0.5:
            recommendations.append("Evidence pack needs significant improvement")
        
        if validation["warnings"]:
            recommendations.append("Address warnings to improve evidence quality")
        
        if validation["errors"]:
            recommendations.append("Fix errors before export")
        
        if validation["score"] >= 0.8:
            recommendations.append("High-quality evidence pack - ready for export")
        elif validation["score"] >= 0.6:
            recommendations.append("Good evidence pack - minor improvements recommended")
        else:
            recommendations.append("Evidence pack needs revision before export")
        
        return recommendations
    
    def validate_stix_export(self, stix_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Validate STIX 2.1 export bundle."""
        validation = {
            "valid": True,
            "score": 0.0,
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        try:
            if not stix_bundle:
                validation["errors"].append("STIX bundle is empty")
                validation["valid"] = False
                return validation
            
            # Check required properties
            required_props = self.validation_rules["stix_export"]["required_properties"]
            missing_props = []
            for prop in required_props:
                if prop not in stix_bundle:
                    missing_props.append(prop)
            
            if missing_props:
                validation["errors"].append(f"Missing required properties: {', '.join(missing_props)}")
                validation["valid"] = False
            
            # Check objects
            objects = stix_bundle.get('objects', [])
            if not objects:
                validation["errors"].append("No STIX objects found")
                validation["valid"] = False
                return validation
            
            # Check object types
            object_types = [obj.get('type') for obj in objects if obj.get('type')]
            required_types = self.validation_rules["stix_export"]["required_objects"]
            missing_types = [t for t in required_types if t not in object_types]
            
            if missing_types:
                validation["warnings"].append(f"Missing recommended object types: {', '.join(missing_types)}")
            
            # Check minimum object count
            min_objects = self.validation_rules["stix_export"]["min_objects"]
            if len(objects) < min_objects:
                validation["warnings"].append(f"Low object count: {len(objects)} < {min_objects}")
            
            # Validate individual objects
            object_validation = self._validate_stix_objects(objects)
            validation["warnings"].extend(object_validation["warnings"])
            validation["errors"].extend(object_validation["errors"])
            
            # Calculate quality score
            validation["score"] = self._calculate_stix_score(
                len(objects), len(missing_props), len(missing_types), 
                object_validation["errors"]
            )
            
            # Generate recommendations
            validation["recommendations"] = self._generate_stix_recommendations(validation)
            
        except Exception as e:
            validation["errors"].append(f"Validation error: {str(e)}")
            validation["valid"] = False
            logger.error(f"Failed to validate STIX export: {e}")
        
        return validation
    
    def _validate_stix_objects(self, objects: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate individual STIX objects."""
        validation = {"warnings": [], "errors": []}
        
        for i, obj in enumerate(objects):
            # Check required properties for each object
            if 'id' not in obj:
                validation["errors"].append(f"Object {i+1} missing required 'id' property")
            
            if 'type' not in obj:
                validation["errors"].append(f"Object {i+1} missing required 'type' property")
            
            # Check for valid STIX IDs
            if 'id' in obj:
                stix_id = obj['id']
                if not re.match(r'^[a-z-]+--[a-f0-9-]{36}$', stix_id):
                    validation["warnings"].append(f"Object {i+1} has potentially invalid STIX ID format: {stix_id}")
        
        return validation
    
    def _calculate_stix_score(self, object_count: int, missing_props: int, 
                             missing_types: int, object_errors: int) -> float:
        """Calculate quality score for STIX export."""
        score = 1.0
        
        # Penalize for missing properties
        score -= missing_props * 0.2
        
        # Penalize for missing object types
        score -= missing_types * 0.1
        
        # Penalize for object errors
        score -= object_errors * 0.1
        
        # Bonus for good object count
        if object_count >= 10:
            score += 0.1
        
        return max(score, 0.0)
    
    def _generate_stix_recommendations(self, validation: Dict[str, Any]) -> List[str]:
        """Generate recommendations for improving STIX export."""
        recommendations = []
        
        if validation["score"] < 0.5:
            recommendations.append("STIX export needs significant improvement")
        
        if validation["warnings"]:
            recommendations.append("Address warnings to improve export quality")
        
        if validation["errors"]:
            recommendations.append("Fix errors before export")
        
        if validation["score"] >= 0.8:
            recommendations.append("High-quality STIX export - ready for use")
        elif validation["score"] >= 0.6:
            recommendations.append("Good STIX export - minor improvements recommended")
        else:
            recommendations.append("STIX export needs revision before use")
        
        return recommendations
    
    def generate_validation_report(self, validations: Dict[str, Dict[str, Any]]) -> str:
        """Generate a comprehensive validation report."""
        report = f"""# Output Validation Report

**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Overall Status:** {'✅ VALID' if all(v.get('valid', False) for v in validations.values()) else '❌ INVALID'}

## Validation Summary

"""
        
        for output_type, validation in validations.items():
            status = "✅ VALID" if validation.get('valid', False) else "❌ INVALID"
            score = validation.get('score', 0.0)
            
            report += f"### {output_type.replace('_', ' ').title()}\n"
            report += f"**Status:** {status}  \n"
            report += f"**Quality Score:** {score:.2f}/1.00\n\n"
            
            if validation.get('errors'):
                report += "**Errors:**\n"
                for error in validation['errors']:
                    report += f"- ❌ {error}\n"
                report += "\n"
            
            if validation.get('warnings'):
                report += "**Warnings:**\n"
                for warning in validation['warnings']:
                    report += f"- ⚠️ {warning}\n"
                report += "\n"
            
            if validation.get('recommendations'):
                report += "**Recommendations:**\n"
                for rec in validation['recommendations']:
                    report += f"- 💡 {rec}\n"
                report += "\n"
            
            report += "---\n\n"
        
        return report


def get_output_validator() -> OutputValidator:
    """Get the global output validator instance."""
    return OutputValidator()
