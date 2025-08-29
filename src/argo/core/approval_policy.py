"""Policy-driven approval gate for Orpheus with configurable rules."""

import os
import json
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from pathlib import Path
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)


class PolicyRule(BaseModel):
    """Individual policy rule for approval decisions."""
    name: str
    description: str
    condition: str  # Simple condition expression
    threshold: Optional[float] = None
    weight: float = 1.0
    required: bool = False
    enabled: bool = True


class ApprovalPolicy(BaseModel):
    """Collection of policy rules for approval decisions."""
    name: str = "default"
    description: str = "Default Orpheus approval policy"
    min_total_score: float = 0.7
    require_all_required_rules: bool = True
    rules: List[PolicyRule] = Field(default_factory=list)


@dataclass
class PolicyEvaluation:
    """Result of policy evaluation."""
    approved: bool
    total_score: float
    rule_results: Dict[str, Dict[str, Any]]
    failed_required_rules: List[str]
    recommendation: str
    details: Dict[str, Any]


class ApprovalPolicyEngine:
    """Policy engine for evaluating approval decisions."""
    
    def __init__(self, policy_path: Optional[str] = None):
        """Initialize policy engine with optional custom policy."""
        self.policy = self._load_policy(policy_path)
        
    def _load_policy(self, policy_path: Optional[str] = None) -> ApprovalPolicy:
        """Load policy from file or use default."""
        if policy_path and Path(policy_path).exists():
            try:
                with open(policy_path, 'r') as f:
                    policy_data = json.load(f)
                return ApprovalPolicy(**policy_data)
            except Exception as e:
                logger.warning(f"Failed to load policy from {policy_path}: {e}")
        
        return self._get_default_policy()
    
    def _get_default_policy(self) -> ApprovalPolicy:
        """Get default approval policy rules."""
        rules = [
            PolicyRule(
                name="min_evidence_count",
                description="Minimum number of evidence items required",
                condition="evidence_count >= threshold",
                threshold=3.0,
                weight=2.0,
                required=True
            ),
            PolicyRule(
                name="min_avg_confidence",
                description="Minimum average evidence confidence score",
                condition="avg_confidence >= threshold",
                threshold=0.6,
                weight=2.5,
                required=True
            ),
            PolicyRule(
                name="multi_source_evidence",
                description="Evidence from multiple sources preferred",
                condition="unique_sources >= threshold",
                threshold=2.0,
                weight=1.5,
                required=False
            ),
            PolicyRule(
                name="multi_document_evidence",
                description="Evidence from multiple documents preferred",
                condition="unique_documents >= threshold",
                threshold=2.0,
                weight=1.5,
                required=False
            ),
            PolicyRule(
                name="high_confidence_evidence",
                description="At least some high-confidence evidence",
                condition="high_conf_count >= threshold",
                threshold=1.0,
                weight=1.0,
                required=False
            ),
            PolicyRule(
                name="recent_evidence",
                description="Evidence from recent documents preferred",
                condition="recent_evidence_ratio >= threshold",
                threshold=0.3,
                weight=1.0,
                required=False
            ),
            PolicyRule(
                name="alias_confidence_check",
                description="New aliases must meet confidence threshold",
                condition="min_alias_confidence >= threshold",
                threshold=0.65,
                weight=2.0,
                required=True,
                enabled=True  # Only applies when aliases are discovered
            )
        ]
        
        return ApprovalPolicy(
            name="default_orpheus",
            description="Default policy for Orpheus CTI agent approval",
            min_total_score=0.7,
            require_all_required_rules=True,
            rules=rules
        )
    
    def evaluate_state(self, state: Dict[str, Any]) -> PolicyEvaluation:
        """Evaluate state against policy rules."""
        evidence = state.get("evidence", [])
        evidence_count = len(evidence)
        
        # Calculate metrics from state
        metrics = self._calculate_metrics(state, evidence)
        
        # Evaluate each rule
        rule_results = {}
        total_score = 0.0
        failed_required = []
        
        for rule in self.policy.rules:
            if not rule.enabled:
                continue
                
            # Skip alias rule if no aliases being evaluated
            if rule.name == "alias_confidence_check" and not state.get("needs_alias_write_approval"):
                continue
                
            result = self._evaluate_rule(rule, metrics)
            rule_results[rule.name] = result
            
            if result["passed"]:
                total_score += rule.weight
            elif rule.required:
                failed_required.append(rule.name)
        
        # Normalize score
        max_possible_score = sum(rule.weight for rule in self.policy.rules if rule.enabled)
        if rule.name == "alias_confidence_check" and not state.get("needs_alias_write_approval"):
            max_possible_score -= 2.0  # Subtract alias rule weight if not applicable
            
        normalized_score = total_score / max_possible_score if max_possible_score > 0 else 0.0
        
        # Determine approval
        approved = (
            normalized_score >= self.policy.min_total_score and
            (not self.policy.require_all_required_rules or len(failed_required) == 0)
        )
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            approved, normalized_score, failed_required, rule_results
        )
        
        return PolicyEvaluation(
            approved=approved,
            total_score=normalized_score,
            rule_results=rule_results,
            failed_required_rules=failed_required,
            recommendation=recommendation,
            details={
                "metrics": metrics,
                "policy_name": self.policy.name,
                "total_weighted_score": total_score,
                "max_possible_score": max_possible_score
            }
        )
    
    def _calculate_metrics(self, state: Dict[str, Any], evidence: List[Any]) -> Dict[str, float]:
        """Calculate metrics from state for rule evaluation."""
        if not evidence:
            return {
                "evidence_count": 0,
                "avg_confidence": 0.0,
                "unique_sources": 0,
                "unique_documents": 0,
                "high_conf_count": 0,
                "recent_evidence_ratio": 0.0,
                "min_alias_confidence": 1.0
            }
        
        confidences = [getattr(e, 'confidence', 0.5) for e in evidence]
        sources = set(getattr(e, 'source', 'unknown') for e in evidence)
        documents = set(getattr(e, 'document_id', 'unknown') for e in evidence)
        
        # High confidence evidence (>= 0.8)
        high_conf_count = sum(1 for conf in confidences if conf >= 0.8)
        
        # Recent evidence ratio (placeholder - would need document dates)
        recent_evidence_ratio = 0.5  # Default assumption
        
        # Alias confidence check
        min_alias_confidence = 1.0
        if state.get("alias_candidates"):
            alias_confidences = [
                c.get("confidence", 0.0) for c in state.get("alias_candidates", [])
            ]
            min_alias_confidence = min(alias_confidences) if alias_confidences else 0.0
        
        return {
            "evidence_count": len(evidence),
            "avg_confidence": sum(confidences) / len(confidences),
            "unique_sources": len(sources),
            "unique_documents": len(documents),
            "high_conf_count": high_conf_count,
            "recent_evidence_ratio": recent_evidence_ratio,
            "min_alias_confidence": min_alias_confidence
        }
    
    def _evaluate_rule(self, rule: PolicyRule, metrics: Dict[str, float]) -> Dict[str, Any]:
        """Evaluate a single rule against metrics."""
        try:
            # Simple condition evaluation
            if rule.condition == "evidence_count >= threshold":
                passed = metrics["evidence_count"] >= rule.threshold
                actual_value = metrics["evidence_count"]
            elif rule.condition == "avg_confidence >= threshold":
                passed = metrics["avg_confidence"] >= rule.threshold
                actual_value = metrics["avg_confidence"]
            elif rule.condition == "unique_sources >= threshold":
                passed = metrics["unique_sources"] >= rule.threshold
                actual_value = metrics["unique_sources"]
            elif rule.condition == "unique_documents >= threshold":
                passed = metrics["unique_documents"] >= rule.threshold
                actual_value = metrics["unique_documents"]
            elif rule.condition == "high_conf_count >= threshold":
                passed = metrics["high_conf_count"] >= rule.threshold
                actual_value = metrics["high_conf_count"]
            elif rule.condition == "recent_evidence_ratio >= threshold":
                passed = metrics["recent_evidence_ratio"] >= rule.threshold
                actual_value = metrics["recent_evidence_ratio"]
            elif rule.condition == "min_alias_confidence >= threshold":
                passed = metrics["min_alias_confidence"] >= rule.threshold
                actual_value = metrics["min_alias_confidence"]
            else:
                # Unknown condition
                passed = True
                actual_value = None
                
            return {
                "passed": passed,
                "actual_value": actual_value,
                "threshold": rule.threshold,
                "weight": rule.weight,
                "required": rule.required,
                "description": rule.description
            }
            
        except Exception as e:
            logger.warning(f"Error evaluating rule {rule.name}: {e}")
            return {
                "passed": False,
                "actual_value": None,
                "threshold": rule.threshold,
                "weight": rule.weight,
                "required": rule.required,
                "description": rule.description,
                "error": str(e)
            }
    
    def _generate_recommendation(
        self, 
        approved: bool, 
        score: float, 
        failed_required: List[str],
        rule_results: Dict[str, Dict[str, Any]]
    ) -> str:
        """Generate human-readable recommendation."""
        if approved:
            if score >= 0.9:
                return "✅ EXCELLENT - High confidence recommendation to proceed"
            elif score >= 0.8:
                return "✅ GOOD - Recommend proceeding with publication"
            else:
                return "✅ ACCEPTABLE - Meets minimum requirements, proceed"
        else:
            issues = []
            if failed_required:
                issues.append(f"Failed required rules: {', '.join(failed_required)}")
            if score < 0.7:
                issues.append(f"Score too low: {score:.2f} < 0.70")
            
            suggestions = []
            for rule_name, result in rule_results.items():
                if not result["passed"] and result.get("actual_value") is not None:
                    suggestions.append(
                        f"• {result['description']}: {result['actual_value']:.2f} < {result['threshold']:.2f}"
                    )
            
            recommendation = f"❌ NOT RECOMMENDED - {'; '.join(issues)}"
            if suggestions:
                recommendation += f"\n\nSuggestions:\n{chr(10).join(suggestions)}"
            
            return recommendation


def load_policy_from_env() -> ApprovalPolicyEngine:
    """Load policy engine from environment configuration."""
    policy_path = os.getenv("APPROVAL_POLICY_PATH")
    return ApprovalPolicyEngine(policy_path)
