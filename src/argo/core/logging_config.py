"""Structured logging configuration for Argo."""

import sys
import os
from typing import Dict, Any
import structlog
from structlog.stdlib import LoggerFactory
import logging


def configure_logging(log_level: str = "INFO", json_logs: bool = True) -> None:
    """Configure structured logging for Argo with audit capabilities."""
    
    # Set log level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(level=numeric_level)
    
    # Configure structlog processors
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
    ]
    
    if json_logs:
        # JSON output for production/audit
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Human-readable for development
        processors.extend([
            structlog.dev.ConsoleRenderer(colors=True),
        ])
    
    structlog.configure(
        processors=processors,
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        cache_logger_on_first_use=True,
    )


def get_audit_logger(component: str) -> structlog.BoundLogger:
    """Get a logger with audit context for a specific component."""
    logger = structlog.get_logger(component)
    return logger.bind(component=component, audit=True)


def log_evidence_retrieval(
    logger: structlog.BoundLogger,
    query: str,
    namespaces: tuple,
    evidence_count: int,
    sources_used: list,
    execution_time_ms: float,
    filters_applied: Dict[str, Any] = None
) -> None:
    """Log evidence retrieval with full audit trail."""
    logger.info(
        "evidence_retrieval_completed",
        query=query,
        namespaces=list(namespaces),
        evidence_count=evidence_count,
        sources_used=sources_used,
        execution_time_ms=execution_time_ms,
        filters_applied=filters_applied or {},
        event_type="evidence_retrieval"
    )


def log_alias_discovery(
    logger: structlog.BoundLogger,
    actor: str,
    discovered_aliases: list,
    method: str,
    confidence_scores: Dict[str, float],
    provenance: Dict[str, Any],
    approved: bool = False
) -> None:
    """Log alias discovery events for audit trail."""
    logger.info(
        "alias_discovery_event",
        actor=actor,
        discovered_aliases=discovered_aliases,
        method=method,  # 'deterministic' or 'rag_llm'
        confidence_scores=confidence_scores,
        provenance=provenance,
        approved=approved,
        event_type="alias_discovery"
    )


def log_approval_gate(
    logger: structlog.BoundLogger,
    state: Dict[str, Any],
    decision: bool,
    decision_time_ms: float,
    evidence_stats: Dict[str, Any],
    approver_context: Dict[str, Any] = None
) -> None:
    """Log approval gate decisions with full context."""
    logger.info(
        "approval_gate_decision",
        decision=decision,
        decision_time_ms=decision_time_ms,
        evidence_stats=evidence_stats,
        approver_context=approver_context or {},
        state_summary={
            "actor": state.get("actor"),
            "aliases_count": len(state.get("aliases", [])),
            "evidence_count": len(state.get("evidence", [])),
            "needs_alias_approval": state.get("needs_alias_write_approval", False)
        },
        event_type="approval_gate"
    )


def log_report_generation(
    logger: structlog.BoundLogger,
    actor: str,
    report_path: str,
    evidence_pack_path: str,
    evidence_count: int,
    generation_time_ms: float,
    report_hash: str
) -> None:
    """Log report generation for provenance tracking."""
    logger.info(
        "report_generated",
        actor=actor,
        report_path=report_path,
        evidence_pack_path=evidence_pack_path,
        evidence_count=evidence_count,
        generation_time_ms=generation_time_ms,
        report_hash=report_hash,
        event_type="report_generation"
    )


def log_ingestion_event(
    logger: structlog.BoundLogger,
    file_path: str,
    document_id: str,
    pages: int,
    chunks_created: int,
    ocr_pages: int,
    file_hash: str,
    processing_time_ms: float
) -> None:
    """Log document ingestion for audit trail."""
    logger.info(
        "document_ingested",
        file_path=file_path,
        document_id=document_id,
        pages=pages,
        chunks_created=chunks_created,
        ocr_pages=ocr_pages,
        file_hash=file_hash,
        processing_time_ms=processing_time_ms,
        event_type="document_ingestion"
    )
