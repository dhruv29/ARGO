"""Workflow manager for complex CLI operations and automation."""

import os
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timezone
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)


class WorkflowStep:
    """Represents a single step in a workflow."""
    
    def __init__(self, name: str, function: Callable, description: str = "", 
                 required: bool = True, retry_count: int = 0):
        self.name = name
        self.function = function
        self.description = description
        self.required = required
        self.retry_count = retry_count
        self.status = "pending"  # pending, running, completed, failed, skipped
        self.result = None
        self.error = None
        self.start_time = None
        self.end_time = None
        self.duration = 0.0
    
    def execute(self, context: Dict[str, Any], console: Console) -> bool:
        """Execute this workflow step."""
        self.status = "running"
        self.start_time = datetime.now(timezone.utc)
        
        try:
            console.print(f"[blue]🔄 {self.name}[/]")
            if self.description:
                console.print(f"  {self.description}")
            
            # Execute the function
            self.result = self.function(context)
            self.status = "completed"
            
            self.end_time = datetime.now(timezone.utc)
            self.duration = (self.end_time - self.start_time).total_seconds()
            
            console.print(f"[green]✅ {self.name} completed in {self.duration:.1f}s[/]")
            return True
            
        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            self.end_time = datetime.now(timezone.utc)
            self.duration = (self.end_time - self.start_time).total_seconds()
            
            console.print(f"[red]❌ {self.name} failed: {e}[/]")
            
            # Retry logic
            if self.retry_count > 0:
                console.print(f"[yellow]🔄 Retrying {self.name}...[/]")
                return self._retry(context, console)
            
            return False
    
    def _retry(self, context: Dict[str, Any], console: Console) -> bool:
        """Retry the step execution."""
        for attempt in range(1, self.retry_count + 1):
            try:
                console.print(f"[yellow]Retry attempt {attempt}/{self.retry_count}[/]")
                
                # Reset status
                self.status = "running"
                self.start_time = datetime.now(timezone.utc)
                
                # Execute again
                self.result = self.function(context)
                self.status = "completed"
                
                self.end_time = datetime.now(timezone.utc)
                self.duration = (self.end_time - self.start_time).total_seconds()
                
                console.print(f"[green]✅ {self.name} succeeded on retry {attempt}[/]")
                return True
                
            except Exception as e:
                self.error = str(e)
                console.print(f"[red]Retry {attempt} failed: {e}[/]")
        
        # All retries failed
        self.status = "failed"
        return False
    
    def skip(self, console: Console):
        """Skip this step."""
        self.status = "skipped"
        console.print(f"[yellow]⏭️ {self.name} skipped[/]")


class Workflow:
    """Represents a complete workflow with multiple steps."""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.steps: List[WorkflowStep] = []
        self.context: Dict[str, Any] = {}
        self.start_time = None
        self.end_time = None
        self.duration = 0.0
        self.status = "pending"  # pending, running, completed, failed
    
    def add_step(self, step: WorkflowStep):
        """Add a step to the workflow."""
        self.steps.append(step)
    
    def add_context(self, key: str, value: Any):
        """Add context data for the workflow."""
        self.context[key] = value
    
    def execute(self, console: Console, stop_on_failure: bool = True) -> bool:
        """Execute the complete workflow."""
        self.status = "running"
        self.start_time = datetime.now(timezone.utc)
        
        console.print(f"\n[bold]🚀 Starting Workflow: {self.name}[/]")
        if self.description:
            console.print(f"[dim]{self.description}[/]")
        
        console.print(f"[blue]Total steps: {len(self.steps)}[/]\n")
        
        # Execute each step
        for i, step in enumerate(self.steps, 1):
            console.print(f"[bold]Step {i}/{len(self.steps)}:[/]")
            
            # Check if step should be skipped
            if step.required and not step.execute(self.context, console):
                if stop_on_failure:
                    self.status = "failed"
                    self.end_time = datetime.now(timezone.utc)
                    self.duration = (self.end_time - self.start_time).total_seconds()
                    
                    console.print(f"\n[red]❌ Workflow failed at step: {step.name}[/]")
                    return False
                else:
                    console.print(f"[yellow]⚠️ Step failed but continuing...[/]")
            elif not step.required:
                step.skip(console)
        
        # Workflow completed
        self.status = "completed"
        self.end_time = datetime.now(timezone.utc)
        self.duration = (self.end_time - self.start_time).total_seconds()
        
        console.print(f"\n[green]✅ Workflow completed successfully in {self.duration:.1f}s[/]")
        return True
    
    def get_summary(self) -> Dict[str, Any]:
        """Get workflow execution summary."""
        completed_steps = [s for s in self.steps if s.status == "completed"]
        failed_steps = [s for s in self.steps if s.status == "failed"]
        skipped_steps = [s for s in self.steps if s.status == "skipped"]
        
        return {
            "name": self.name,
            "status": self.status,
            "total_steps": len(self.steps),
            "completed_steps": len(completed_steps),
            "failed_steps": len(failed_steps),
            "skipped_steps": len(skipped_steps),
            "duration": self.duration,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "step_details": [
                {
                    "name": step.name,
                    "status": step.status,
                    "duration": step.duration,
                    "error": step.error
                }
                for step in self.steps
            ]
        }


class WorkflowManager:
    """Manages workflow execution and provides predefined workflows."""
    
    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        self._register_predefined_workflows()
    
    def _register_predefined_workflows(self):
        """Register predefined workflows."""
        # Full CTI Pipeline Workflow
        full_pipeline = Workflow(
            "full_cti_pipeline",
            "Complete CTI pipeline from ingestion to analysis"
        )
        
        # Add steps (these would be actual functions)
        full_pipeline.add_step(WorkflowStep(
            "validate_environment",
            lambda ctx: self._validate_environment(ctx),
            "Validate system environment and configuration",
            required=True
        ))
        
        full_pipeline.add_step(WorkflowStep(
            "ingest_documents",
            lambda ctx: self._ingest_documents(ctx),
            "Ingest PDF documents from source directory",
            required=True
        ))
        
        full_pipeline.add_step(WorkflowStep(
            "generate_embeddings",
            lambda ctx: self._generate_embeddings(ctx),
            "Generate embeddings for document chunks",
            required=True
        ))
        
        full_pipeline.add_step(WorkflowStep(
            "build_search_index",
            lambda ctx: self._build_search_index(ctx),
            "Build FAISS search index",
            required=True
        ))
        
        full_pipeline.add_step(WorkflowStep(
            "analyze_threat_actor",
            lambda ctx: self._analyze_threat_actor(ctx),
            "Run Orpheus analysis on threat actor",
            required=False
        ))
        
        self.workflows["full_cti_pipeline"] = full_pipeline
        
        # Quick Analysis Workflow
        quick_analysis = Workflow(
            "quick_analysis",
            "Quick threat actor analysis using existing data"
        )
        
        quick_analysis.add_step(WorkflowStep(
            "validate_data",
            lambda ctx: self._validate_data(ctx),
            "Validate existing data and indexes",
            required=True
        ))
        
        quick_analysis.add_step(WorkflowStep(
            "run_analysis",
            lambda ctx: self._run_analysis(ctx),
            "Run Orpheus analysis",
            required=True
        ))
        
        self.workflows["quick_analysis"] = quick_analysis
    
    def register_workflow(self, name: str, workflow: Workflow):
        """Register a custom workflow."""
        self.workflows[name] = workflow
        logger.info(f"Registered workflow: {name}")
    
    def get_workflow(self, name: str) -> Optional[Workflow]:
        """Get a workflow by name."""
        return self.workflows.get(name)
    
    def list_workflows(self) -> List[str]:
        """List available workflow names."""
        return list(self.workflows.keys())
    
    def execute_workflow(self, name: str, context: Dict[str, Any], 
                        console: Console, stop_on_failure: bool = True) -> bool:
        """Execute a workflow by name."""
        workflow = self.get_workflow(name)
        if not workflow:
            console.print(f"[red]Error:[/] Workflow '{name}' not found")
            return False
        
        # Add context to workflow
        for key, value in context.items():
            workflow.add_context(key, value)
        
        return workflow.execute(console, stop_on_failure)
    
    def _validate_environment(self, context: Dict[str, Any]) -> bool:
        """Validate system environment."""
        # This would contain actual validation logic
        logger.info("Environment validation completed")
        return True
    
    def _ingest_documents(self, context: Dict[str, Any]) -> bool:
        """Ingest documents step."""
        # This would contain actual ingestion logic
        logger.info("Document ingestion completed")
        return True
    
    def _generate_embeddings(self, context: Dict[str, Any]) -> bool:
        """Generate embeddings step."""
        # This would contain actual embedding logic
        logger.info("Embedding generation completed")
        return True
    
    def _build_search_index(self, context: Dict[str, Any]) -> bool:
        """Build search index step."""
        # This would contain actual index building logic
        logger.info("Search index building completed")
        return True
    
    def _analyze_threat_actor(self, context: Dict[str, Any]) -> bool:
        """Analyze threat actor step."""
        # This would contain actual analysis logic
        logger.info("Threat actor analysis completed")
        return True
    
    def _validate_data(self, context: Dict[str, Any]) -> bool:
        """Validate existing data step."""
        # This would contain actual validation logic
        logger.info("Data validation completed")
        return True
    
    def _run_analysis(self, context: Dict[str, Any]) -> bool:
        """Run analysis step."""
        # This would contain actual analysis logic
        logger.info("Analysis execution completed")
        return True


def get_workflow_manager() -> WorkflowManager:
    """Get the global workflow manager instance."""
    return WorkflowManager()
