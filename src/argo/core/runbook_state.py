"""Stateful runbook persistence for audit trails and replay capability."""

import os
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)


class RunbookStateManager:
    """Manage persistent state for LangGraph runbooks."""
    
    def __init__(self, storage_dir: str = "./runbook_states"):
        """
        Initialize state manager.
        
        Args:
            storage_dir: Directory to store runbook states
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    def save_node_state(
        self, 
        run_id: str, 
        node_name: str, 
        inputs: Dict[str, Any], 
        outputs: Dict[str, Any],
        execution_time_ms: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Save state for a specific node execution.
        
        Args:
            run_id: Unique identifier for the run
            node_name: Name of the node/step
            inputs: Input state to the node
            outputs: Output state from the node
            execution_time_ms: Execution time in milliseconds
            metadata: Additional metadata about the execution
        
        Returns:
            State file path
        """
        state_id = f"{run_id}_{node_name}_{uuid.uuid4().hex[:8]}"
        state_file = self.storage_dir / f"{state_id}.json"
        
        state_data = {
            "state_id": state_id,
            "run_id": run_id,
            "node_name": node_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": execution_time_ms,
            "inputs": self._sanitize_state(inputs),
            "outputs": self._sanitize_state(outputs),
            "metadata": metadata or {}
        }
        
        try:
            with open(state_file, 'w') as f:
                json.dump(state_data, f, indent=2, default=str)
            
            logger.info(
                "node_state_saved",
                state_id=state_id,
                run_id=run_id,
                node_name=node_name,
                execution_time_ms=execution_time_ms
            )
            
            return str(state_file)
            
        except Exception as e:
            logger.error(f"Failed to save node state: {e}")
            return ""
    
    def save_run_summary(
        self, 
        run_id: str, 
        final_state: Dict[str, Any],
        total_execution_time_ms: float,
        node_executions: List[Dict[str, Any]]
    ) -> str:
        """
        Save summary of the entire run.
        
        Args:
            run_id: Unique identifier for the run
            final_state: Final state after all nodes executed
            total_execution_time_ms: Total execution time
            node_executions: List of node execution records
        
        Returns:
            Summary file path
        """
        summary_file = self.storage_dir / f"{run_id}_summary.json"
        
        summary_data = {
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_execution_time_ms": total_execution_time_ms,
            "node_count": len(node_executions),
            "final_state": self._sanitize_state(final_state),
            "node_executions": node_executions,
            "status": "completed"
        }
        
        try:
            with open(summary_file, 'w') as f:
                json.dump(summary_data, f, indent=2, default=str)
            
            logger.info(
                "run_summary_saved",
                run_id=run_id,
                total_execution_time_ms=total_execution_time_ms,
                node_count=len(node_executions)
            )
            
            return str(summary_file)
            
        except Exception as e:
            logger.error(f"Failed to save run summary: {e}")
            return ""
    
    def load_run_state(self, run_id: str) -> Optional[Dict[str, Any]]:
        """
        Load the complete state for a specific run.
        
        Args:
            run_id: Unique identifier for the run
        
        Returns:
            Complete run state or None if not found
        """
        summary_file = self.storage_dir / f"{run_id}_summary.json"
        
        if not summary_file.exists():
            logger.warning(f"Run summary not found for run_id: {run_id}")
            return None
        
        try:
            with open(summary_file, 'r') as f:
                summary_data = json.load(f)
            
            # Load individual node states
            node_states = []
            for node_exec in summary_data.get("node_executions", []):
                state_id = node_exec.get("state_id")
                if state_id:
                    state_file = self.storage_dir / f"{state_id}.json"
                    if state_file.exists():
                        with open(state_file, 'r') as sf:
                            node_states.append(json.load(sf))
            
            summary_data["detailed_node_states"] = node_states
            return summary_data
            
        except Exception as e:
            logger.error(f"Failed to load run state: {e}")
            return None
    
    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        List available runs with basic information.
        
        Args:
            limit: Maximum number of runs to return
        
        Returns:
            List of run information
        """
        runs = []
        
        try:
            for summary_file in self.storage_dir.glob("*_summary.json"):
                try:
                    with open(summary_file, 'r') as f:
                        summary = json.load(f)
                    
                    runs.append({
                        "run_id": summary.get("run_id"),
                        "timestamp": summary.get("timestamp"),
                        "execution_time_ms": summary.get("total_execution_time_ms"),
                        "node_count": summary.get("node_count"),
                        "status": summary.get("status"),
                        "summary_file": str(summary_file)
                    })
                    
                except Exception as e:
                    logger.warning(f"Failed to read summary file {summary_file}: {e}")
                    continue
            
            # Sort by timestamp (newest first)
            runs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            return runs[:limit]
            
        except Exception as e:
            logger.error(f"Failed to list runs: {e}")
            return []
    
    def replay_run(self, run_id: str, target_node: Optional[str] = None) -> Dict[str, Any]:
        """
        Replay a run up to a specific node.
        
        Args:
            run_id: Unique identifier for the run
            target_node: Node to replay up to (if None, replay entire run)
        
        Returns:
            Replay results
        """
        run_state = self.load_run_state(run_id)
        if not run_state:
            return {"error": f"Run {run_id} not found"}
        
        replay_results = {
            "run_id": run_id,
            "target_node": target_node,
            "replay_timestamp": datetime.now(timezone.utc).isoformat(),
            "executed_nodes": [],
            "final_state": None
        }
        
        try:
            # Replay nodes in order
            for node_exec in run_state.get("node_executions", []):
                node_name = node_exec.get("node_name")
                
                if target_node and node_name == target_node:
                    # Stop at target node
                    replay_results["final_state"] = node_exec.get("outputs", {})
                    break
                
                # Simulate node execution
                replay_results["executed_nodes"].append({
                    "node_name": node_name,
                    "execution_time_ms": node_exec.get("execution_time_ms", 0),
                    "inputs": node_exec.get("inputs", {}),
                    "outputs": node_exec.get("outputs", {})
                })
                
                if not target_node:
                    # Replay entire run
                    replay_results["final_state"] = node_exec.get("outputs", {})
            
            logger.info(
                "run_replayed",
                run_id=run_id,
                target_node=target_node,
                nodes_executed=len(replay_results["executed_nodes"])
            )
            
        except Exception as e:
            logger.error(f"Failed to replay run: {e}")
            replay_results["error"] = str(e)
        
        return replay_results
    
    def _sanitize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize state data for JSON serialization."""
        sanitized = {}
        
        for key, value in state.items():
            try:
                # Test JSON serialization
                json.dumps(value, default=str)
                sanitized[key] = value
            except (TypeError, ValueError):
                # Convert non-serializable objects to strings
                sanitized[key] = str(value)
        
        return sanitized
    
    def cleanup_old_runs(self, days_to_keep: int = 30) -> int:
        """
        Clean up old run states.
        
        Args:
            days_to_keep: Number of days to keep run states
        
        Returns:
            Number of files cleaned up
        """
        cutoff_time = datetime.now(timezone.utc).timestamp() - (days_to_keep * 24 * 60 * 60)
        cleaned_count = 0
        
        try:
            for state_file in self.storage_dir.glob("*.json"):
                try:
                    file_time = state_file.stat().st_mtime
                    if file_time < cutoff_time:
                        state_file.unlink()
                        cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Failed to clean up {state_file}: {e}")
                    continue
            
            logger.info(f"Cleaned up {cleaned_count} old run state files")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old runs: {e}")
        
        return cleaned_count


def get_runbook_state_manager() -> RunbookStateManager:
    """Get the global runbook state manager instance."""
    storage_dir = os.getenv("RUNBOOK_STATE_DIR", "./runbook_states")
    return RunbookStateManager(storage_dir)
