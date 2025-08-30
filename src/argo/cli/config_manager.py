"""Configuration manager for Argo CLI settings."""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ArgoConfigManager:
    """Manage Argo configuration settings with persistence."""
    
    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "argo_cli.json"
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        default_config = {
            "database_url": "postgresql://hunter:hunter@localhost:5433/hunter",
            "openai_api_key": "",
            "log_level": "INFO",
            "json_logs": False,
            "policy_path": "./config/approval_policy.yaml",
            "runbook_state_dir": "./runbook_states",
            "local_embedding_model": "all-MiniLM-L6-v2",
            "batch_size": 5,
            "max_workers": 4,
            "timeout": 300,
            "retry_attempts": 3
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    # Merge with defaults
                    default_config.update(file_config)
                    logger.info("Configuration loaded from file")
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}, using defaults")
        else:
            logger.info("No config file found, using defaults")
        
        return default_config
    
    def _save_config(self):
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info("Configuration saved to file")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any, persist: bool = True):
        """Set configuration value."""
        self.config[key] = value
        
        # Update environment variable for immediate use
        env_key = key.upper()
        if isinstance(value, bool):
            os.environ[env_key] = str(value).lower()
        else:
            os.environ[env_key] = str(value)
        
        if persist:
            self._save_config()
        
        logger.info(f"Set {key} = {value}")
    
    def reset(self, key: str, persist: bool = True):
        """Reset configuration value to default."""
        default_config = {
            "database_url": "postgresql://hunter:hunter@localhost:5433/hunter",
            "openai_api_key": "",
            "log_level": "INFO",
            "json_logs": False,
            "policy_path": "./config/approval_policy.yaml",
            "runbook_state_dir": "./runbook_states",
            "local_embedding_model": "all-MiniLM-L6-v2",
            "batch_size": 5,
            "max_workers": 4,
            "timeout": 300,
            "retry_attempts": 3
        }
        
        if key in default_config:
            self.set(key, default_config[key], persist)
            logger.info(f"Reset {key} to default")
        else:
            logger.warning(f"No default value for {key}")
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        return self.config.copy()
    
    def validate(self) -> Dict[str, Any]:
        """Validate current configuration."""
        validation = {
            "valid": True,
            "issues": [],
            "warnings": []
        }
        
        # Check required settings
        if not self.get("database_url"):
            validation["issues"].append("DATABASE_URL not set")
            validation["valid"] = False
        
        if not self.get("openai_api_key"):
            validation["warnings"].append("OPENAI_API_KEY not set (required for LLM operations)")
        
        # Check file paths
        policy_path = Path(self.get("policy_path", ""))
        if not policy_path.exists():
            validation["warnings"].append(f"Policy file not found: {policy_path}")
        
        runbook_dir = Path(self.get("runbook_state_dir", ""))
        if not runbook_dir.exists():
            validation["warnings"].append(f"Runbook state directory not found: {runbook_dir}")
        
        # Check numeric values
        batch_size = self.get("batch_size", 5)
        if not isinstance(batch_size, int) or batch_size < 1:
            validation["issues"].append("batch_size must be a positive integer")
            validation["valid"] = False
        
        max_workers = self.get("max_workers", 4)
        if not isinstance(max_workers, int) or max_workers < 1:
            validation["issues"].append("max_workers must be a positive integer")
            validation["valid"] = False
        
        return validation
    
    def export(self, format: str = "json", output_path: Optional[str] = None) -> str:
        """Export configuration in various formats."""
        if not output_path:
            output_path = self.config_dir / f"argo_config_export.{format}"
        
        if format.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        elif format.lower() == "env":
            with open(output_path, 'w') as f:
                for key, value in self.config.items():
                    if isinstance(value, bool):
                        f.write(f"{key.upper()}={str(value).lower()}\n")
                    else:
                        f.write(f"{key.upper()}={value}\n")
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Configuration exported to {output_path}")
        return str(output_path)
    
    def import_config(self, import_path: str, merge: bool = True):
        """Import configuration from file."""
        import_file = Path(import_path)
        if not import_file.exists():
            raise FileNotFoundError(f"Import file not found: {import_path}")
        
        try:
            with open(import_file, 'r') as f:
                if import_file.suffix == '.json':
                    imported_config = json.load(f)
                elif import_file.suffix == '.env':
                    imported_config = {}
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            imported_config[key.lower()] = value
                else:
                    raise ValueError(f"Unsupported import format: {import_file.suffix}")
            
            if merge:
                self.config.update(imported_config)
            else:
                self.config = imported_config
            
            self._save_config()
            logger.info(f"Configuration imported from {import_path}")
            
        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            raise


def get_config_manager() -> ArgoConfigManager:
    """Get the global configuration manager instance."""
    config_dir = os.getenv("ARGO_CONFIG_DIR", "./config")
    return ArgoConfigManager(config_dir)
