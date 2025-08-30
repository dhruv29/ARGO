"""Watch folder functionality for automatic PDF ingestion."""

import os
import time
import json
import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psycopg
from rich.console import Console

from .ingest import ingest_directory
from .logging_config import get_audit_logger

logger = get_audit_logger("watch_folder")
console = Console()

# Global singleton instance
_watch_manager_instance: Optional['WatchFolderManager'] = None

class PDFWatcher(FileSystemEventHandler):
    """Watch for PDF files and automatically ingest them."""
    
    def __init__(self, watch_dir: str, db_url: str, object_store_dir: str, 
                 debounce_time: float = 2.0, callback: Optional[Callable] = None):
        self.watch_dir = Path(watch_dir)
        self.db_url = db_url
        self.object_store_dir = Path(object_store_dir)
        self.debounce_time = debounce_time
        self.callback = callback
        
        # Statistics
        self.stats = {
            'start_time': datetime.now(),
            'files_detected': 0,
            'files_processed': 0,
            'files_skipped': 0,
            'files_failed': 0,
            'total_bytes': 0,
            'currently_processing': set()
        }
        
        # Debouncing
        self.pending_files: Dict[str, float] = {}
        
        # Ensure object store exists
        self.object_store_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"PDF watcher initialized for {watch_dir}")
    
    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path.suffix.lower() != '.pdf':
            return
        
        self._handle_pdf_event('created', file_path)
    
    def on_moved(self, event):
        """Handle file move events (e.g., from downloads folder)."""
        if event.is_directory:
            return
        
        file_path = Path(event.dest_path)
        if file_path.suffix.lower() != '.pdf':
            return
        
        self._handle_pdf_event('moved', file_path)
    
    def _handle_pdf_event(self, event_type: str, file_path: Path):
        """Handle PDF file events with debouncing."""
        try:
            # Check if file is ready (not being written)
            if not self._is_file_ready(file_path):
                logger.debug(f"File {file_path} not ready yet, skipping")
                return
            
            # Calculate file hash for idempotency
            file_hash = self._calculate_file_hash(file_path)
            file_key = f"{file_path}:{file_hash}"
            
            # Check if we're already processing this file
            if file_key in self.stats['currently_processing']:
                logger.debug(f"Already processing {file_path}, skipping")
                return
            
            # Check if we've already processed this file
            if self._is_file_already_processed(file_hash):
                logger.info(f"File {file_path} already processed (hash: {file_hash[:8]}), skipping")
                self.stats['files_skipped'] += 1
                return
            
            # Add to pending files with debouncing
            self.pending_files[file_key] = time.time()
            self.stats['files_detected'] += 1
            
            logger.info(f"PDF event detected: {event_type} - {file_path}")
            
            # Schedule processing after debounce delay
            self._schedule_processing(file_key, file_path, file_hash)
            
        except Exception as e:
            logger.error(f"Error handling PDF event: {e}")
            self.stats['files_failed'] += 1
    
    def _is_file_ready(self, file_path: Path) -> bool:
        """Check if file is ready for processing (not being written)."""
        try:
            # Wait a bit for file to be fully written
            time.sleep(0.5)
            
            # Check if file size is stable
            initial_size = file_path.stat().st_size
            time.sleep(0.5)
            current_size = file_path.stat().st_size
            
            return initial_size == current_size
        except Exception:
            return False
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            return ""
    
    def _is_file_already_processed(self, file_hash: str) -> bool:
        """Check if file hash already exists in object store."""
        if not file_hash:
            return False
        
        # Check if file exists in object store
        object_store_file = self.object_store_dir / f"{file_hash}.pdf"
        return object_store_file.exists()
    
    def _schedule_processing(self, file_key: str, file_path: Path, file_hash: str):
        """Schedule file processing after debounce delay."""
        def process_file():
            try:
                # Remove from pending
                if file_key in self.pending_files:
                    del self.pending_files[file_key]
                
                # Check if file still exists
                if not file_path.exists():
                    logger.warning(f"File {file_path} no longer exists, skipping")
                    return
                
                # Process the file
                self._process_pdf_file(file_path, file_hash)
                
            except Exception as e:
                logger.error(f"Error in scheduled processing: {e}")
                self.stats['files_failed'] += 1
                if file_key in self.stats['currently_processing']:
                    self.stats['currently_processing'].remove(file_key)
        
        # Schedule processing
        import threading
        timer = threading.Timer(self.debounce_time, process_file)
        timer.start()
    
    def _process_pdf_file(self, file_path: Path, file_hash: str):
        """Process a PDF file for ingestion."""
        file_key = f"{file_path}:{file_hash}"
        
        try:
            # Mark as currently processing
            self.stats['currently_processing'].add(file_key)
            
            logger.info(f"Processing new PDF: {file_path}")
            
            # Create temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Copy file to temp directory
                temp_pdf = temp_path / file_path.name
                shutil.copy2(file_path, temp_pdf)
                
                # Process with existing ingestion logic
                results = ingest_directory(
                    directory_path=temp_path,
                    object_store_dir=self.object_store_dir,
                    db_url=self.db_url,
                    min_tokens=300,
                    max_tokens=800,
                    use_ocr_fallback=True
                )
                
                if results:
                    # Update statistics
                    self.stats['files_processed'] += 1
                    self.stats['total_bytes'] += file_path.stat().st_size
                    
                    # Log success
                    logger.info(f"Successfully processed: {file_path}")
                    logger.info(f"File hash: {file_hash[:8]}")
                    logger.info(f"File size: {file_path.stat().st_size} bytes")
                    
                    # Call callback if provided
                    if self.callback:
                        try:
                            self.callback(file_path, results)
                        except Exception as e:
                            logger.error(f"Error in callback: {e}")
                    
                    # Audit log
                    audit_logger = get_audit_logger("watch_folder")
                    audit_logger.info(
                        "pdf_auto_ingested",
                        file_path=str(file_path),
                        file_hash=file_hash,
                        file_size=file_path.stat().st_size,
                        results=results,
                        audit=True
                    )
                    
                else:
                    logger.warning(f"No results from ingestion for {file_path}")
                    self.stats['files_failed'] += 1
                    
        except Exception as e:
            logger.error(f"Error processing PDF {file_path}: {e}")
            self.stats['files_failed'] += 1
            
        finally:
            # Remove from currently processing
            if file_key in self.stats['currently_processing']:
                self.stats['currently_processing'].remove(file_key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        uptime = datetime.now() - self.stats['start_time']
        uptime_seconds = uptime.total_seconds()
        
        # Calculate processing rate
        if uptime_seconds > 0:
            files_per_minute = (self.stats['files_processed'] / uptime_seconds) * 60
        else:
            files_per_minute = 0.0
        
        return {
            'uptime_seconds': uptime_seconds,
            'files_detected': self.stats['files_detected'],
            'files_processed': self.stats['files_processed'],
            'files_skipped': self.stats['files_skipped'],
            'files_failed': self.stats['files_failed'],
            'total_bytes': self.stats['total_bytes'],
            'files_per_minute': files_per_minute,
            'currently_processing': len(self.stats['currently_processing']),
            'pending_files': len(self.pending_files)
        }
    
    def print_stats(self):
        """Print statistics to console."""
        stats = self.get_stats()
        
        if console:
            console.print(f"\n[bold]📊 Watch Folder Statistics[/]")
            console.print(f"   [blue]Uptime:[/] {stats['uptime_seconds']:.1f}s")
            console.print(f"   [blue]Files Detected:[/] {stats['files_detected']}")
            console.print(f"   [blue]Files Processed:[/] {stats['files_processed']}")
            console.print(f"   [blue]Files Skipped:[/] {stats['files_skipped']}")
            console.print(f"   [blue]Files Failed:[/] {stats['files_failed']}")
            console.print(f"   [blue]Total Bytes:[/] {stats['total_bytes']:,}")
            console.print(f"   [blue]Processing Rate:[/] {stats['files_per_minute']:.1f} files/min")
            console.print(f"   [blue]Currently Processing:[/] {stats['currently_processing']}")
            console.print(f"   [blue]Pending Files:[/] {stats['pending_files']}")
        else:
            logger.info(f"Watch folder stats: {stats}")


class WatchFolderManager:
    """Manage multiple folder watchers with persistent state."""
    
    def __init__(self, state_file: str = ".argo_watch_state.json"):
        self.watchers: Dict[str, PDFWatcher] = {}
        self.observer = Observer()
        self.running = False
        self.state_file = Path(state_file)
        self._load_state()
    
    def _load_state(self):
        """Load watcher configurations from state file."""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    logger.info(f"Loaded watch folder state from {self.state_file}")
                    # Restore watchers immediately
                    self._restore_watchers_from_state()
        except Exception as e:
            logger.warning(f"Could not load watch folder state: {e}")
    
    def _save_state(self):
        """Save watcher configurations to state file."""
        try:
            state = {
                'watchers': {},
                'timestamp': datetime.now().isoformat(),
                'running': self.running
            }
            
            for name, watcher in self.watchers.items():
                state['watchers'][name] = {
                    'watch_dir': str(watcher.watch_dir),
                    'db_url': watcher.db_url,
                    'object_store_dir': str(watcher.object_store_dir),
                    'debounce_time': watcher.debounce_time
                }
            
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
                
            logger.debug(f"Saved watch folder state to {self.state_file}")
        except Exception as e:
            logger.warning(f"Could not save watch folder state: {e}")
    
    def _restore_watchers_from_state(self):
        """Restore watchers from saved state."""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                
                for name, config in state.get('watchers', {}).items():
                    try:
                        watcher = PDFWatcher(
                            config['watch_dir'],
                            config['db_url'],
                            config['object_store_dir'],
                            config.get('debounce_time', 2.0)
                        )
                        self.watchers[name] = watcher
                        logger.info(f"Restored watcher '{name}' for {config['watch_dir']}")
                    except Exception as e:
                        logger.warning(f"Could not restore watcher '{name}': {e}")
                        
        except Exception as e:
            logger.warning(f"Could not restore watchers from state: {e}")
    
    def add_watcher(self, name: str, watch_dir: str, db_url: str, 
                    object_store_dir: str, debounce_time: float = 2.0,
                    callback: Optional[Callable] = None) -> str:
        """Add a new folder watcher."""
        if name in self.watchers:
            raise ValueError(f"Watcher '{name}' already exists")
        
        # Create watcher
        watcher = PDFWatcher(watch_dir, db_url, object_store_dir, debounce_time, callback)
        self.watchers[name] = watcher
        
        # Schedule with observer if running
        if self.running:
            self.observer.schedule(watcher, watch_dir, recursive=True)
        
        # Save state
        self._save_state()
        
        logger.info(f"Added watcher '{name}' for {watch_dir}")
        return name
    
    def remove_watcher(self, name: str):
        """Remove a folder watcher."""
        if name not in self.watchers:
            raise ValueError(f"Watcher '{name}' not found")
        
        # Remove from observer if running
        if self.running:
            watcher = self.watchers[name]
            self.observer.unschedule(watcher)
        
        # Remove from watchers
        del self.watchers[name]
        
        # Save state
        self._save_state()
        
        logger.info(f"Removed watcher '{name}'")
    
    def start(self):
        """Start all watchers."""
        if self.running:
            logger.warning("Watch folder manager already running")
            return
        
        # Schedule all watchers with observer
        for name, watcher in self.watchers.items():
            self.observer.schedule(watcher, watcher.watch_dir, recursive=True)
            logger.debug(f"Scheduled watcher '{name}' with observer")
        
        # Start observer
        self.observer.start()
        self.running = True
        
        # Save state
        self._save_state()
        
        logger.info("Watch folder manager started")
    
    def stop(self):
        """Stop all watchers."""
        if not self.running:
            logger.warning("Watch folder manager not running")
            return
        
        self.observer.stop()
        self.observer.join()
        self.running = False
        
        # Save state
        self._save_state()
        
        logger.info("Watch folder manager stopped")
    
    def get_watcher(self, name: str) -> Optional[PDFWatcher]:
        """Get a watcher by name."""
        return self.watchers.get(name)
    
    def list_watchers(self) -> List[str]:
        """List all watcher names."""
        return list(self.watchers.keys())
    
    def get_all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all watchers."""
        return {name: watcher.get_stats() for name, watcher in self.watchers.items()}
    
    def print_all_stats(self):
        """Print statistics for all watchers."""
        if not self.watchers:
            logger.info("No watchers configured")
            return
        
        for name, watcher in self.watchers.items():
            logger.info(f"\n--- Watcher: {name} ---")
            watcher.print_stats()
    
    def is_running(self) -> bool:
        """Check if the watch folder manager is running."""
        return self.running


def get_watch_folder_manager() -> WatchFolderManager:
    """Get the global watch folder manager instance (singleton)."""
    global _watch_manager_instance
    
    if _watch_manager_instance is None:
        _watch_manager_instance = WatchFolderManager()
    
    return _watch_manager_instance
