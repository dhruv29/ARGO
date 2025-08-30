#!/usr/bin/env python3
"""Simple test script for watch folder functionality."""

import os
import time
from pathlib import Path
from src.argo.core.watch_folder import get_watch_folder_manager

def main():
    """Test watch folder functionality."""
    print("🧪 Testing Watch Folder Functionality")
    
    # Get watch manager
    watch_manager = get_watch_folder_manager()
    
    # Add a watcher
    print("\n1. Adding watcher...")
    watch_manager.add_watcher(
        name="test_watcher",
        watch_dir="./samples",
        db_url="postgresql://hunter:hunter@localhost:5433/hunter",
        object_store_dir="./object_store",
        debounce_time=1.0
    )
    
    # Check watchers
    print(f"\n2. Watchers: {watch_manager.list_watchers()}")
    
    # Start watching
    print("\n3. Starting watchers...")
    watch_manager.start()
    
    print("\n4. Watch folder is now active!")
    print("   Drop a PDF file into ./samples to test auto-ingestion")
    print("   Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(5)
            # Show stats
            stats = watch_manager.get_all_stats()
            for name, stat in stats.items():
                print(f"\n📊 {name}: {stat['files_processed']} files processed")
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping watch folder...")
        watch_manager.stop()
        print("✅ Watch folder stopped")

if __name__ == "__main__":
    main()
