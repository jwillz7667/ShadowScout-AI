import json
from datetime import datetime
from pathlib import Path
import asyncio
from typing import Any, Dict

class ResultsLogger:
    def __init__(self, output_dir: str = "scan_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.current_scan = None
        self._lock = asyncio.Lock()

    async def start_new_scan(self, target_url: str) -> None:
        """Start a new scan session."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_scan = {
            "target_url": target_url,
            "timestamp": timestamp,
            "phases": {},
            "errors": []
        }

    async def log_phase_result(self, phase: str, data: Any) -> None:
        """Log results from a specific phase."""
        async with self._lock:
            if self.current_scan is None:
                raise ValueError("No active scan session")
            
            self.current_scan["phases"][phase] = data
            await self._save_results()

    async def log_error(self, error: str) -> None:
        """Log an error."""
        async with self._lock:
            if self.current_scan is None:
                raise ValueError("No active scan session")
            
            self.current_scan["errors"].append({
                "timestamp": datetime.now().isoformat(),
                "error": error
            })
            await self._save_results()

    async def _save_results(self) -> None:
        """Save current results to file."""
        if self.current_scan:
            filename = f"scan_{self.current_scan['timestamp']}_{self.current_scan['target_url'].replace('://', '_').replace('/', '_')}.json"
            filepath = self.output_dir / filename
            
            async with self._lock:
                with open(filepath, 'w') as f:
                    json.dump(self.current_scan, f, indent=2)

    def get_results_path(self) -> str:
        """Get the path to current results file."""
        if self.current_scan:
            filename = f"scan_{self.current_scan['timestamp']}_{self.current_scan['target_url'].replace('://', '_').replace('/', '_')}.json"
            return str(self.output_dir / filename) 