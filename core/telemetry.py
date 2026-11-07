"""
Telemetry and Resource Monitoring Module.

Monitors RAM and CPU usage using psutil to ensure compliance with the 4 GB RAM limit.
"""

import os
import psutil
import config
from typing import Dict, Any


class SystemMonitor:
    @staticmethod
    def get_metrics() -> Dict[str, Any]:
        """Returns current process and system memory metrics in Megabytes."""
        try:
            # Current python process memory
            process = psutil.Process(os.getpid())
            proc_mem_mb = process.memory_info().rss / (1024 * 1024)

            # Total host system memory
            sys_mem = psutil.virtual_memory()
            sys_used_mb = sys_mem.used / (1024 * 1024)
            sys_total_mb = sys_mem.total / (1024 * 1024)
            sys_percent = sys_mem.percent

            # Check if exceeding the 4 GB limit
            is_warning = sys_used_mb > (config.MAX_RAM_MB * 0.9)  # Alert at 90% of 4GB

            return {
                "process_ram_mb": round(proc_mem_mb, 1),
                "system_used_ram_mb": round(sys_used_mb, 1),
                "system_total_ram_mb": round(sys_total_mb, 1),
                "ram_usage_percent": sys_percent,
                "ram_limit_mb": config.MAX_RAM_MB,
                "is_near_ram_limit": is_warning,
                "cpu_percent": psutil.cpu_percent(interval=None)
            }
        except Exception:
            # Fallback if psutil fails
            return {
                "process_ram_mb": 0.0,
                "system_used_ram_mb": 0.0,
                "system_total_ram_mb": config.MAX_RAM_MB,
                "ram_usage_percent": 0.0,
                "ram_limit_mb": config.MAX_RAM_MB,
                "is_near_ram_limit": False,
                "cpu_percent": 0.0
            }
