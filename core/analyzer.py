"""
Analysis Coordinator Module.

Executes sequential, token-budgeted analysis of log chunks with state tracking,
resilient error handling, and live progress callbacks.
"""

import os
import json
import gc
import uuid
import re
from typing import Dict, Any, Callable, Optional
from core.chunker import LogChunker
from core.memory import SecurityMemory
from core.model_runner import LocalModelRunner
from core.synthesizer import ReportSynthesizer
from core.telemetry import SystemMonitor


class LogAnalyzerPipeline:
    def __init__(self, model_runner: Optional[LocalModelRunner] = None):
        self.chunker = LogChunker()
        self.model_runner = model_runner or LocalModelRunner()

    def _prepopulate_memory_from_raw_lines(self, lines: list, memory: SecurityMemory):
        """
        Lightweight pre-scan to seed the memory blackboard with basic observed events
        (e.g., 401s, 403s on sensitive files, SQL injection keywords).
        This gives the local AI model accurate historical context right away.
        """
        for i, line in enumerate(lines, start=1):
            # Check for failed logins
            if "login" in line and ("401" in line or "invalid_password" in line):
                ip_match = re.search(r'("client_ip"|\bclient_ip\b)[\s:=]+"([^"]+)"', line)
                ip = ip_match.group(2) if ip_match else "unknown"
                memory.register_event(ip, "failed_login", i)

            # Check for successful logins
            elif "login" in line and ("200" in line or "auth_result\":\"success\"" in line):
                ip_match = re.search(r'("client_ip"|\bclient_ip\b)[\s:=]+"([^"]+)"', line)
                ip = ip_match.group(2) if ip_match else "unknown"
                memory.register_event(ip, "successful_login", i)

            # Check for path scanning / secret probing
            elif any(s in line for s in [".env", ".git", "wp-admin", "phpmyadmin", "backup.sql", "etc/passwd"]):
                ip_match = re.search(r'("client_ip"|\bclient_ip\b)[\s:=]+"([^"]+)"', line)
                ip = ip_match.group(2) if ip_match else "unknown"
                path_match = re.search(r'("path"|\bpath\b)[\s:=]+"([^"]+)"', line)
                path = path_match.group(2) if path_match else "secret-file"
                memory.register_event(ip, "path_scan", i, path)

            # Check for SQL injection
            elif any(sqli in line for sqli in ["%27", "UNION", "SELECT", "SLEEP", "1=1", "--"]):
                ip_match = re.search(r'("client_ip"|\bclient_ip\b)[\s:=]+"([^"]+)"', line)
                ip = ip_match.group(2) if ip_match else "unknown"
                memory.register_event(ip, "injection", i)

    def run_analysis(
        self,
        log_content: str,
        job_id: str,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Processes the log file through the pipeline:
        1. Chunks logs while preserving line numbers.
        2. Maintains state memory across chunks.
        3. Calls local model one chunk at a time.
        4. Emits real-time progress events.
        5. Combines findings into final consolidated report.
        """
        raw_lines = log_content.splitlines()
        chunks = self.chunker.split_logs(log_content)
        total_chunks = len(chunks)

        memory = SecurityMemory()
        self._prepopulate_memory_from_raw_lines(raw_lines, memory)

        chunk_results = []

        for idx, chunk in enumerate(chunks, start=1):
            # Fetch context summary carried over from prior parts
            memory_summary = memory.get_context_summary()

            # Emit start of chunk processing
            if progress_callback:
                progress_callback({
                    "type": "progress",
                    "job_id": job_id,
                    "chunk_index": idx,
                    "total_chunks": total_chunks,
                    "start_line": chunk["start_line"],
                    "end_line": chunk["end_line"],
                    "status": f"Analyzing chunk {idx} of {total_chunks} (Lines {chunk['start_line']} - {chunk['end_line']})...",
                    "telemetry": SystemMonitor.get_metrics()
                })

            try:
                # Run through the local AI model
                result = self.model_runner.analyze_chunk(chunk, memory_summary)
            except Exception as e:
                # Resilient error handling: if a call fails, record fallback finding and continue
                result = {
                    "chunk_index": idx,
                    "total_chunks": total_chunks,
                    "prompt_tokens": 0,
                    "output_tokens": 0,
                    "duration_seconds": 0.0,
                    "findings": [],
                    "error": str(e)
                }

            # If the model found attacks, record them into memory for subsequent chunks
            for f in result.get("findings", []):
                memory.record_finding(f)

            chunk_results.append(result)

            # Emit chunk completion
            if progress_callback:
                progress_callback({
                    "type": "chunk_done",
                    "job_id": job_id,
                    "chunk_index": idx,
                    "total_chunks": total_chunks,
                    "new_findings": result.get("findings", []),
                    "tokens_used": result.get("total_tokens", 0),
                    "duration": result.get("duration_seconds", 0),
                    "telemetry": SystemMonitor.get_metrics()
                })

            # Force garbage collection to keep RAM usage well below 4 GB
            gc.collect()

        # Combine all findings into one consolidated report
        final_report = ReportSynthesizer.synthesize(chunk_results, len(raw_lines))
        final_report["job_id"] = job_id
        final_report["status"] = "COMPLETED"

        # Save report locally for persistence & resume support
        os.makedirs("runs", exist_ok=True)
        with open(f"runs/{job_id}.json", "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=2)

        if progress_callback:
            progress_callback({
                "type": "completed",
                "job_id": job_id,
                "report": final_report,
                "telemetry": SystemMonitor.get_metrics()
            })

        return final_report
