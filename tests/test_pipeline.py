"""
Verification test for Chunker, Memory, Parser, and Synthesizer.
"""

import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.chunker import LogChunker
from core.memory import SecurityMemory
from core.parser import ResilientParser
from core.synthesizer import ReportSynthesizer
from core.telemetry import SystemMonitor


def test_chunking():
    with open("sample_logs/server.log", "r", encoding="utf-8") as f:
        content = f.read()

    chunker = LogChunker()
    chunks = chunker.split_logs(content)

    print(f"[TEST CHUNKER] Total log lines: {len(content.splitlines())}")
    print(f"[TEST CHUNKER] Total chunks produced: {len(chunks)}")
    for c in chunks:
        print(f"  Chunk {c['chunk_index']}: Lines {c['start_line']} - {c['end_line']} ({c['token_count']} tokens, {c['line_count']} lines)")
        assert c["token_count"] <= 1100, "Chunk exceeded token budget!"
        assert c["text"].startswith(f"[L{c['start_line']}]"), "Line numbering mismatch!"

    print("[TEST CHUNKER] PASS!")


def test_parser_resilience():
    # Test valid JSON
    valid_json = '{"findings": [{"attack_type": "Brute Force", "severity": "High", "line_numbers": [5, 13]}]}'
    res = ResilientParser.parse_findings(valid_json)
    assert len(res) == 1
    assert res[0]["attack_type"] == "Brute Force"

    # Test markdown fenced JSON
    fenced_json = '```json\n{"findings": [{"attack_type": "SQLi", "severity": "Critical", "line_numbers": [29]}]}\n```'
    res = ResilientParser.parse_findings(fenced_json)
    assert len(res) == 1
    assert res[0]["attack_type"] == "SQLi"

    # Test broken / truncated JSON with missing closing brackets
    truncated_json = '{"findings": [{"attack_type": "Scanning", "severity": "Medium", "line_numbers": [54]'
    res = ResilientParser.parse_findings(truncated_json)
    assert len(res) == 1

    print("[TEST PARSER] PASS! Successfully repaired truncated JSON.")


def test_telemetry():
    metrics = SystemMonitor.get_metrics()
    print(f"[TEST TELEMETRY] Process RAM: {metrics['process_ram_mb']} MB, System Used: {metrics['system_used_ram_mb']} MB / {metrics['system_total_ram_mb']} MB")
    assert metrics["process_ram_mb"] > 0
    print("[TEST TELEMETRY] PASS!")


if __name__ == "__main__":
    test_chunking()
    test_parser_resilience()
    test_telemetry()
