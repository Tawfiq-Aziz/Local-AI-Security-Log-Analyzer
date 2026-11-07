"""
End-to-End Pipeline Test on sample_logs/server.log.
"""

import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.analyzer import LogAnalyzerPipeline


def test_full_run():
    print("Starting full pipeline analysis on server.log...")
    with open("sample_logs/server.log", "r", encoding="utf-8") as f:
        content = f.read()

    pipeline = LogAnalyzerPipeline()

    def callback(ev):
        if ev["type"] == "chunk_done":
            if ev["new_findings"]:
                print(f"  [ALERT] Chunk {ev['chunk_index']}: Found {len(ev['new_findings'])} finding(s)!", flush=True)
            else:
                print(f"  [DONE] Chunk {ev['chunk_index']} analyzed ({ev['tokens_used']} tokens)", flush=True)
        elif ev["type"] == "completed":
            print("  [COMPLETED] Pipeline execution finished!", flush=True)

    report = pipeline.run_analysis(
        log_content=content,
        job_id="test_run_01",
        progress_callback=callback
    )

    print("\n================ FINAL REPORT SUMMARY ================")
    print(json.dumps(report["summary"], indent=2))
    print("\n================ IDENTIFIED INCIDENTS ================")
    for inc in report["incidents"]:
        print(f"[{inc['severity']}] {inc['attack_type']} - Target: {inc['target_identifier']}")
        print(f"  Evidence Lines ({inc['evidence_count']}): {inc['line_numbers'][:10]}...")
        print(f"  Reason: {inc['reason']}")
        print(f"  Action: {inc['suggested_action']}\n")

    assert report["summary"]["total_chunks_processed"] > 0
    assert len(report["incidents"]) > 0
    print("ALL ASSERTIONS PASSED! Pipeline works end-to-end.")


if __name__ == "__main__":
    test_full_run()
