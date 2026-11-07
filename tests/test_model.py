"""
Test model loading and inference on 1 chunk.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.model_runner import LocalModelRunner
from core.chunker import LogChunker
from core.memory import SecurityMemory
import time

def run():
    print("Initializing model runner...")
    runner = LocalModelRunner()
    
    with open("sample_logs/server.log", "r", encoding="utf-8") as f:
        content = f.read()

    chunker = LogChunker()
    chunks = chunker.split_logs(content)
    test_chunk = chunks[0]  # First chunk: lines 1-7
    print(f"Testing chunk 1 ({test_chunk['token_count']} tokens)...")

    mem = SecurityMemory()
    summary = mem.get_context_summary()

    t0 = time.time()
    result = runner.analyze_chunk(test_chunk, summary)
    print(f"Inference completed in {result['duration_seconds']}s")
    print(f"Prompt tokens: {result['prompt_tokens']}, Output tokens: {result['output_tokens']}")
    print(f"Findings: {result['findings']}")
    print(f"Raw output:\n{result['raw_output']}")

if __name__ == "__main__":
    run()
