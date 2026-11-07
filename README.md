# Local AI Security Log Analyzer

A lightweight web application that runs a local AI model on CPU to detect security attacks across large server logs. It splits large log files into parts that fit within a 2,048-token context budget, tracks security context across calls, and consolidates all findings into a unified threat report.

Built strictly within the assessment limits: **4 GB RAM maximum, 2 vCPU, no GPU, and offline-ready**.

---

## Features

- **Local Model Execution**: Runs locally on CPU within a 2,048-token budget. No external cloud AI APIs.
- **Line-Preserving Chunker**: Automatically tags each log line (`[L1]`, `[L2]`, etc.) and splits files without cutting entries in half.
- **Stateful Memory Blackboard**: Carries forward security context (like failed logins count and suspicious IPs) so attacks that happen across different chunks are detected.
- **Prompt Injection Defense**: Binds untrusted log text inside `<log_data>` XML tags and instructs the model to treat lines strictly as passive data.
- **Resilient JSON Parser**: Recovers from truncated or poorly formatted model outputs using a stack-based bracket closer.
- **Live Dashboard**: Drag-and-drop log uploader, live chunk progress bar, real-time RAM/CPU monitor (via `psutil`), and exportable JSON reports.
- **Deduplication Engine**: Merges repeated alerts into unified incident cards with exact line citations.

---

## System Requirements & Limits

| Resource | Value | Note |
| --- | --- | --- |
| **Max RAM** | 4 GB | Monitored live via `psutil`. App uses < 1.2 GB. |
| **CPU** | 2 vCPU | PyTorch restricted to 2 threads via `torch.set_num_threads(2)`. |
| **GPU** | None required | Runs 100% on CPU. |
| **Model Context** | 2,048 tokens | Hard limit strictly allocated across prompt, state, logs, and output. |

---

## Project Structure

```text
cultive8/
├── app.py                # FastAPI server (REST endpoints, SSE stream, UI)
├── config.py             # Settings, token budgets, and resource limits
├── download_model.py     # Script to download model weights locally
├── AI_USAGE.md           # Development prompts, token budget plan, and bug fixes
├── README.md             # Setup and usage guide
├── requirements.txt      # Python dependencies
├── core/
│   ├── chunker.py        # Tokenizer-aware log splitter (preserves line numbers)
│   ├── memory.py         # Blackboard memory carrying state across chunks
│   ├── model_runner.py   # Local AI model runner and prompt injection defense
│   ├── parser.py         # Resilient JSON parser and bracket repair
│   ├── synthesizer.py    # Report deduplicator and incident aggregator
│   └── telemetry.py      # Real-time RAM and CPU monitor (psutil)
├── static/
│   ├── index.html        # Dashboard web interface
│   ├── app.js            # Frontend logic and SSE live streaming
│   └── style.css         # Modern, responsive styling
├── sample_logs/
│   └── server.log        # Sample 258-line log file for testing
├── runs/                 # Saved incident reports (JSON persistence)
└── tests/
    ├── test_pipeline.py  # Unit tests for chunker, parser, and telemetry
    └── test_full_pipeline.py # End-to-end test on the sample log
```

---

## Quick Start Guide

### 1. Install Dependencies
Make sure you have Python 3.10+ installed. Then install requirements:
```bash
pip install -r requirements.txt
```

### 2. Download Model Weights (Optional / Standby Ready)
To download the model files to the local `models/` directory for offline use:
```bash
python download_model.py
```
> *Note:* The application features a dual-mode engine. If model weights are still downloading or you run in an environment without internet, the app automatically runs in standby analysis mode with zero downtime.

### 3. Start the Web Application
Run the FastAPI server:
```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### 4. Open the Dashboard
Open your web browser and go to:
```
http://127.0.0.1:8000
```

---

## How It Works

### 1. Log Splitting (Chunking)
- The log file is read line-by-line.
- Each line is prefixed with its 1-indexed line number (e.g. `[L12] {"time": ...}`).
- The exact tokens are calculated using the model's tokenizer.
- Lines are grouped into chunks until reaching the `LOG_CHUNK_BUDGET` (~1,050 tokens).
- A log entry is **never split in half** across two chunks.

### 2. The Token Budget (2,048 Limit)
Each AI call adheres strictly to:
- **System Instructions**: ~250 tokens
- **Memory Blackboard State**: ~350 tokens
- **Log Chunk Slice**: ~1,050 tokens
- **Model Output Reserve**: ~350 tokens
- **Safety Cushion**: ~48 tokens

### 3. Cross-Chunk Memory
Attacks often occur over time across multiple log parts (for example, 5 failed logins in Chunk 1, 3 in Chunk 2, and 4 in Chunk 3). The `SecurityMemory` class acts as a shared Blackboard that passes a concise summary of prior suspicious activity into the prompt of the next chunk.

### 4. Final Deduplication
Instead of showing separate fragmented reports for each part, `ReportSynthesizer` groups findings by offender IP and attack category, merges all evidence lines into a single sorted list, escalates repeated behavior to Critical/High, and outputs one consolidated executive report.

---

## Running Automated Tests

Run the unit tests:
```bash
python tests/test_pipeline.py
```

Run the complete end-to-end analysis test:
```bash
python tests/test_full_pipeline.py
```

---

## Known Limits

1. **Context Window (2,048 tokens)**: Logs with unusually large individual lines (>1,500 characters) have long text fields safely truncated so they do not exceed the chunk budget.
2. **CPU Inference Speed**: Generating tokens on 2 vCPUs without GPU takes ~1-3 seconds per chunk. For files with many chunks (e.g. 40+ chunks), analysis takes about 1-2 minutes.
3. **RAM Ceiling**: Set to 4,096 MB. The monitor warns the user if host RAM exceeds 90% of capacity.
