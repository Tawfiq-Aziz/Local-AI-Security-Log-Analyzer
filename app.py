"""
Local AI Security Log Analyzer - FastAPI Server.

Provides REST and SSE endpoints for log uploads, real-time analysis streaming,
telemetry monitoring, and report retrieval.
"""

import os
import json
import uuid
import asyncio
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import config
from core.analyzer import LogAnalyzerPipeline
from core.telemetry import SystemMonitor


app = FastAPI(
    title="Local AI Security Log Analyzer",
    description="Analyzes server logs using local LLMs within 4GB RAM and 2,048-token context limits.",
    version="1.0.0"
)

# Enable CORS for convenience
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared in-memory event queues for SSE streaming: job_id -> asyncio.Queue
active_job_queues: Dict[str, asyncio.Queue] = {}
# Active pipeline instance
pipeline = LogAnalyzerPipeline()


# Ensure directories exist
os.makedirs("runs", exist_ok=True)
os.makedirs("sample_logs", exist_ok=True)
os.makedirs("static", exist_ok=True)


def background_worker(job_id: str, log_content: str):
    """Executes log analysis and pushes events to the SSE queue."""
    queue = active_job_queues.get(job_id)

    def on_progress(event_data: Dict[str, Any]):
        if queue:
            # Put event into async queue safely from sync callback
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(queue.put(event_data))
            loop.close()

    try:
        pipeline.run_analysis(
            log_content=log_content,
            job_id=job_id,
            progress_callback=on_progress
        )
    except Exception as e:
        if queue:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(queue.put({
                "type": "error",
                "job_id": job_id,
                "error": str(e)
            }))
            loop.close()


@app.post("/api/upload")
async def upload_log_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Uploads a .log or .txt file and queues it for analysis."""
    # Validate extension
    filename = file.filename or ""
    if not (filename.endswith(".log") or filename.endswith(".txt")):
        raise HTTPException(status_code=400, detail="Only .log or .txt files are allowed.")

    content_bytes = await file.read()
    try:
        log_content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        log_content = content_bytes.decode("latin-1")

    if not log_content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    job_id = str(uuid.uuid4())[:8]
    active_job_queues[job_id] = asyncio.Queue()

    # Launch analysis in background task
    background_tasks.add_task(background_worker, job_id, log_content)

    return {
        "job_id": job_id,
        "filename": filename,
        "line_count": len(log_content.splitlines()),
        "status": "QUEUED"
    }


@app.post("/api/use-sample")
async def use_sample_log(background_tasks: BackgroundTasks):
    """Loads the included sample log file and queues it for analysis."""
    sample_path = "sample_logs/server.log"
    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail="Sample log file not found.")

    with open(sample_path, "r", encoding="utf-8") as f:
        log_content = f.read()

    job_id = str(uuid.uuid4())[:8]
    active_job_queues[job_id] = asyncio.Queue()

    background_tasks.add_task(background_worker, job_id, log_content)

    return {
        "job_id": job_id,
        "filename": "server.log (Sample)",
        "line_count": len(log_content.splitlines()),
        "status": "QUEUED"
    }


@app.get("/api/stream/{job_id}")
async def stream_progress(job_id: str):
    """Server-Sent Events endpoint streaming live chunk progress and final findings."""
    queue = active_job_queues.get(job_id)
    if not queue:
        # Check if this job is already completed on disk
        saved_file = f"runs/{job_id}.json"
        if os.path.exists(saved_file):
            with open(saved_file, "r", encoding="utf-8") as f:
                saved_report = json.load(f)
            async def once_generator():
                yield f"data: {json.dumps({'type': 'completed', 'job_id': job_id, 'report': saved_report})}\n\n"
            return StreamingResponse(once_generator(), media_type="text/event-stream")
        raise HTTPException(status_code=404, detail="Job not found.")

    async def event_generator():
        while True:
            try:
                # Wait for next event with a 60s timeout
                event = await asyncio.wait_for(queue.get(), timeout=60.0)
                yield f"data: {json.dumps(event)}\n\n"

                if event.get("type") in ("completed", "error"):
                    break
            except asyncio.TimeoutError:
                # Send keep-alive ping
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/api/report/{job_id}")
async def get_report(job_id: str):
    """Retrieves saved final report by job_id."""
    path = f"runs/{job_id}.json"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/runs")
async def list_runs():
    """Lists past completed runs for resuming / inspection."""
    runs = []
    if os.path.exists("runs"):
        for fname in os.listdir("runs"):
            if fname.endswith(".json"):
                job_id = fname[:-5]
                filepath = os.path.join("runs", fname)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        runs.append({
                            "job_id": job_id,
                            "summary": data.get("summary", {})
                        })
                except Exception:
                    continue
    return runs


@app.get("/api/telemetry")
async def get_telemetry():
    """Returns current RAM and CPU metrics."""
    return SystemMonitor.get_metrics()


# Mount static directory for frontend
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serves the dashboard user interface."""
    index_file = "static/index.html"
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Local AI Security Log Analyzer is running.</h1><p>Visit /static/index.html</p>"
