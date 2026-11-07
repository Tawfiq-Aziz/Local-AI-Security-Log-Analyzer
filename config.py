"""
Configuration settings for the Local Security Log Analyzer.
All token budgets and system limits are defined here.
"""

# Hard limit set by the assessment brief
MAX_CONTEXT_TOKENS = 2048

# Token budget allocation per AI call:
# Prompt (~250) + Memory State (~350) + Log Chunk (~1050) + Model Output (~350) = ~2000 tokens
SYSTEM_PROMPT_BUDGET = 250
MEMORY_STATE_BUDGET = 350
LOG_CHUNK_BUDGET = 1050
RESERVED_OUTPUT_TOKENS = 350

# Default model: Qwen2.5-0.5B-Instruct
# It is very lightweight (~980MB weights), fast on 2 CPU cores, and fits easily inside 4GB RAM.
DEFAULT_MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"

# Default compute device: 'cpu' strictly complies with the 2 vCPU, no-GPU requirement.
DEFAULT_DEVICE = "cpu"

# Memory limit in Megabytes (4 GB from the brief)
MAX_RAM_MB = 4096
