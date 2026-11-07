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

# Default model: HuggingFaceTB/SmolLM2-135M-Instruct
DEFAULT_MODEL_NAME = "HuggingFaceTB/SmolLM2-135M-Instruct"

# Default compute device: 'cpu' strictly complies with the 2 vCPU, no-GPU requirement.
DEFAULT_DEVICE = "cpu"

# Memory limit in Megabytes 
MAX_RAM_MB = 4096
