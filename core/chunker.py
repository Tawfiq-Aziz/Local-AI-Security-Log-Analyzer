"""
Log Chunking Module.

Splits large log files into smaller parts that fit within the token budget.
Key Rules:
1. Keeps original line numbers (1-indexed) prefixed as [L<number>].
2. Never cuts a log entry in half across chunks.
3. If an individual line is abnormally long, it trims long text fields safely.
4. Counts exact tokens using the model's tokenizer.
"""

from typing import List, Dict, Any
from transformers import AutoTokenizer
import config


class LogChunker:
    def __init__(self, model_name: str = config.DEFAULT_MODEL_NAME):
        """Initialize the tokenizer for counting tokens accurately."""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        except Exception:
            # Fallback fast tokenizer if offline or loading from cache
            self.tokenizer = None

    def count_tokens(self, text: str) -> int:
        """Count tokens in a string. Uses tokenizer if available, else approximate ~4 chars per token."""
        if self.tokenizer:
            return len(self.tokenizer.encode(text, add_special_tokens=False))
        # Simple fallback approximation: 1 token ≈ 4 characters
        return max(1, len(text) // 4)

    def _truncate_long_line(self, line: str, max_chars: int = 1500) -> str:
        """Trims extremely long single lines (e.g. huge payloads) so they don't break the chunk budget."""
        if len(line) > max_chars:
            return line[:max_chars] + "... [TRUNCATED]"
        return line

    def split_logs(self, log_content: str, token_limit: int = config.LOG_CHUNK_BUDGET) -> List[Dict[str, Any]]:
        """
        Takes raw log text, numbers each line as [L1], [L2], etc.,
        and groups them into chunks under the token_limit.
        """
        lines = log_content.splitlines()
        chunks = []

        current_lines = []
        current_tokens = 0
        current_start_line = 1

        for i, raw_line in enumerate(lines, start=1):
            cleaned = raw_line.strip()
            if not cleaned:
                continue  # skip empty lines

            # Truncate if this single line is unusually huge
            safe_line = self._truncate_long_line(cleaned)
            formatted_line = f"[L{i}] {safe_line}"
            line_tokens = self.count_tokens(formatted_line + "\n")

            # If adding this line would exceed the token limit, close the current chunk
            if current_lines and (current_tokens + line_tokens > token_limit):
                chunk_text = "\n".join(current_lines)
                chunks.append({
                    "chunk_index": len(chunks) + 1,
                    "start_line": current_start_line,
                    "end_line": i - 1,
                    "token_count": current_tokens,
                    "line_count": len(current_lines),
                    "text": chunk_text
                })
                # Reset for new chunk
                current_lines = [formatted_line]
                current_tokens = line_tokens
                current_start_line = i
            else:
                current_lines.append(formatted_line)
                current_tokens += line_tokens

        # Add any remaining lines in the final chunk
        if current_lines:
            chunk_text = "\n".join(current_lines)
            chunks.append({
                "chunk_index": len(chunks) + 1,
                "start_line": current_start_line,
                "end_line": len(lines),
                "token_count": current_tokens,
                "line_count": len(current_lines),
                "text": chunk_text
            })

        # Update total_chunks in metadata for each chunk
        total = len(chunks)
        for c in chunks:
            c["total_chunks"] = total

        return chunks
