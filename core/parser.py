"""
Resilient JSON Parser for AI Outputs.

Handles incomplete, cut-off, or poorly formatted JSON from local LLMs without crashing.
Uses a stack-based bracket closer and a regex fallback.
"""

import json
import re
from typing import Dict, Any, List


class ResilientParser:
    @staticmethod
    def clean_text(text: str) -> str:
        """Removes markdown code fences and extraneous whitespace."""
        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        return text.strip()

    @staticmethod
    def repair_truncated_json(text: str) -> str:
        """
        Uses a bracket stack to close open structures in the exact reverse order they were opened.
        For example: '{ [ { [' gets closed as '] } ] }'.
        """
        # Remove trailing commas or incomplete string keys at the very end
        trimmed = re.sub(r',\s*$', '', text.strip())
        
        # If it cut off inside an open string quote, close the quote
        # (count unescaped quotes)
        quotes = [m.start() for m in re.finditer(r'(?<!\\)"', trimmed)]
        if len(quotes) % 2 != 0:
            trimmed += '"'

        # Track opening brackets/braces using a stack
        stack = []
        in_string = False
        escape = False

        for char in trimmed:
            if char == '"' and not escape:
                in_string = not in_string
            elif not in_string:
                if char in ('{', '['):
                    stack.append(char)
                elif char == '}' and stack and stack[-1] == '{':
                    stack.pop()
                elif char == ']' and stack and stack[-1] == '[':
                    stack.pop()

            escape = (char == '\\' and not escape)

        # Close all remaining open structures in reverse order
        closing_map = {'{': '}', '[': ']'}
        closing_chars = "".join(closing_map[c] for c in reversed(stack))
        return trimmed + closing_chars

    @classmethod
    def parse_findings(cls, raw_response: str) -> List[Dict[str, Any]]:
        """
        Parses LLM response into a list of finding dictionaries.
        Guaranteed never to crash.
        """
        cleaned = cls.clean_text(raw_response)
        if not cleaned:
            return []

        # 1. Direct JSON parse
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                return data.get("findings", [])
            elif isinstance(data, list):
                return data
        except Exception:
            pass

        # 2. Try JSON parse after repairing unclosed brackets and quotes
        try:
            repaired = cls.repair_truncated_json(cleaned)
            data = json.loads(repaired)
            if isinstance(data, dict):
                return data.get("findings", [])
            elif isinstance(data, list):
                return data
        except Exception:
            pass

        # 3. Regex Fallback: Search for JSON-like objects inside the text
        findings = []
        pattern = re.compile(
            r'\{[^{}]*?"attack_type"[^{}]*?\}',
            re.DOTALL | re.IGNORECASE
        )
        for match in pattern.finditer(cleaned):
            chunk = match.group(0)
            try:
                # Attempt to parse each individual block
                item = json.loads(chunk)
                findings.append(item)
            except Exception:
                try:
                    item = json.loads(cls.repair_truncated_json(chunk))
                    findings.append(item)
                except Exception:
                    continue

        return findings
