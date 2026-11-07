"""
Report Synthesizer and Deduplicator.

Combines findings from multiple chunks into a unified security report.
Eliminates duplicate alerts and links multi-stage attack events.
"""

from typing import List, Dict, Any


class ReportSynthesizer:
    @staticmethod
    def _normalize_severity(sev: str) -> str:
        s = str(sev).strip().capitalize()
        if s in ["Critical", "High", "Medium", "Low"]:
            return s
        return "Medium"

    @classmethod
    def synthesize(cls, chunk_results: List[Dict[str, Any]], total_log_lines: int) -> Dict[str, Any]:
        """
        Takes raw findings from all chunks and builds one consolidated final report.
        """
        all_raw_findings = []
        total_prompt_tokens = 0
        total_output_tokens = 0
        total_time = 0.0

        for r in chunk_results:
            all_raw_findings.extend(r.get("findings", []))
            total_prompt_tokens += r.get("prompt_tokens", 0)
            total_output_tokens += r.get("output_tokens", 0)
            total_time += r.get("duration_seconds", 0.0)

        # Group findings by (target_identifier, normalized_attack_type)
        grouped_incidents: Dict[str, Dict[str, Any]] = {}

        for item in all_raw_findings:
            target = str(item.get("target_identifier", "Unknown Target")).strip()
            attack_type = str(item.get("attack_type", "Suspicious Activity")).strip()
            
            # Skip any template placeholders
            if "ip or username" in target.lower() or "|" in attack_type:
                continue

            # Simple grouping key: IP/Identifier + Attack Category
            key = f"{target}::{attack_type.lower()}"

            # Extract line numbers as integers
            raw_lines = item.get("line_numbers", [])
            valid_lines = []
            for ln in raw_lines:
                try:
                    if isinstance(ln, str):
                        clean_ln = ln.replace("[", "").replace("]", "").replace("L", "").replace("l", "")
                        valid_lines.append(int(clean_ln))
                    else:
                        valid_lines.append(int(ln))
                except (ValueError, TypeError):
                    continue

            if key not in grouped_incidents:
                grouped_incidents[key] = {
                    "attack_type": attack_type,
                    "target_identifier": target,
                    "severity": cls._normalize_severity(item.get("severity", "Medium")),
                    "line_numbers": set(valid_lines),
                    "reasons": [item.get("reason", "")],
                    "suggested_actions": [item.get("suggested_action", "")]
                }
            else:
                # Merge evidence lines
                grouped_incidents[key]["line_numbers"].update(valid_lines)
                
                # Update severity if the new finding is higher priority
                current_sev = grouped_incidents[key]["severity"]
                new_sev = cls._normalize_severity(item.get("severity", "Medium"))
                sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                if sev_order.get(new_sev, 1) > sev_order.get(current_sev, 1):
                    grouped_incidents[key]["severity"] = new_sev

                # Collect distinct reasons
                reason = item.get("reason", "")
                if reason and reason not in grouped_incidents[key]["reasons"]:
                    grouped_incidents[key]["reasons"].append(reason)
                
                action = item.get("suggested_action", "")
                if action and action not in grouped_incidents[key]["suggested_actions"]:
                    grouped_incidents[key]["suggested_actions"].append(action)

        # Convert set of line numbers back to sorted lists
        final_incidents = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for inc in grouped_incidents.values():
            sorted_lines = sorted(list(inc["line_numbers"]))
            
            # Cross-part escalation rule: if repeated failures cross multiple lines, ensure high severity
            if len(sorted_lines) >= 5 and inc["severity"] in ["Low", "Medium"]:
                inc["severity"] = "High"

            # Deduplicate reasons
            clean_reasons = []
            for r in inc["reasons"]:
                clean_r = r.strip()
                if clean_r and clean_r not in clean_reasons and "short explanation" not in clean_r.lower():
                    clean_reasons.append(clean_r)

            final_incidents.append({
                "attack_type": inc["attack_type"],
                "target_identifier": inc["target_identifier"],
                "severity": inc["severity"],
                "line_numbers": sorted_lines,
                "evidence_count": len(sorted_lines),
                "reason": " ".join(clean_reasons[:2]) if clean_reasons else "Suspicious event observed in log stream.",
                "suggested_action": inc["suggested_actions"][0] if inc["suggested_actions"] else "Monitor entity"
            })
            severity_counts[inc["severity"]] += 1

        # Sort incidents: Critical first, then High, Medium, Low
        priority_map = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        final_incidents.sort(key=lambda x: priority_map.get(x["severity"], 4))

        return {
            "summary": {
                "total_lines_analyzed": total_log_lines,
                "total_chunks_processed": len(chunk_results),
                "total_incidents_found": len(final_incidents),
                "severity_counts": severity_counts,
                "total_tokens_used": total_prompt_tokens + total_output_tokens,
                "prompt_tokens": total_prompt_tokens,
                "output_tokens": total_output_tokens,
                "total_analysis_time_seconds": round(total_time, 2)
            },
            "incidents": final_incidents
        }
