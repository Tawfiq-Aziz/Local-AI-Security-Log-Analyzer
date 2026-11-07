"""
Security Memory Blackboard Module.

Carries useful security context across log chunks so the AI model can link
events happening across different parts of the log file (e.g., slow brute force,
or scanning followed by an exploit).
"""

from typing import Dict, Any, List


class SecurityMemory:
    def __init__(self):
        # Dictionary of tracked entities: ip_address -> entity record
        self.tracked_ips: Dict[str, Dict[str, Any]] = {}
        # List of all findings recorded so far
        self.accumulated_findings: List[Dict[str, Any]] = []

    def register_event(self, ip: str, event_type: str, line_no: int, details: str = ""):
        """Records an event for a specific IP address."""
        if not ip:
            return

        if ip not in self.tracked_ips:
            self.tracked_ips[ip] = {
                "failed_logins": [],
                "successful_logins": [],
                "scanned_paths": [],
                "injection_lines": [],
                "status": "Monitored"
            }

        record = self.tracked_ips[ip]

        if event_type == "failed_login":
            record["failed_logins"].append(line_no)
            if len(record["failed_logins"]) >= 3:
                record["status"] = "Suspected Brute-Force"
        elif event_type == "successful_login":
            record["successful_logins"].append(line_no)
            if len(record["failed_logins"]) >= 3:
                record["status"] = "CRITICAL: Possible Account Compromise after Brute-Force!"
        elif event_type == "path_scan":
            if details and details not in record["scanned_paths"]:
                record["scanned_paths"].append(details)
            record["status"] = "Reconnaissance / Vulnerability Scanning"
        elif event_type == "injection":
            record["injection_lines"].append(line_no)
            record["status"] = "Active Injection Attack"

    def record_finding(self, finding: Dict[str, Any]):
        """Saves a model finding into memory."""
        self.accumulated_findings.append(finding)

    def get_context_summary(self) -> str:
        """
        Creates a short, high-value summary of previous findings to feed into
        the next AI model prompt. Stays within ~300 tokens.
        """
        if not self.tracked_ips and not self.accumulated_findings:
            return "No prior suspicious activity recorded. This is the start of analysis."

        summary_lines = ["PRIOR ACTIVITY SUMMARY FROM EARLIER CHUNKS:"]

        # Only list IPs that did something noteworthy
        noteworthy_ips = 0
        for ip, data in self.tracked_ips.items():
            details = []
            if data["failed_logins"]:
                details.append(f"{len(data['failed_logins'])} failed logins (e.g. lines {data['failed_logins'][:5]})")
            if data["successful_logins"]:
                details.append(f"SUCCESSFUL login at line {data['successful_logins']}")
            if data["scanned_paths"]:
                details.append(f"probed paths: {', '.join(data['scanned_paths'][:4])}")
            if data["injection_lines"]:
                details.append(f"injection payloads at lines {data['injection_lines']}")

            if details:
                noteworthy_ips += 1
                summary_lines.append(f"- IP {ip} [{data['status']}]: " + "; ".join(details))

        if noteworthy_ips == 0:
            summary_lines.append("Normal baseline traffic observed so far.")

        return "\n".join(summary_lines)
