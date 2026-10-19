import logging
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger()

SEVERITY_EMOJIS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}


def format_inline_comment_body(finding: Dict[str, Any]) -> str:
    """Format an inline review comment with severity emoji, CWE tag, explanation, and fix."""
    severity = finding.get("severity", "medium").lower()
    emoji = SEVERITY_EMOJIS.get(severity, "🟡")
    title = finding.get("title", "Security Finding")
    cwe = finding.get("cwe", "CWE-Unknown")
    explanation = finding.get("explanation", "")
    fix = finding.get("fix", "")

    return (
        f"{emoji} **[{severity.upper()}]** {title} ({cwe})\n\n"
        f"{explanation}\n\n"
        f"**Suggested Fix:**\n"
        f"```suggestion\n"
        f"{fix}\n"
        f"```" if fix else f"{emoji} **[{severity.upper()}]** {title} ({cwe})\n\n{explanation}"
    )


def build_review_payload(
    findings_by_file: Dict[str, List[Dict[str, Any]]],
    files_scanned: int,
    files_skipped: int,
    is_truncated: bool,
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Constructs the top-level review summary body and the list of inline comments.
    Returns (summary_body_markdown, comments_list).
    """
    comments: List[Dict[str, Any]] = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_findings = 0

    for path, findings in findings_by_file.items():
        for finding in findings:
            sev = finding.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["low"] += 1
            total_findings += 1

            line_no = finding.get("line")
            if line_no and isinstance(line_no, int):
                comments.append({
                    "path": path,
                    "line": line_no,
                    "side": "RIGHT",
                    "body": format_inline_comment_body(finding),
                })

    # Build markdown summary table
    summary_lines = [
        "## 🛡️ Automated Code Review & Security Audit",
        "",
    ]

    if total_findings == 0:
        summary_lines.append("✅ **No security vulnerabilities or policy violations detected.**")
    else:
        summary_lines.extend([
            f"⚠️ **Found {total_findings} security finding(s) across reviewed files.**",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| 🔴 Critical | {severity_counts['critical']} |",
            f"| 🟠 High | {severity_counts['high']} |",
            f"| 🟡 Medium | {severity_counts['medium']} |",
            f"| 🔵 Low | {severity_counts['low']} |",
        ])

    summary_lines.extend([
        "",
        "---",
        f"📊 **Files Scanned:** {files_scanned} | **Files Skipped:** {files_skipped}",
    ])

    if is_truncated:
        summary_lines.append("\n> ⚠️ **Note:** Diff size exceeded the maximum configured limit. Remaining files were skipped.")

    summary_body = "\n".join(summary_lines)
    return summary_body, comments
