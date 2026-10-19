import json
import logging
import os
import re
from typing import Dict, List, Set, Tuple

logger = logging.getLogger()

# Files/extensions that should be skipped from security review
SKIP_EXTENSIONS = {
    # Images & binary assets
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".jar", ".war",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Compiled / bytecode
    ".pyc", ".pyo", ".pyd", ".class", ".dll", ".exe", ".so", ".dylib",
    # Media
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
}

SKIP_FILENAMES = {
    # Lockfiles
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock",
    "poetry.lock", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock",
    # Config/bundle lock
    "flake.lock", "packages.lock.json",
}

SKIP_PATTERNS = [
    re.compile(r"\.min\.(js|css)$", re.IGNORECASE),
    re.compile(r"\.bundle\.(js|css)$", re.IGNORECASE),
    re.compile(r"\.generated\.", re.IGNORECASE),
    re.compile(r"^(dist|build|vendor|\.git|\.next|\.nuxt)/", re.IGNORECASE),
]

HUNK_HEADER_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def should_skip_file(filename: str, patch: str | None) -> Tuple[bool, str]:
    """
    Check if a file in the PR diff should be skipped from auditing.
    Returns (should_skip, reason).
    """
    if not patch or not patch.strip():
        return True, "No patch content / binary file"

    basename = os.path.basename(filename)
    if basename in SKIP_FILENAMES:
        return True, f"Lockfile ({basename})"

    _, ext = os.path.splitext(filename)
    if ext.lower() in SKIP_EXTENSIONS:
        return True, f"Excluded file extension ({ext})"

    normalized_path = filename.replace("\\", "/")
    for pattern in SKIP_PATTERNS:
        if pattern.search(normalized_path):
            return True, f"Matched skip pattern ({pattern.pattern})"

    return False, ""


def parse_numbered_diff(patch: str) -> Tuple[str, Set[int]]:
    """
    Parses a unified diff patch string.
    Emits a numbered diff where added lines are prefixed with their new-file line numbers.
    Returns:
        - numbered_diff: formatted string of lines with line numbers for added lines
        - added_lines: set of integers containing valid new-file line numbers of additions
    """
    lines = patch.splitlines()
    numbered_lines: List[str] = []
    added_lines: Set[int] = set()

    current_new_line = 0

    for line in lines:
        if line.startswith("@@"):
            match = HUNK_HEADER_PATTERN.match(line)
            if match:
                current_new_line = int(match.group(1))
                numbered_lines.append(f"--- Hunk starting at new line {current_new_line} ---")
            continue

        if not line:
            numbered_lines.append("")
            continue

        prefix = line[0]
        content = line[1:]

        if prefix == "+":
            # Added line in new file
            numbered_lines.append(f"{current_new_line:4d}: + {content}")
            added_lines.add(current_new_line)
            current_new_line += 1
        elif prefix == "-":
            # Removed line in old file (does not increment new file line)
            numbered_lines.append(f"      - {content}")
        else:
            # Context line (space or no prefix)
            numbered_lines.append(f"{current_new_line:4d}:   {content}")
            current_new_line += 1

    return "\n".join(numbered_lines), added_lines
