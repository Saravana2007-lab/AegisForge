"""Static security checks for uploaded AI-agent source/configuration files.

This module never executes uploaded content and does not persist uploaded files.
Findings are heuristic indicators, not proof that a file is vulnerable or safe.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 1_000_000  # 1 MB
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".txt", ".md", ".env", ".example",
}

SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("SECRET_PRIVATE_KEY", "Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("SECRET_AWS_ACCESS_KEY", "Possible AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SECRET_GITHUB_TOKEN", "Possible GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("SECRET_API_TOKEN", "Possible API token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("SECRET_ASSIGNMENT", "Possible hard-coded password, token, or API key", re.compile(
        r"""(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key)\b\s*[:=]\s*["']?([^\s"'#,]{8,})"""
    )),
]

DANGEROUS_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("CODE_EVAL", "HIGH", "Dynamic eval/exec can run untrusted input", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("SHELL_TRUE", "HIGH", "Shell execution with shell=True can enable command injection", re.compile(r"\bshell\s*=\s*True\b")),
    ("OS_SYSTEM", "HIGH", "Direct operating-system command execution", re.compile(r"\bos\.system\s*\(")),
    ("SUBPROCESS_SHELL", "HIGH", "Subprocess command uses a shell", re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\(")),
    ("NODE_CHILD_EXEC", "HIGH", "Node.js child_process command execution", re.compile(r"\b(?:child_process\.)?(?:exec|execSync)\s*\(")),
    ("PICKLE_LOAD", "HIGH", "Deserializing untrusted pickle data can execute code", re.compile(r"\bpickle\.(?:load|loads)\s*\(")),
    ("TLS_VERIFY_DISABLED", "MEDIUM", "TLS certificate verification appears disabled", re.compile(r"\bverify\s*=\s*False\b")),
    ("UNSAFE_YAML_LOAD", "MEDIUM", "yaml.load may be unsafe without a safe loader", re.compile(r"\byaml\.load\s*\(")),
]

PROMPT_INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("PROMPT_OVERRIDE", "Potential prompt-injection instruction to override prior instructions", re.compile(
        r"(?i)\b(ignore|disregard|override)\b.{0,45}\b(previous|prior|system|developer|all)\b.{0,25}\b(instructions|rules|prompt)\b"
    )),
    ("PROMPT_SECRET_REQUEST", "Potential instruction to reveal credentials or hidden prompts", re.compile(
        r"(?i)\b(reveal|print|exfiltrate|send|dump)\b.{0,45}\b(secrets|credentials|api keys|system prompt)\b"
    )),
]

PLACEHOLDERS = {
    "your_api_key", "your-secret", "changeme", "change_me", "example",
    "placeholder", "replace_me", "replace-this", "xxxxxxxx", "********",
}

SEVERITY_POINTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _redact_evidence(line: str) -> str:
    """Redact likely secret values before returning evidence to the browser."""
    redacted = line
    redacted = re.sub(
        r"""(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key)\b\s*[:=]\s*["']?)([^\s"'#,]+)""",
        r"\1[REDACTED]",
        redacted,
    )
    redacted = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]", redacted)
    redacted = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", "[REDACTED_TOKEN]", redacted)
    redacted = re.sub(r"\bsk-[A-Za-z0-9_-]{20,}\b", "[REDACTED_TOKEN]", redacted)
    if "PRIVATE KEY-----" in redacted:
        redacted = re.sub(r"-----BEGIN .*?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", redacted)
    return redacted.strip()[:240]


def _add_finding(
    findings: list[dict[str, Any]],
    *,
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    line_number: int | None = None,
    evidence: str | None = None,
) -> None:
    findings.append({
        "id": f"{rule_id}-{line_number or 'file'}",
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "line": line_number,
        "evidence": evidence,
    })


def _extract_text(filename: str, content: bytes) -> str:
    extension = Path(filename).suffix.lower()
    if extension == ".pdf":
        try:
            from pypdf import PdfReader
            from io import BytesIO
        except ImportError as exc:
            raise ValueError("PDF scanning requires pypdf. Install it with: python -m pip install pypdf") from exc
        try:
            reader = PdfReader(BytesIO(content), strict=True)
            if reader.is_encrypted:
                raise ValueError("Encrypted PDFs are not supported.")
            pages = []
            for page in reader.pages[:100]:
                pages.append(page.extract_text() or "")
            return "\n".join(pages)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("The PDF could not be parsed. It may be malformed or image-only.") from exc

    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("This file is not valid UTF-8 text. Binary files are not supported.") from exc


def scan_file(filename: str, content: bytes) -> dict[str, Any]:
    """Analyze one in-memory file and return a structured, secret-redacted report."""
    if not filename or Path(filename).name != filename or filename in {".", ".."}:
        raise ValueError("Invalid filename.")
    if not content:
        raise ValueError("The uploaded file is empty.")
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("File exceeds the 1 MB limit.")
    extension = Path(filename).suffix.lower()
    if filename.lower() == ".env":
        extension = ".env"
    if extension not in SUPPORTED_EXTENSIONS and extension != ".pdf":
        raise ValueError(
            "Unsupported file type. Supported: Python, JavaScript/TypeScript, JSON, YAML, TOML, INI, TXT, Markdown, ENV, and PDF."
        )

    text = _extract_text(filename, content)
    lines = text.splitlines()
    findings: list[dict[str, Any]] = []

    # Secret checks: never include the detected raw secret in the response.
    for line_number, line in enumerate(lines, start=1):
        lowered = line.lower()
        for rule_id, title, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            # Avoid common obvious placeholders in key/value assignments.
            if rule_id == "SECRET_ASSIGNMENT":
                value = (match.group(1) or "").strip().lower()
                if value in PLACEHOLDERS or value.startswith("your_") or value.startswith("example_"):
                    continue
            _add_finding(
                findings,
                rule_id=rule_id,
                title=title,
                severity="CRITICAL" if rule_id == "SECRET_PRIVATE_KEY" else "HIGH",
                description="A credential-like value appears in the uploaded file. This is a heuristic match and needs review.",
                recommendation="Remove the value from source/configuration, rotate it if real, and load secrets from a secret manager or environment variable.",
                line_number=line_number,
                evidence=_redact_evidence(line),
            )

        for rule_id, severity, title, pattern in DANGEROUS_PATTERNS:
            if pattern.search(line):
                # Refine subprocess rule so a normal subprocess call is not automatically flagged.
                if rule_id == "SUBPROCESS_SHELL" and not re.search(r"\bshell\s*=\s*True\b", line):
                    continue
                _add_finding(
                    findings,
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    description="A code pattern associated with a risky operation was found. Context determines whether it is exploitable.",
                    recommendation={
                        "CODE_EVAL": "Avoid eval/exec on untrusted data. Prefer explicit parsers and allow-listed operations.",
                        "SHELL_TRUE": "Pass commands as argument lists with shell=False and validate all inputs.",
                        "OS_SYSTEM": "Prefer subprocess with an argument list and shell=False; validate arguments.",
                        "SUBPROCESS_SHELL": "If shell execution is unnecessary, use an argument list with shell=False.",
                        "NODE_CHILD_EXEC": "Avoid passing untrusted input to command-execution APIs; use allow-listed arguments.",
                        "PICKLE_LOAD": "Do not load pickle data from untrusted sources; use a data-only format such as JSON.",
                        "TLS_VERIFY_DISABLED": "Enable TLS certificate verification and configure trusted certificates correctly.",
                        "UNSAFE_YAML_LOAD": "Use yaml.safe_load for untrusted YAML, or an explicitly safe loader.",
                    }[rule_id],
                    line_number=line_number,
                    evidence=_redact_evidence(line),
                )

        for rule_id, title, pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(line):
                _add_finding(
                    findings,
                    rule_id=rule_id,
                    title=title,
                    severity="MEDIUM",
                    description="The file contains language resembling a prompt-injection or unsafe agent instruction. Review its role and context.",
                    recommendation="Treat external content as untrusted data. Enforce system policies outside the model and gate sensitive tools through deterministic checks.",
                    line_number=line_number,
                    evidence=_redact_evidence(line),
                )

    # Configuration and agent-tool permission checks.
    lower_text = text.lower()
    wildcard_permission = bool(re.search(
        r"""(?is)(?:permissions?|allowed_tools|allowlist|tool_access)\s*["']?\s*[:=]\s*[\[{]\s*["']?\*["']?""",
        text,
    ))
    if wildcard_permission:
        _add_finding(
            findings,
            rule_id="AGENT_WILDCARD_PERMISSION",
            title="Wildcard or unrestricted tool permission",
            severity="HIGH",
            description="A permission-like configuration appears to grant wildcard access. The exact meaning depends on the configuration schema.",
            recommendation="Replace wildcard access with a minimal allow-list of required tools and require approval for sensitive actions.",
            evidence="A permission/tool-access field appears to include '*'.",
        )

    dangerous_tool_names = {
        "shell", "terminal", "execute_code", "run_command",
        "delete_file", "write_file", "database_drop", "database_delete",
    }
    mentioned = sorted(name for name in dangerous_tool_names if re.search(
        rf"""(?i)["']?{re.escape(name)}["']?""", text
    ))
    if mentioned:
        _add_finding(
            findings,
            rule_id="AGENT_SENSITIVE_TOOLS",
            title="Sensitive tool capability declared or referenced",
            severity="MEDIUM",
            description="The file references one or more tools that can execute commands, modify files, or alter data. This is not necessarily a vulnerability if access is properly constrained.",
            recommendation="Use least-privilege tool registration, validate arguments, log tool calls, and require explicit approval for destructive actions.",
            evidence="Tool names found: " + ", ".join(mentioned[:8]),
        )

    # JSON syntax check is useful, but malformed JSON is not itself a security vulnerability.
    parse_note = None
    if extension == ".json":
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            parse_note = f"JSON syntax issue at line {exc.lineno}, column {exc.colno}."
            _add_finding(
                findings,
                rule_id="JSON_PARSE_ERROR",
                title="Invalid JSON syntax",
                severity="LOW",
                description=parse_note,
                recommendation="Correct the JSON syntax and validate the configuration against its expected schema.",
                line_number=exc.lineno,
                evidence=f"Column {exc.colno}; parser message: {exc.msg[:120]}",
            )

    # Stable ordering and a transparent, illustrative score from detected findings.
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["line"] or 0, item["rule_id"]))
    score = min(100, sum(SEVERITY_POINTS[item["severity"]] for item in findings))
    # A single high/critical finding must not be labeled LOW merely because
    # the aggregate score is still small. The score is additive; severity is
    # a minimum risk floor based on the strongest individual finding.
    if any(item["severity"] == "CRITICAL" for item in findings):
        score = max(score, 70)
    elif any(item["severity"] == "HIGH" for item in findings):
        score = max(score, 40)
    elif any(item["severity"] == "MEDIUM" for item in findings):
        score = max(score, 20)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    counts = {severity: sum(1 for item in findings if item["severity"] == severity)
              for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

    return {
        "filename": filename,
        "file_type": extension.lstrip(".").upper(),
        "bytes_scanned": len(content),
        "lines_scanned": len(lines),
        "risk_score": score,
        "risk_level": level,
        "finding_count": len(findings),
        "severity_counts": counts,
        "findings": findings,
        "notes": [
            "Static heuristic scan only; findings can include false positives and false negatives.",
            "No uploaded code was executed and the uploaded file was not saved by this scanner.",
            "The score is an illustrative prioritization score, not a probability of compromise.",
        ],
        "parse_note": parse_note,
    }
