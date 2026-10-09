from pathlib import Path
from typing import Any

ALLOW = "ALLOW"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
BLOCK = "BLOCK"

APPROVAL_ACTIONS = {"database_delete", "database_drop", "database_truncate"}
SENSITIVE_NAMES = {".ssh", ".aws", ".azure", "secrets", "credentials"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
SENSITIVE_FILES = {".env", "id_rsa", "id_ed25519", "known_hosts"}

def _result(decision: str, reason: str, action: str) -> dict[str, Any]:
    return {"decision": decision, "action": action, "reason": reason}

def _is_sensitive_path(path: Path) -> bool:
    for part in path.parts:
        name = part.lower()
        if name in SENSITIVE_NAMES or name in SENSITIVE_FILES or name.startswith(".env."):
            return True
        if Path(name).suffix in SENSITIVE_SUFFIXES:
            return True
    return False

def evaluate_action(action: str, target: str, project_root: str | Path | None = None) -> dict[str, Any]:
    action = action.strip().lower()
    if not target or not target.strip():
        return _result(BLOCK, "A target must be provided.", action)

    if action == "read_file":
        root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[2]
        try:
            root = root.resolve()
            requested = Path(target)
            if not requested.is_absolute():
                requested = root / requested
            resolved = requested.resolve(strict=False)
            if not resolved.is_relative_to(root):
                return _result(BLOCK, "The requested path is outside the permitted project directory.", action)
            if _is_sensitive_path(resolved):
                return _result(BLOCK, "Access to a protected secret or credential path is prohibited.", action)
            return _result(ALLOW, "File access is permitted by the initial policy.", action)
        except (OSError, RuntimeError, ValueError):
            return _result(BLOCK, "The requested path could not be safely validated.", action)

    if action in APPROVAL_ACTIONS:
        return _result(APPROVAL_REQUIRED, "This destructive database action requires human approval.", action)
    return _result(BLOCK, "The requested action is not recognized or permitted by policy.", action)
