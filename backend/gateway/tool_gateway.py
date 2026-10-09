from typing import Any
from backend.gateway.tool_registry import ToolRegistry
from backend.security.policy_engine import ALLOW, APPROVAL_REQUIRED, BLOCK, evaluate_action

class ToolGateway:
    """Checks policy before dispatching a registered tool."""
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def execute(self, tool_name: str, target: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.registry.has_tool(tool_name):
            return {"decision": BLOCK, "action": tool_name, "status": "rejected", "reason": "Unknown tool.", "result": None}

        policy = evaluate_action(tool_name, target)
        if policy["decision"] == BLOCK:
            return {**policy, "status": "rejected", "result": None}
        if policy["decision"] == APPROVAL_REQUIRED:
            return {**policy, "status": "approval_required", "result": None}
        if policy["decision"] != ALLOW:
            return {"decision": BLOCK, "action": tool_name, "status": "rejected", "reason": "Unexpected policy decision.", "result": None}

        tool = self.registry.get(tool_name)
        if tool is None:
            return {**policy, "status": "rejected", "result": None, "reason": "Registered tool could not be loaded."}
        try:
            result = tool(target=target, arguments=arguments or {})
            return {**policy, "status": "executed", "result": result}
        except Exception:
            return {**policy, "status": "error", "result": None, "reason": "Tool execution failed."}
