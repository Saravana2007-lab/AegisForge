from collections.abc import Callable
from typing import Any

ToolFunction = Callable[..., dict[str, Any]]

class ToolRegistry:
    """Stores the tools available to AegisForge."""
    def __init__(self) -> None:
        self._tools: dict[str, ToolFunction] = {}

    def register(self, name: str, function: ToolFunction) -> None:
        if name in self._tools:
            raise ValueError(f"Tool already registered: {name}")
        self._tools[name] = function

    def get(self, name: str) -> ToolFunction | None:
        return self._tools.get(name)

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def list_tools(self) -> list[str]:
        return sorted(self._tools.keys())
