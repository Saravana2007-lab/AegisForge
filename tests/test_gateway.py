from backend.gateway.tool_gateway import ToolGateway
from backend.gateway.tool_registry import ToolRegistry

def make_gateway():
    registry = ToolRegistry()
    def demo_read_file(*, target, arguments):
        return {"filename": target, "content": "Demo content"}
    registry.register("read_file", demo_read_file)
    return ToolGateway(registry)

def test_safe_read_executes():
    result = make_gateway().execute("read_file", "README.md")
    assert result["decision"] == "ALLOW"
    assert result["status"] == "executed"
    assert result["result"]["content"] == "Demo content"

def test_secret_read_never_executes():
    result = make_gateway().execute("read_file", ".env")
    assert result["decision"] == "BLOCK"
    assert result["status"] == "rejected"
    assert result["result"] is None

def test_unknown_tool_never_executes():
    result = make_gateway().execute("unknown_tool", "anything")
    assert result["decision"] == "BLOCK"
    assert result["status"] == "rejected"

def test_database_delete_requires_approval():
    registry = ToolRegistry()
    registry.register("database_delete", lambda *, target, arguments: {"deleted": True})
    result = ToolGateway(registry).execute("database_delete", "users")
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["status"] == "approval_required"
    assert result["result"] is None
