from backend.security.policy_engine import ALLOW, APPROVAL_REQUIRED, BLOCK, evaluate_action

def test_normal_file_read_is_allowed(tmp_path):
    assert evaluate_action("read_file", "notes.txt", project_root=tmp_path)["decision"] == ALLOW

def test_env_file_is_blocked(tmp_path):
    assert evaluate_action("read_file", ".env", project_root=tmp_path)["decision"] == BLOCK

def test_env_local_file_is_blocked(tmp_path):
    assert evaluate_action("read_file", ".env.local", project_root=tmp_path)["decision"] == BLOCK

def test_parent_directory_traversal_is_blocked(tmp_path):
    assert evaluate_action("read_file", "../outside.txt", project_root=tmp_path)["decision"] == BLOCK

def test_absolute_path_outside_project_is_blocked(tmp_path, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "file.txt"
    assert evaluate_action("read_file", str(outside), project_root=tmp_path)["decision"] == BLOCK

def test_database_delete_requires_approval():
    assert evaluate_action("database_delete", "users")["decision"] == APPROVAL_REQUIRED

def test_unknown_action_is_blocked():
    assert evaluate_action("run_shell_command", "anything")["decision"] == BLOCK

def test_empty_target_is_blocked():
    assert evaluate_action("read_file", "   ")["decision"] == BLOCK
