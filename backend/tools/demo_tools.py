def demo_read_file(*, target, arguments):
    """Simulated tool; it does not read the real filesystem."""
    return {"filename": target, "content": "This is simulated demo content.", "simulated": True}
