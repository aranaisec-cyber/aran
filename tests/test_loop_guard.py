import time

from aran.loop_guard import LoopGuard


def test_record_returns_1_for_the_first_call():
    guard = LoopGuard(threshold=5, window_seconds=60)
    assert guard.record("list_files", {}) == 1


def test_record_counts_identical_repeated_calls():
    guard = LoopGuard(threshold=10, window_seconds=60)
    for _ in range(4):
        count = guard.record("list_files", {"path": "/tmp"})
    assert count == 4


def test_different_arguments_are_tracked_separately():
    guard = LoopGuard(threshold=10, window_seconds=60)
    guard.record("list_files", {"path": "/a"})
    guard.record("list_files", {"path": "/a"})
    count_b = guard.record("list_files", {"path": "/b"})
    assert count_b == 1


def test_different_tool_names_are_tracked_separately():
    guard = LoopGuard(threshold=10, window_seconds=60)
    guard.record("list_files", {})
    count = guard.record("fetch", {})
    assert count == 1


def test_would_block_true_once_count_reaches_threshold():
    guard = LoopGuard(threshold=3, window_seconds=60)
    assert guard.would_block(2) is False
    assert guard.would_block(3) is True
    assert guard.would_block(4) is True


def test_calls_outside_the_window_are_not_counted():
    guard = LoopGuard(threshold=100, window_seconds=0.05)
    guard.record("list_files", {})
    guard.record("list_files", {})
    time.sleep(0.1)
    count = guard.record("list_files", {})
    assert count == 1  # the two old ones aged out of the window


def test_argument_order_does_not_matter_for_the_key():
    """A dict with the same key/value pairs in a different insertion order
    must be treated as the same call - json.dumps(sort_keys=True) is what
    makes that true."""
    guard = LoopGuard(threshold=10, window_seconds=60)
    guard.record("run_command", {"a": 1, "b": 2})
    count = guard.record("run_command", {"b": 2, "a": 1})
    assert count == 2


def test_non_json_serializable_arguments_do_not_raise():
    guard = LoopGuard(threshold=10, window_seconds=60)
    count = guard.record("weird_tool", {"obj": object()})
    assert count == 1


def test_tracked_keys_are_capped(monkeypatch):
    from aran import loop_guard as loop_guard_module
    monkeypatch.setattr(loop_guard_module, "_MAX_TRACKED_KEYS", 5)

    guard = LoopGuard(threshold=100, window_seconds=60)
    for i in range(10):
        guard.record("tool", {"i": i})

    assert len(guard._recent) <= 5
